from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from blueferry_plugin_kit.secrets import (
    KeyringStore,
    SecretsError,
    check_private,
    config_dir,
    private_dir,
    read_private,
    read_private_text,
    state_dir,
    write_private,
)
from blueferry_plugin_kit.testing import FakeSecret


class Store(KeyringStore):
    SECRET_SCHEMA = "io.weirdware.blueferry.test.Password"
    SECRET_ATTRIBUTES = ("server", "user")
    SECRET_LABEL = "BlueFerry test password"


ACCOUNT = {"server": "https://dav.example.org/", "user": "alice"}


def test_directories_follow_xdg(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "c"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "s"))
    assert config_dir("io.x.y") == tmp_path / "c" / "blueferry" / "plugins" / "io.x.y"
    assert state_dir("io.x.y") == tmp_path / "s" / "blueferry" / "plugins" / "io.x.y"


def test_private_files_are_owner_only_and_atomic(tmp_path) -> None:
    path = tmp_path / "conf" / "config.json"
    write_private(path, "äöü\n")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    assert read_private(path) == "äöü\n".encode()
    assert read_private_text(path) == "äöü\n"
    write_private(path, b"\x00\x01")
    assert read_private(path) == b"\x00\x01"
    assert [p.name for p in path.parent.iterdir()] == ["config.json"]  # no temporaries left
    check_private(path)


def test_unsafe_files_are_refused(tmp_path) -> None:
    path = tmp_path / "conf" / "secret"
    write_private(path, "x" * 20)
    with pytest.raises(SecretsError, match="too large"):
        read_private(path, limit=10)
    with pytest.raises(SecretsError, match="too large"):
        read_private_text(path, limit=10)
    path.chmod(0o644)
    for reader in (read_private, read_private_text, check_private):
        with pytest.raises(SecretsError, match="readable by other users"):
            reader(path)
    link = tmp_path / "conf" / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        read_private(link)
    with pytest.raises(SecretsError, match="wrong owner or type"):
        check_private(link)
    with pytest.raises(FileNotFoundError):
        read_private(tmp_path / "conf" / "missing")
    with pytest.raises(SecretsError, match="identity directory has the wrong"):
        private_dir(_symlink_dir(tmp_path), "identity directory")


def _symlink_dir(tmp_path: Path) -> Path:
    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(target, target_is_directory=True)
    return link


def test_secret_falls_back_to_an_owner_only_file(tmp_path) -> None:
    store = Store(tmp_path / "conf", secret=None)
    store._module = lambda: None  # no libsecret
    assert store.save_secret(ACCOUNT, "k3y ") == "file"
    assert stat.S_IMODE(store.key_path.stat().st_mode) == 0o600
    assert store.load_secret("file", ACCOUNT, missing="m", empty="e") == "k3y "
    assert store.load_secret("file", ACCOUNT, missing="m", empty="e", strip=True) == "k3y"
    store.key_path.chmod(0o644)
    with pytest.raises(SecretsError, match="readable by other users"):
        store.load_secret("file", ACCOUNT, missing="m", empty="e")
    store.key_path.unlink()
    with pytest.raises(SecretsError, match=r"^gone$"):
        store.load_secret("file", ACCOUNT, missing="gone", empty="e")
    with pytest.raises(SecretsError, match="no Secret Service client"):
        store.load_secret("keyring", ACCOUNT, missing="m", empty="e")


def test_secret_prefers_the_keyring(tmp_path) -> None:
    secret = FakeSecret()
    store = Store(tmp_path / "conf", secret=secret)
    write_private(store.key_path, "old\n")
    assert store.save_secret(ACCOUNT, "pw") == "keyring"
    assert not store.key_path.exists()
    assert secret.labels == ["BlueFerry test password"]
    assert store.load_secret("keyring", ACCOUNT, missing="m", empty="e") == "pw"
    with pytest.raises(SecretsError, match=r"^empty$"):
        store.load_secret("keyring", {**ACCOUNT, "user": "bob"}, missing="m", empty="empty")
    assert store.save_secret(ACCOUNT, "pw2", prefer_keyring=False) == "file"
    store.clear_keyring(ACCOUNT)
    assert secret.items == {}


def test_a_locked_keyring_is_reported_without_details(tmp_path) -> None:
    store = Store(tmp_path / "conf", secret=FakeSecret(fail=True))
    assert store.save_secret(ACCOUNT, "pw") == "file"
    with pytest.raises(SecretsError, match="locked or unavailable"):
        store.load_secret("keyring", ACCOUNT, missing="m", empty="e")
    store.clear_keyring(ACCOUNT)  # best effort, no error
