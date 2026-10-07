"""Owner-only files and the desktop keyring, with a 0600 file as fallback.

Plugins keep their configuration in ``~/.config/blueferry/plugins/<id>/``.
Everything there is written atomically (temporary file, ``fchmod 0600``,
rename) into a directory that must be the user's own and ``0700``; reading
refuses symlinks, other owners, group or world access and oversized files.

Secrets (passwords, API keys, tokens) go to the Secret Service through
libsecret. Without a usable keyring they fall back to an owner-only file
next to the config. :class:`KeyringStore` is the base class for a plugin's
settings store; it never logs a secret and never puts one on a command line.
"""
from __future__ import annotations

import os
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any, ClassVar

MAX_FILE_BYTES = 16 * 1024


class SecretsError(Exception):
    """A private file or the keyring is unusable; the message names no secret."""


def config_dir(plugin_id: str) -> Path:
    """``$XDG_CONFIG_HOME/blueferry/plugins/<plugin_id>``."""
    config_home = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    return Path(config_home) / "blueferry" / "plugins" / plugin_id


def state_dir(plugin_id: str) -> Path:
    """``$XDG_STATE_HOME/blueferry/plugins/<plugin_id>``."""
    state_home = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state"
    )
    return Path(state_home) / "blueferry" / "plugins" / plugin_id


def private_dir(path: Path, what: str = "config directory") -> Path:
    """Create ``path`` (0700) or check that it is the user's own directory."""
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise SecretsError(f"{what} has the wrong owner or type")
    path.chmod(0o700)
    return path


def write_private(path: Path, data: str | bytes, *, what: str = "config directory") -> None:
    """Replace ``path`` atomically with an owner-only file holding ``data``.

    ``what`` names the parent directory in the error message.
    """
    private_dir(path.parent, what)
    descriptor, temporary = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data.encode("utf-8") if isinstance(data, str) else data)
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        Path(temporary).unlink(missing_ok=True)


def _open_private(path: Path, mode: str) -> Any:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    if "b" in mode:
        stream = os.fdopen(descriptor, mode)
    else:
        stream = os.fdopen(descriptor, mode, encoding="utf-8")
    try:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise SecretsError(f"{path.name} has the wrong owner or type")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise SecretsError(f"{path.name} is readable by other users")
    except BaseException:
        stream.close()
        raise
    return stream


def read_private(path: Path, limit: int = MAX_FILE_BYTES) -> bytes:
    """The bytes of an owner-only file of at most ``limit`` bytes.

    ``FileNotFoundError`` passes through; anything unsafe raises
    :class:`SecretsError`.
    """
    with _open_private(path, "rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise SecretsError(f"{path.name} is too large")
    return data


def read_private_text(path: Path, limit: int = MAX_FILE_BYTES) -> str:
    """Like :func:`read_private`, as UTF-8 text of at most ``limit`` characters."""
    with _open_private(path, "r") as stream:
        text = stream.read(limit + 1)
    if len(text) > limit:
        raise SecretsError(f"{path.name} is too large")
    return text


def check_private(path: Path) -> None:
    """Raise :class:`SecretsError` unless ``path`` is the user's 0600 file."""
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise SecretsError(f"{path.name} has the wrong owner or type")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise SecretsError(f"{path.name} is readable by other users")


def load_secret_module() -> Any:
    """``gi.repository.Secret``, or None without libsecret's introspection data."""
    try:
        import gi

        gi.require_version("Secret", "1")
        from gi.repository import Secret
    except (ImportError, ValueError):
        return None
    return Secret


class KeyringStore:
    """Base class for a settings store with one secret per account.

    Subclasses set :attr:`SECRET_SCHEMA`, :attr:`SECRET_ATTRIBUTES` (the
    names of the string attributes that identify the account, e.g.
    ``("server", "user")``) and :attr:`SECRET_LABEL`, and define
    :attr:`key_path`, the fallback file. ``secret`` replaces
    ``gi.repository.Secret`` (tests pass
    :class:`blueferry_plugin_kit.testing.FakeSecret`).
    """

    SECRET_SCHEMA: ClassVar[str] = ""
    SECRET_ATTRIBUTES: ClassVar[tuple[str, ...]] = ("server", "user")
    SECRET_LABEL: ClassVar[str] = ""

    def __init__(self, directory: Path, *, secret: Any = None) -> None:
        self.directory = directory
        self._secret = secret

    @property
    def key_path(self) -> Path:
        return self.directory / "password"

    # ---- secret, keyring first --------------------------------------------

    def save_secret(
        self, attributes: Mapping[str, str], value: str, *, prefer_keyring: bool = True,
    ) -> str:
        """Store ``value``; return ``"keyring"`` or ``"file"``.

        The keyring wins and removes an old fallback file; the file is the
        fallback when the keyring is unusable or not wanted.
        """
        if prefer_keyring and self._store_keyring(attributes, value):
            self.key_path.unlink(missing_ok=True)
            return "keyring"
        write_private(self.key_path, value + "\n")
        return "file"

    def load_secret(
        self, key_store: str, attributes: Mapping[str, str], *, missing: str, empty: str,
        strip: bool = False,
    ) -> str:
        """The stored secret; raise :class:`SecretsError` with ``missing``
        (no fallback file) or ``empty`` (nothing stored)."""
        if key_store == "file":
            try:
                text = read_private_text(self.key_path)
            except FileNotFoundError:
                raise SecretsError(missing) from None
            value = text.strip() if strip else text.rstrip("\n")
        else:
            value = self._lookup_keyring(attributes)
        if not value:
            raise SecretsError(empty)
        return value

    def clear_keyring(self, attributes: Mapping[str, str]) -> None:
        """Drop a keyring entry; best effort."""
        secret = self._module()
        if secret is None:
            return
        try:
            secret.password_clear_sync(self._schema(secret), dict(attributes), None)
        except Exception:  # nosec B110 - best effort
            pass

    # ---- libsecret ----------------------------------------------------------

    def _module(self) -> Any:
        if self._secret is not None:
            return self._secret
        secret = load_secret_module()
        if secret is not None:
            self._secret = secret
        return secret

    @classmethod
    def _schema(cls, secret: Any) -> Any:
        return secret.Schema.new(cls.SECRET_SCHEMA, secret.SchemaFlags.NONE, {
            name: secret.SchemaAttributeType.STRING for name in cls.SECRET_ATTRIBUTES
        })

    def _store_keyring(self, attributes: Mapping[str, str], value: str) -> bool:
        secret = self._module()
        if secret is None:
            return False
        try:
            return bool(secret.password_store_sync(
                self._schema(secret), dict(attributes), secret.COLLECTION_DEFAULT,
                self.SECRET_LABEL, value, None,
            ))
        except Exception:
            return False

    def _lookup_keyring(self, attributes: Mapping[str, str]) -> str:
        secret = self._module()
        if secret is None:
            raise SecretsError("no Secret Service client is installed")
        try:
            value = secret.password_lookup_sync(self._schema(secret), dict(attributes), None)
        except Exception:
            raise SecretsError("the desktop keyring is locked or unavailable") from None
        return str(value or "")
