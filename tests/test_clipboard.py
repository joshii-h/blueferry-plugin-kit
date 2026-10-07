"""The clipboard helpers (from blueferry-plugin-shortcuts and -webdav)."""
from __future__ import annotations

import subprocess

import pytest

from blueferry_plugin_kit.clipboard import (
    Clipboard,
    ClipboardError,
    copy_to_clipboard,
    helper_environment,
)


class _Runner:
    def __init__(self, help_text="  --sensitive  Hint", returncode=0, stdout=b"") -> None:
        self.calls = []
        self.help_text = help_text
        self.returncode = returncode
        self.stdout = stdout

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[-1] == "--help":
            return subprocess.CompletedProcess(argv, 0, self.help_text, "")
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, b"")


def _clipboard(runner, environ=None) -> Clipboard:
    environ = environ or {"WAYLAND_DISPLAY": "wayland-0", "PATH": "/usr/bin",
                          "SECRET_ENV": "x", "LC_ALL": "C"}
    return Clipboard(environ=environ, which=lambda name: f"/usr/bin/{name}", run=runner)


def test_copy_uses_stdin_sensitive_hint_and_clean_environment() -> None:
    runner = _Runner()
    assert _clipboard(runner).copy_text("geheim") is True
    argv, kwargs = runner.calls[-1]
    assert argv == ["/usr/bin/wl-copy", "--type", "text/plain;charset=utf-8", "--sensitive"]
    assert kwargs["input"] == b"geheim" and "geheim" not in " ".join(argv)
    assert kwargs["stdout"] == subprocess.DEVNULL
    assert "SECRET_ENV" not in kwargs["env"] and kwargs["env"]["LC_ALL"] == "C"


def test_copy_without_sensitive_support_and_failures() -> None:
    runner = _Runner(help_text="usage")
    assert _clipboard(runner).copy(b"\x89PNG", "image/png") is False
    assert "--sensitive" not in runner.calls[-1][0]
    with pytest.raises(ClipboardError):
        _clipboard(_Runner(returncode=1)).copy_text("x")
    missing = Clipboard(environ={"WAYLAND_DISPLAY": "w"}, which=lambda name: None)
    with pytest.raises(ClipboardError, match="not installed"):
        missing.copy_text("x")


def test_read_text_limits() -> None:
    assert _clipboard(_Runner(stdout="äöü".encode())).read_text(100) == "äöü"
    assert _clipboard(_Runner(stdout=b"x" * 11)).read_text(10) is None
    assert _clipboard(_Runner(returncode=1)).read_text(10) == ""


def test_wayland_socket_discovery(tmp_path) -> None:
    import socket

    runtime = tmp_path / "run"
    runtime.mkdir()
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(runtime / "wayland-1"))
        env = helper_environment({"XDG_RUNTIME_DIR": str(runtime)})
        assert env is not None and env["WAYLAND_DISPLAY"] == "wayland-1"
    assert helper_environment({"XDG_RUNTIME_DIR": str(tmp_path / "none")}) is None


def _which(name: str) -> str:
    return f"/usr/bin/{name}"


def test_clipboard_uses_stdin_sensitive_hint_and_a_clean_environment() -> None:
    import subprocess

    runner = _Runner()
    environ = {"WAYLAND_DISPLAY": "wayland-0", "PATH": "/usr/bin", "SECRET_ENV": "x",
               "LC_ALL": "C"}
    assert copy_to_clipboard("https://cloud/s/abc", environ=environ, which=_which, run=runner)
    argv, kwargs = runner.calls[-1]
    assert argv == ["/usr/bin/wl-copy", "--type", "text/plain;charset=utf-8", "--sensitive"]
    assert kwargs["input"] == b"https://cloud/s/abc" and kwargs["stdout"] == subprocess.DEVNULL
    assert "SECRET_ENV" not in kwargs["env"] and kwargs["env"]["LC_ALL"] == "C"


def test_clipboard_finds_the_wayland_socket_and_falls_back_to_x11(tmp_path) -> None:
    import socket

    
    runtime = tmp_path / "run"
    runtime.mkdir()
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(runtime / "wayland-1"))
        env = helper_environment({"XDG_RUNTIME_DIR": str(runtime)})
        assert env is not None and env["WAYLAND_DISPLAY"] == "wayland-1"
    assert helper_environment({"XDG_RUNTIME_DIR": str(tmp_path / "none")}) is None
    runner = _Runner()
    x11 = {"DISPLAY": ":0", "XAUTHORITY": "/tmp/xa", "SECRET_ENV": "x",
           "XDG_RUNTIME_DIR": str(tmp_path / "none")}
    assert copy_to_clipboard("link", environ=x11, which=_which, run=runner)
    argv, kwargs = runner.calls[-1]
    assert argv[0] == "/usr/bin/xclip" and kwargs["input"] == b"link"
    assert kwargs["env"] == {"DISPLAY": ":0", "XAUTHORITY": "/tmp/xa"}
    assert not copy_to_clipboard("link", environ={}, which=_which, run=runner)
