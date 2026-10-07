"""Small doubles: the clipboard, libsecret, and an isolated environment."""
from __future__ import annotations

import os
import tempfile
from collections.abc import Iterable
from typing import Any


class FakeClipboard:
    """Stands in for :class:`blueferry_plugin_kit.clipboard.Clipboard`.

    :attr:`copies` records ``(data, mime)``; :attr:`current` is what
    :meth:`read_text` returns.
    """

    def __init__(self, current: str = "") -> None:
        self.copies: list[tuple[bytes, str]] = []
        self.current = current

    def copy(self, data: bytes, mime: str) -> bool:
        self.copies.append((data, mime))
        return True

    def copy_text(self, text: str) -> bool:
        return self.copy(text.encode(), "text/plain;charset=utf-8")

    def read_text(self, limit: int) -> str | None:
        data = self.current.encode()
        return None if len(data) > limit else self.current


class FakeSecret:
    """Stands in for ``gi.repository.Secret`` (libsecret's simple API).

    ``fail=True`` makes storing fail and lookups raise, like a locked or
    missing keyring. :attr:`items` maps ``(schema, attributes)`` to values.
    """

    COLLECTION_DEFAULT = "default"

    class SchemaFlags:
        NONE = 0

    class SchemaAttributeType:
        STRING = 0

    class Schema:
        @staticmethod
        def new(name: str, _flags: Any, _attributes: Any) -> str:
            return name

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.items: dict[tuple[str, tuple[tuple[str, str], ...]], str] = {}
        self.labels: list[str] = []

    @staticmethod
    def _key(schema: str, attributes: dict[str, str]) -> tuple:
        return schema, tuple(sorted(attributes.items()))

    def password_store_sync(self, schema, attributes, _collection, label, value, _cancel):
        if self.fail:
            raise RuntimeError("keyring locked")
        self.items[self._key(schema, attributes)] = value
        self.labels.append(label)
        return True

    def password_lookup_sync(self, schema, attributes, _cancel):
        if self.fail:
            raise RuntimeError("keyring locked")
        return self.items.get(self._key(schema, attributes))

    def password_clear_sync(self, schema, attributes, _cancel):
        return self.items.pop(self._key(schema, attributes), None) is not None


def isolate_environment(
    prefix: str, *, keep: Iterable[str] = (), bus_name: str | None = None,
) -> str:
    """Point XDG directories at a scratch tree and cut off bus and display.

    Call it at import time of a ``conftest.py``, before the plugin is
    imported. ``keep`` names variables not to remove (``WAYLAND_DISPLAY``,
    ``DISPLAY``). Returns the scratch directory.
    """
    scratch = tempfile.mkdtemp(prefix=prefix)
    for variable in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"):
        os.environ[variable] = os.path.join(scratch, variable.lower())
        os.makedirs(os.environ[variable], mode=0o700, exist_ok=True)
    os.environ["XDG_DATA_DIRS"] = os.path.join(scratch, "system")
    os.environ["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/nonexistent/{bus_name or prefix}"
    for variable in ("WAYLAND_DISPLAY", "DISPLAY"):
        if variable not in keep:
            os.environ.pop(variable, None)
    return scratch
