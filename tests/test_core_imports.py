"""The core imports without any extra; extras fail with a clear message."""
from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

from blueferry_plugin_kit import MissingExtraError
from blueferry_plugin_kit._extras import need

HEAVY = (
    "cryptography", "defusedxml", "icalendar", "recurring_ical_events", "x_wr_timezone",
    "wsgidav", "cheroot",
)


def _run(code: str) -> subprocess.CompletedProcess:
    blocker = textwrap.dedent(f"""
        import importlib.abc, sys
        class Block(importlib.abc.MetaPathFinder):
            def find_spec(self, name, path=None, target=None):
                if name.split(".")[0] in {HEAVY!r}:
                    raise ImportError("blocked: " + name)
        sys.meta_path.insert(0, Block())
    """)
    return subprocess.run(
        [sys.executable, "-c", blocker + textwrap.dedent(code)],
        capture_output=True, text=True, timeout=60, check=False,
    )


def test_every_module_imports_without_extras() -> None:
    result = _run("""
        import blueferry_plugin_kit
        from blueferry_plugin_kit import (
            auth, clipboard, dav, lanserver, netaddr, secrets, testing, xmlsafe,
        )
        from blueferry_plugin_kit.dav import caldav, ical, webdav
        from blueferry_plugin_kit.lanserver import http, limits, tls
        from blueferry_plugin_kit.testing import ca, davserver, fakes, host
        loaded = [m for m in sys.modules if m.split(".")[0] in {HEAVY!r}]
        assert not loaded, loaded
        print("ok")
    """.replace("{HEAVY!r}", repr(HEAVY)))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


@pytest.mark.parametrize("call,extra", [
    ("from blueferry_plugin_kit import xmlsafe; xmlsafe.fromstring(b'<x/>')", "xml"),
    ("from blueferry_plugin_kit.lanserver.tls import CertificateStore;"
     "import pathlib, tempfile; CertificateStore(pathlib.Path(tempfile.mkdtemp())).ensure([])",
     "lanserver"),
    ("from blueferry_plugin_kit.dav.ical import occurrences; import datetime as d;"
     "n = d.datetime.now(d.timezone.utc); occurrences([], n, n, d.timezone.utc)", "caldav"),
    ("from blueferry_plugin_kit.testing import DavServer; import pathlib, tempfile;"
     "DavServer(pathlib.Path(tempfile.mkdtemp()), 'u', 'p')", "testing"),
])
def test_a_missing_extra_names_itself(call, extra) -> None:
    result = _run(call)
    assert result.returncode != 0
    assert f"install blueferry-plugin-kit[{extra}]" in result.stderr


def test_need() -> None:
    assert need("json", "none").dumps(1) == "1"
    with pytest.raises(MissingExtraError) as caught:
        need("blueferry_plugin_kit_no_such_module", "dav")
    assert caught.value.extra == "dav" and isinstance(caught.value, ImportError)
