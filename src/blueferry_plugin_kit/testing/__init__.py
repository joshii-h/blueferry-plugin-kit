"""Test doubles for plugin test suites.

* :class:`FakeHost`: the BlueFerry core side of PLUGIN-SURFACES v1.2
  (card, share, notify), checking every reply against the spec.
* :class:`FakeClipboard`, :class:`FakeSecret` (libsecret) and
  :func:`isolate_environment` for ``conftest.py``.
* :class:`TestCA` (:mod:`.ca`, extra ``lanserver``): a throwaway CA with a
  matching client context.
* :class:`DavServer`/:class:`WsgiServer` (:mod:`.davserver`, extra
  ``testing``): a real WebDAV server on 127.0.0.1.

The extras are imported on first use, so this package imports without them.
"""
from __future__ import annotations

from blueferry_plugin_kit.testing.ca import TestCA
from blueferry_plugin_kit.testing.davserver import DavServer, WsgiServer
from blueferry_plugin_kit.testing.fakes import FakeClipboard, FakeSecret, isolate_environment
from blueferry_plugin_kit.testing.host import FakeHost, SpecViolation

__all__ = [
    "DavServer",
    "FakeClipboard",
    "FakeHost",
    "FakeSecret",
    "SpecViolation",
    "TestCA",
    "WsgiServer",
    "isolate_environment",
]
