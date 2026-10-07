"""Test doubles for plugin test suites.

* :class:`FakeHost`: the BlueFerry core side of the plugin API (the 1.2
  surfaces card, share, notify and the 1.3 settings helpers TestConfig and
  ConfigLogin), checking every reply against the spec.
* :class:`FakeClipboard`, :class:`FakeSecret` (libsecret) and
  :func:`isolate_environment` for ``conftest.py``.
* :class:`TestCA` (:mod:`.ca`, extra ``lanserver``): a throwaway CA with a
  matching client context.
* :class:`DavServer`/:class:`WsgiServer` (:mod:`.davserver`, extra
  ``testing``): a real WebDAV server on 127.0.0.1, any WSGI app over
  http or (with a ``TestCA``) https.
* :class:`FakeNextcloudLogin` (:mod:`.nextcloud`): Nextcloud Login Flow v2
  as a WSGI app.
* :func:`check_versions` (:mod:`.versions`): manifest, pyproject and
  ``__version__`` name the same version.

The extras are imported on first use, so this package imports without them.
"""
from __future__ import annotations

from blueferry_plugin_kit.testing.ca import TestCA
from blueferry_plugin_kit.testing.davserver import DavServer, WsgiServer
from blueferry_plugin_kit.testing.fakes import FakeClipboard, FakeSecret, isolate_environment
from blueferry_plugin_kit.testing.host import FakeHost, SpecViolation
from blueferry_plugin_kit.testing.nextcloud import FakeNextcloudLogin
from blueferry_plugin_kit.testing.versions import check_versions

__all__ = [
    "DavServer",
    "FakeClipboard",
    "FakeHost",
    "FakeNextcloudLogin",
    "FakeSecret",
    "SpecViolation",
    "TestCA",
    "WsgiServer",
    "check_versions",
    "isolate_environment",
]
