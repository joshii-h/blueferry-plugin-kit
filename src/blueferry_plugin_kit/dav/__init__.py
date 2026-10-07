"""WebDAV and CalDAV clients.

* :mod:`.webdav`: PROPFIND, MKCOL, PUT/GET streamed, Nextcloud chunked
  upload v2 and OCS public links, DNS-rebinding-safe plain HTTP on the LAN
  (extra ``dav``).
* :mod:`.caldav`: RFC 6764/4791 discovery with a host allowlist, Basic and
  Digest login, ``calendar-query`` REPORT (extra ``dav``).
* :mod:`.ical`: recurring events and time zones expanded into the
  occurrences of a window (extra ``caldav``).

The modules import without their extras; the first call that needs a
missing library raises :class:`blueferry_plugin_kit.MissingExtraError`.
"""
from __future__ import annotations

from blueferry_plugin_kit.dav.caldav import CalDavClient, CalDavError, CalendarInfo
from blueferry_plugin_kit.dav.ical import Occurrence, local_zone, occurrences
from blueferry_plugin_kit.dav.webdav import DavError, Entry, WebDavClient

__all__ = [
    "CalDavClient",
    "CalDavError",
    "CalendarInfo",
    "DavError",
    "Entry",
    "Occurrence",
    "WebDavClient",
    "local_zone",
    "occurrences",
]
