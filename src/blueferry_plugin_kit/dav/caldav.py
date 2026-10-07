"""A small CalDAV client: discovery and one ``calendar-query`` REPORT.

Needs the ``dav`` extra (defusedxml); expanding the returned objects into
occurrences is :mod:`blueferry_plugin_kit.dav.ical` (extra ``caldav``).

Discovery follows RFC 6764 and RFC 4791:

1. ``PROPFIND`` (Depth 0) for ``DAV:current-user-principal`` on the URL the
   user gave, else on ``/.well-known/caldav`` (redirects are followed with
   the method kept), else on ``/``.
2. ``PROPFIND`` (Depth 0) on the principal for ``C:calendar-home-set``.
3. ``PROPFIND`` (Depth 1) on the home set for the calendars (collections
   whose resource type is ``C:calendar`` and that hold ``VEVENT``).

Events come from ``REPORT calendar-query`` with a ``time-range`` filter; the
server returns whole objects (recurring masters included) and the caller
expands them locally (:func:`blueferry_plugin_kit.dav.ical.occurrences`),
because server-side expansion is patchy (iCloud).

Every request has a timeout, every body a size limit. Credentials go only
to https URLs (http only on loopback) whose host is on an explicit
allowlist: the configured host, plus the hosts the user confirmed during
setup (iCloud's ``caldav.icloud.com`` hands out ``pNN-caldav.icloud.com``).
A redirect or an href to any other host stops with ``foreign-host`` and
names the host, before a request goes there. Basic and Digest
authentication (Baikal's default) are supported.
Errors are short tokens; nothing a server sends is logged.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import ipaddress
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from blueferry_plugin_kit import __version__, xmlsafe
from blueferry_plugin_kit.xmlsafe import Element

TIMEOUT_SEC = 15.0
MAX_XML_BYTES = 8 * 1024 * 1024
MAX_REDIRECTS = 5
MAX_CALENDARS = 64
DAV = "DAV:"
CALDAV = "urn:ietf:params:xml:ns:caldav"
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_REDIRECTS = {301, 302, 303, 307, 308}


class CalDavError(Exception):
    """``token`` is one of: unauthorized, forbidden, not-found, server-error,
    network, too-large, bad-response, redirect, foreign-host, invalid-url,
    no-principal, no-calendars."""

    def __init__(self, token: str, host: str = "") -> None:
        super().__init__(token)
        self.token = token
        self.host = host  # for foreign-host: the host that was not allowed


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    headers: Mapping[str, str]   # lower-case names; repeated headers joined by "\n"
    body: bytes
    url: str


Send = Callable[[str, str, Mapping[str, str], "bytes | None", float], Response]


@dataclass(frozen=True, slots=True)
class CalendarInfo:
    url: str     # absolute collection URL
    name: str    # display name (untrusted text)


# ---- URLs --------------------------------------------------------------------


def normalize_url(raw: str) -> str:
    """The server URL: https (http only on loopback), no credentials."""
    value = raw.strip()
    if value and "://" not in value:
        value = "https://" + value
    parts = urllib.parse.urlsplit(value)
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("https", "http") or not host:
        raise CalDavError("invalid-url")
    if parts.scheme == "http" and host not in _LOOPBACK:
        raise CalDavError("invalid-url")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise CalDavError("invalid-url")
    path = parts.path or "/"
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def host_of(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")


_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*$")


def valid_host(value: str) -> bool:
    """A DNS name or an IP address, nothing else (no port, no scheme)."""
    value = value.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return len(value) <= 253 and bool(_HOST.fullmatch(value))


def split_hosts(value: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(
        part.strip().lower().rstrip(".") for part in value.replace(";", ",").split(",")
        if part.strip()
    ))


def _allowed(url: str, base: str, hosts: frozenset[str]) -> bool:
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.username or parts.password:
        return False
    if parts.scheme == "http":
        return host in _LOOPBACK and host == host_of(base)
    if parts.scheme != "https" or not host:
        return False
    return host in hosts


# ---- transport -----------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None  # the client follows redirects itself, keeping the method


# Without an explicit ProxyHandler, urllib takes http(s)_proxy from the
# environment, and the login (Basic or Digest) would pass through whatever
# proxy the session happens to have. Direct unless the user opts in.
_direct = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def urllib_send(
    method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float,
    *, proxy: bool = False,
) -> Response:
    request = urllib.request.Request(  # nosec B310 - scheme checked by the caller
        url, data=body, method=method, headers=dict(headers),
    )
    # The default ProxyHandler reads the environment when it is built.
    opener = urllib.request.build_opener(_NoRedirect) if proxy else _direct
    try:
        reply = opener.open(request, timeout=timeout)  # nosec B310
    except urllib.error.HTTPError as error:
        reply = error
    try:
        data = reply.read(MAX_XML_BYTES + 1)
        status = reply.status if hasattr(reply, "status") else reply.code
        merged: dict[str, str] = {}
        for name, value in reply.headers.items():
            key = name.lower()
            merged[key] = merged[key] + "\n" + value if key in merged else value
        return Response(int(status), merged, bytes(data), url)
    finally:
        reply.close()


# ---- authentication ------------------------------------------------------------------

_PARAM = re.compile(r'([A-Za-z0-9_-]+)\s*=\s*("((?:[^"\\]|\\.)*)"|[^,\s]*)')


def _challenges(header: str) -> dict[str, dict[str, str]]:
    """``{"basic": {...}, "digest": {...}}`` from WWW-Authenticate values."""
    found: dict[str, dict[str, str]] = {}
    for line in header.split("\n"):
        for match in re.finditer(r"(?:^|,)\s*(Basic|Digest)\b", line, re.IGNORECASE):
            scheme = match.group(1).lower()
            rest = line[match.end():]
            following = re.search(r",\s*(Basic|Digest|Bearer|Negotiate)\b", rest, re.IGNORECASE)
            if following:
                rest = rest[:following.start()]
            params = {
                key.lower(): (quoted if quoted is not None else raw)
                for key, raw, quoted in (
                    (m.group(1), m.group(2), m.group(3)) for m in _PARAM.finditer(rest)
                )
            }
            found.setdefault(scheme, params)
    return found


class _Auth:
    def __init__(self, username: str, password: str) -> None:
        self._username = username
        self._password = password
        self._scheme = ""
        self._digest: dict[str, str] = {}
        self._count = 0

    def ready(self) -> bool:
        return bool(self._scheme)

    def learn(self, header: str) -> bool:
        """Pick a scheme from a 401; False when nothing usable was offered."""
        offered = _challenges(header)
        digest = offered.get("digest")
        if digest and digest.get("nonce") and digest.get("algorithm", "MD5").upper() in (
            "MD5", "SHA-256",
        ) and (not digest.get("qop") or "auth" in digest["qop"].split(",")):
            stale = self._scheme == "digest" and digest.get("stale", "").lower() == "true"
            if self._scheme == "digest" and not stale:
                return False  # the same credentials were already refused
            self._scheme, self._digest, self._count = "digest", digest, 0
            return True
        if "basic" in offered and self._scheme != "basic":
            self._scheme = "basic"
            return True
        return False

    def header(self, method: str, url: str) -> str:
        if self._scheme == "basic":
            token = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
            return "Basic " + token
        challenge = self._digest
        algorithm = challenge.get("algorithm", "MD5").upper()
        digest = hashlib.sha256 if algorithm == "SHA-256" else hashlib.md5

        def h(text: str) -> str:
            return digest(text.encode()).hexdigest()  # nosec B324 - required by RFC 7616

        parts = urllib.parse.urlsplit(url)
        uri = parts.path + (f"?{parts.query}" if parts.query else "")
        realm, nonce = challenge.get("realm", ""), challenge["nonce"]
        ha1 = h(f"{self._username}:{realm}:{self._password}")
        ha2 = h(f"{method}:{uri}")
        self._count += 1
        fields = [
            f'username="{self._username}"', f'realm="{realm}"', f'nonce="{nonce}"',
            f'uri="{uri}"', f"algorithm={algorithm}",
        ]
        if challenge.get("qop"):
            cnonce = os.urandom(8).hex()
            nc = f"{self._count:08x}"
            response = h(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")
            fields += ["qop=auth", f"nc={nc}", f'cnonce="{cnonce}"']
        else:
            response = h(f"{ha1}:{nonce}:{ha2}")
        fields.append(f'response="{response}"')
        if challenge.get("opaque"):
            fields.append(f'opaque="{challenge["opaque"]}"')
        return "Digest " + ", ".join(fields)


# ---- XML -------------------------------------------------------------------------------


def _xml(body: bytes) -> Element:
    """Parse a server answer; any DOCTYPE, wherever it is, is refused."""
    if len(body) > MAX_XML_BYTES:
        raise CalDavError("too-large")
    try:
        return xmlsafe.fromstring(body)
    except xmlsafe.XmlError:
        raise CalDavError("bad-response") from None


def _tag(namespace: str, name: str) -> str:
    return f"{{{namespace}}}{name}"


@dataclass(frozen=True, slots=True)
class _Entry:
    href: str
    props: dict[str, Element]


def _multistatus(root: Element) -> list[_Entry]:
    if root.tag != _tag(DAV, "multistatus"):
        raise CalDavError("bad-response")
    entries = []
    for response in root.findall(_tag(DAV, "response")):
        href = (response.findtext(_tag(DAV, "href")) or "").strip()
        props: dict[str, Element] = {}
        for propstat in response.findall(_tag(DAV, "propstat")):
            status = propstat.findtext(_tag(DAV, "status")) or ""
            if " 200 " not in f"{status} ":
                continue
            prop = propstat.find(_tag(DAV, "prop"))
            for child in prop if prop is not None else ():
                props[child.tag] = child
        if href:
            entries.append(_Entry(href, props))
    return entries


def _href(prop: Element | None) -> str:
    if prop is None:
        return ""
    return (prop.findtext(_tag(DAV, "href")) or "").strip()


_PROPFIND_PRINCIPAL = (
    b'<?xml version="1.0" encoding="utf-8"?>'
    b'<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>'
)
_PROPFIND_HOME = (
    b'<?xml version="1.0" encoding="utf-8"?>'
    b'<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">'
    b"<d:prop><c:calendar-home-set/></d:prop></d:propfind>"
)
_PROPFIND_CALENDARS = (
    b'<?xml version="1.0" encoding="utf-8"?>'
    b'<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">'
    b"<d:prop><d:resourcetype/><d:displayname/><c:supported-calendar-component-set/>"
    b"</d:prop></d:propfind>"
)
_REPORT = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">'
    "<d:prop><d:getetag/><c:calendar-data/></d:prop>"
    '<c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT">'
    '<c:time-range start="{start}" end="{end}"/>'
    "</c:comp-filter></c:comp-filter></c:filter></c:calendar-query>"
)


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# ---- client ----------------------------------------------------------------------------


class CalDavClient:
    def __init__(
        self, url: str, username: str, password: str, *, hosts: tuple[str, ...] = (),
        use_proxy: bool = False, send: Send | None = None, timeout: float = TIMEOUT_SEC,
        user_agent: str = f"blueferry-plugin-kit/{__version__}",
    ) -> None:
        self.url = normalize_url(url)
        # The configured host always; others only when the user allowed them.
        self.hosts = frozenset({host_of(self.url), *(h.lower().rstrip(".") for h in hosts)})
        self.seen_hosts: set[str] = set()
        self._auth = _Auth(username, password)
        self._send = send or functools.partial(urllib_send, proxy=use_proxy)
        self._timeout = timeout
        self.user_agent = user_agent

    def _check(self, url: str) -> None:
        if not _allowed(url, self.url, self.hosts):
            raise CalDavError("foreign-host", host_of(url))

    def _request(
        self, method: str, url: str, body: bytes | None = None, *, depth: str | None = None,
    ) -> Response:
        """One request, with authentication and same-site redirects."""
        for _hop in range(MAX_REDIRECTS + 1):
            self._check(url)
            for _attempt in range(3):
                headers = {
                    "User-Agent": self.user_agent,
                    "Accept": "application/xml, text/xml",
                }
                if body is not None:
                    headers["Content-Type"] = "application/xml; charset=utf-8"
                if depth is not None:
                    headers["Depth"] = depth
                if self._auth.ready():
                    headers["Authorization"] = self._auth.header(method, url)
                try:
                    reply = self._send(method, url, headers, body, self._timeout)
                except CalDavError:
                    raise
                except (urllib.error.URLError, OSError, ValueError):
                    raise CalDavError("network") from None
                if reply.status == 401 and self._auth.learn(
                    reply.headers.get("www-authenticate", ""),
                ):
                    continue
                break
            if reply.status in _REDIRECTS:
                location = reply.headers.get("location", "").split("\n")[0].strip()
                if not location:
                    raise CalDavError("redirect")
                url = urllib.parse.urljoin(url, location)
                continue
            if reply.status == 401:
                raise CalDavError("unauthorized")
            if reply.status == 403:
                raise CalDavError("forbidden")
            if reply.status in (404, 405, 410):
                raise CalDavError("not-found")
            if not 200 <= reply.status < 300:
                raise CalDavError("server-error")
            if len(reply.body) > MAX_XML_BYTES:
                raise CalDavError("too-large")
            self.seen_hosts.add(host_of(url))
            return Response(reply.status, reply.headers, reply.body, url)
        raise CalDavError("redirect")

    def _propfind(self, url: str, body: bytes, depth: str) -> tuple[str, list[_Entry]]:
        reply = self._request("PROPFIND", url, body, depth=depth)
        if reply.status != 207:
            raise CalDavError("bad-response")
        return reply.url, _multistatus(_xml(reply.body))

    def _absolute(self, base: str, href: str) -> str:
        url = urllib.parse.urljoin(base, href)
        self._check(url)
        return url

    # ---- discovery ----------------------------------------------------------

    def principal(self) -> str:
        parts = urllib.parse.urlsplit(self.url)
        origin = f"{parts.scheme}://{parts.netloc}"
        candidates = []
        if parts.path not in ("", "/"):
            candidates.append(self.url)
        candidates += [origin + "/.well-known/caldav", origin + "/"]
        last = CalDavError("no-principal")
        for candidate in candidates:
            try:
                where, entries = self._propfind(candidate, _PROPFIND_PRINCIPAL, "0")
            except CalDavError as error:
                if error.token in ("unauthorized", "forbidden", "network", "foreign-host"):
                    raise
                last = error
                continue
            for entry in entries:
                href = _href(entry.props.get(_tag(DAV, "current-user-principal")))
                if href:
                    return self._absolute(where, href)
            last = CalDavError("no-principal")
        raise CalDavError("no-principal") if last.token == "not-found" else last

    def home_set(self, principal: str) -> str:
        where, entries = self._propfind(principal, _PROPFIND_HOME, "0")
        for entry in entries:
            href = _href(entry.props.get(_tag(CALDAV, "calendar-home-set")))
            if href:
                return self._absolute(where, href)
        raise CalDavError("no-calendars")

    def calendars(self, home: str | None = None) -> list[CalendarInfo]:
        """The event calendars below the home set, in server order."""
        home = home or self.home_set(self.principal())
        where, entries = self._propfind(home, _PROPFIND_CALENDARS, "1")
        found: list[CalendarInfo] = []
        for entry in entries:
            kind = entry.props.get(_tag(DAV, "resourcetype"))
            if kind is None or kind.find(_tag(CALDAV, "calendar")) is None:
                continue
            components = entry.props.get(_tag(CALDAV, "supported-calendar-component-set"))
            if components is not None and len(components):
                names = {(comp.get("name") or "").upper() for comp in components}
                if "VEVENT" not in names:
                    continue
            url = self._absolute(where, entry.href)
            name = (entry.props.get(_tag(DAV, "displayname")) is not None
                    and (entry.props[_tag(DAV, "displayname")].text or "").strip()) or ""
            if not name:
                name = urllib.parse.unquote(url.rstrip("/").rsplit("/", 1)[-1])
            found.append(CalendarInfo(url=url, name=name[:200]))
            if len(found) >= MAX_CALENDARS:
                break
        return found

    # ---- events ---------------------------------------------------------------

    def events(self, calendar_url: str, start: datetime, end: datetime) -> list[str]:
        """The iCalendar texts of objects with an event in ``[start, end)``."""
        self._check(calendar_url)
        body = _REPORT.format(start=_utc(start), end=_utc(end)).encode()
        reply = self._request("REPORT", calendar_url, body, depth="1")
        if reply.status != 207:
            raise CalDavError("bad-response")
        texts = []
        for entry in _multistatus(_xml(reply.body)):
            data = entry.props.get(_tag(CALDAV, "calendar-data"))
            if data is not None and data.text and data.text.strip():
                texts.append(data.text)
        return texts
