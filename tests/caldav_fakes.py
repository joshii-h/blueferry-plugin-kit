"""A CalDAV server replayed from fixtures (taken from blueferry-plugin-calendar).

``FakeServer`` replays ``fixtures/<server>/routes.json``: ``"METHOD URL"``
maps to a status, headers and a body file. The bodies are modelled on what
iCloud, Nextcloud, Radicale and Baikal send (namespace prefixes, absolute vs.
relative hrefs, extra collections, auth challenges); they were written from
the servers' documented behaviour, not captured from live accounts.
``{{ics:NAME}}`` in a body is replaced by ``fixtures/ics/NAME`` (XML-escaped),
``{{raw:NAME}}`` by the raw text (for CDATA sections).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.parse
from pathlib import Path
from xml.sax.saxutils import escape

from blueferry_plugin_kit.dav.caldav import Response

FIXTURES = Path(__file__).parent / "fixtures"
USER, PASSWORD = "alice", "abcd-efgh-ijkl-mnop"


class FakeServer:
    def __init__(self, name: str, *, password: str = PASSWORD) -> None:
        self.directory = FIXTURES / name
        config = json.loads((self.directory / "routes.json").read_text())
        self.auth = config["auth"]
        self.challenge = config["challenge"]
        self.routes = dict(config["routes"])
        self.password = password
        self.requests: list[tuple[str, str, dict, bytes | None]] = []
        self.overrides: dict[str, Response] = {}

    def body(self, name: str) -> bytes:
        text = (self.directory / name).read_text()

        def ics(match: re.Match) -> str:
            raw = (FIXTURES / "ics" / match.group(2)).read_text()
            return raw if match.group(1) == "raw" else escape(raw)

        return re.sub(r"\{\{(ics|raw):([\w.-]+)\}\}", ics, text).encode()

    def _authorized(self, method: str, url: str, header: str) -> bool:
        if self.auth == "basic":
            expected = base64.b64encode(f"{USER}:{self.password}".encode()).decode()
            return header == f"Basic {expected}"
        if not header.startswith("Digest "):
            return False
        fields = dict(
            (key, quoted or raw) for key, quoted, raw in
            re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]*))', header[7:])
        )
        realm = re.search(r'realm="([^"]*)"', self.challenge).group(1)
        nonce = re.search(r'nonce="([^"]*)"', self.challenge).group(1)
        uri = urllib.parse.urlsplit(url).path

        def h(text: str) -> str:
            return hashlib.md5(text.encode()).hexdigest()

        ha1 = h(f"{USER}:{realm}:{self.password}")
        ha2 = h(f"{method}:{uri}")
        expected = h(f"{ha1}:{nonce}:{fields.get('nc')}:{fields.get('cnonce')}:auth:{ha2}")
        return (fields.get("username") == USER and fields.get("uri") == uri
                and fields.get("nonce") == nonce and fields.get("response") == expected
                and fields.get("opaque") is not None)

    def __call__(self, method, url, headers, body, timeout) -> Response:
        assert timeout <= 30
        self.requests.append((method, url, dict(headers), body))
        if not self._authorized(method, url, headers.get("Authorization", "")):
            return Response(401, {"www-authenticate": self.challenge}, b"", url)
        key = f"{method} {url}"
        if key in self.overrides:
            return self.overrides[key]
        route = self.routes.get(key)
        if route is None:
            return Response(404, {}, b"", url)
        if method == "REPORT":
            assert headers.get("Depth") == "1"
            assert b"<c:time-range start=" in body and b'name="VEVENT"' in body
        if method == "PROPFIND":
            assert headers.get("Depth") in ("0", "1")
        reply_headers = {k.lower(): v for k, v in route.get("headers", {}).items()}
        data = self.body(route["body"]) if "body" in route else b""
        return Response(route["status"], reply_headers, data, url)

    def urls(self, method: str | None = None) -> list[str]:
        return [url for m, url, *_ in self.requests if method in (None, m)]
