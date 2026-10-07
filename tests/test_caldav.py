"""Discovery and REPORT against iCloud, Nextcloud, Radicale and Baikal fixtures."""
from __future__ import annotations

import urllib.parse
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest
from caldav_fakes import PASSWORD, USER, FakeServer

from blueferry_plugin_kit.dav.caldav import (
    CalDavClient,
    CalDavError,
    Response,
    _challenges,
    normalize_url,
    split_hosts,
    valid_host,
)

ZURICH = ZoneInfo("Europe/Zurich")
START = datetime(2026, 10, 6, tzinfo=ZURICH)
END = datetime(2026, 10, 8, tzinfo=ZURICH)

ICLOUD_PARTITION = ("p42-caldav.icloud.com",)
SERVERS = {
    "icloud": ("https://caldav.icloud.com", ["Home", "Work"]),
    "nextcloud": ("https://cloud.example.org", ["Personal", "Contact birthdays"]),
    "radicale": ("http://localhost:5232", ["Calendar"]),
    "baikal": ("https://dav.example.org/dav.php", ["Default calendar"]),
}


@pytest.mark.parametrize("name", sorted(SERVERS))
def test_discovery_finds_the_event_calendars(name) -> None:
    url, expected = SERVERS[name]
    server = FakeServer(name)
    hosts = ICLOUD_PARTITION if name == "icloud" else ()
    client = CalDavClient(url, USER, PASSWORD, send=server, hosts=hosts)
    calendars = client.calendars()
    assert [c.name for c in calendars] == expected
    # Every calendar answers the time-range REPORT with objects.
    for calendar in calendars:
        assert client.events(calendar.url, START, END)
    # The password went only to the configured host and the allowed ones.
    allowed = {urllib.parse.urlsplit(url).hostname, *hosts}
    assert {urllib.parse.urlsplit(u).hostname for u in server.urls()} <= allowed
    assert client.seen_hosts <= allowed


def test_icloud_follows_the_home_set_to_its_partition_host() -> None:
    server = FakeServer("icloud")
    client = CalDavClient("caldav.icloud.com", USER, PASSWORD, send=server,
                          hosts=ICLOUD_PARTITION)
    calendars = client.calendars()
    assert all(c.url.startswith("https://p42-caldav.icloud.com:443/1234567890/") for c in calendars)
    assert server.urls("PROPFIND")[:2] == [
        "https://caldav.icloud.com/.well-known/caldav",   # 401, then with credentials
        "https://caldav.icloud.com/.well-known/caldav",
    ]
    # The redirect kept the method (PROPFIND, not GET).
    assert ("PROPFIND", "https://caldav.icloud.com/") in [(m, u) for m, u, *_ in server.requests]


def test_nextcloud_well_known_redirect_and_report_window() -> None:
    server = FakeServer("nextcloud")
    client = CalDavClient("https://cloud.example.org/", USER, PASSWORD, send=server)
    personal = client.calendars()[0]
    texts = client.events(personal.url, START, END)
    assert len(texts) == 2 and all(t.startswith("BEGIN:VCALENDAR") for t in texts)
    _method, _url, _headers, body = server.requests[-1]
    assert b'start="20261005T220000Z" end="20261007T220000Z"' in body


def test_baikal_uses_digest_authentication() -> None:
    server = FakeServer("baikal")
    client = CalDavClient("https://dav.example.org/dav.php", USER, PASSWORD, send=server)
    assert client.calendars()
    auth = [h.get("Authorization", "") for _m, _u, h, _b in server.requests]
    assert auth[0] == "" and all(a.startswith("Digest ") for a in auth[1:])
    assert not any(a.startswith("Basic") for a in auth)


@pytest.mark.parametrize("name", ["nextcloud", "baikal"])
def test_a_wrong_password_is_unauthorized(name) -> None:
    url, _ = SERVERS[name]
    server = FakeServer(name, password="something-else")
    with pytest.raises(CalDavError) as caught:
        CalDavClient(url, USER, PASSWORD, send=server).calendars()
    assert caught.value.token == "unauthorized"
    assert len(server.requests) == 2   # one challenge, one refused try; no loop


def test_redirect_to_another_site_is_refused() -> None:
    server = FakeServer("nextcloud")
    server.overrides["PROPFIND https://cloud.example.org/.well-known/caldav"] = Response(
        301, {"location": "https://evil.example.net/dav/"}, b"", "",
    )
    with pytest.raises(CalDavError) as caught:
        CalDavClient("https://cloud.example.org", USER, PASSWORD, send=server).calendars()
    assert caught.value.token == "foreign-host"
    assert not any("evil" in url for url in server.urls())


def test_home_set_on_another_site_is_refused() -> None:
    server = FakeServer("icloud")
    server.overrides["PROPFIND https://caldav.icloud.com/1234567890/principal/"] = Response(
        207, {}, b'<multistatus xmlns="DAV:"><response><href>/p/</href><propstat><prop>'
        b'<calendar-home-set xmlns="urn:ietf:params:xml:ns:caldav"><href xmlns="DAV:">'
        b"https://attacker.example/home/</href></calendar-home-set></prop>"
        b"<status>HTTP/1.1 200 OK</status></propstat></response></multistatus>", "",
    )
    with pytest.raises(CalDavError) as caught:
        CalDavClient("https://caldav.icloud.com", USER, PASSWORD, send=server).calendars()
    assert caught.value.token == "foreign-host"


def test_doctype_and_entities_are_refused() -> None:
    server = FakeServer("radicale")
    server.overrides["PROPFIND http://localhost:5232/"] = Response(
        207, {}, b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]>'
        b'<multistatus xmlns="DAV:">&a;</multistatus>', "",
    )
    server.routes.pop("PROPFIND http://localhost:5232/.well-known/caldav")
    with pytest.raises(CalDavError) as caught:
        CalDavClient("http://localhost:5232", USER, PASSWORD, send=server).principal()
    assert caught.value.token == "bad-response"


def test_a_doctype_after_the_first_kilobytes_is_refused() -> None:
    server = FakeServer("radicale")
    server.overrides["PROPFIND http://localhost:5232/"] = Response(
        207, {}, b'<?xml version="1.0"?><!--' + b"x" * 8192 + b'-->'
        b'<!DOCTYPE multistatus SYSTEM "http://evil.example/x.dtd">'
        b'<multistatus xmlns="DAV:"></multistatus>', "",
    )
    server.routes.pop("PROPFIND http://localhost:5232/.well-known/caldav")
    with pytest.raises(CalDavError) as caught:
        CalDavClient("http://localhost:5232", USER, PASSWORD, send=server).principal()
    assert caught.value.token == "bad-response"


def test_network_errors_become_a_token() -> None:
    def broken(*_args):
        raise OSError("connection refused")

    with pytest.raises(CalDavError) as caught:
        CalDavClient("https://dav.example.org", USER, PASSWORD, send=broken).calendars()
    assert caught.value.token == "network"


def test_no_principal_anywhere() -> None:
    def empty(method, url, headers, body, timeout):
        return Response(404, {}, b"", url)

    with pytest.raises(CalDavError) as caught:
        CalDavClient("https://dav.example.org", USER, PASSWORD, send=empty).principal()
    assert caught.value.token == "no-principal"


@pytest.mark.parametrize("raw,expected", [
    ("https://caldav.icloud.com", "https://caldav.icloud.com/"),
    ("caldav.icloud.com", "https://caldav.icloud.com/"),
    ("https://cloud.example.org/remote.php/dav", "https://cloud.example.org/remote.php/dav"),
    ("http://localhost:5232/", "http://localhost:5232/"),
])
def test_urls_are_normalized(raw, expected) -> None:
    assert normalize_url(raw) == expected


@pytest.mark.parametrize("raw", [
    "http://dav.example.org", "ftp://dav.example.org", "https://user:pw@dav.example.org",
    "https://dav.example.org/?x=1", "", "https://",
])
def test_bad_urls_are_refused(raw) -> None:
    with pytest.raises(CalDavError):
        normalize_url(raw)


def test_only_the_exact_host_without_an_allowlist() -> None:
    # No more "same site" guess: p42-caldav.icloud.com is a different host
    # until the user allows it, and the error names it before any request.
    server = FakeServer("icloud")
    with pytest.raises(CalDavError) as caught:
        CalDavClient("caldav.icloud.com", USER, PASSWORD, send=server).calendars()
    assert (caught.value.token, caught.value.host) == ("foreign-host", "p42-caldav.icloud.com")
    assert not any("p42" in url for url in server.urls())
    # A sibling subdomain is just as foreign.
    server = FakeServer("nextcloud")
    server.overrides["PROPFIND https://cloud.example.org/.well-known/caldav"] = Response(
        301, {"location": "https://other.example.org/dav/"}, b"", "",
    )
    with pytest.raises(CalDavError) as caught:
        CalDavClient("https://cloud.example.org", USER, PASSWORD, send=server).calendars()
    assert caught.value.host == "other.example.org"


def test_host_list_parsing() -> None:
    assert split_hosts(" P42-caldav.icloud.com, x.example.org;x.example.org ") == (
        "p42-caldav.icloud.com", "x.example.org")
    assert valid_host("10.0.0.5") and valid_host("p42-caldav.icloud.com")
    for bad in ("https://x.org", "x.org:443", "a b", "-x.org", "x..org"):
        assert not valid_host(bad), bad


def test_challenge_parsing() -> None:
    found = _challenges('Basic realm="Nextcloud", charset="UTF-8"\n'
                        'Digest realm="x", nonce="n1", qop="auth,auth-int", algorithm=MD5')
    assert found["basic"]["realm"] == "Nextcloud"
    assert found["digest"]["nonce"] == "n1" and found["digest"]["qop"] == "auth,auth-int"


def test_real_http_transport_against_a_local_server(monkeypatch) -> None:
    """urllib_send end to end: 401 challenge, redirect kept as PROPFIND, 207."""
    import base64
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    expected = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
    seen: list[tuple[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            pass

        def do_PROPFIND(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            seen.append((self.command, self.path))
            if self.headers.get("Authorization") != expected:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="test"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path == "/.well-known/caldav":
                self.send_response(308)
                self.send_header("Location", "/dav/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = (b'<multistatus xmlns="DAV:"><response><href>/dav/</href><propstat><prop>'
                    b"<current-user-principal><href>/dav/alice/</href></current-user-principal>"
                    b"</prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>")
            self.send_response(207)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    # A proxy in the environment (nothing listens on port 9) is ignored
    # unless the user opted in.
    for variable in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"):
        monkeypatch.setenv(variable, "http://127.0.0.1:9")
    for variable in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(variable, raising=False)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        client = CalDavClient(url, USER, PASSWORD)
        principal = client.principal()
        with pytest.raises(CalDavError) as caught:
            CalDavClient(url, USER, PASSWORD, use_proxy=True).principal()
        assert caught.value.token == "network"
    finally:
        server.shutdown()
    assert principal == f"http://127.0.0.1:{server.server_port}/dav/alice/"
    assert seen == [("PROPFIND", "/.well-known/caldav"), ("PROPFIND", "/.well-known/caldav"),
                    ("PROPFIND", "/dav/")]
