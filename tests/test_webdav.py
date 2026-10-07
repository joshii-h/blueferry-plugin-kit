"""The WebDAV client against wsgidav and a fake Nextcloud (from blueferry-plugin-webdav)."""
from __future__ import annotations

import io
import urllib.parse

import pytest
from fake_nextcloud import FakeNextcloud

from blueferry_plugin_kit.dav import webdav
from blueferry_plugin_kit.dav.webdav import (
    DavError,
    WebDavClient,
    folder_segments,
    normalize_base,
    parse_multistatus,
    safe_name,
)
from blueferry_plugin_kit.testing import DavServer, WsgiServer

USER = "alice"
PASSWORD = "Pa55-w0rd-not-for-logs"


@pytest.fixture
def dav_server(tmp_path):
    with DavServer(tmp_path / "dav-root", USER, PASSWORD) as server:
        yield server


@pytest.fixture
def nextcloud(monkeypatch):
    chunk = 64 * 1024
    monkeypatch.setattr(webdav, "CHUNK_BYTES", chunk)
    fake = FakeNextcloud(USER, PASSWORD, min_chunk=chunk)
    with WsgiServer(fake) as server:
        fake.base = server.base
        fake.url = f"{fake.base}/nc/remote.php/dav/files/{USER}/"
        yield fake


@pytest.mark.parametrize("raw,lan,expected", [
    ("https://cloud.example.org/remote.php/dav/files/me", False,
     "https://cloud.example.org/remote.php/dav/files/me/"),
    ("https://dav.example.org", False, "https://dav.example.org/"),
    ("http://localhost:8080/dav/", False, "http://localhost:8080/dav/"),
    ("http://192.168.1.5/dav", True, "http://192.168.1.5/dav/"),
    ("http://nas.local/dav", True, "http://nas.local/dav/"),
    ("http://nas/dav", True, "http://nas/dav/"),
])
def test_urls_are_normalized(raw, lan, expected) -> None:
    assert normalize_base(raw, allow_http_lan=lan) == expected


@pytest.mark.parametrize("raw,lan,token", [
    ("http://192.168.1.5/dav", False, "insecure"),
    ("http://dav.example.org/", True, "insecure"),
    ("http://8.8.8.8/", True, "insecure"),
    ("https://user:pw@dav.example.org/", False, "invalid-url"),
    ("https://dav.example.org/?x=1", False, "invalid-url"),
    ("https://dav.example.org/a/../b", False, "invalid-url"),
    ("https://dav.example.org/a/%2e%2e/b", False, "invalid-url"),
    ("ftp://dav.example.org/", False, "invalid-url"),
    ("", False, "invalid-url"),
])
def test_bad_urls_are_refused(raw, lan, token) -> None:
    with pytest.raises(DavError) as caught:
        normalize_base(raw, allow_http_lan=lan)
    assert caught.value.token == token


def test_lan_http_is_checked_against_resolved_addresses() -> None:
    client = WebDavClient("http://nas.local/dav/", USER, PASSWORD, allow_http_lan=True,
                          resolve=lambda host: ["93.184.216.34"])
    with pytest.raises(DavError) as caught:
        client.check()
    assert caught.value.token == "insecure"


def test_lan_http_connects_to_the_checked_address_only(dav_server) -> None:
    port = urllib.parse.urlsplit(dav_server.url).port
    answers = iter([["127.0.0.1"], ["93.184.216.34"]])
    lookups: list[str] = []

    def resolve(host: str) -> list[str]:
        lookups.append(host)
        return next(answers)

    client = WebDavClient(f"http://nas.local:{port}/dav/", USER, PASSWORD, allow_http_lan=True,
                          resolve=resolve)
    client.check()
    client.list_folder(())
    client.ensure_folder(("pinned",))
    # One lookup for the whole operation: a second answer (now public)
    # is never asked for, and the requests went to the checked address.
    assert lookups == ["nas.local"]


def test_requests_never_leave_the_configured_server() -> None:
    client = WebDavClient("https://dav.example.org/", USER, PASSWORD)
    with pytest.raises(DavError) as caught:
        client.download("https://evil.example.org/x", io.BytesIO(), 10)
    assert caught.value.token == "invalid-url"
    assert PASSWORD not in repr(client)


@pytest.mark.parametrize("raw,expected", [
    ("/home/me/report.pdf", "report.pdf"),
    ("/tmp/../../etc/passwd", "passwd"),
    ("/tmp/a\\..\\b.txt", "a_.._b.txt"),
    ("/tmp/.hidden", "hidden"),
    ("/tmp/...", "file"),
    ("/tmp/bad\x1bname\n.txt", "bad_name_.txt"),
    ("/tmp/Café.txt", "Café.txt"),
])
def test_file_names_are_made_safe(raw, expected) -> None:
    assert safe_name(raw) == expected


def test_long_names_keep_their_extension() -> None:
    name = safe_name("/tmp/" + "ä" * 300 + ".jpeg")
    assert name.endswith(".jpeg") and len(name.encode()) <= 200


def test_folder_segments() -> None:
    assert folder_segments(" Phone//Uploads/./x ") == ("Phone", "Uploads", "x")
    assert folder_segments("") == ()
    for bad in ("a/../b", "..", "a/\x00b"):
        with pytest.raises(ValueError):
            folder_segments(bad)


def test_listing_ignores_foreign_and_nested_entries() -> None:
    folder = "https://dav.example.org/files/BlueFerry/"
    xml = b"""<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">
    <d:response><d:href>/files/BlueFerry/</d:href><d:propstat><d:prop>
      <d:resourcetype><d:collection/></d:resourcetype></d:prop>
      <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
    <d:response><d:href>/files/BlueFerry/a%20b.txt</d:href><d:propstat><d:prop>
      <d:resourcetype/><d:getcontentlength>12</d:getcontentlength>
      <d:getlastmodified>Mon, 06 Oct 2026 18:00:00 GMT</d:getlastmodified></d:prop>
      <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
    <d:response><d:href>/files/BlueFerry/sub/x.txt</d:href></d:response>
    <d:response><d:href>/files/other.txt</d:href></d:response>
    <d:response><d:href>https://evil.example.org/files/BlueFerry/e.txt</d:href></d:response>
    <d:response><d:href>/files/BlueFerry/%2e%2e</d:href></d:response>
    </d:multistatus>"""
    entries = parse_multistatus(xml, folder)
    assert [(e.name, e.size) for e in entries] == [("a b.txt", 12)]
    assert entries[0].url == folder + "a%20b.txt" and entries[0].modified > 0
    with pytest.raises(DavError):
        parse_multistatus(b'<!DOCTYPE x [<!ENTITY a "b">]><x/>', folder)


# ---- generic WebDAV (wsgidav) ---------------------------------------------------


@pytest.mark.parametrize("doctype", [
    b'<!DOCTYPE d:multistatus SYSTEM "http://evil.example/x.dtd">',
    b'<!DOCTYPE x [<!ENTITY e "boom">]>',
])
def test_listing_refuses_a_doctype_anywhere(doctype) -> None:
    # A long comment pushes the DOCTYPE past the first 4 KiB.
    data = (b'<?xml version="1.0"?><!--' + b"x" * 8192 + b"-->" + doctype
            + b'<d:multistatus xmlns:d="DAV:"></d:multistatus>')
    with pytest.raises(DavError) as caught:
        parse_multistatus(data, "https://dav.example.org/f/")
    assert caught.value.token == "bad-response"


def test_redirects_are_refused(tmp_path) -> None:
    def app(_environ, start_response):
        start_response("302 Found", [("Location", "https://evil.example.org/"),
                                     ("Content-Length", "0")])
        return [b""]

    server = WsgiServer(app)
    try:
        client = WebDavClient(f"http://127.0.0.1:{server.server_port}/", USER, PASSWORD)
        with pytest.raises(DavError) as caught:
            client.check()
        assert caught.value.token == "redirect"
    finally:
        server.stop()


def test_upload_list_download_and_user_agent(dav_server) -> None:
    client = WebDavClient(dav_server.url, USER, PASSWORD, user_agent="blueferry-test/1")
    assert client.user_agent == "blueferry-test/1"
    client.check()
    folder = client.ensure_folder(("Phone", "Uploads"))
    name = client.free_name(folder, "we ird #?%.txt")
    url = client.upload(io.BytesIO(b"hello"), 5, folder, name)
    assert (dav_server.root / "Phone" / "Uploads" / "we ird #?%.txt").read_bytes() == b"hello"
    assert client.free_name(folder, name) == "we ird #?% (2).txt"
    assert [(e.name, e.size) for e in client.list_folder(("Phone", "Uploads"))] == [(name, 5)]
    assert client.list_folder(("missing",)) == []
    target = io.BytesIO()
    assert client.download(url, target, 100) == 5 and target.getvalue() == b"hello"
    with pytest.raises(DavError) as caught:
        client.download(url, io.BytesIO(), 4)
    assert caught.value.token == "too-large"
    with pytest.raises(DavError) as caught:
        WebDavClient(dav_server.url, USER, "wrong").check()
    assert caught.value.token == "unauthorized"


def test_nextcloud_chunked_upload_and_public_link(nextcloud) -> None:
    client = WebDavClient(nextcloud.url, USER, PASSWORD, nextcloud=True)
    assert client.detect_nextcloud()
    folder = client.ensure_folder(("BlueFerry",))
    data = bytes(range(256)) * 1024             # 256 KiB: four chunks of 64 KiB
    client.upload(io.BytesIO(data), len(data), folder, "big.bin")
    assert nextcloud.files["/BlueFerry/big.bin"] == data
    puts = [path for method, path in nextcloud.log if method == "PUT"]
    assert len(puts) == 4 and all("/uploads/" in path for path in puts)
    link = client.share_link(("BlueFerry",), "big.bin")
    assert link.startswith("http") and nextcloud.shares[-1]["path"] == "/BlueFerry/big.bin"
    assert client.web_folder_url(("BlueFerry",)).endswith("?dir=/BlueFerry")


def test_nextcloud_failed_chunk_cleans_up(nextcloud) -> None:
    client = WebDavClient(nextcloud.url, USER, PASSWORD, nextcloud=True)
    folder = client.ensure_folder(("BlueFerry",))
    nextcloud.fail_chunk = 2
    data = b"x" * (200 * 1024)
    with pytest.raises(DavError) as caught:
        client.upload(io.BytesIO(data), len(data), folder, "big.bin")
    assert caught.value.token == "no-space"
    assert nextcloud.uploads == {} and "/BlueFerry/big.bin" not in nextcloud.files


def test_share_link_needs_nextcloud(dav_server) -> None:
    client = WebDavClient(dav_server.url, USER, PASSWORD)
    with pytest.raises(DavError):
        client.share_link((), "x")
    assert client.web_folder_url(()) is None and not client.detect_nextcloud()
    assert urllib.parse.urlsplit(client.base).path == "/dav/"
