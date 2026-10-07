"""The hardened LAN server: limits, deadlines, TLS (from shortcuts and localsend)."""
from __future__ import annotations

import datetime as dt
import http.client
import ipaddress
import json
import os
import socket
import ssl
import stat
import time

import pytest
from cryptography import x509

from blueferry_plugin_kit.lanserver import (
    ConnectionsPerAddress,
    DeadlineRequestHandler,
    HardenedHTTPServer,
    RateLimiter,
    RequestError,
    ServerGroup,
    SlidingWindows,
    serve_in_thread,
)
from blueferry_plugin_kit.lanserver.tls import SERVER_DAYS, CertificateStore
from blueferry_plugin_kit.testing import TestCA

# ---- certificates ---------------------------------------------------------------


def test_certificates_chain_and_follow_the_address(tmp_path) -> None:
    store = CertificateStore(tmp_path / "certs")
    first = store.ensure(["192.168.1.20"])
    ca = x509.load_pem_x509_certificate(first.ca_pem)
    leaf = x509.load_pem_x509_certificate(first.cert_path.read_bytes())
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert leaf.issuer == ca.subject
    leaf.verify_directly_issued_by(ca)
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert ipaddress.ip_address("192.168.1.20") in sans.get_values_for_type(x509.IPAddress)
    lifetime = leaf.not_valid_after_utc - leaf.not_valid_before_utc
    assert lifetime <= dt.timedelta(days=SERVER_DAYS, minutes=5) < dt.timedelta(days=825)
    for path in (store.ca_key_path, store.key_path):
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert len(first.fingerprint) == 95 and first.fingerprint == store.ca_fingerprint()
    # Same address: nothing changes. New address: new leaf, same CA (no new trust on iOS).
    serial = leaf.serial_number
    assert x509.load_pem_x509_certificate(
        store.ensure(["192.168.1.20"]).cert_path.read_bytes()).serial_number == serial
    second = store.ensure(["192.168.1.33"])
    assert second.fingerprint == first.fingerprint
    assert x509.load_pem_x509_certificate(second.cert_path.read_bytes()).serial_number != serial


def test_ca_name_and_forget(tmp_path) -> None:
    store = CertificateStore(tmp_path / "certs", ca_name="BlueFerry Shortcuts CA")
    material = store.ensure(["127.0.0.1"])
    ca = x509.load_pem_x509_certificate(material.ca_pem)
    name = ca.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert name.startswith("BlueFerry Shortcuts CA (")
    store.forget()
    assert store.ca_fingerprint() is None and not store.cert_path.exists()


# ---- limits ---------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_rate_limiter_counts_requests_and_locks_out_failures() -> None:
    clock = Clock()
    limiter = RateLimiter(clock, requests_per_minute=3, failures_allowed=2, failure_window=600)
    assert [limiter.admit("a") for _ in range(4)] == [True, True, True, False]
    assert limiter.admit("b")
    clock.now += 61
    assert limiter.admit("a")
    limiter.failed("a")
    limiter.failed("a")
    clock.now += 61
    assert not limiter.admit("a")          # locked out for the failure window
    clock.now += 600
    assert limiter.admit("a")


def test_sliding_windows_and_connections_per_address() -> None:
    clock = Clock()
    windows = SlidingWindows(60, 2, clock, max_tracked=2)
    assert windows.take("a") and windows.take("a") and not windows.take("a")
    assert windows.full("a")
    clock.now += 61
    assert not windows.full("a")
    for address in ("b", "c", "d"):
        windows.add(address)               # idle entries are dropped beyond max_tracked
    per = ConnectionsPerAddress(2)
    assert per.acquire("x") and per.acquire("x") and not per.acquire("x")
    per.release("x")
    assert per.acquire("x")


# ---- the server -----------------------------------------------------------------


class Handler(DeadlineRequestHandler):
    request_deadline_s = 0.6
    linger_s = 0.5

    def do_GET(self) -> None:
        self._reply(200, {"path": self.path})

    def do_POST(self) -> None:
        try:
            body = self.read_body(64, min_rate=1024)
        except RequestError as error:
            self.close_connection = True
            self._reply(error.status, {"error": error.token})
            return
        self._reply(200, {"length": len(body)})

    def _reply(self, status: int, value: dict) -> None:
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def server(tmp_path):
    ca = TestCA(tmp_path / "ca")
    started = []

    def start(**kwargs):
        instance = HardenedHTTPServer(
            ("127.0.0.1", 0), Handler, context=ca.server_context(), **kwargs,
        )
        serve_in_thread(instance, "kit-test")
        started.append(instance)
        return instance, ca.client_context()

    yield start
    for instance in started:
        instance.shutdown()
        instance.server_close()


def _request(port, context, method="GET", path="/", body=None, headers=None):
    connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, json.loads(response.read() or b"null")
    finally:
        connection.close()


def _raw_tls(port, context):
    return context.wrap_socket(
        socket.create_connection(("127.0.0.1", port), timeout=5), server_hostname="127.0.0.1",
    )


def test_requests_and_body_limits(server) -> None:
    instance, context = server()
    port = instance.server_address[1]
    assert _request(port, context, path="/a?pin=1") == (200, {"path": "/a?pin=1"})
    assert _request(port, context, "POST", "/", b"x" * 10) == (200, {"length": 10})
    assert _request(port, context, "POST", "/", b"x" * 65) == (413, {"error": "too-large"})
    chunked = _request(port, context, "POST", "/", b"x", {"Transfer-Encoding": "chunked"})
    assert chunked[0] == 411


def test_a_trickling_client_is_cut_off_at_the_deadline(server) -> None:
    instance, context = server()
    sock = _raw_tls(instance.server_address[1], context)
    started, closed = time.monotonic(), False
    for byte in b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slow: 1\r\n":
        try:
            sock.sendall(bytes([byte]))
            time.sleep(0.05)
            sock.setblocking(False)
            try:
                if sock.recv(1) == b"":
                    closed = True
                    break
            except (BlockingIOError, ssl.SSLWantReadError):
                pass
            finally:
                sock.setblocking(True)
        except OSError:
            closed = True
            break
    sock.close()
    assert closed and time.monotonic() - started < 3


def test_at_most_two_connections_per_address(server) -> None:
    instance, context = server()
    port = instance.server_address[1]
    first, second = _raw_tls(port, context), _raw_tls(port, context)
    with pytest.raises(OSError):
        third = _raw_tls(port, context)
        third.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        if third.recv(1) == b"":
            raise ConnectionResetError
    first.close()
    second.close()
    time.sleep(0.2)
    assert _request(port, context)[0] == 200


def test_addresses_outside_the_allowlist_are_dropped(server) -> None:
    instance, context = server(allowed=lambda address: address != "127.0.0.1")
    with pytest.raises((OSError, http.client.HTTPException)):
        _request(instance.server_address[1], context)


def test_server_group_binds_every_address_and_reports_failures(tmp_path) -> None:
    group = ServerGroup()
    try:
        failed = group.start(
            ["127.0.0.1", "192.0.2.123"], 0,
            lambda address, per: HardenedHTTPServer(address, Handler, per_address=per),
        )
        assert failed == ["192.0.2.123"] and len(group.ports) == 1
        connection = http.client.HTTPConnection("127.0.0.1", group.ports[0], timeout=5)
        connection.request("GET", "/plain")
        assert connection.getresponse().status == 200
        connection.close()
    finally:
        group.stop()
    assert group.servers == []
