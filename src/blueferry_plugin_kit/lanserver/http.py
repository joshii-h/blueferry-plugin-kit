"""A hardened HTTP(S) server for endpoints on the local network.

:class:`HardenedHTTPServer` bounds the number of concurrent connections in
total and per client address, can drop connections from addresses outside
an allowlist (``allowed``), and runs the TLS handshake on the connection's
own thread with a timeout, so a slow client never blocks ``accept()``.
CPython bounds the whole handshake by the socket timeout, not each read, so
a trickled ClientHello ends there too.

:class:`DeadlineRequestHandler` gives every request a total deadline for
the request line, headers and small bodies; large bodies get a grace time
plus a minimum rate (:meth:`DeadlineRequestHandler.read_body`). It never
logs request lines, headers or bodies (query strings may carry PINs or
tokens). Routes stay in the plugin's subclass.
"""
from __future__ import annotations

import logging
import socket
import ssl
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from blueferry_plugin_kit.lanserver.limits import (
    ConnectionsPerAddress,
    DeadlineReader,
    deadline_rfile,
)

log = logging.getLogger(__name__)


class RequestError(Exception):
    """An HTTP error answer: ``status`` and a short machine-readable ``token``."""

    def __init__(self, status: int, token: str) -> None:
        super().__init__(token)
        self.status = status
        self.token = token


class HardenedHTTPServer(ThreadingHTTPServer):
    """A threading HTTP server with connection limits and TLS on the worker.

    ``context`` is the server TLS context (None: plain HTTP); it may be
    replaced at runtime through :attr:`ssl_context`. ``per_address`` may be
    shared between several servers so a client cannot multiply its share
    by using every address.
    """

    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16
    #: Seconds for the whole TLS handshake; see :meth:`handshake_timeout`.
    handshake_timeout_s = 20.0

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        *,
        context: ssl.SSLContext | None = None,
        allowed: Callable[[str], bool] | None = None,
        max_connections: int = 8,
        max_per_address: int = 2,
        per_address: ConnectionsPerAddress | None = None,
    ) -> None:
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        self.ssl_context = context
        self._allowed = allowed
        self._slots = threading.BoundedSemaphore(max_connections)
        self._per_address = per_address or ConnectionsPerAddress(max_per_address)
        super().__init__(address, handler)

    def handshake_timeout(self) -> float:
        """Override to read the value at runtime (e.g. a module constant)."""
        return self.handshake_timeout_s

    def verify_request(self, request: Any, client_address: Any) -> bool:
        return self._allowed is None or self._allowed(str(client_address[0]))

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        if not self._per_address.acquire(str(client_address[0])):
            self._slots.release()
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._release(client_address)
            raise

    def _release(self, client_address: Any) -> None:
        self._per_address.release(str(client_address[0]))
        self._slots.release()

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release(client_address)

    def finish_request(self, request: Any, client_address: Any) -> None:
        request.settimeout(self.handshake_timeout())
        context = self.ssl_context
        if context is not None:
            try:
                request = context.wrap_socket(request, server_side=True)
            except (OSError, ssl.SSLError):
                return  # untrusted CA, a probe, a timeout
        super().finish_request(request, client_address)

    def handle_error(self, request: Any, client_address: Any) -> None:
        # Peers hang up mid-request; never print tracebacks with addresses.
        log.debug("connection ended with an error", exc_info=True)


class DeadlineRequestHandler(BaseHTTPRequestHandler):
    """Base handler: request deadline, body limits, quiet logging, linger.

    Class attributes to tune: ``timeout`` (idle seconds per read),
    ``request_deadline_s`` (request line, headers, small bodies; see
    :meth:`request_deadline`), ``linger_s``/``linger_bytes`` (swallow what
    the client still sends after an early answer; 0 turns it off) and
    ``log_prefix`` for the one debug line per request.
    """

    protocol_version = "HTTP/1.1"
    sys_version = ""
    timeout = 15.0
    request_deadline_s = 20.0
    linger_s = 0.0
    linger_bytes = 1024 * 1024
    log_prefix = ""
    deadline: DeadlineReader

    def request_deadline(self) -> float:
        """Override to read the value at runtime (e.g. a module constant)."""
        return self.request_deadline_s

    def setup(self) -> None:
        super().setup()
        # Every read gets the time left of the request, so a client
        # trickling a byte now and then cannot keep the connection.
        self.rfile.close()
        self.deadline, self.rfile = deadline_rfile(self.connection, float(self.timeout))

    def handle_one_request(self) -> None:
        # The wait between keep-alive requests counts towards the deadline.
        self.deadline.start(self.request_deadline())
        super().handle_one_request()

    def finish(self) -> None:
        try:
            super().finish()
        finally:
            if self.linger_s > 0:
                self.linger()

    def linger(self) -> None:
        """Swallow what the client still sends before closing.

        An early answer (401, 413, …) leaves the body unread; closing then
        would reset the connection and the client would show a network
        error instead of the answer. Bounded in total time (not per read,
        or a trickling client would keep it going) and size.
        """
        deadline = time.monotonic() + self.linger_s
        try:
            budget = self.linger_bytes
            while budget > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.connection.settimeout(remaining)
                chunk = self.connection.recv(min(65536, budget))
                if not chunk:
                    break
                budget -= len(chunk)
        except (OSError, ValueError):
            pass

    def log_message(self, format: str, *args: object) -> None:
        """Never log paths, queries, headers or bodies."""

    def log_request(self, code: object = "-", size: object = "-") -> None:
        log.debug("%s%s %s", self.log_prefix, self.command, code)

    def read_body(self, limit: int, *, min_rate: float, grace: float | None = None) -> bytes:
        """Exactly ``Content-Length`` bytes, at most ``limit``.

        No chunked bodies (411). The body gets the time left of the request
        plus ``grace`` seconds (default: the request deadline) and one more
        second per ``min_rate`` bytes received.
        """
        if self.headers.get("Transfer-Encoding"):
            raise RequestError(411, "length-required")
        raw = self.headers.get("Content-Length")
        if raw is None:
            raise RequestError(411, "length-required")
        try:
            length = int(raw)
        except ValueError:
            raise RequestError(400, "bad-length") from None
        if length < 0:
            raise RequestError(400, "bad-length")
        if length > limit:
            raise RequestError(413, "too-large")
        extra = self.request_deadline() if grace is None else grace
        self.deadline.stream(max(0.0, self.deadline.remaining()) + extra, min_rate)
        data = self.rfile.read(length)
        if len(data) != length:
            raise RequestError(400, "short-body")
        return data


def serve_in_thread(server: ThreadingHTTPServer, name: str) -> threading.Thread:
    """Run ``server.serve_forever`` on a daemon thread and return it."""
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.5}, name=name, daemon=True,
    )
    thread.start()
    return thread


class ServerGroup:
    """One server per bound address, each on its own thread.

    ``factory((address, port), per_address)`` builds a server; the
    :class:`ConnectionsPerAddress` is shared by all servers of the group.
    """

    def __init__(self, max_per_address: int = 2, *, name: str = "blueferry-http") -> None:
        self.servers: list[ThreadingHTTPServer] = []
        self._threads: list[threading.Thread] = []
        self._name = name
        self.per_address = ConnectionsPerAddress(max_per_address)

    def start(
        self, addresses: list[str], port: int,
        factory: Callable[[tuple[str, int], ConnectionsPerAddress], ThreadingHTTPServer],
    ) -> list[str]:
        """Bind every address; return those that failed."""
        self.stop()
        failed = []
        for address in addresses:
            try:
                server = factory((address, port), self.per_address)
            except OSError as error:
                log.warning("cannot listen on %s:%d: %s", address, port, error.strerror)
                failed.append(address)
                continue
            self.servers.append(server)
            self._threads.append(serve_in_thread(server, f"{self._name}-{address}"))
        return failed

    @property
    def ports(self) -> list[int]:
        return [server.server_address[1] for server in self.servers]

    def stop(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self._threads:
            thread.join(timeout=2)
        self.servers, self._threads = [], []
