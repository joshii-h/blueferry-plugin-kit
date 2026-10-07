"""Limits against slow and greedy clients.

A total deadline per request (:class:`DeadlineReader`), a cap on open
connections per address (:class:`ConnectionsPerAddress`) and sliding-window
rate limits (:class:`SlidingWindows`, :class:`RateLimiter`).

A socket timeout alone restarts with every byte, so a client that trickles
one byte every few seconds ("slowloris") keeps a connection, and with it one
of the few server slots, open forever. :class:`DeadlineReader` sets the
socket timeout to the time that is *left* before each read instead.
"""
from __future__ import annotations

import io
import math
import socket
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable


class DeadlineReader(io.RawIOBase):
    """Raw reader over a socket that gives up at a deadline.

    :meth:`start` sets a fixed deadline (request line, headers, small
    bodies). :meth:`stream` is for large bodies: the deadline is ``grace``
    seconds plus one second per ``min_rate`` bytes received, so a real
    transfer of any size finishes, but a trickle does not.
    """

    def __init__(
        self, sock: socket.socket, idle: float, clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__()
        self._sock = sock
        self._idle = idle
        self._clock = clock
        self._deadline = math.inf
        self._rate = 0.0
        self._streamed = 0

    def start(self, seconds: float) -> None:
        self._deadline = self._clock() + seconds
        self._rate = 0.0

    def stream(self, grace: float, min_rate: float) -> None:
        self._deadline = self._clock() + grace
        self._rate = min_rate
        self._streamed = 0

    def remaining(self) -> float:
        extra = self._streamed / self._rate if self._rate else 0.0
        return self._deadline + extra - self._clock()

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:  # type: ignore[override]
        remaining = self.remaining()
        if remaining <= 0:
            raise TimeoutError("request deadline passed")
        self._sock.settimeout(min(remaining, self._idle))
        count = self._sock.recv_into(buffer)
        self._streamed += count
        return count


def deadline_rfile(sock: socket.socket, idle: float) -> tuple[DeadlineReader, io.BufferedReader]:
    reader = DeadlineReader(sock, idle)
    return reader, io.BufferedReader(reader)


class ConnectionsPerAddress:
    """At most ``limit`` open connections per client address."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._lock = threading.Lock()
        self._open: dict[str, int] = {}

    def acquire(self, address: str) -> bool:
        with self._lock:
            count = self._open.get(address, 0)
            if count >= self._limit:
                return False
            self._open[address] = count + 1
            return True

    def release(self, address: str) -> None:
        with self._lock:
            count = self._open.get(address, 0) - 1
            if count > 0:
                self._open[address] = count
            else:
                self._open.pop(address, None)


class SlidingWindows:
    """Sliding time windows of events per client address (not thread-safe).

    At most ``max_tracked`` addresses are kept; idle ones are dropped first.
    """

    def __init__(
        self, span: float, limit: int, clock: Callable[[], float] = time.monotonic,
        *, max_tracked: int = 1024,
    ) -> None:
        self._span = span
        self._limit = limit
        self._clock = clock
        self._max_tracked = max_tracked
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def _window(self, address: str, now: float) -> deque[float]:
        if address not in self._events and len(self._events) >= self._max_tracked:
            for key in [k for k, w in self._events.items() if not w or now - w[-1] > self._span]:
                del self._events[key]
        window = self._events[address]
        while window and now - window[0] > self._span:
            window.popleft()
        return window

    def full(self, address: str) -> bool:
        return len(self._window(address, self._clock())) >= self._limit

    def add(self, address: str) -> None:
        now = self._clock()
        self._window(address, now).append(now)

    def take(self, address: str) -> bool:
        """Count one event; False (and not counted) when the window is full."""
        if self.full(address):
            return False
        self.add(address)
        return True


class RateLimiter:
    """Requests per minute and a lockout after failed logins, per address.

    Thread-safe. :meth:`admit` refuses an address that made
    ``requests_per_minute`` requests in the last minute or failed
    ``failures_allowed`` times within ``failure_window`` seconds.
    """

    def __init__(
        self, clock: Callable[[], float] = time.monotonic, *,
        requests_per_minute: int = 30, failures_allowed: int = 5,
        failure_window: float = 600.0, max_tracked: int = 1024,
    ) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._per_minute = requests_per_minute
        self._failures_allowed = failures_allowed
        self._failure_window = failure_window
        self._max_tracked = max_tracked
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _trim(self, window: deque[float], span: float, now: float) -> None:
        while window and now - window[0] > span:
            window.popleft()

    def admit(self, client: str) -> bool:
        now = self._clock()
        with self._lock:
            failures = self._failures[client]
            self._trim(failures, self._failure_window, now)
            if len(failures) >= self._failures_allowed:
                return False
            requests = self._requests[client]
            self._trim(requests, 60, now)
            if len(requests) >= self._per_minute:
                return False
            requests.append(now)
            if len(self._requests) > self._max_tracked:
                self._forget_idle(now)
            return True

    def failed(self, client: str) -> None:
        with self._lock:
            self._failures[client].append(self._clock())

    def _forget_idle(self, now: float) -> None:
        for table, span in ((self._requests, 60), (self._failures, self._failure_window)):
            for key in [k for k, window in table.items() if not window or now - window[-1] > span]:
                del table[key]
