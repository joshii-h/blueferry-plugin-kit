"""A hardened HTTPS server for endpoints on the local network.

* :mod:`.limits`: request deadline with a minimum body rate, connections
  per address, sliding-window rate limits and a failed-login lockout.
* :mod:`.http`: :class:`HardenedHTTPServer` (connection caps, address
  allowlist, TLS handshake on the worker thread) and
  :class:`DeadlineRequestHandler` (deadline, body limits, no request
  logging, linger), plus :class:`ServerGroup` for one server per address.
* :mod:`.tls`: a local CA and the server certificate it signs (extra
  ``lanserver`` for cryptography, imported on first use).

Which address to bind (LAN, not VPN or Docker) is in
:mod:`blueferry_plugin_kit.netaddr`. Routes stay in the plugin.
"""
from __future__ import annotations

from blueferry_plugin_kit.lanserver.http import (
    DeadlineRequestHandler,
    HardenedHTTPServer,
    RequestError,
    ServerGroup,
    handshake_reason,
    serve_in_thread,
)
from blueferry_plugin_kit.lanserver.limits import (
    ConnectionsPerAddress,
    DeadlineReader,
    RateLimiter,
    SlidingWindows,
    deadline_rfile,
)
from blueferry_plugin_kit.lanserver.tls import CertificateStore, Material, fingerprint

__all__ = [
    "CertificateStore",
    "ConnectionsPerAddress",
    "DeadlineReader",
    "DeadlineRequestHandler",
    "HardenedHTTPServer",
    "Material",
    "RateLimiter",
    "RequestError",
    "ServerGroup",
    "SlidingWindows",
    "deadline_rfile",
    "fingerprint",
    "handshake_reason",
    "serve_in_thread",
]
