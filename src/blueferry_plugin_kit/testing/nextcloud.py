"""A fake Nextcloud Login Flow v2 as a WSGI app, for sign-in tests.

Serve it over https with :class:`~blueferry_plugin_kit.testing.WsgiServer`
and a :class:`~blueferry_plugin_kit.testing.TestCA`::

    login = FakeNextcloudLogin(login_name="anna", app_password="xxxx-…")
    with WsgiServer(login, ca=ca) as server:
        flow = NextcloudLogin(user_agent="Test", context=ca.client_context())
        pending = flow.start(server.base)
        login.grant()                     # the user pressed "Grant access"
        credentials = flow.poll(pending.login_id)

Requests outside the flow go to ``fallback`` (another WSGI app, e.g. a
fake WebDAV server), else 404. ``requests`` records ``(method, path,
user_agent)``; poll tokens and passwords are not recorded.
"""
from __future__ import annotations

import json
import secrets
import threading
import urllib.parse
from typing import Any


class FakeNextcloudLogin:
    def __init__(
        self, *, prefix: str = "", login_name: str = "anna",
        app_password: str = "Fake1-App2-Pass3-Word4-Here5", fallback: Any = None,
    ) -> None:
        self.prefix = prefix.rstrip("/")
        self.login_name = login_name
        self.app_password = app_password
        self.fallback = fallback
        #: Answer the start with this status instead of the flow (e.g. 404).
        self.start_status = 200
        #: Grant automatically on this poll (1 = the first one); None: wait for grant().
        self.grant_after: int | None = None
        #: ``server`` in the final answer; None: this fake's own address.
        self.server: str | None = None
        #: Replace ``login`` or ``poll.endpoint`` in the start answer (e.g. with http).
        self.login_override: str | None = None
        self.endpoint_override: str | None = None
        self.requests: list[tuple[str, str, str]] = []
        self.flows: dict[str, dict[str, Any]] = {}   # token -> state
        self._lock = threading.Lock()

    # ---- control ------------------------------------------------------------

    def grant(self, login_name: str | None = None, app_password: str | None = None) -> None:
        """The user grants access to the newest open flow."""
        with self._lock:
            if not self.flows:
                raise AssertionError("no sign-in is open")
            flow = list(self.flows.values())[-1]
            flow["granted"] = True
            if login_name is not None:
                flow["login_name"] = login_name
            if app_password is not None:
                flow["app_password"] = app_password

    @property
    def open_flows(self) -> int:
        with self._lock:
            return len(self.flows)

    def polls(self) -> int:
        with self._lock:
            return sum(1 for method, path, _ua in self.requests
                       if method == "POST" and path.endswith("/login/v2/poll"))

    # ---- WSGI ---------------------------------------------------------------

    def __call__(self, environ, start_response):
        method = environ["REQUEST_METHOD"]
        path = urllib.parse.unquote(environ.get("PATH_INFO", ""))
        with self._lock:
            self.requests.append((method, path, environ.get("HTTP_USER_AGENT", "")))
        base = f"{environ['wsgi.url_scheme']}://{environ['HTTP_HOST']}{self.prefix}"
        if path == f"{self.prefix}/index.php/login/v2":
            if method != "POST":
                return self._reply(start_response, 405)
            return self._start(start_response, base)
        if path == f"{self.prefix}/login/v2/poll":
            if method != "POST":
                return self._reply(start_response, 405)
            length = int(environ.get("CONTENT_LENGTH") or 0)
            form = dict(urllib.parse.parse_qsl(environ["wsgi.input"].read(length).decode()))
            return self._poll(start_response, base, form.get("token", ""))
        if path.startswith(f"{self.prefix}/login/v2/flow/"):
            return self._reply(start_response, 200, b"<html>Grant access</html>", "text/html")
        if self.fallback is not None:
            return self.fallback(environ, start_response)
        return self._reply(start_response, 404)

    def _start(self, start_response, base: str):
        if self.start_status != 200:
            return self._reply(start_response, self.start_status)
        token = secrets.token_urlsafe(32)
        with self._lock:
            self.flows[token] = {
                "granted": False, "polls": 0,
                "login_name": self.login_name, "app_password": self.app_password,
            }
        body = {
            "poll": {
                "token": token,
                "endpoint": self.endpoint_override or f"{base}/login/v2/poll",
            },
            "login": self.login_override or f"{base}/login/v2/flow/{secrets.token_hex(16)}",
        }
        return self._reply(start_response, 200, json.dumps(body).encode(), "application/json")

    def _poll(self, start_response, base: str, token: str):
        with self._lock:
            flow = self.flows.get(token)
            if flow is None:
                return self._reply(start_response, 404)
            flow["polls"] += 1
            if self.grant_after is not None and flow["polls"] >= self.grant_after:
                flow["granted"] = True
            if not flow["granted"]:
                return self._reply(start_response, 404)
            del self.flows[token]   # a token answers once
        body = {
            "server": self.server if self.server is not None else base,
            "loginName": flow["login_name"], "appPassword": flow["app_password"],
        }
        return self._reply(start_response, 200, json.dumps(body).encode(), "application/json")

    @staticmethod
    def _reply(start_response, status: int, body: bytes = b"", content_type: str = "text/plain"):
        reason = {200: "OK", 404: "Not Found", 405: "Method Not Allowed",
                  500: "Internal Server Error", 403: "Forbidden"}.get(status, "X")
        start_response(f"{status} {reason}", [
            ("Content-Type", content_type), ("Content-Length", str(len(body))),
        ])
        return [body]
