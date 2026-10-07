"""Nextcloud Login Flow v2: sign in through the browser, get an app password.

The plugin side of ``ConfigLogin=nextcloud`` (plugin-api 1.3)::

    from blueferry_plugin_kit.auth.nextcloud import NextcloudLogin

    class MyPlugin(PluginService):
        def __init__(self, manifest, bus=None, **kwargs):
            super().__init__(manifest, bus, **kwargs)
            self._login = NextcloudLogin(user_agent="BlueFerry WebDAV")

        def config_login(self, provider, values):
            return self._login.login_step(str(values.get("url") or ""))

        def config_login_status(self, login_id):
            return self._login.status_step(login_id, self._store_login)

        def config_login_cancel(self, login_id):
            self._login.cancel(login_id)

        def _store_login(self, credentials):        # Credentials -> message
            self.settings.save(credentials.webdav_url, credentials.login_name,
                               credentials.app_password)
            return f"Connected as {credentials.login_name}"

The flow (https://docs.nextcloud.com/server/latest/developer_manual/client_apis/LoginFlow/):

1. ``POST <server>/index.php/login/v2`` answers ``{poll: {token, endpoint},
   login}``. The plugin keeps ``token`` and ``endpoint`` and hands ``login``
   to BlueFerry, which opens it in the browser.
2. ``POST <endpoint>`` with the form field ``token`` answers 404 until the
   user has granted access, then once ``{server, loginName, appPassword}``.

Only https is used: the typed server, the login page, the poll endpoint and
the server the answer names. Redirects are not followed and no proxy is
used unless ``use_proxy`` is set. The app password lives in
:class:`Credentials` (its ``repr`` hides it) and goes to the store
callback; it is never logged. Flows expire after 20 minutes like
Nextcloud's tokens.
"""
from __future__ import annotations

import json
import logging
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from blueferry.plugin_api.config import ConfigError
from blueferry.plugin_api.config_flow import LOGIN_TIMEOUT_SECONDS, LoginStep

__all__ = [
    "MESSAGES",
    "Credentials",
    "NextcloudLogin",
    "NextcloudLoginError",
    "PendingLogin",
    "server_root",
]

log = logging.getLogger(__name__)

TIMEOUT_SEC = 15.0
MAX_REPLY_BYTES = 64 * 1024
MAX_URL = 2048
MAX_TOKEN = 512
MAX_NAME = 256
MAX_PASSWORD = 512
#: Concurrent sign-ins kept per plugin; a new one drops the oldest.
MAX_FLOWS = 4
#: Polls of Nextcloud closer together than this answer "pending" locally.
MIN_POLL_INTERVAL = 1.0
#: Network failures in a row while polling before the flow gives up.
MAX_POLL_FAILURES = 5
# Path parts that mark a deeper URL below the server root.
_ROOT_MARKERS = ("/remote.php", "/index.php", "/ocs/", "/apps/", "/login", "/status.php")

#: Default messages by reason; pass ``messages=`` to translate.
MESSAGES: Mapping[str, str] = {
    "insecure": "Sign-in needs an https:// server address.",
    "invalid-url": "Enter the server address, e.g. https://cloud.example.com.",
    "unreachable": "The server could not be reached.",
    "not-nextcloud": "This server does not offer the Nextcloud sign-in.",
    "redirect": "The server redirects; enter the address you end up at.",
    "refused": "The server refused the sign-in.",
    "bad-reply": "The server sent an answer that is not a Nextcloud sign-in.",
    "expired": "The sign-in took too long; start it again.",
    "unknown": "This sign-in is no longer running; start it again.",
    "cancelled": "Sign-in cancelled.",
    "store-failed": "Signed in, but the app password could not be stored.",
}


class NextcloudLoginError(Exception):
    """The flow could not start or continue; ``reason`` is a key of MESSAGES."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class Credentials:
    """What Nextcloud hands over at the end of the flow."""

    server: str          # https root, without a trailing slash
    login_name: str
    app_password: str = field(repr=False)

    def __repr__(self) -> str:  # never show the app password
        return f"Credentials(server={self.server!r}, login_name={self.login_name!r})"

    @property
    def dav_url(self) -> str:
        """The DAV root, e.g. for CalDAV discovery."""
        return f"{self.server}/remote.php/dav"

    @property
    def webdav_url(self) -> str:
        """The user's files: ``<server>/remote.php/dav/files/<loginName>/``."""
        user = urllib.parse.quote(self.login_name, safe="@")
        return f"{self.server}/remote.php/dav/files/{user}/"


@dataclass(frozen=True, slots=True)
class PendingLogin:
    """A started flow: open ``login_url`` in the browser, poll ``login_id``."""

    login_id: str
    login_url: str
    server: str


@dataclass(slots=True)
class _Flow:
    server: str
    endpoint: str
    token: str = field(repr=False)
    started: float
    last_poll: float = float("-inf")
    failures: int = 0


def _clean(text: str) -> bool:
    return all(ch.isprintable() and not ch.isspace() for ch in text)


def _https(value: object, *, limit: int = MAX_URL) -> str | None:
    """An absolute https URL without user info, else None."""
    if not isinstance(value, str) or not value or len(value) > limit or not _clean(value):
        return None
    try:
        parts = urllib.parse.urlsplit(value)
        parts.port  # noqa: B018 - raises ValueError for a bad port
    except ValueError:
        return None
    if parts.scheme != "https" or not parts.hostname or "@" in parts.netloc:
        return None
    return value


def server_root(url: str) -> str:
    """The Nextcloud root for a typed address.

    Accepts the root (``https://cloud.example.com/nextcloud``) or any URL
    below it (a WebDAV or CalDAV address, the login page) and cuts it back.
    Raises :class:`NextcloudLoginError` (``insecure``, ``invalid-url``).
    """
    text = (url or "").strip()
    if not text:
        raise NextcloudLoginError("invalid-url")
    if "://" not in text:
        text = "https://" + text
    try:
        parts = urllib.parse.urlsplit(text)
    except ValueError:
        raise NextcloudLoginError("invalid-url") from None
    if parts.scheme.lower() == "http":
        raise NextcloudLoginError("insecure")
    if _https(text) is None or parts.query or parts.fragment:
        raise NextcloudLoginError("invalid-url")
    path = parts.path
    for marker in _ROOT_MARKERS:
        index = path.find(marker)
        if index != -1:
            path = path[:index]
    return f"https://{parts.netloc}{path.rstrip('/')}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class NextcloudLogin:
    """Runs Login Flow v2 sign-ins for one plugin; thread-safe.

    ``user_agent`` is what Nextcloud shows on its "Connect to your account"
    page and later in the user's list of devices, e.g. ``BlueFerry WebDAV``.
    ``context``: the TLS context (tests pass one that trusts a test CA).
    ``min_interval``: polls closer together answer "pending" without asking
    the server (tests set 0).
    """

    def __init__(
        self, *, user_agent: str, context: ssl.SSLContext | None = None,
        timeout: float = TIMEOUT_SEC, lifetime: float = LOGIN_TIMEOUT_SECONDS,
        clock: Callable[[], float] = time.monotonic, use_proxy: bool = False,
        messages: Mapping[str, str] | None = None,
        min_interval: float = MIN_POLL_INTERVAL,
    ) -> None:
        self.user_agent = user_agent
        self.min_interval = min_interval
        self.timeout = timeout
        self.lifetime = lifetime
        self._clock = clock
        self.messages = {**MESSAGES, **(messages or {})}
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.HTTPSHandler(context=context or ssl.create_default_context()),
            _NoRedirect(),
        ]
        if not use_proxy:
            handlers.append(urllib.request.ProxyHandler({}))
        self._opener = urllib.request.build_opener(*handlers)
        self._lock = threading.Lock()
        self._flows: OrderedDict[str, _Flow] = OrderedDict()
        self._cancelled: OrderedDict[str, None] = OrderedDict()

    # ---- HTTP ---------------------------------------------------------------

    def _post(self, url: str, form: Mapping[str, str] | None = None) -> tuple[int, bytes]:
        if _https(url) is None:
            raise NextcloudLoginError("insecure")
        data = urllib.parse.urlencode(form or {}).encode()
        request = urllib.request.Request(url, data=data, method="POST", headers={
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        })
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                return response.status, self._read(response)
        except urllib.error.HTTPError as error:
            error.close()
            return error.code, b""
        except (urllib.error.URLError, OSError, ValueError):
            raise NextcloudLoginError("unreachable") from None

    @staticmethod
    def _read(response) -> bytes:
        body = response.read(MAX_REPLY_BYTES + 1)
        if len(body) > MAX_REPLY_BYTES:
            raise NextcloudLoginError("bad-reply")
        return body

    @staticmethod
    def _json(body: bytes) -> dict:
        try:
            value = json.loads(body)
        except ValueError:
            raise NextcloudLoginError("bad-reply") from None
        if not isinstance(value, dict):
            raise NextcloudLoginError("bad-reply")
        return value

    # ---- the flow -----------------------------------------------------------

    def start(self, url: str) -> PendingLogin:
        """Start a sign-in at the server behind ``url``."""
        server = server_root(url)
        status, body = self._post(f"{server}/index.php/login/v2")
        if 300 <= status < 400:
            raise NextcloudLoginError("redirect")
        if status in (404, 405):
            raise NextcloudLoginError("not-nextcloud")
        if status != 200:
            raise NextcloudLoginError("refused")
        reply = self._json(body)
        poll = reply.get("poll")
        if not isinstance(poll, dict):
            raise NextcloudLoginError("bad-reply")
        token, endpoint, login = poll.get("token"), poll.get("endpoint"), reply.get("login")
        if not isinstance(token, str) or not 0 < len(token) <= MAX_TOKEN or not _clean(token):
            raise NextcloudLoginError("bad-reply")
        if _https(endpoint) is None or _https(login) is None:
            raise NextcloudLoginError("insecure")
        login_id = secrets.token_urlsafe(16)
        with self._lock:
            self._flows[login_id] = _Flow(server, endpoint, token, self._clock())
            while len(self._flows) > MAX_FLOWS:
                self._flows.popitem(last=False)
        log.info("nextcloud sign-in started")
        return PendingLogin(login_id, login, server)

    def poll(self, login_id: str) -> Credentials | None:
        """``None`` while the user has not answered, then the credentials.

        Raises :class:`NextcloudLoginError` (``unknown``, ``cancelled``,
        ``expired``, ``refused``, ``unreachable``, ``bad-reply``,
        ``insecure``); the flow is gone afterwards.
        """
        now = self._clock()
        with self._lock:
            flow = self._flows.get(login_id)
            if flow is None:
                raise NextcloudLoginError(
                    "cancelled" if login_id in self._cancelled else "unknown",
                )
            if now - flow.started > self.lifetime:
                del self._flows[login_id]
                raise NextcloudLoginError("expired")
            if now - flow.last_poll < self.min_interval:
                return None
            flow.last_poll = now
        try:
            status, body = self._post(flow.endpoint, {"token": flow.token})
        except NextcloudLoginError as error:
            if error.reason != "unreachable":
                self._drop(login_id)
                raise
            with self._lock:
                flow.failures += 1
                if flow.failures < MAX_POLL_FAILURES:
                    return None
            self._drop(login_id)
            raise
        if status == 404 or status == 429 or status >= 500:
            with self._lock:
                flow.failures = 0 if status == 404 else flow.failures
            return None
        self._drop(login_id)
        if status != 200:
            raise NextcloudLoginError("refused")
        return self._credentials(flow, self._json(body))

    def _credentials(self, flow: _Flow, reply: dict) -> Credentials:
        name, password = reply.get("loginName"), reply.get("appPassword")
        if not isinstance(name, str) or not 0 < len(name) <= MAX_NAME or not all(
            ch.isprintable() for ch in name
        ) or "/" in name:
            raise NextcloudLoginError("bad-reply")
        if not isinstance(password, str) or not 0 < len(password) <= MAX_PASSWORD or not _clean(
            password,
        ):
            raise NextcloudLoginError("bad-reply")
        # Nextcloud names its canonical address; a misconfigured one may say
        # http. The typed server answered the flow over https, so keep it.
        try:
            server = server_root(reply.get("server") or "")
        except NextcloudLoginError:
            server = flow.server
        log.info("nextcloud sign-in granted")
        return Credentials(server, name, password)

    def _drop(self, login_id: str) -> None:
        with self._lock:
            self._flows.pop(login_id, None)

    def cancel(self, login_id: str) -> None:
        """Forget the flow; later polls answer ``cancelled``."""
        with self._lock:
            known = self._flows.pop(login_id, None) is not None
            if known:
                self._cancelled[login_id] = None
                while len(self._cancelled) > 16:
                    self._cancelled.popitem(last=False)
        if known:
            log.info("nextcloud sign-in cancelled")

    @property
    def running(self) -> int:
        with self._lock:
            return len(self._flows)

    # ---- plugin-api 1.3 hooks -----------------------------------------------

    def message(self, reason: str) -> str:
        return self.messages.get(reason, self.messages["refused"])

    def login_step(self, url: str) -> LoginStep:
        """The answer to ``ConfigLogin``: ``open`` with the login page, or ``error``."""
        try:
            pending = self.start(url)
        except NextcloudLoginError as error:
            log.info("nextcloud sign-in could not start: %s", error.reason)
            return LoginStep("error", self.message(error.reason))
        return LoginStep("open", login_id=pending.login_id, open_uri=pending.login_url)

    def status_step(
        self, login_id: str, store: Callable[[Credentials], str],
    ) -> LoginStep:
        """The answer to ``ConfigLoginStatus``.

        ``store(credentials)`` saves server, user and app password and returns
        the ``done`` message (``"Connected as anna"``); it may raise
        :class:`ConfigError` with a message for the user.
        """
        try:
            credentials = self.poll(login_id)
        except NextcloudLoginError as error:
            log.info("nextcloud sign-in ended: %s", error.reason)
            state = error.reason if error.reason in ("expired", "cancelled") else "error"
            return LoginStep(state, self.message(error.reason))
        if credentials is None:
            return LoginStep("pending")
        try:
            message = store(credentials)
        except ConfigError as error:
            log.info("nextcloud sign-in not stored: the plugin refused it")
            return LoginStep("error", error.message or self.message("store-failed"))
        except Exception as error:  # never let the password reach a traceback reply
            log.info("nextcloud sign-in not stored: %s", type(error).__name__)
            return LoginStep("error", self.message("store-failed"))
        return LoginStep("done", message or f"Connected as {credentials.login_name}")
