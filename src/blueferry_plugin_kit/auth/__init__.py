"""Token storage and refresh, and browser sign-ins.

:mod:`blueferry_plugin_kit.auth.nextcloud` runs Nextcloud's Login Flow v2
(``ConfigLogin=nextcloud``). For OAuth-style logins a plugin stores a :class:`Token` with a
:class:`TokenStore` (keyring first, 0600 file as fallback, like every
other secret) and asks a :class:`TokenSource` for a valid access token;
the source refreshes through a :class:`Refresher` shortly before the
token expires and stores the result. OAuth flows (device code,
authorization code with PKCE) come in a later release.
"""
from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, ClassVar, Protocol

from blueferry_plugin_kit.secrets import KeyringStore, SecretsError

__all__ = ["AuthError", "Refresher", "Token", "TokenSource", "TokenStore"]

#: Refresh this many seconds before the token expires.
REFRESH_LEEWAY = 60.0
MAX_TOKEN_CHARS = 8192


class AuthError(Exception):
    """No usable token: never stored, revoked or the refresh failed.

    ``reason`` is a short token (``no-token``, ``refresh-failed``,
    ``bad-token``); the message names no credential.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class Token:
    access_token: str
    refresh_token: str = ""
    expires_at: float | None = None   # POSIX time; None: does not expire
    token_type: str = "Bearer"
    scope: tuple[str, ...] = field(default_factory=tuple)

    def __repr__(self) -> str:  # never show the secrets
        return f"Token(type={self.token_type!r}, expires_at={self.expires_at!r})"

    def expired(self, now: float, leeway: float = REFRESH_LEEWAY) -> bool:
        return self.expires_at is not None and now >= self.expires_at - leeway

    def authorization(self) -> str:
        """The value of an ``Authorization`` header."""
        return f"{self.token_type} {self.access_token}"

    def to_json(self) -> str:
        return json.dumps({
            "access_token": self.access_token, "refresh_token": self.refresh_token,
            "expires_at": self.expires_at, "token_type": self.token_type,
            "scope": list(self.scope),
        })

    @classmethod
    def from_json(cls, text: str) -> Token:
        try:
            raw = json.loads(text)
        except ValueError:
            raise AuthError("bad-token") from None
        if not isinstance(raw, dict) or not isinstance(raw.get("access_token"), str):
            raise AuthError("bad-token")
        expires = raw.get("expires_at")
        if isinstance(expires, bool) or not isinstance(expires, (int, float, type(None))):
            expires = None
        scope = raw.get("scope") if isinstance(raw.get("scope"), list) else []
        return cls(
            access_token=raw["access_token"],
            refresh_token=raw.get("refresh_token") if isinstance(
                raw.get("refresh_token"), str) else "",
            expires_at=float(expires) if expires is not None else None,
            token_type=raw.get("token_type") if isinstance(raw.get("token_type"), str)
            else "Bearer",
            scope=tuple(s for s in scope if isinstance(s, str)),
        )


class Refresher(Protocol):
    """Exchanges a token's refresh token for a new token (one provider)."""

    def refresh(self, token: Token) -> Token: ...


class TokenStore(KeyringStore):
    """One token per account, as JSON in the keyring or a 0600 file.

    ``account`` identifies the login (e.g. ``{"server": url, "user": name}``,
    matching :attr:`SECRET_ATTRIBUTES`). :meth:`save` returns where the token
    went; pass that back to :meth:`load`.
    """

    SECRET_SCHEMA: ClassVar[str] = "io.weirdware.blueferry.plugin_kit.Token"
    SECRET_LABEL: ClassVar[str] = "BlueFerry plugin login"

    def __init__(
        self, directory: Path, account: Mapping[str, str], *, secret: Any = None,
        file_name: str = "token",
    ) -> None:
        super().__init__(directory, secret=secret)
        self.account = dict(account)
        self._file_name = file_name

    @property
    def key_path(self) -> Path:
        return self.directory / self._file_name

    def save(self, token: Token, *, prefer_keyring: bool = True) -> str:
        return self.save_secret(self.account, token.to_json(), prefer_keyring=prefer_keyring)

    def load(self, key_store: str) -> Token:
        try:
            text = self.load_secret(
                key_store, self.account, missing="no-token", empty="no-token", strip=True,
            )
        except SecretsError:
            raise AuthError("no-token") from None
        if len(text) > MAX_TOKEN_CHARS:
            raise AuthError("bad-token")
        return Token.from_json(text)

    def clear(self) -> None:
        self.clear_keyring(self.account)
        self.key_path.unlink(missing_ok=True)


class TokenSource:
    """A valid access token on demand, refreshed and stored when due.

    Thread-safe: concurrent callers share one refresh.
    """

    def __init__(
        self, store: TokenStore, key_store: str, refresher: Refresher, *,
        clock: Callable[[], float] = time.time, leeway: float = REFRESH_LEEWAY,
    ) -> None:
        self._store = store
        self.key_store = key_store
        self._refresher = refresher
        self._clock = clock
        self._leeway = leeway
        self._lock = threading.Lock()
        self._token: Token | None = None

    def token(self) -> Token:
        with self._lock:
            token = self._token or self._store.load(self.key_store)
            if token.expired(self._clock(), self._leeway):
                if not token.refresh_token:
                    raise AuthError("refresh-failed")
                try:
                    fresh = self._refresher.refresh(token)
                except AuthError:
                    raise
                except Exception:
                    raise AuthError("refresh-failed") from None
                if not fresh.refresh_token:
                    # Providers may omit an unchanged refresh token.
                    fresh = replace(fresh, refresh_token=token.refresh_token)
                self.key_store = self._store.save(fresh, prefer_keyring=self.key_store != "file")
                token = fresh
            self._token = token
            return token

    def access_token(self) -> str:
        return self.token().access_token

    def forget(self) -> None:
        with self._lock:
            self._token = None
