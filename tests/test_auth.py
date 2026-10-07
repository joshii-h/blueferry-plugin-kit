from __future__ import annotations

import pytest

from blueferry_plugin_kit.auth import AuthError, Token, TokenSource, TokenStore
from blueferry_plugin_kit.testing import FakeSecret

ACCOUNT = {"server": "https://id.example.org", "user": "alice"}


class Refresher:
    def __init__(self, fail: bool = False) -> None:
        self.calls = 0
        self.fail = fail

    def refresh(self, token: Token) -> Token:
        self.calls += 1
        if self.fail:
            raise RuntimeError("provider said no: secret details")
        return Token(f"access-{self.calls}", expires_at=2000.0 + self.calls * 1000)


def test_token_json_round_trip_and_repr() -> None:
    token = Token("a", "r", 1234.5, "Bearer", ("files", "calendar"))
    assert Token.from_json(token.to_json()) == token
    assert "a" not in repr(token).replace("Bearer", "").replace("expires_at", "")
    assert token.authorization() == "Bearer a"
    assert token.expired(1200) and not token.expired(1000) and not Token("x").expired(1e12)
    for bad in ("", "[]", '{"access_token": 1}'):
        with pytest.raises(AuthError):
            Token.from_json(bad)
    loose = Token.from_json('{"access_token": "a", "expires_at": true, "scope": "x"}')
    assert loose.expires_at is None and loose.scope == ()


def test_token_store_keyring_and_file(tmp_path) -> None:
    secret = FakeSecret()
    store = TokenStore(tmp_path / "conf", ACCOUNT, secret=secret)
    assert store.save(Token("a", "r")) == "keyring"
    assert store.load("keyring") == Token("a", "r")
    assert store.save(Token("b"), prefer_keyring=False) == "file"
    assert store.load("file") == Token("b")
    store.clear()
    with pytest.raises(AuthError, match="no-token"):
        store.load("file")
    with pytest.raises(AuthError, match="no-token"):
        store.load("keyring")


def test_token_source_refreshes_when_due_and_keeps_the_refresh_token(tmp_path) -> None:
    now = [1000.0]
    store = TokenStore(tmp_path / "conf", ACCOUNT, secret=FakeSecret())
    where = store.save(Token("old", "refresh-1", expires_at=1030.0))
    refresher = Refresher()
    source = TokenSource(store, where, refresher, clock=lambda: now[0])
    assert source.access_token() == "access-1"          # within the 60 s leeway
    assert store.load(where) == Token("access-1", "refresh-1", 3000.0)
    assert source.access_token() == "access-1" and refresher.calls == 1
    now[0] = 2950.0
    assert source.access_token() == "access-2"


def test_token_source_failures_name_no_secret(tmp_path) -> None:
    store = TokenStore(tmp_path / "conf", ACCOUNT, secret=FakeSecret())
    source = TokenSource(store, "keyring", Refresher(fail=True), clock=lambda: 5000.0)
    with pytest.raises(AuthError, match="no-token"):
        source.token()
    store.save(Token("old", "r", expires_at=10.0))
    with pytest.raises(AuthError) as caught:
        source.token()
    assert caught.value.reason == "refresh-failed" and "secret" not in str(caught.value)
    store.save(Token("old", "", expires_at=10.0))
    source.forget()
    with pytest.raises(AuthError, match="refresh-failed"):
        source.token()
