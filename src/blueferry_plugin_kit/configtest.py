"""Helpers for ``TestConfig`` ("Test connection", plugin-api 1.3).

``test_config(values)`` runs on the worker thread with the values typed into
the form; nothing may be stored. A secret the user did not retype is missing
from ``values`` and the stored one applies::

    from blueferry_plugin_kit.configtest import connected, passed, secret_or_stored

    def test_config(self, values):
        key = secret_or_stored(values, "api_key", self._stored_key)
        user, version = self._check(values["url"], key)   # raises ConfigError
        return passed(connected(user, "Immich", version))

Messages are one line in the user's terms and never contain the secret
(:func:`scrub` removes it from text that came from a server).
"""
from __future__ import annotations

from collections.abc import Callable, Mapping

from blueferry.plugin_api.config import ConfigError
from blueferry.plugin_api.config_flow import MAX_MESSAGE, ConfigTestResult, plain

__all__ = ["ConfigTestResult", "connected", "failed", "passed", "scrub", "secret_or_stored"]


def secret_or_stored(
    values: Mapping[str, object], key: str, stored: Callable[[], str | None],
    *, missing: str = "is required",
) -> str:
    """The secret typed into the form, else the stored one.

    ``stored()`` may raise; that counts as nothing stored. Raises
    :class:`ConfigError` on ``key`` when there is neither.
    """
    typed = values.get(key)
    if isinstance(typed, str) and typed:
        return typed
    try:
        value = stored()
    except Exception:
        value = None
    if not value:
        raise ConfigError(key, missing)
    return value


def connected(user: str | None = None, service: str | None = None,
              version: str | None = None) -> str:
    """``Connected as anna to Immich 1.135`` with the parts that are known."""
    text = "Connected"
    if user:
        text += f" as {user}"
    if service:
        text += f" to {service}" + (f" {version}" if version else "")
    return plain(text)


def scrub(text: object, *secrets: str | None, limit: int = MAX_MESSAGE) -> str:
    """One line of ``text`` with every secret replaced by ``***``."""
    result = str(text or "")
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        result = result.replace(secret, "***")
    return plain(result, limit)


def passed(message: str) -> ConfigTestResult:
    return ConfigTestResult(True, plain(message))


def failed(message: str, **errors: str) -> ConfigTestResult:
    """A failed test; ``errors`` mark fields (``api_key="refused"``)."""
    return ConfigTestResult(False, plain(message), {k: plain(v) for k, v in errors.items()})
