"""A strict stand-in for the BlueFerry core of PLUGIN-SURFACES v1.2.

:class:`FakeHost` calls a plugin service in-process (no bus) the way the
core does (``card``, ``share``, ``notify``): with a sender and, for
methods declared with D-Bus async callbacks, ``reply``/``error``. Every
reply is checked field by field against the limits of
:mod:`blueferry.plugin_api.surfaces`; a violation raises
:class:`SpecViolation` (an ``AssertionError``). The content-free
``CardChanged()`` and the ``Notify(...)`` signals are recorded.
"""
from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from blueferry.plugin_api import surfaces

MAX_REPLY_BYTES = 512 * 1024


class SpecViolation(AssertionError):
    """A plugin reply or signal breaks PLUGIN-SURFACES v1.2."""


def _text(value: object, limit: int, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str) or len(value) > limit:
        raise SpecViolation(f"text over {limit}: {value!r}")
    if any(not ch.isprintable() for ch in value):
        raise SpecViolation(f"control characters: {value!r}")


def _icon(value: object, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str) or (value and not surfaces.icon_name(value)):
        raise SpecViolation(f"icon must be a freedesktop icon name: {value!r}")


def _id(value: object, what: str) -> None:
    if not surfaces.valid_id(value):
        raise SpecViolation(f"bad {what} id: {value!r}")


def _json(reply: object) -> Any:
    if not isinstance(reply, str) or len(reply.encode()) > MAX_REPLY_BYTES:
        raise SpecViolation("reply is not a string within 512 KiB")
    return json.loads(reply)


def check_card(reply: str) -> list[dict]:
    """The items of a ``GetCardItems`` reply, checked."""
    data = _json(reply)
    if not isinstance(data, dict) or set(data) != {"items"} or not isinstance(
        data["items"], list,
    ):
        raise SpecViolation("card reply must be {items: [...]}")
    items = data["items"]
    if len(items) > surfaces.MAX_CARD_ITEMS:
        raise SpecViolation(f"more than {surfaces.MAX_CARD_ITEMS} items")
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {
            "id", "icon", "title", "subtitle", "actions",
        }:
            raise SpecViolation(f"card item keys: {sorted(item)}")
        _id(item["id"], "item")
        if item["id"] in seen:
            raise SpecViolation(f"duplicate item id: {item['id']!r}")
        seen.add(item["id"])
        _icon(item["icon"])
        _text(item["title"], surfaces.MAX_TITLE)
        if not item["title"]:
            raise SpecViolation("card item without a title")
        _text(item["subtitle"], surfaces.MAX_SUBTITLE, optional=True)
        actions = item["actions"]
        if not isinstance(actions, list) or len(actions) > surfaces.MAX_ACTIONS:
            raise SpecViolation(f"at most {surfaces.MAX_ACTIONS} actions")
        for action in actions:
            if not isinstance(action, dict) or set(action) != {"id", "label", "icon", "kind"}:
                raise SpecViolation(f"action keys: {sorted(action)}")
            _id(action["id"], "action")
            if action["kind"] not in surfaces.ACTION_KINDS:
                raise SpecViolation(f"action kind {action['kind']!r}")
            _text(action["label"], surfaces.MAX_LABEL)
            if not action["label"]:
                raise SpecViolation("action without a label")
            _icon(action["icon"], optional=True)
    return items


def check_result(reply: str, cache_roots: list[Path] | None = None) -> dict:
    """An ``InvokeAction`` reply, checked; ``file://`` needs ``cache_roots``."""
    data = _json(reply)
    if not isinstance(data, dict) or set(data) != {"ok", "message", "open_uri"} or not isinstance(
        data["ok"], bool,
    ):
        raise SpecViolation("InvokeAction reply must be {ok, message, open_uri}")
    _text(data["message"], surfaces.MAX_MESSAGE, optional=True)
    uri = data["open_uri"]
    if uri is not None and surfaces.checked_open_uri(uri, cache_roots or []) is None:
        raise SpecViolation(f"open_uri BlueFerry would refuse: {uri!r}")
    return data


def check_targets(reply: str) -> list[dict]:
    data = _json(reply)
    targets = data.get("targets") if isinstance(data, dict) else None
    if not isinstance(targets, list) or len(targets) > surfaces.MAX_SHARE_TARGETS:
        raise SpecViolation("ShareTargets reply must be {targets: [...]}")
    for target in targets:
        if not isinstance(target, dict) or set(target) != {"id", "label", "icon"}:
            raise SpecViolation("share target keys")
        _id(target["id"], "share target")
        _text(target["label"], surfaces.MAX_LABEL)
        if not target["label"]:
            raise SpecViolation("share target without a label")
        _icon(target["icon"])
    return targets


def check_send(reply: str) -> dict:
    data = _json(reply)
    if not isinstance(data, dict) or set(data) != {"ok", "message", "job"} or not isinstance(
        data["ok"], bool,
    ):
        raise SpecViolation("SendFiles reply must be {ok, message, job}")
    _text(data["message"], surfaces.MAX_MESSAGE, optional=True)
    return data


def check_notification(args: tuple) -> tuple[str, str, str, str, str]:
    if len(args) != 5 or not all(isinstance(a, str) for a in args):
        raise SpecViolation("Notify takes five strings")
    title, body, icon, label, action = args
    _text(title, surfaces.MAX_TITLE)
    _text(body, surfaces.MAX_NOTIFY_BODY)
    _text(label, surfaces.MAX_LABEL)
    _icon(icon)
    if not title:
        raise SpecViolation("notification without a title")
    if bool(label) != bool(action):
        raise SpecViolation("notify action label and id come together")
    if action:
        _id(action, "notify action")
    return title, body, icon, label, action


class FakeHost:
    """Plays the core for one plugin service.

    ``cache_roots``: where ``file://`` answers may point (the plugin cache).
    ``refetch``: re-read the card on every ``CardChanged()`` like the core,
    keeping each result in :attr:`snapshots`.
    """

    def __init__(
        self, service: Any, *, cache_roots: list[Path] | None = None, refetch: bool = False,
        sender: str = ":1.host",
    ) -> None:
        self.service = service
        self.cache_roots = list(cache_roots or [])
        self.refetch = refetch
        self.sender = sender
        self.card_changed = 0
        self.snapshots: list[list[dict]] = []
        self.notifications: list[tuple[str, str, str, str, str]] = []
        self._changed = threading.Condition()
        # Instance attributes shadow the dbus-decorated signal methods.
        service.CardChanged = self._on_card_changed
        service.Notify = self._on_notify

    # ---- signals --------------------------------------------------------------

    def _on_card_changed(self, *args: Any) -> None:
        if args:
            raise SpecViolation("CardChanged carries no content")
        with self._changed:
            self.card_changed += 1
            self._changed.notify_all()
        if self.refetch:
            self.snapshots.append(self.card_items())

    def _on_notify(self, *args: Any) -> None:
        notification = check_notification(args)
        with self._changed:
            self.notifications.append(notification)
            self._changed.notify_all()

    def wait_for(self, predicate: Callable[[], bool], timeout: float = 10.0) -> None:
        """Block until ``predicate()`` holds (checked on every signal)."""
        deadline = time.monotonic() + timeout
        with self._changed:
            while not predicate():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError("timed out waiting for the plugin")
                self._changed.wait(min(remaining, 0.05))

    # ---- calls ----------------------------------------------------------------

    def call(self, method: str, *args: Any) -> Any:
        """Call a service method like the core; return the raw reply."""
        function = getattr(self.service, method)
        if getattr(function, "_dbus_async_callbacks", None):
            outcome: dict[str, Any] = {}
            function(
                *args,
                reply=lambda value=None: outcome.setdefault("reply", value),
                error=lambda failure: outcome.setdefault("error", failure),
                sender=self.sender,
            )
            if "error" in outcome:
                raise outcome["error"]
            if "reply" not in outcome:
                raise SpecViolation(f"{method} answered neither reply nor error")
            return outcome["reply"]
        return function(*args, sender=self.sender)

    def card_items(self) -> list[dict]:
        return check_card(self.call("GetCardItems"))

    def item(self, item_id: str) -> dict | None:
        """The card item with exactly this id, or None."""
        return next((i for i in self.card_items() if i["id"] == item_id), None)

    def find(self, prefix: str) -> dict | None:
        """The first card item whose id starts with ``prefix``, or None."""
        return next((i for i in self.card_items() if i["id"].startswith(prefix)), None)

    def invoke(self, item_id: str, action_id: str, args: str | dict | None = None) -> dict:
        text = args if isinstance(args, str) else json.dumps(args or {})
        return check_result(
            self.call("InvokeAction", item_id, action_id, text), self.cache_roots,
        )

    def click_notification(self, notification: int | tuple = -1) -> dict:
        """The user clicks the action of a shown notification."""
        if isinstance(notification, int):
            notification = self.notifications[notification]
        return self.invoke(surfaces.NOTIFY_ITEM_ID, notification[4])

    def share_targets(self) -> list[dict]:
        return check_targets(self.call("ShareTargets"))

    def send_files(self, target_id: str, paths: list[str]) -> dict:
        return check_send(self.call("SendFiles", target_id, paths))

    def info(self) -> dict:
        return _json(self.call("GetInfo"))

    def status(self) -> dict:
        return _json(self.call("Status"))

    def get_config(self) -> dict:
        return _json(self.call("GetConfig"))

    def set_config(self, values: dict) -> dict:
        return _json(self.call("SetConfig", json.dumps(values)))
