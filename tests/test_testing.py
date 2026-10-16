"""The fakes themselves: FakeHost checks replies against the plugin API spec."""
from __future__ import annotations

import json

import pytest

from blueferry_plugin_kit.testing import FakeClipboard, FakeHost, SpecViolation, TestCA
from blueferry_plugin_kit.testing.host import check_card, check_pending, check_result


def _item(**changes) -> dict:
    item = {"id": "a.b", "icon": "folder", "title": "T", "subtitle": None, "actions": [
        {"id": "open", "label": "Öffnen", "icon": None, "kind": "primary"},
    ]}
    item.update(changes)
    return item


class Service:
    """Synchronous methods; ShareTargets with D-Bus style async callbacks."""

    def __init__(self, items, result=None) -> None:
        self.items = items
        self.result = result or {"ok": True, "message": None, "open_uri": None}
        self.calls = []
        self.pending = []

    def notify(self, title, body, icon, action_label, action_id) -> None:
        """Queue a popup and signal it, the plugin-api 1.5 way."""
        self.pending.append({"title": title, "body": body, "icon": icon,
                             "action_label": action_label, "action_id": action_id})
        self.NotifyChanged()

    def GetPendingNotification(self, sender=None):
        note = self.pending.pop(0) if self.pending else None
        return json.dumps({"notification": note, "more": bool(self.pending)})

    def GetCardItems(self, sender=None):
        self.calls.append(("GetCardItems", sender))
        return json.dumps({"items": self.items})

    def InvokeAction(self, item_id, action_id, args, sender=None):
        self.calls.append(("InvokeAction", item_id, action_id, json.loads(args)))
        return json.dumps(self.result)

    def ShareTargets(self, reply, error, sender=None):
        reply(json.dumps({"targets": [{"id": "dav", "label": "WebDAV", "icon": "folder"}]}))

    ShareTargets._dbus_async_callbacks = ("reply", "error")  # type: ignore[attr-defined]


def test_fake_host_calls_and_records_signals(tmp_path) -> None:
    service = Service([_item()])
    host = FakeHost(service, refetch=True)
    assert host.item("a.b")["title"] == "T" and host.find("a.") is not None
    assert host.item("nope") is None
    service.CardChanged()
    service.notify("Titel", "Text", "folder", "Öffnen", "open-1")
    host.wait_for(lambda: len(host.notifications) == 1)
    assert host.card_changed == 1 and len(host.snapshots) == 1
    assert host.click_notification()["ok"] is True
    assert service.calls[-1] == ("InvokeAction", "notify", "open-1", {})
    assert host.invoke("a.b", "open", {"x": 1})["ok"] is True
    assert host.share_targets()[0]["id"] == "dav"
    with pytest.raises(SpecViolation):
        service.notify("x" * 81, "", "", "", "")
    with pytest.raises(SpecViolation):
        service.CardChanged("content")
    with pytest.raises(SpecViolation):
        service.NotifyChanged("content")
    with pytest.raises(SpecViolation):
        service.notify("Titel", "", "", "Öffnen", "")     # label without action
    with pytest.raises(SpecViolation):
        check_card(json.dumps({"items": [_item(), _item()]}))   # duplicate ids


@pytest.mark.parametrize("item", [
    _item(id="bad:id"), _item(title="x" * 81), _item(icon="/usr/share/x.png"),
    _item(subtitle="line\nbreak"), _item(actions=[_item()["actions"][0]] * 4),
    _item(extra=1), _item(title=""),
    _item(actions=[{"id": "x", "label": "", "icon": None, "kind": "button"}]),
    _item(actions=[{"id": "x", "label": "Send", "icon": None, "kind": "button",
                    "send_to": "a:b"}]),
    _item(actions=[{"id": "x", "label": "Send", "icon": None, "kind": "button",
                    "target": "a"}]),
])
def test_card_violations(item) -> None:
    with pytest.raises(SpecViolation):
        check_card(json.dumps({"items": [item]}))


def test_open_uri_rules(tmp_path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "f.txt").write_text("x")
    (tmp_path / "outside.txt").write_text("x")
    ok = {"ok": True, "message": None}
    assert check_result(json.dumps({**ok, "open_uri": "https://x.org/"}))
    assert check_result(json.dumps({**ok, "open_uri": (cache / "f.txt").as_uri()}), [cache])
    for uri in ((tmp_path / "outside.txt").as_uri(), "javascript:alert(1)"):
        with pytest.raises(SpecViolation):
            check_result(json.dumps({**ok, "open_uri": uri}), [cache])


def test_fake_clipboard_and_test_ca(tmp_path) -> None:
    clipboard = FakeClipboard("äöü")
    assert clipboard.copy_text("x") and clipboard.copies == [(b"x", "text/plain;charset=utf-8")]
    assert clipboard.read_text(6) == "äöü" and clipboard.read_text(5) is None
    ca = TestCA(tmp_path / "ca")
    assert ca.client_context().verify_mode.name == "CERT_REQUIRED"
    assert ca.material.fingerprint.count(":") == 31


class _Manifest:
    def __init__(self, capabilities) -> None:
        self.capabilities = capabilities

    def has(self, capability) -> bool:
        return capability in self.capabilities


class SendingService(Service):
    """A device item whose primary action sends files (plugin API 1.4)."""

    def __init__(self, capabilities=("card", "share")) -> None:
        super().__init__([_item(id="dev-1", actions=[
            {"id": "send", "label": "Send files…", "icon": "document-send",
             "kind": "primary", "send_to": "ls-1"},
            {"id": "trust", "label": "Always accept", "icon": None, "kind": "button"},
        ])])
        self.manifest = _Manifest(capabilities)
        self.sent = []

    def SendFiles(self, target, paths, sender=None):
        self.sent.append((target, list(paths)))
        return json.dumps({"ok": True, "message": "Sending", "job": "j1"})


def test_send_action_calls_send_files_on_the_target(tmp_path) -> None:
    service = SendingService()
    host = FakeHost(service)
    assert host.item("dev-1")["actions"][0]["send_to"] == "ls-1"
    assert host.send_action("dev-1", "send", ["/tmp/a"])["ok"] is True
    assert service.sent == [("ls-1", ["/tmp/a"])]
    assert not any(call[0] == "InvokeAction" for call in service.calls)
    with pytest.raises(SpecViolation, match="does not send"):
        host.send_action("dev-1", "trust", ["/tmp/a"])
    with pytest.raises(SpecViolation, match="no card item"):
        host.send_action("gone", "send", ["/tmp/a"])
    with pytest.raises(SpecViolation, match="share capability"):
        FakeHost(SendingService(("card",))).send_action("dev-1", "send", ["/tmp/a"])


def test_fake_host_fetches_every_waiting_popup() -> None:
    service = Service([])
    host = FakeHost(service)
    service.pending = [
        {"title": f"T{n}", "body": "", "icon": "", "action_label": "", "action_id": ""}
        for n in range(3)
    ]
    service.NotifyChanged()
    assert [note[0] for note in host.notifications] == ["T0", "T1", "T2"]
    service.NotifyChanged()                             # nothing waits: no popup
    assert len(host.notifications) == 3


@pytest.mark.parametrize("reply", [
    {"notification": None},
    {"notification": None, "more": True},
    {"notification": None, "more": "no"},
    {"notification": {"title": "T", "body": ""}, "more": False},
    {"notification": "T", "more": False},
    {"notification": None, "more": False, "extra": 1},
])
def test_check_pending_rejects_malformed_replies(reply) -> None:
    with pytest.raises(SpecViolation):
        check_pending(json.dumps(reply))


def _pending(title: object, body: object) -> str:
    return json.dumps({"notification": {
        "title": title, "body": body, "icon": "", "action_label": "", "action_id": "",
    }, "more": False})


def test_check_pending_accepts_a_popup_with_only_a_body_like_blueferry() -> None:
    from blueferry.plugin_api import surfaces

    assert surfaces.parse_notification("", "Akku 15 %") is not None
    assert check_pending(_pending("", "Akku 15 %")) == (("", "Akku 15 %", "", "", ""), False)
    assert check_pending(_pending("Titel", "")) == (("Titel", "", "", "", ""), False)


def test_check_pending_rejects_an_empty_popup_and_wrong_field_types() -> None:
    with pytest.raises(SpecViolation, match="title and a body"):
        check_pending(_pending("", ""))
    with pytest.raises(SpecViolation, match="five string fields"):
        check_pending(_pending(1, "Text"))


def test_fake_host_rejects_the_removed_notify_signal() -> None:
    class Legacy(Service):
        def Notify(self, *args) -> None:
            pass

    service = Legacy([])
    FakeHost(service)
    with pytest.raises(SpecViolation, match=r"removed in plugin-api 1\.5"):
        service.Notify("Titel", "Text", "", "", "")


def test_fake_host_with_the_plugin_api_notify_service() -> None:
    from blueferry.plugin_api.service import NotifyService
    from blueferry.plugin_api.testing import inline_service, manifest

    class Popups(NotifyService):
        def invoke_action(self, item_id, action_id, args):
            from blueferry.plugin_api.surfaces import ActionResult
            return ActionResult(ok=item_id == "notify" and action_id == "open-1")

    service = inline_service(Popups, manifest("io.example.popups", capabilities="notify;"))
    host = FakeHost(service)
    service.emit_notify("Titel", "Text", "folder", "Öffnen", "open-1")
    service.emit_notify("Zweiter", "Text")
    service.emit_notify("", "Nur Text")
    assert host.notifications == [
        ("Titel", "Text", "folder", "Öffnen", "open-1"),
        ("Zweiter", "Text", "", "", ""),
        ("", "Nur Text", "", "", ""),
    ]
    assert host.click_notification(0)["ok"] is True
