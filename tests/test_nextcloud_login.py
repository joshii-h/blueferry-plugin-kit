"""Nextcloud Login Flow v2 against a fake Nextcloud over https."""
from __future__ import annotations

import json
import logging

import pytest
from blueferry.plugin_api.config import ConfigError
from blueferry.plugin_api.service import PluginService
from blueferry.plugin_api.testing import inline_service, manifest

from blueferry_plugin_kit.auth.nextcloud import (
    Credentials,
    NextcloudLogin,
    NextcloudLoginError,
    server_root,
)
from blueferry_plugin_kit.configtest import connected, failed, passed, scrub, secret_or_stored
from blueferry_plugin_kit.testing import (
    FakeHost,
    FakeNextcloudLogin,
    SpecViolation,
    TestCA,
    WsgiServer,
)

PASSWORD = "Abcde-Fghij-Klmno-Pqrst-Uvwxy"


@pytest.fixture(scope="module")
def ca(tmp_path_factory) -> TestCA:
    return TestCA(tmp_path_factory.mktemp("ca"))


@pytest.fixture
def fake(ca):
    login = FakeNextcloudLogin(prefix="/nc", login_name="anna@example.org",
                               app_password=PASSWORD)
    with WsgiServer(login, ca=ca) as server:
        login.url = f"{server.base}/nc"
        yield login


def _flow(ca, **kwargs) -> NextcloudLogin:
    kwargs.setdefault("min_interval", 0)
    return NextcloudLogin(user_agent="BlueFerry Test", context=ca.client_context(), **kwargs)


@pytest.mark.parametrize(("typed", "root"), [
    ("https://cloud.example.org", "https://cloud.example.org"),
    ("cloud.example.org/", "https://cloud.example.org"),
    ("https://cloud.example.org/nextcloud/remote.php/dav/files/anna/",
     "https://cloud.example.org/nextcloud"),
    ("https://cloud.example.org:8443/index.php/apps/files", "https://cloud.example.org:8443"),
    (" https://cloud.example.org/remote.php/dav ", "https://cloud.example.org"),
])
def test_server_root(typed, root) -> None:
    assert server_root(typed) == root


@pytest.mark.parametrize(("typed", "reason"), [
    ("http://cloud.example.org", "insecure"), ("", "invalid-url"),
    ("https://anna:pw@cloud.example.org", "invalid-url"),
    ("https://cloud.example.org/?x=1", "invalid-url"), ("ftp://x", "invalid-url"),
    ("https://cloud.example.org:99999", "invalid-url"),
])
def test_server_root_refuses(typed, reason) -> None:
    with pytest.raises(NextcloudLoginError) as caught:
        server_root(typed)
    assert caught.value.reason == reason


def test_flow_start_poll_grant(ca, fake, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    flow = _flow(ca)
    pending = flow.start(fake.url + "/remote.php/dav/files/anna/")
    assert pending.login_url.startswith(fake.url + "/login/v2/flow/")
    assert pending.server == fake.url
    assert fake.requests[0][2] == "BlueFerry Test"
    assert flow.poll(pending.login_id) is None
    fake.grant()
    credentials = flow.poll(pending.login_id)
    assert credentials == Credentials(fake.url, "anna@example.org", PASSWORD)
    assert PASSWORD not in repr(credentials)
    assert credentials.webdav_url == f"{fake.url}/remote.php/dav/files/anna@example.org/"
    assert credentials.dav_url == f"{fake.url}/remote.php/dav"
    assert flow.running == 0
    with pytest.raises(NextcloudLoginError) as caught:
        flow.poll(pending.login_id)
    assert caught.value.reason == "unknown"
    assert PASSWORD not in caplog.text


def test_poll_is_throttled(ca, fake) -> None:
    now = [100.0]
    flow = _flow(ca, clock=lambda: now[0], min_interval=1.0)
    pending = flow.start(fake.url)
    assert flow.poll(pending.login_id) is None
    assert flow.poll(pending.login_id) is None
    assert fake.polls() == 1
    now[0] += 1.5
    flow.poll(pending.login_id)
    assert fake.polls() == 2


def test_flow_expires_and_cancels(ca, fake) -> None:
    now = [0.0]
    flow = _flow(ca, clock=lambda: now[0], lifetime=60)
    first = flow.start(fake.url)
    now[0] = 61
    with pytest.raises(NextcloudLoginError) as caught:
        flow.poll(first.login_id)
    assert caught.value.reason == "expired"
    second = flow.start(fake.url)
    flow.cancel(second.login_id)
    with pytest.raises(NextcloudLoginError) as caught:
        flow.poll(second.login_id)
    assert caught.value.reason == "cancelled"
    assert flow.running == 0


def test_only_https_everywhere(ca, fake) -> None:
    flow = _flow(ca)
    with pytest.raises(NextcloudLoginError) as caught:
        flow.start(fake.url.replace("https://", "http://"))
    assert caught.value.reason == "insecure"
    fake.endpoint_override = "http://127.0.0.1:1/login/v2/poll"
    with pytest.raises(NextcloudLoginError) as caught:
        flow.start(fake.url)
    assert caught.value.reason == "insecure"
    fake.endpoint_override = None
    fake.login_override = "javascript:alert(1)"
    with pytest.raises(NextcloudLoginError):
        flow.start(fake.url)
    fake.login_override = None
    # A server that names itself over http: the typed https root is kept.
    fake.server = "http://cloud.example.org"
    fake.grant_after = 1
    pending = flow.start(fake.url)
    assert flow.poll(pending.login_id).server == fake.url


def test_untrusted_certificate_is_unreachable(fake) -> None:
    flow = NextcloudLogin(user_agent="x", min_interval=0)   # system CAs only
    with pytest.raises(NextcloudLoginError) as caught:
        flow.start(fake.url)
    assert caught.value.reason == "unreachable"


def test_not_nextcloud_and_bad_answers(ca, fake) -> None:
    flow = _flow(ca)
    fake.start_status = 404
    with pytest.raises(NextcloudLoginError) as caught:
        flow.start(fake.url)
    assert caught.value.reason == "not-nextcloud"
    fake.start_status = 403
    with pytest.raises(NextcloudLoginError) as caught:
        flow.start(fake.url)
    assert caught.value.reason == "refused"
    fake.start_status = 200
    pending = flow.start(fake.url)
    fake.grant(login_name="../evil")
    with pytest.raises(NextcloudLoginError) as caught:
        flow.poll(pending.login_id)
    assert caught.value.reason == "bad-reply"
    pending = flow.start(fake.url)
    fake.grant(app_password="has space")
    with pytest.raises(NextcloudLoginError):
        flow.poll(pending.login_id)


def test_unreachable_poll_gives_up(ca) -> None:
    flow = _flow(ca)
    # A flow whose endpoint vanished: a closed port answers nothing.
    login = FakeNextcloudLogin()
    with WsgiServer(login, ca=ca) as server:
        login.endpoint_override = "https://127.0.0.1:1/login/v2/poll"
        pending = flow.start(server.base)
    for _ in range(4):
        assert flow.poll(pending.login_id) is None
    with pytest.raises(NextcloudLoginError) as caught:
        flow.poll(pending.login_id)
    assert caught.value.reason == "unreachable"


def test_at_most_four_flows(ca, fake) -> None:
    flow = _flow(ca)
    first = flow.start(fake.url)
    for _ in range(4):
        flow.start(fake.url)
    assert flow.running == 4
    with pytest.raises(NextcloudLoginError):
        flow.poll(first.login_id)


# ---- through the plugin API ------------------------------------------------------

MANIFEST = """
ConfigTest=true
ConfigLogin=nextcloud

[Config url]
Label=Server URL
Type=url
Required=true

[Config user]
Label=User name
Type=string

[Config app_password]
Label=App password
Type=secret
Required=true
"""


class Plugin(PluginService):
    def __init__(self, manifest_, ca, **kwargs) -> None:
        super().__init__(manifest_, None, **kwargs)
        self.stored: dict[str, object] = {}
        self.login = _flow(ca, messages={"cancelled": "Abgebrochen."})
        self.refuse = False

    def config_values(self):
        return dict(self.stored)

    def apply_config(self, values):
        self.stored.update(values)

    def test_config(self, values):
        password = secret_or_stored(values, "app_password",
                                    lambda: self.stored.get("app_password"))
        if password != PASSWORD:
            return failed(scrub(f"refused {password}", password), app_password="refused")
        return passed(connected(values.get("user") or None, "Nextcloud", "31"))

    def config_login(self, provider, values):
        return self.login.login_step(str(values["url"]))

    def config_login_status(self, login_id):
        return self.login.status_step(login_id, self._store)

    def config_login_cancel(self, login_id):
        self.login.cancel(login_id)

    def _store(self, credentials: Credentials) -> str:
        if self.refuse:
            raise ConfigError("url", "Nur für Tests abgelehnt.")
        self.stored.update(url=credentials.webdav_url, user=credentials.login_name,
                           app_password=credentials.app_password)
        return f"Connected as {credentials.login_name}"


@pytest.fixture
def host(ca):
    plugin = inline_service(Plugin, manifest(
        "io.example.nc", capabilities="card;", api_version="1.3", extra=MANIFEST,
    ), ca)
    return FakeHost(plugin)


def test_fake_host_signs_in(host, fake, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    step = host.sign_in({"url": fake.url}, before_poll=lambda n: n == 2 and fake.grant())
    assert step == {"state": "done", "message": "Connected as anna@example.org"}
    assert host.opened and host.opened[0].startswith(fake.url + "/login/v2/flow/")
    assert host.service.stored["app_password"] == PASSWORD
    assert host.get_config()["values"]["app_password"] == "********"
    host.assert_never_sent(PASSWORD)
    assert PASSWORD not in caplog.text


def test_fake_host_sign_in_errors_and_cancel(host, fake) -> None:
    step = host.sign_in({"url": fake.url.replace("https", "http")})
    assert step["state"] == "error" and "https" in step["message"]
    step = host.config_login({"url": fake.url})
    assert host.login_status(step["login_id"]) == {"state": "pending"}
    assert host.cancel_sign_in(step["login_id"]) == {"ok": True}
    assert host.login_status(step["login_id"]) == {"state": "cancelled", "message": "Abgebrochen."}
    host.service.refuse = True
    fake.grant_after = 1
    step = host.sign_in({"url": fake.url})
    assert step == {"state": "error", "message": "Nur für Tests abgelehnt."}
    assert "app_password" not in host.service.stored


def test_fake_host_test_config(host) -> None:
    result = host.test_config({"url": "https://cloud.example.org", "user": "anna",
                               "app_password": PASSWORD})
    assert result == {"ok": True, "message": "Connected as anna to Nextcloud 31"}
    result = host.test_config({"url": "https://cloud.example.org", "app_password": "wrong-pw"})
    assert result["ok"] is False and "wrong-pw" not in json.dumps(result)
    assert result["errors"] == {"app_password": "refused"}
    result = host.test_config({"url": "https://cloud.example.org"})
    assert result["ok"] is False and result["errors"] == {"app_password": "is required"}
    host.assert_never_sent(PASSWORD)
    with pytest.raises(SpecViolation):
        host.assert_never_sent("Connected")


def test_spec_checks_for_settings_replies() -> None:
    from blueferry_plugin_kit.testing.host import check_login_step, check_test_config

    with pytest.raises(SpecViolation):
        check_test_config(json.dumps({"ok": True, "message": "two\nlines"}))
    with pytest.raises(SpecViolation):
        check_test_config(json.dumps({"ok": True, "message": ""}))
    with pytest.raises(SpecViolation):
        check_test_config(json.dumps({"ok": 1, "message": "x"}))
    with pytest.raises(SpecViolation):
        check_login_step(json.dumps({"state": "open", "login_id": "a b",
                                     "open_uri": "https://x"}), start=True)
    with pytest.raises(SpecViolation):
        check_login_step(json.dumps({"state": "open", "login_id": "a",
                                     "open_uri": "http://example.org"}), start=True)
    with pytest.raises(SpecViolation):
        check_login_step(json.dumps({"state": "pending"}), start=True)
    with pytest.raises(SpecViolation):
        check_login_step(json.dumps({"state": "done", "login_id": "a"}), start=False)


def test_secret_or_stored_and_scrub() -> None:
    assert secret_or_stored({"k": "typed"}, "k", lambda: "stored") == "typed"
    assert secret_or_stored({"k": ""}, "k", lambda: "stored") == "stored"

    def broken():
        raise OSError("keyring locked")

    with pytest.raises(ConfigError) as caught:
        secret_or_stored({}, "k", broken)
    assert caught.value.field == "k"
    assert scrub("key abc and abcdef\nend", "abc", "abcdef") == "key *** and *** end"
    assert connected() == "Connected" and connected("anna") == "Connected as anna"
