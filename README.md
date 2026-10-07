# blueferry-plugin-kit

Shared SDK for [BlueFerry](https://github.com/joshii-h/blueferry) plugins:
owner-only files and the desktop keyring, a safe clipboard, a hardened HTTPS
server for the local network, LAN/VPN address choice, safe XML, WebDAV and
CalDAV clients, token storage and the Nextcloud browser sign-in, helpers for
"Test connection", and test fakes.

Most of it was extracted from the plugins that use it (shortcuts,
localsend, webdav, calendar, immich), where it has been reviewed and
tested. 0.2 adds the plugin-api 1.3 pieces (`auth.nextcloud`,
`configtest`, the settings checks in `FakeHost`).

It targets the plugin contract **plugin-api 1.3**
(`blueferry-plugin-api @ git+https://github.com/joshii-h/blueferry@plugin-api-v1.3.0#subdirectory=plugin-api`)
and Python 3.10+.

## Install

One package, modular through pip extras. The core has no third-party
dependencies; pick the extras a plugin needs:

| Extra       | Pulls in                                                    | For                                     |
|-------------|-------------------------------------------------------------|-----------------------------------------|
| *(none)*    | –                                                           | `secrets`, `clipboard`, `netaddr`, `auth`, `configtest`, `testing` (host and fakes), `lanserver` limits and server |
| `lanserver` | cryptography                                                | `lanserver.tls` (local CA, certificates), `testing.TestCA` |
| `xml`       | defusedxml                                                  | `xmlsafe`                               |
| `dav`       | defusedxml                                                  | `dav.webdav`, `dav.caldav`              |
| `caldav`    | defusedxml, icalendar, recurring-ical-events, x-wr-timezone | `dav.ical` (recurrences, time zones)    |
| `auth`      | –                                                           | `auth`, `auth.nextcloud`                |
| `testing`   | wsgidav, cheroot                                            | `testing.DavServer`, `testing.WsgiServer` |

In a plugin's `pyproject.toml`:

```toml
dependencies = [
  "blueferry-plugin-api @ git+https://github.com/joshii-h/blueferry@plugin-api-v1.3.0#subdirectory=plugin-api",
  "blueferry-plugin-kit[dav] @ git+https://github.com/joshii-h/blueferry-plugin-kit@kit-v0.2.0",
]

[project.optional-dependencies]
dev = [
  "blueferry-plugin-kit[dav,testing] @ git+https://github.com/joshii-h/blueferry-plugin-kit@kit-v0.2.0",
  "pytest>=7,<10",
]
```

Every module imports without its extra. Heavy libraries load on first use;
when one is missing the call raises `blueferry_plugin_kit.MissingExtraError`
(an `ImportError`) saying, e.g., `install blueferry-plugin-kit[dav]`.

dbus-python, PyGObject and libsecret come from the distribution: BlueFerry
creates plugin venvs with `--system-site-packages`.

## Modules

### `secrets`: owner-only files and the keyring

```python
from blueferry_plugin_kit.secrets import (
    KeyringStore, SecretsError, config_dir, read_private_text, write_private,
)

class SettingsStore(KeyringStore):
    SECRET_SCHEMA = "io.example.blueferry.myplugin.Password"
    SECRET_ATTRIBUTES = ("server", "user")
    SECRET_LABEL = "BlueFerry My Plugin password"

    def __init__(self, directory=None, *, secret=None):
        super().__init__(directory or config_dir("io.example.myplugin"), secret=secret)

    def save(self, url, user, password):
        where = self.save_secret({"server": url, "user": user}, password)  # "keyring" | "file"
        write_private(self.directory / "config.json", f'{{"key_store": "{where}"}}\n')

    def password(self, url, user, where):
        return self.load_secret(where, {"server": url, "user": user},
                                missing="the password file is missing",
                                empty="no password stored")
```

`write_private` writes atomically with mode 0600 into a 0700 directory;
`read_private`/`read_private_text` refuse symlinks, foreign owners, group or
world access and oversized files (`SecretsError`). The keyring is libsecret's
Secret Service; without it the secret goes to `key_path` (0600).

### `clipboard`: Wayland first, sensitive, no argv

```python
from blueferry_plugin_kit.clipboard import Clipboard, ClipboardError, copy_to_clipboard

Clipboard().copy_text("one-time code")    # wl-copy --sensitive when supported
Clipboard().read_text(limit=64 * 1024)    # None when larger than the limit
copy_to_clipboard("https://…")            # Wayland, else xclip/xsel; False if neither
```

Data goes through stdin/stdout only, helpers get an allowlisted environment,
and a bus-activated plugin without `WAYLAND_DISPLAY` finds a single
`wayland-N` socket in `XDG_RUNTIME_DIR`.

### `netaddr`: LAN, not VPN or Docker

```python
from blueferry_plugin_kit import netaddr

host = netaddr.resolve(setting="", allow_all=False)   # default-route LAN address
netaddr.default_route_tunnel()                        # ("wg0", True) when a VPN has the route
netaddr.lan_interfaces()                              # physical, up, not p2p, not Docker/VPN
```

### `lanserver`: hardened HTTPS on the LAN

```python
from blueferry_plugin_kit.lanserver import (
    CertificateStore, DeadlineRequestHandler, HardenedHTTPServer, RateLimiter,
    RequestError, serve_in_thread,
)

class Handler(DeadlineRequestHandler):
    request_deadline_s = 20     # request line, headers, small bodies
    linger_s = 1.0              # read what the client still sends after an early answer

    def do_POST(self):
        if not self.server.limiter.admit(self.client_address[0]):
            ...                 # 429
        try:
            body = self.read_body(64 * 1024, min_rate=32 * 1024)
        except RequestError as error:
            ...                 # error.status, error.token

material = CertificateStore(directory, ca_name="BlueFerry My Plugin CA").ensure([host])
server = HardenedHTTPServer((host, 47801), Handler, context=material.server_context(),
                            max_connections=8, max_per_address=2)
server.limiter = RateLimiter(requests_per_minute=30, failures_allowed=5)
serve_in_thread(server, "my-plugin-https")
```

The TLS handshake runs on the worker thread with a total timeout; every read
gets only the time left of the request; bodies need a minimum rate; request
lines, headers and bodies are never logged. `ServerGroup` runs one server per
address of `netaddr.lan_interfaces()` with a shared per-address cap.

A failed TLS handshake (a phone that does not trust the CA yet, a probe,
plain HTTP on the TLS port, a timeout) calls
`HardenedHTTPServer.handshake_failed(reason, client_address)`. By default it
logs one debug line with the reason only (the TLS alert name, `timeout` or
the error class, from `handshake_reason(error)`), never the address or any
bytes; override it to react, and keep the address out of logs:

```python
class Server(HardenedHTTPServer):
    def handshake_failed(self, reason, client_address):
        super().handshake_failed(reason, client_address)   # the debug line
        if reason == "tlsv1_alert_unknown_ca":
            self.untrusted.set()                           # e.g. a hint on the card
```

`CertificateStore` keeps a ten-year local CA (what iOS can trust once) and a
397-day server certificate that follows the listen address. Routes stay in
the plugin.

### `xmlsafe`

```python
from blueferry_plugin_kit import xmlsafe
root = xmlsafe.fromstring(body, limit=4 * 1024 * 1024)   # XmlError on DTD, entities, garbage
```

### `dav`: WebDAV and CalDAV

```python
from blueferry_plugin_kit.dav.webdav import WebDavClient, DavError

client = WebDavClient("https://cloud.example.org/remote.php/dav/files/alice/", "alice", pw,
                      nextcloud=True, user_agent="blueferry-myplugin/1.0")
client.check()
folder = client.ensure_folder(("BlueFerry",))
url = client.upload(open(path, "rb"), size, folder, client.free_name(folder, "photo.jpg"))
link = client.share_link(("BlueFerry",), "photo.jpg")   # Nextcloud OCS, read-only
```

https only (http on loopback, or on the LAN when allowed: resolved once, all
addresses private, every request of the client goes to the checked address).
Redirects are refused; Nextcloud uploads above 10 MiB use chunking v2.

```python
from blueferry_plugin_kit.dav.caldav import CalDavClient
from blueferry_plugin_kit.dav.ical import local_zone, occurrences

client = CalDavClient("caldav.icloud.com", user, pw, hosts=("p42-caldav.icloud.com",))
for calendar in client.calendars():                 # RFC 6764 discovery
    texts = client.events(calendar.url, start, end)  # calendar-query REPORT
    events = occurrences(texts, start, end, local_zone(), calendar=calendar.name)
```

Credentials only go to the configured host and hosts the user confirmed; a
redirect or href elsewhere raises `CalDavError("foreign-host", host)`. Basic
and Digest (MD5, SHA-256) login; `http_proxy` is ignored unless `use_proxy`.

### `auth`: token storage, refresh and the Nextcloud sign-in

```python
from blueferry_plugin_kit.auth import Token, TokenSource, TokenStore

store = TokenStore(directory, {"server": issuer, "user": account})
where = store.save(Token(access, refresh, expires_at))
source = TokenSource(store, where, refresher)      # refresher.refresh(token) -> Token
headers = {"Authorization": source.token().authorization()}
```

#### `auth.nextcloud`: Nextcloud Login Flow v2 (`ConfigLogin=nextcloud`)

The browser sign-in of plugin-api 1.3: BlueFerry opens Nextcloud's
"Connect to your account" page, the plugin polls Nextcloud and receives
server, login name and a fresh app password. https only (typed server,
login page, poll endpoint), no redirects, no proxy, flows expire after
20 minutes, at most four at a time. The app password goes from Nextcloud
into the `store` callback and never into a reply or a log.

```python
from blueferry_plugin_kit.auth.nextcloud import NextcloudLogin

self._login = NextcloudLogin(user_agent="BlueFerry WebDAV")

def config_login(self, provider, values):            # ConfigLogin
    return self._login.login_step(str(values.get("url") or ""))

def config_login_status(self, login_id):            # every 2 s
    return self._login.status_step(login_id, self._store_login)

def config_login_cancel(self, login_id):
    self._login.cancel(login_id)

def _store_login(self, credentials):                # -> the "done" message
    # credentials.server, .login_name, .app_password, .webdav_url, .dav_url
    self._settings.save(credentials.webdav_url, credentials.login_name,
                        credentials.app_password)
    return f"Connected as {credentials.login_name}"
```

`server_root(url)` cuts a typed WebDAV/CalDAV address back to the
Nextcloud root. Messages default to English; pass `messages={reason: text}`
to translate.

### `configtest`: "Test connection" (`ConfigTest=true`)

```python
from blueferry_plugin_kit.configtest import connected, failed, passed, scrub, secret_or_stored

def test_config(self, values):                      # nothing is stored
    key = secret_or_stored(values, "api_key", self._stored_key)  # typed or stored
    user, version = self._check(values["url"], key)              # raises ConfigError
    return passed(connected(user, "Immich", version))  # "Connected as anna to Immich 1.135"
```

`scrub(text, secret)` makes server text safe to show; `failed(message,
field=reason)` marks fields.

### `testing`: fakes for plugin tests

```python
from blueferry_plugin_kit.testing import (
    DavServer, FakeClipboard, FakeHost, FakeNextcloudLogin, FakeSecret, TestCA,
    WsgiServer, check_versions, isolate_environment,
)

# conftest.py, before the plugin is imported:
isolate_environment("blueferry-myplugin-tests-")

host = FakeHost(service, cache_roots=[cache_dir])  # plays the core for card/share/notify
items = host.card_items()                          # SpecViolation on any 1.2 breach
result = host.invoke("item-id", "action-id", {"x": 1})
host.wait_for(lambda: host.notifications)

# 1.3 settings helpers, checked against the spec as well
host.test_config({"url": "https://photos.example.com", "api_key": "…"})  # {ok, message}
login = FakeNextcloudLogin(login_name="anna")
with WsgiServer(login, ca=TestCA(tmp_path)) as server:   # https
    step = host.sign_in({"url": server.base}, before_poll=lambda n: login.grant())
host.assert_never_sent(app_password)                # no reply or popup leaked it

# tests/test_versions.py: manifest Version=, pyproject and __version__ agree
check_versions(Path(__file__).parent.parent, __version__)
```

`FakeSecret` replaces `gi.repository.Secret` (`KeyringStore(secret=…)`),
`TestCA` gives a server and a trusting client context, `DavServer` runs
wsgidav on 127.0.0.1 and `WsgiServer` any WSGI app, with `ca=` over https
(extra `testing`). Code that uses the default TLS context trusts the test
CA when the test sets `SSL_CERT_FILE` to `ca.store.ca_cert_path`.

## Stability

The public API is every name without a leading underscore in the modules
above. From 0.1 on, a **minor** release (0.1 → 0.2) may change it; a
**patch** release (0.1.0 → 0.1.1) never does, it only fixes bugs. Plugins
pin a tag (`@kit-v0.2.0`). From 1.0 on the usual semantic-versioning rules
apply. Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## Development

```sh
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/ruff check . && .venv/bin/python -m pytest -q
```

## License

GPL-2.0-or-later, like BlueFerry.
