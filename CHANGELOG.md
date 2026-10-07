# Changelog

All notable changes to blueferry-plugin-kit. Minor releases (0.x) may
change the public API; patch releases only fix bugs (see README, Stability).

## 0.2.1 – 2026-10-07

- `lanserver`: `HardenedHTTPServer.handshake_failed(reason, client_address)`
  is called when a TLS handshake fails. The default logs one debug line
  with the reason only (TLS alert name, `timeout` or error class), never
  the address or request bytes; plugins override it to react. Before, a
  failed handshake was dropped silently.
- `lanserver.handshake_reason(error)`: the content-free reason used for it.

## 0.2.0 – 2026-10-07

Targets plugin-api 1.3 (guided settings, TestConfig, ConfigLogin).

- Pins `blueferry-plugin-api` at `plugin-api-v1.3.0`.
- `auth.nextcloud`: Nextcloud Login Flow v2 for `ConfigLogin=nextcloud`
  (https only, no redirects, 20-minute expiry, throttled polling, app
  password never logged); `login_step`/`status_step`/`cancel` map it onto
  the plugin hooks. `auth` is a package now; `from blueferry_plugin_kit.auth
  import Token, …` keeps working.
- `configtest`: `secret_or_stored`, `connected`, `scrub`, `passed`,
  `failed` for `TestConfig`.
- `testing.FakeHost`: `test_config`, `config_login`, `login_status`,
  `sign_in`, `cancel_sign_in` with spec checks, `opened`, `replies` and
  `assert_never_sent(secret)`.
- `testing.FakeNextcloudLogin` (Login Flow v2 as WSGI app),
  `WsgiServer(app, ca=TestCA)` for https, `check_versions` (manifest,
  pyproject and `__version__` agree).

## 0.1.0 – 2026-10-07

First release, extracted from the BlueFerry plugins without changing
behaviour. Targets plugin-api 1.2.

- `secrets`: owner-only files (atomic, 0600/0700, no symlinks) and
  `KeyringStore` (libsecret first, 0600 file as fallback), from immich,
  webdav and calendar.
- `clipboard`: wl-clipboard with `--sensitive`, environment allowlist,
  Wayland socket discovery, X11 copy fallback, from shortcuts and webdav.
- `netaddr`: default-route LAN address with VPN detection (shortcuts) and
  LAN interface selection without Docker/VPN (localsend).
- `lanserver`: request deadline with minimum body rate, connections per
  address, rate limits and failed-login lockout, `HardenedHTTPServer`
  with TLS on the worker, `DeadlineRequestHandler`, `ServerGroup`, local
  CA and server certificates (extra `lanserver`), from shortcuts and
  localsend.
- `xmlsafe`: defusedxml wrapper (extra `xml`).
- `dav`: WebDAV client with Nextcloud chunking v2, OCS shares and
  rebinding protection (webdav); CalDAV discovery with a host allowlist,
  Basic/Digest, REPORT (calendar) (extra `dav`); recurrence and time zone
  expansion (extra `caldav`).
- `auth`: `Token`, `TokenStore`, `TokenSource` and the `Refresher`
  protocol; no providers yet.
- `testing`: `FakeHost` for the 1.2 surfaces, `FakeClipboard`,
  `FakeSecret`, `TestCA`, `DavServer`/`WsgiServer` (extra `testing`),
  `isolate_environment`.
