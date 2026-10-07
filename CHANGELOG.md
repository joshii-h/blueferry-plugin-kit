# Changelog

All notable changes to blueferry-plugin-kit. Minor releases (0.x) may
change the public API; patch releases only fix bugs (see README, Stability).

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
