"""A real WebDAV server on 127.0.0.1 for plugin tests (extra ``testing``).

wsgidav serves a directory below ``/dav`` with Basic authentication on a
cheroot server with a random port, in a thread::

    with DavServer(tmp_path / "root", "alice", "secret") as dav:
        client = WebDavClient(dav.url, "alice", "secret")

:class:`WsgiServer` runs any WSGI app the same way (e.g. a fake Nextcloud).
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any

from blueferry_plugin_kit._extras import need


class WsgiServer:
    """A cheroot WSGI server on 127.0.0.1 with a random port, in a thread."""

    def __init__(self, app: Any) -> None:
        wsgi = need("cheroot.wsgi", "testing")
        self._server = wsgi.Server(("127.0.0.1", 0), app, numthreads=4)
        self._server.prepare()
        self.server_port: int = self._server.bind_addr[1]
        self._thread = threading.Thread(target=self._server.serve, daemon=True)
        self._thread.start()
        self._stopped = False

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server_port}"

    def stop(self) -> None:
        if not self._stopped:
            self._stopped = True
            self._server.stop()
            self._thread.join(5)
            time.sleep(0.05)

    def __enter__(self) -> WsgiServer:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()


class DavServer(WsgiServer):
    """wsgidav on ``root``, one user with Basic authentication."""

    def __init__(self, root: Path, user: str, password: str) -> None:
        app_module = need("wsgidav.wsgidav_app", "testing")
        root.mkdir(parents=True, exist_ok=True)
        self.root = root
        app = app_module.WsgiDAVApp({
            "host": "127.0.0.1",
            "port": 0,
            "provider_mapping": {"/dav": str(root)},
            "simple_dc": {"user_mapping": {"*": {user: {"password": password}}}},
            "http_authenticator": {
                "accept_basic": True, "accept_digest": False, "default_to_digest": False,
                "domain_controller": None,
            },
            "verbose": 0,
            "logging": {"enable": False},
            "property_manager": True,
            "lock_storage": True,
        })
        logging.getLogger("wsgidav").setLevel(logging.ERROR)
        super().__init__(app)

    @property
    def url(self) -> str:
        return f"{self.base}/dav/"

    def __enter__(self) -> DavServer:
        return self
