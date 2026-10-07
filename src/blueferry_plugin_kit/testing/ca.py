"""A throwaway local CA for HTTPS tests (extra ``lanserver``)."""
from __future__ import annotations

import ssl
from pathlib import Path

from blueferry_plugin_kit.lanserver.tls import CertificateStore, Material


class TestCA:
    """A CA plus server certificate below ``directory``, and a client
    context that trusts exactly that CA."""

    __test__ = False  # not a pytest test class

    def __init__(self, directory: Path, addresses: list[str] | None = None) -> None:
        self.store = CertificateStore(directory, ca_name="BlueFerry Test CA")
        self.material: Material = self.store.ensure(addresses or ["127.0.0.1"])

    def server_context(self) -> ssl.SSLContext:
        return self.material.server_context()

    def client_context(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=str(self.store.ca_cert_path))
