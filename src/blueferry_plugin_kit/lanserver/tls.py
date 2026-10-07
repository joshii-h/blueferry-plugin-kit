"""A private certificate authority and the server certificate it signs.

iOS only trusts a self-signed certificate (e.g. for Shortcuts) after it
was installed as a profile and enabled under Certificate Trust Settings,
and that list only offers authority certificates. So a plugin creates a
small local CA once (ten years, P-256) and from it a server certificate
for the current listen addresses (397 days, renewed 30 days before it
expires). The phone trusts the CA once; a new IP address or a renewal
needs nothing on the phone. :attr:`Material.fingerprint` is the CA's
SHA-256, which iOS shows in the profile details for comparison.

Needs the ``lanserver`` extra (cryptography), imported on first use.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from blueferry_plugin_kit._extras import need
from blueferry_plugin_kit.secrets import read_private, write_private

if TYPE_CHECKING:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec

CA_DAYS = 3650
SERVER_DAYS = 397
RENEW_BEFORE = dt.timedelta(days=30)
MAX_PEM = 64 * 1024


class _Crypto:
    """cryptography's modules, loaded on first use (extra ``lanserver``)."""

    def __getattr__(self, name: str) -> Any:
        need("cryptography", "lanserver")
        from cryptography import x509 as x509_module
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec as ec_module
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

        self.__dict__.update(
            x509=x509_module, hashes=hashes, serialization=serialization, ec=ec_module,
            ExtendedKeyUsageOID=ExtendedKeyUsageOID, NameOID=NameOID,
        )
        return self.__dict__[name]


_c = _Crypto()


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def fingerprint(certificate: x509.Certificate) -> str:
    digest = certificate.fingerprint(_c.hashes.SHA256()).hex().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        _c.serialization.Encoding.PEM, _c.serialization.PrivateFormat.PKCS8,
        _c.serialization.NoEncryption(),
    )


def _names(addresses: list[str]) -> list[x509.GeneralName]:
    names: list[x509.GeneralName] = []
    for address in addresses:
        try:
            names.append(_c.x509.IPAddress(ipaddress.ip_address(address.split("%", 1)[0])))
        except ValueError:
            continue
    host = socket.gethostname().split(".", 1)[0]
    if host and host.isascii() and all(ch.isalnum() or ch == "-" for ch in host):
        names.append(_c.x509.DNSName(host.lower() + ".local"))
    names.append(_c.x509.DNSName("localhost"))
    return names


@dataclass(frozen=True, slots=True)
class Material:
    """The CA certificate (PEM, for the phone), its fingerprint and the
    server certificate's files."""

    ca_pem: bytes
    fingerprint: str
    cert_path: Path
    key_path: Path

    def server_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.cert_path), str(self.key_path))
        return context


class CertificateStore:
    """The CA and server certificate in an owner-only directory.

    Files: ``ca.pem``, ``ca-key.pem``, ``server.pem``, ``server-key.pem``
    (all 0600). ``ca_name`` becomes the CA's common name, followed by the
    short host name: ``"<ca_name> (<host>)"``.
    """

    def __init__(self, directory: Path, ca_name: str = "BlueFerry Plugin CA") -> None:
        self.directory = directory
        self.ca_name = ca_name

    @property
    def ca_cert_path(self) -> Path:
        return self.directory / "ca.pem"

    @property
    def ca_key_path(self) -> Path:
        return self.directory / "ca-key.pem"

    @property
    def cert_path(self) -> Path:
        return self.directory / "server.pem"

    @property
    def key_path(self) -> Path:
        return self.directory / "server-key.pem"

    def _load_ca(self) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None:
        try:
            certificate = _c.x509.load_pem_x509_certificate(
                read_private(self.ca_cert_path, MAX_PEM),
            )
            key = _c.serialization.load_pem_private_key(
                read_private(self.ca_key_path, MAX_PEM), None,
            )
        except (OSError, ValueError):
            return None
        if not isinstance(key, _c.ec.EllipticCurvePrivateKey):
            return None
        if certificate.not_valid_after_utc - RENEW_BEFORE < _now():
            return None
        return certificate, key

    def _new_ca(self) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
        key = _c.ec.generate_private_key(_c.ec.SECP256R1())
        host = socket.gethostname().split(".", 1)[0][:30] or "PC"
        name = _c.x509.Name([
            _c.x509.NameAttribute(_c.NameOID.COMMON_NAME, f"{self.ca_name} ({host})"),
        ])
        now = _now()
        certificate = (
            _c.x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(_c.x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=CA_DAYS))
            .add_extension(_c.x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_c.x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ), critical=True)
            .add_extension(
                _c.x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False,
            )
            .sign(key, _c.hashes.SHA256())
        )
        write_private(self.ca_key_path, _key_pem(key))
        write_private(self.ca_cert_path, certificate.public_bytes(_c.serialization.Encoding.PEM))
        # A new CA invalidates the old server certificate.
        self.cert_path.unlink(missing_ok=True)
        return certificate, key

    def _server_ok(self, ca: x509.Certificate, addresses: list[str]) -> bool:
        try:
            certificate = _c.x509.load_pem_x509_certificate(
                read_private(self.cert_path, MAX_PEM),
            )
            read_private(self.key_path, MAX_PEM)
        except (OSError, ValueError):
            return False
        if certificate.issuer != ca.subject:
            return False
        if certificate.not_valid_after_utc - RENEW_BEFORE < _now():
            return False
        try:
            names = certificate.extensions.get_extension_for_class(
                _c.x509.SubjectAlternativeName,
            ).value.get_values_for_type(_c.x509.IPAddress)
        except _c.x509.ExtensionNotFound:
            return False
        wanted = set()
        for address in addresses:
            try:
                wanted.add(ipaddress.ip_address(address.split("%", 1)[0]))
            except ValueError:
                continue
        return wanted <= set(names)

    def _new_server(
        self, ca: x509.Certificate, ca_key: ec.EllipticCurvePrivateKey, addresses: list[str],
    ) -> None:
        key = _c.ec.generate_private_key(_c.ec.SECP256R1())
        now = _now()
        first = addresses[0] if addresses else "localhost"
        certificate = (
            _c.x509.CertificateBuilder()
            .subject_name(_c.x509.Name([_c.x509.NameAttribute(_c.NameOID.COMMON_NAME, first)]))
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(_c.x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=SERVER_DAYS))
            .add_extension(_c.x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_c.x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ), critical=True)
            .add_extension(
                _c.x509.ExtendedKeyUsage([_c.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False,
            )
            .add_extension(_c.x509.SubjectAlternativeName(_names(addresses)), critical=False)
            .add_extension(
                _c.x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, _c.hashes.SHA256())
        )
        write_private(self.key_path, _key_pem(key))
        write_private(self.cert_path, certificate.public_bytes(_c.serialization.Encoding.PEM))

    def ensure(self, addresses: list[str]) -> Material:
        """Create or renew what is missing; return the paths and the CA fingerprint."""
        loaded = self._load_ca()
        ca, ca_key = loaded if loaded is not None else self._new_ca()
        if not self._server_ok(ca, addresses):
            self._new_server(ca, ca_key, addresses)
        return Material(
            ca_pem=ca.public_bytes(_c.serialization.Encoding.PEM),
            fingerprint=fingerprint(ca),
            cert_path=self.cert_path,
            key_path=self.key_path,
        )

    def ca_fingerprint(self) -> str | None:
        loaded = self._load_ca()
        return fingerprint(loaded[0]) if loaded else None

    def forget(self) -> None:
        for path in (self.ca_cert_path, self.ca_key_path, self.cert_path, self.key_path):
            path.unlink(missing_ok=True)
