"""Listener policy and built-in TLS (G-8, NIST SP 800-207 tenet 2, CIS 4.1).

LSADRA listens on loopback by default. Listening on any other address is an
explicit opt-in (LSADRA_API_HOST), and then plain HTTP is refused unless one of
these holds:

1. LSADRA_TLS_CERT and LSADRA_TLS_KEY name a certificate: served directly.
2. LSADRA_TRUSTED_PROXY_IPS is set: TLS ends at that reverse proxy.
3. LSADRA_ALLOW_PLAINTEXT_LISTENER=true: an explicit, logged exception (for a
   container whose port is published on 127.0.0.1 only, or a lab network).

Otherwise a self-signed certificate is generated on first boot under
``data/tls/`` and reused afterwards. Its SHA-256 fingerprint is printed at
start-up and served at ``GET /api/server/identity``, so the dashboard can show
it beside the device registration token and agents can pin it
(``server_cert_sha256`` in the agent config).
"""

import hashlib
import ipaddress
import logging
import os
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from lsadra import config

logger = logging.getLogger(__name__)

# Set by the launcher once it knows which certificate it serves.
ACTIVE_FINGERPRINT: Optional[str] = None


class ListenerPolicyError(RuntimeError):
    """The requested listener would expose plain HTTP beyond loopback."""


@dataclass(frozen=True)
class ListenerPlan:
    host: str
    port: int
    certfile: Optional[str] = None
    keyfile: Optional[str] = None
    reason: str = ""

    @property
    def tls(self) -> bool:
        return self.certfile is not None


def is_loopback(host: str) -> bool:
    if host.strip().lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def fingerprint_pem(cert_path: str) -> str:
    """SHA-256 of the certificate's DER bytes, lower-case hex with colons."""
    pem = Path(cert_path).read_text(encoding="ascii")
    der = ssl.PEM_cert_to_DER_cert(pem)
    digest = hashlib.sha256(der).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def ensure_self_signed(tls_dir: Path, host: str) -> tuple:
    """Return ``(cert, key)`` paths, generating a self-signed pair on first use."""
    cert_path, key_path = tls_dir / "server.crt", tls_dir / "server.key"
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
    except ImportError as exc:  # pragma: no cover - dependency is in requirements.txt
        raise ListenerPolicyError(
            "Cannot generate a TLS certificate: the 'cryptography' package is missing. "
            "Install requirements.txt, or set LSADRA_TLS_CERT and LSADRA_TLS_KEY."
        ) from exc

    tls_dir.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(tls_dir, 0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    names = {"localhost", socket.gethostname()}
    ips = {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")}
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_unspecified:
            ips.add(ip)
    except ValueError:
        if host:
            names.add(host)
    san = [x509.DNSName(n) for n in sorted(names) if n] + [
        x509.IPAddress(i) for i in sorted(ips, key=str)
    ]
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LSADRA server")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=5 * 365))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key_bytes)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    logger.warning("Generated a self-signed TLS certificate at %s", cert_path)
    return str(cert_path), str(key_path)


def plan_listener(
    host: Optional[str] = None,
    port: Optional[int] = None,
    *,
    cert: Optional[str] = None,
    key: Optional[str] = None,
    trusted_proxies: Optional[frozenset] = None,
    allow_plaintext: Optional[bool] = None,
    tls_dir: Optional[Path] = None,
) -> ListenerPlan:
    """Decide how to listen. Arguments default to the configuration."""
    host = config.API_HOST if host is None else host
    port = config.API_PORT if port is None else port
    cert = config.TLS_CERT_PATH if cert is None else cert
    key = config.TLS_KEY_PATH if key is None else key
    trusted_proxies = config.TRUSTED_PROXY_IPS if trusted_proxies is None else trusted_proxies
    allow_plaintext = (
        config.ALLOW_PLAINTEXT_LISTENER if allow_plaintext is None else allow_plaintext
    )
    tls_dir = config.TLS_DIR if tls_dir is None else tls_dir

    if bool(cert) != bool(key):
        raise ListenerPolicyError("Set both LSADRA_TLS_CERT and LSADRA_TLS_KEY, or neither.")
    if cert and key:
        return ListenerPlan(host, port, cert, key, "configured certificate")
    if is_loopback(host):
        return ListenerPlan(host, port, reason="loopback only")
    if trusted_proxies:
        return ListenerPlan(host, port, reason="TLS terminated by a trusted proxy")
    if allow_plaintext:
        return ListenerPlan(host, port, reason="LSADRA_ALLOW_PLAINTEXT_LISTENER=true")
    gen_cert, gen_key = ensure_self_signed(Path(tls_dir), host)
    return ListenerPlan(host, port, gen_cert, gen_key, "self-signed certificate")


def activate(plan: ListenerPlan) -> Optional[str]:
    """Record the served certificate's fingerprint and print it for operators."""
    global ACTIVE_FINGERPRINT
    if not plan.tls:
        ACTIVE_FINGERPRINT = None
        if not is_loopback(plan.host):
            logger.warning(
                "Serving plain HTTP on %s:%s (%s). Device keys and logins cross this "
                "listener unencrypted unless a TLS proxy fronts it.",
                plan.host,
                plan.port,
                plan.reason,
            )
        return None
    ACTIVE_FINGERPRINT = fingerprint_pem(plan.certfile)
    banner = (
        f"LSADRA TLS ({plan.reason}) on https://{plan.host}:{plan.port}\n"
        f"  Certificate SHA-256 fingerprint: {ACTIVE_FINGERPRINT}\n"
        f"  Agents pin it with server_cert_sha256 in their config."
    )
    print(banner, flush=True)
    logger.info(banner)
    return ACTIVE_FINGERPRINT


def adopt_configured_certificate() -> Optional[str]:
    """When uvicorn was started directly with LSADRA_TLS_CERT, still expose its fingerprint."""
    global ACTIVE_FINGERPRINT
    if ACTIVE_FINGERPRINT is None and config.TLS_CERT_PATH:
        try:
            ACTIVE_FINGERPRINT = fingerprint_pem(config.TLS_CERT_PATH)
        except (OSError, ValueError):
            logger.warning("Could not read LSADRA_TLS_CERT to compute its fingerprint.")
    return ACTIVE_FINGERPRINT
