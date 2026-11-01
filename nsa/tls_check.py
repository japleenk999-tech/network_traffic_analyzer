"""Check a server's TLS version, cipher and certificate health."""
import socket
import ssl
import time
from typing import List

from .models import Finding

WEAK_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def check_tls(host: str, port: int = 443, timeout: float = 5.0) -> List[Finding]:
    target = f"{host}:{port}"
    findings: List[Finding] = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                version = tls.version() or "unknown"
                cipher = tls.cipher()
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return [Finding("high", "tls-cert", target, f"Certificate verification failed: {e.verify_message}",
                        "Install a valid certificate from a trusted CA with a matching hostname.")]
    except (OSError, ssl.SSLError) as e:
        return [Finding("info", "tls", target, f"Could not complete TLS handshake: {e}")]

    findings.append(Finding("info", "tls", target, f"Negotiated {version}, cipher {cipher[0] if cipher else '?'}"))
    if version in WEAK_VERSIONS:
        findings.append(Finding("high", "tls-version", target, f"Weak protocol {version} negotiated",
                                "Require TLS 1.2 or newer."))
    if cert and "notAfter" in cert:
        not_after = str(cert["notAfter"])
days: int = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
        if days < 0:
            findings.append(Finding("high", "tls-cert", target, f"Certificate expired {-days} days ago",
                                    "Renew the certificate."))
        elif days < 30:
            findings.append(Finding("medium", "tls-cert", target, f"Certificate expires in {days} days",
                                    "Renew soon; consider automated renewal."))
        else:
            findings.append(Finding("info", "tls-cert", target, f"Certificate valid for {days} more days"))
    return findings
