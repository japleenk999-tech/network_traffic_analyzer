"""TCP connect scanner that flags risky exposed services.

Only scan hosts you own or have explicit written permission to test.
"""
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Optional

from .models import Finding

# port -> (service, severity, issue, recommendation)
RISKY_PORTS = {
    21: ("FTP", "medium", "Cleartext credentials and data", "Use SFTP/FTPS instead."),
    23: ("Telnet", "high", "Cleartext remote shell", "Disable Telnet; use SSH."),
    25: ("SMTP", "low", "Open mail relay risk", "Restrict relaying and require auth."),
    69: ("TFTP", "high", "Unauthenticated file transfer", "Disable or firewall TFTP."),
    110: ("POP3", "medium", "Cleartext mail retrieval", "Use POP3S (995)."),
    135: ("MS-RPC", "medium", "Windows RPC exposure", "Block at the perimeter."),
    139: ("NetBIOS", "medium", "Legacy file sharing", "Block at the perimeter."),
    143: ("IMAP", "medium", "Cleartext mail retrieval", "Use IMAPS (993)."),
    445: ("SMB", "high", "SMB exposure (ransomware vector)", "Never expose SMB to the internet."),
    512: ("rexec", "high", "Legacy remote execution", "Disable r-services."),
    513: ("rlogin", "high", "Legacy remote login", "Disable r-services."),
    514: ("rsh", "high", "Legacy remote shell", "Disable r-services."),
    1433: ("MSSQL", "high", "Database exposed", "Restrict to trusted hosts/VPN."),
    1521: ("Oracle", "high", "Database exposed", "Restrict to trusted hosts/VPN."),
    3306: ("MySQL", "high", "Database exposed", "Restrict to trusted hosts/VPN."),
    3389: ("RDP", "high", "Remote desktop exposed", "Use VPN/gateway with MFA."),
    5432: ("PostgreSQL", "high", "Database exposed", "Restrict to trusted hosts/VPN."),
    5900: ("VNC", "high", "Remote desktop exposed", "Tunnel over SSH/VPN."),
    6379: ("Redis", "high", "Often unauthenticated", "Bind to localhost; require auth."),
    9200: ("Elasticsearch", "high", "Often unauthenticated", "Restrict access; enable security."),
    11211: ("Memcached", "high", "Unauthenticated; amplification abuse", "Bind to localhost."),
    27017: ("MongoDB", "high", "Database exposed", "Enable auth; restrict network access."),
}

COMMON_PORTS = sorted(set(list(RISKY_PORTS) + [22, 53, 80, 123, 443, 465, 587, 993, 995, 8080, 8443]))


def parse_ports(spec: str) -> List[int]:
    """Parse '22,80,8000-8010' into a sorted list of ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"Invalid port(s): {sorted(bad)[:5]}")
    return sorted(ports)


def _probe(host: str, port: int, timeout: float) -> Optional[Tuple[int, str]]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(0.6)
            banner = ""
            try:
                banner = s.recv(128).decode("utf-8", "replace").strip().splitlines()[0]
            except (socket.timeout, OSError, IndexError):
                pass
            return port, banner
    except OSError:
        return None


def scan_host(host: str, ports: List[int], timeout: float = 1.0, workers: int = 100):
    """Return (open_ports, findings)."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda p: _probe(host, p, timeout), ports))
    open_ports = sorted([r for r in results if r], key=lambda r: r[0])
    return open_ports, analyze_open_ports(host, open_ports)


def analyze_open_ports(host: str, open_ports: List[Tuple[int, str]]) -> List[Finding]:
    findings = []
    for port, banner in open_ports:
        if port in RISKY_PORTS:
            svc, sev, issue, rec = RISKY_PORTS[port]
            findings.append(Finding(sev, "exposed-service", f"{host}:{port}",
                                    f"{svc} open - {issue}", rec))
        else:
            findings.append(Finding("info", "open-port", f"{host}:{port}", "Port is open"))
        if banner:
            findings.append(Finding("info", "banner", f"{host}:{port}", f"Banner: {banner}",
                                    "Consider hiding version details in banners."))
    return findings
