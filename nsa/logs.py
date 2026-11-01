"""Log analysis: SSH brute force and firewall-based port scan detection."""
import re
from collections import defaultdict
from typing import List

from .models import Finding

IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(\S+) from " + IP)
INVALID_RE = re.compile(r"Invalid user (\S+) from " + IP)
ACCEPTED_RE = re.compile(r"Accepted \S+ for (\S+) from " + IP)
FW_RE = re.compile(r"SRC=" + IP + r".*?DPT=(\d+)")


def analyze_auth_log(path: str, threshold: int = 5) -> List[Finding]:
    fails = defaultdict(int)
    users = defaultdict(set)
    accepted = defaultdict(set)
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            m = FAILED_RE.search(line)
            if m:
                user, ip = m.groups()
                fails[ip] += 1
                users[ip].add(user)
                continue
            m = INVALID_RE.search(line)
            if m:
                users[m.group(2)].add(m.group(1))
                continue
            m = ACCEPTED_RE.search(line)
            if m:
                accepted[m.group(2)].add(m.group(1))

    findings = []
    for ip, count in sorted(fails.items(), key=lambda x: -x[1]):
        if count >= threshold:
            sev = "high" if count >= threshold * 4 else "medium"
            findings.append(Finding(
                sev, "brute-force", ip,
                f"{count} failed SSH logins across {len(users[ip])} account(s): "
                f"{', '.join(sorted(users[ip])[:5])}",
                "Block the IP, enable fail2ban, disable password auth, use keys + MFA."))
            if ip in accepted:
                findings.append(Finding(
                    "high", "possible-compromise", ip,
                    f"IP had a SUCCESSFUL login ({', '.join(sorted(accepted[ip]))}) after failures",
                    "Investigate the account immediately and rotate credentials."))
    return findings


def analyze_firewall_log(path: str, port_threshold: int = 10) -> List[Finding]:
    ports = defaultdict(set)
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            m = FW_RE.search(line)
            if m:
                ports[m.group(1)].add(int(m.group(2)))
    findings = []
    for ip, p in sorted(ports.items(), key=lambda x: -len(x[1])):
        if len(p) >= port_threshold:
            findings.append(Finding(
                "high" if len(p) >= port_threshold * 3 else "medium", "port-scan", ip,
                f"Probed {len(p)} distinct ports (e.g. {', '.join(map(str, sorted(p)[:8]))})",
                "Block or rate-limit the source; review exposed services."))
    return findings
