import argparse
import sys

from . import __version__
from .scanner import scan_host, parse_ports, COMMON_PORTS
from .logs import analyze_auth_log, analyze_firewall_log
from .tls_check import check_tls
from .report import render_text, render_json


def build_parser():
    p = argparse.ArgumentParser(prog="nsa", description="Network Security Analyzer (defensive toolkit)")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("-o", "--output", help="Write report to file")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan a host you own for risky open ports")
    s.add_argument("host")
    s.add_argument("-p", "--ports", default=None, help="e.g. 22,80,8000-8100 (default: common ports)")
    s.add_argument("-t", "--timeout", type=float, default=1.0)
    s.add_argument("--i-have-permission", action="store_true",
                   help="Confirm you are authorized to scan this host")

    l = sub.add_parser("logs", help="Analyze auth or firewall logs")
    l.add_argument("file")
    l.add_argument("--type", choices=["auth", "firewall"], default="auth")
    l.add_argument("--threshold", type=int, default=None)

    t = sub.add_parser("tls", help="Check TLS configuration")
    t.add_argument("host")
    t.add_argument("--port", type=int, default=443)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            if not args.i_have_permission:
                print("Refusing to scan: pass --i-have-permission to confirm you are authorized.", file=sys.stderr)
                return 2
            ports = parse_ports(args.ports) if args.ports else COMMON_PORTS
            _, findings = scan_host(args.host, ports, args.timeout)
        elif args.command == "logs":
            if args.type == "auth":
                findings = analyze_auth_log(args.file, args.threshold or 5)
            else:
                findings = analyze_firewall_log(args.file, args.threshold or 10)
        else:
            findings = check_tls(args.host, args.port)
    except (OSError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    out = render_json(findings) if args.format == "json" else render_text(findings)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(out + "\n")
        print(f"Report written to {args.output}")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
