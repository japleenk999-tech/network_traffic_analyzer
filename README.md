# Network Security Analyzer

A small, dependency-free (Python 3.8+) defensive toolkit for checking your own network and servers.

## Features
- **scan**: TCP connect scan that flags risky exposed services (Telnet, SMB, RDP, databases, ...) and grabs banners
- **logs**: detects SSH brute-force attempts (and success-after-failure) in auth logs, and port scans in firewall (iptables-style) logs
- **tls**: checks negotiated TLS version, certificate validity and expiry
- Text or JSON reports, optional output file

## Usage
```bash
python -m nsa scan 127.0.0.1 --i-have-permission
python -m nsa scan 192.168.1.10 -p 1-1024 --i-have-permission
python -m nsa logs sample_data/auth.log --type auth
python -m nsa logs sample_data/firewall.log --type firewall
python -m nsa tls example.com
python -m nsa --format json -o report.json logs sample_data/auth.log
```

## Tests
```bash
python -m unittest discover tests
```

## Legal / ethical notice
Only scan systems you own or have explicit written authorization to test.
The scanner requires `--i-have-permission` as a reminder.

## Layout
```
nsa/            package (scanner, logs, tls_check, report, cli)
sample_data/    example auth and firewall logs
tests/          unit tests
```
