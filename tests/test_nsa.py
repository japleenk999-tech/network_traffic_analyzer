import os, socket, sys, threading, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from nsa.scanner import parse_ports, scan_host
from nsa.logs import analyze_auth_log, analyze_firewall_log

DATA = os.path.join(os.path.dirname(__file__), "..", "sample_data")


class Tests(unittest.TestCase):
    def test_parse_ports(self):
        self.assertEqual(parse_ports("22,80,100-102"), [22, 80, 100, 101, 102])
        with self.assertRaises(ValueError):
            parse_ports("70000")

    def test_auth_log(self):
        f = analyze_auth_log(os.path.join(DATA, "auth.log"))
        cats = {x.category for x in f}
        self.assertIn("brute-force", cats)
        self.assertIn("possible-compromise", cats)

    def test_firewall_log(self):
        f = analyze_firewall_log(os.path.join(DATA, "firewall.log"))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].target, "192.0.2.9")

    def test_scan_local(self):
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]
        threading.Thread(target=srv.accept, daemon=True).start()
        open_ports, _ = scan_host("127.0.0.1", [port], timeout=0.5)
        srv.close()
        self.assertEqual([p for p, _ in open_ports], [port])


if __name__ == "__main__":
    unittest.main()
