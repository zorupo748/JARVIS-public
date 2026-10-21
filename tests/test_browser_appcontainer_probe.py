"""Real Windows API/CLR/socket tests; pure classification tests use no process.

No administrator, firewall change, loopback exemption or external destination.
Compilation uses the pre-existing Framework C# compiler, never downloads tools.
"""

import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path

from jarvis.experimental.appcontainer_probe import classify_probe, run_appcontainer_probe


class ProbeClassificationTests(unittest.TestCase):
    def test_only_verified_identity_and_all_explicit_denials_are_success(self):
        base = (("appcontainer", "1"), ("sid", "S-test"), ("capabilities", "0"))
        self.assertEqual(classify_probe(base + (("endpoint_0", "blocked_10013"),), "S-test", 1), "network_blocked")
        for value, expected in (("connected", "network_not_blocked"), ("udp_sent", "inconclusive"), ("timeout", "inconclusive"),
                                ("error_10061", "inconclusive")):
            with self.subTest(value=value):
                self.assertEqual(classify_probe(base + (("endpoint_0", value),), "S-test", 1), expected)
        self.assertEqual(classify_probe(base, "S-test", 1), "inconclusive")
        self.assertEqual(classify_probe(base, "S-other", 1), "identity_failed")

    def test_identity_failure_malformed_and_duplicate_reports_never_pass(self):
        for report in ((), (("appcontainer", "0"),),
                       (("appcontainer", "1"), ("sid", "S-test"), ("capabilities", "1")),
                       (("appcontainer", "1"), ("appcontainer", "1")), [], (("x", 1),)):
            with self.subTest(report=report):
                self.assertNotEqual(classify_probe(report, "S-test", 1), "network_blocked")


@unittest.skipUnless(os.name == "nt", "Windows AppContainer unavailable")
class RealAppContainerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = Path(os.environ.get("WINDIR", "C:/Windows")) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
        if not cls.compiler.is_file():
            raise unittest.SkipTest("BLOCKED: existing C# compiler unavailable; no installation attempted")
        root = Path(__file__).resolve().parents[1]
        cache = root / ".cache"
        cache.mkdir(exist_ok=True)
        cls.temporary = tempfile.TemporaryDirectory(prefix="appcontainer-test-", dir=cache)
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.helper = cls.directory / "probe.exe"
        source = Path(__file__).parent / "fixtures/appcontainer_probe.cs"
        compiled = subprocess.run([str(cls.compiler), "/nologo", "/target:exe", "/out:" + str(cls.helper), str(source)],
                                  capture_output=True, text=True, timeout=30)
        if compiled.returncode != 0:
            raise RuntimeError("helper_compilation_failed: " + compiled.stdout + compiled.stderr)

    def test_real_launch_identity_positive_controls_and_network_observations(self):
        listeners, specs = [], []
        try:
            for family, host, suffix in ((socket.AF_INET, "127.0.0.1", "4"),
                                         (socket.AF_INET6, "::1", "6")):
                for kind, socktype in (("tcp", socket.SOCK_STREAM), ("udp", socket.SOCK_DGRAM)):
                    listener = socket.socket(family, socktype)
                    try:
                        if family == socket.AF_INET6:
                            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                        listener.bind((host, 0))
                    except OSError:
                        listener.close()
                        if family == socket.AF_INET6:
                            self.skipTest("INCONCLUSIVE: IPv6 loopback listeners unavailable")
                        raise
                    if kind == "tcp":
                        listener.listen(2)
                    listener.settimeout(2)
                    listeners.append((kind, listener))
                    specs.append(kind + suffix + ":" + str(listener.getsockname()[1]))
            output = self.directory / "positive.txt"
            positive = subprocess.run([str(self.helper), str(output), *specs], timeout=15)
            self.assertEqual(positive.returncode, 0, "Positive helper failed, not a network blocking result")
            report = dict(line.split("=") for line in output.read_text(encoding="ascii").splitlines())
            self.assertEqual(report["appcontainer"], "0")
            for i, (kind, listener) in enumerate(listeners):
                self.assertEqual(report["endpoint_" + str(i)], "connected" if kind == "tcp" else "udp_sent")
                if kind == "tcp":
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(2)
                        self.assertEqual(connection.recv(6), b"JARVIS")
                else:
                    self.assertEqual(listener.recvfrom(64)[0], b"JARVIS")
            result = run_appcontainer_probe(str(self.helper), tuple(specs))
            self.assertTrue(result.cleanup_complete, result.remaining_resources)
            self.assertEqual(result.exit_code, 0, result)
            self.assertIn(result.status, {"network_blocked", "inconclusive"}, result)
            self.assertEqual(dict(result.report)["sid"], result.expected_sid)
            for kind, listener in listeners:
                listener.settimeout(0.2)
                with self.assertRaises(TimeoutError):
                    if kind == "tcp":
                        connection, _ = listener.accept()
                        connection.close()
                    else:
                        listener.recvfrom(64)
            # Repeat the same positive control AFTER the restricted probe:
            # silence is not explained by dead listeners. Still do not convert
            # timeout/UDP send acceptance into an explicit OS access denial.
            positive_after = subprocess.run([str(self.helper), str(output), *specs], timeout=15)
            self.assertEqual(positive_after.returncode, 0)
            for kind, listener in listeners:
                listener.settimeout(2)
                if kind == "tcp":
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(2)
                        self.assertEqual(connection.recv(6), b"JARVIS")
                else:
                    self.assertEqual(listener.recvfrom(64)[0], b"JARVIS")
            print("REAL_PROBE:", result.status, result.report,
                  "positive_receipts_before_and_after=4;restricted_receipts=0;cleanup=complete")
        finally:
            for _, listener in listeners:
                listener.close()

    def test_real_missing_executable_is_launch_failure_not_blocked(self):
        result = run_appcontainer_probe(str(self.directory / "missing.exe"), ("tcp4:9",))
        self.assertEqual(result.status, "launch_failed")
        self.assertIsNone(result.exit_code)
        self.assertEqual(result.report, ())
        self.assertTrue(result.cleanup_complete, result.remaining_resources)

    def test_real_invalid_executable_is_createprocess_failure_not_blocked(self):
        invalid = self.directory / "invalid.exe"
        invalid.write_bytes(b"not an executable")
        result = run_appcontainer_probe(str(invalid), ("tcp4:9",))
        self.assertEqual(result.status, "launch_failed")
        self.assertIsNone(result.exit_code)
        self.assertEqual(result.report, ())
        self.assertTrue(result.cleanup_complete, result.remaining_resources)

    def variant(self, definition):
        path = self.directory / (definition + ".exe")
        source = Path(__file__).parent / "fixtures/appcontainer_probe.cs"
        compiled = subprocess.run([str(self.compiler), "/nologo", "/target:exe",
                                   "/define:" + definition, "/out:" + str(path), str(source)],
                                  capture_output=True, text=True, timeout=30)
        self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
        return path

    def test_real_started_helper_failure_is_inconclusive(self):
        result = run_appcontainer_probe(str(self.variant("PROBE_NO_REPORT")), ("tcp4:9",))
        self.assertEqual(result.status, "inconclusive")
        self.assertEqual(result.exit_code, 7)
        self.assertEqual(result.report, ())
        self.assertTrue(result.cleanup_complete, result.remaining_resources)

    def test_real_timeout_terminates_helper_and_cleans_own_profile(self):
        result = run_appcontainer_probe(str(self.variant("PROBE_HANG")), ("tcp4:9",), timeout_ms=200)
        self.assertEqual(result.status, "inconclusive")
        self.assertIsNone(result.exit_code)
        self.assertTrue(result.cleanup_complete, result.remaining_resources)


if __name__ == "__main__":
    unittest.main()
