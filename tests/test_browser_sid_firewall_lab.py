"""Pure/mocked account tests and REAL current-identity echo controls.

No dedicated account or firewall rule is created. No restricted run is claimed.
"""
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch, Mock

from jarvis.experimental import sid_firewall_lab as lab

SID = "S-1-5-21-100-200-300-1001"
IDENTITY = lab.LocalTestIdentity("JarvisLab", SID, True, True)
PLAN = lab.SIDBlockPlan(IDENTITY, "jarvis-sid-lab-test")


class SIDFirewallUnitTests(unittest.TestCase):
    def test_preparation_scopes_all_protocols_addresses_to_sid(self):
        args = PLAN.privileged_install_arguments()
        self.assertEqual(PLAN.local_user_sddl, "D:(A;;CC;;;" + SID + ")")
        for name, value in (("-Direction", "Outbound"), ("-Action", "Block"), ("-Profile", "Any"),
                            ("-Protocol", "Any"), ("-Program", "Any"), ("-LocalUser", PLAN.local_user_sddl)):
            self.assertEqual(args[args.index(name)+1], value)

    def test_structural_identity_and_admin_checks(self):
        for sid in (None, "S-1-5-32-544", "S-1-5-21-1-2-3-4294967296", SID + ")"):
            with self.subTest(sid=sid), self.assertRaises(ValueError):
                lab.LocalTestIdentity("JarvisLab", sid, True, True)
        for standard, enabled in ((False, True), (True, False)):
            with self.assertRaises(ValueError):
                lab.SIDBlockPlan(lab.LocalTestIdentity("JarvisLab", SID, standard, enabled), "jarvis-sid-lab-test")
        with self.assertRaises(ValueError):
            lab.inspect_local_identity("bad';New-LocalUser")

    def test_identity_inspection_read_only_and_unknown_fails(self):
        with patch.object(lab, "_read_powershell", return_value=dict(account_name="JarvisLab", sid=SID, standard=True, enabled=True)) as query:
            self.assertEqual(lab.inspect_local_identity("JarvisLab"), IDENTITY)
            self.assertIn("Get-LocalUser", query.call_args.args[0])
            self.assertNotIn("New-LocalUser", query.call_args.args[0])
        with patch.object(lab, "_read_powershell", return_value={}):
            with self.assertRaises(lab.SIDLabError):
                lab.inspect_local_identity("JarvisLab")

    def report(self):
        return dict(name=PLAN.rule_name, enabled="True", direction="Outbound", action="Block", profile="Any",
            local_user=PLAN.local_user_sddl, program="Any", protocol="Any", local_port="Any", remote_port="Any",
            local_address="Any", remote_address="Any", profiles_enabled=True, services_running=True)

    def test_effective_configuration_fail_closed(self):
        self.assertTrue(lab.rule_report_matches(PLAN, self.report()))
        for key in self.report():
            with self.subTest(key=key):
                changed = self.report(); changed[key] = None
                self.assertFalse(lab.rule_report_matches(PLAN, changed))
        with patch.object(lab, "_read_powershell", return_value=self.report()) as query:
            self.assertTrue(lab.validate_effective_rule(PLAN))
            self.assertIn("ActiveStore", query.call_args.args[0])
            self.assertNotIn("New-NetFirewallRule", query.call_args.args[0])

    def test_controlled_endpoints_no_public_dns_or_scopes(self):
        for protocol, address in (("tcp", "127.0.0.1"), ("udp", "::1"), ("tcp", "192.168.1.5")):
            lab.ControlledEndpoint(protocol, address, 12345)
        for address in ("8.8.8.8", "example.com", "fe80::1%3", "::ffff:127.0.0.1", "0.0.0.0", "ff02::1"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                lab.ControlledEndpoint("tcp", address, 12345)
        with self.assertRaises(ValueError):
            lab.ControlledEndpoint("udp", "::1", True)

    def test_classification_requires_identity_effective_rule_and_controls(self):
        good = ("echo_received",)
        args = dict(effective_rule=True, identity_verified=True, cleanup_complete=True)
        self.assertEqual(lab.classify_attempts(("denied_10013",), good, good, **args), "access_denied_observed")
        for attempt in ("timeout", "udp_sent", "error"):
            self.assertEqual(lab.classify_attempts((attempt,), good, good, **args), "inconclusive")
        self.assertEqual(lab.classify_attempts(good, good, good, **args), "network_not_blocked")
        for key in args:
            changed = dict(args); changed[key] = False
            self.assertEqual(lab.classify_attempts(("denied_10013",), good, good, **changed), "inconclusive")
        self.assertEqual(lab.classify_attempts(("denied_10013",), ("timeout",), good, **args), "inconclusive")

    def test_rule_removal_guard_cleanup_and_concurrency(self):
        guard = lab.RuleLifetimeGuard(); a = guard.acquire(); b = guard.acquire()
        self.assertFalse(guard.may_remove_rule)
        guard.settle(a, confirmed_job_empty=True)
        self.assertFalse(guard.may_remove_rule)
        guard.settle(b, confirmed_job_empty=True)
        self.assertTrue(guard.may_remove_rule)
        with self.assertRaises(lab.SIDLabError):
            guard.settle(b, confirmed_job_empty=True)
        guard.settle(guard.acquire(), confirmed_job_empty=False)
        self.assertFalse(guard.may_remove_rule)

    def test_launcher_requires_account_rule_and_never_leaks_password(self):
        guard = lab.RuleLifetimeGuard(); endpoint = lab.ControlledEndpoint("tcp", "127.0.0.1", 12345)
        with patch.object(lab, "inspect_local_identity", return_value=IDENTITY), patch.object(lab, "validate_effective_rule", return_value=False), patch.object(lab.subprocess, "run") as run:
            with self.assertRaises(lab.SIDLabError):
                lab.run_account_probe(PLAN, str(Path("helper.exe").absolute()), (endpoint,), password="DO_NOT_LEAK", guard=guard)
            run.assert_not_called()
        with patch.object(lab, "inspect_local_identity", return_value=IDENTITY), patch.object(lab, "validate_effective_rule", return_value=True), patch.object(lab.subprocess, "run", return_value=Mock(returncode=0, stdout="report_version=2\nprocess_created=1\nroot_identity=1\nroot_in_job=1\nroot_exited=1\nroot_exit_code=1140850691\nchild_identity=1\nchild_verified=0\nattempt=timeout\nroot_stopped=1\njob_empty=1\nhandles_closed=1\n")) as run:
            result = lab.run_account_probe(PLAN, str(Path("helper.exe").absolute()), (endpoint,), password="DO_NOT_LEAK", guard=guard)
            self.assertNotIn("DO_NOT_LEAK", repr(result))
            self.assertNotIn("DO_NOT_LEAK", repr(run.call_args.args))
            self.assertEqual(result.attempts, ("timeout",))
            self.assertTrue(guard.may_remove_rule)

    def test_launch_timeout_is_inconclusive_and_prevents_rule_removal(self):
        guard=lab.RuleLifetimeGuard()
        with patch.object(lab,"inspect_local_identity",return_value=IDENTITY), patch.object(lab,"validate_effective_rule",return_value=True), patch.object(lab.subprocess,"run",side_effect=subprocess.TimeoutExpired("helper",1)):
            result=lab.run_account_probe(PLAN,str(Path("helper.exe").absolute()),(lab.ControlledEndpoint("tcp","::1",12345),),password="transient",guard=guard)
        self.assertEqual(result.status,"launch_or_cleanup_inconclusive")
        self.assertFalse(guard.may_remove_rule)

    def test_partial_facts_survive_job_query_failure_and_guard_stays_closed(self):
        output = "report_version=2\nprocess_created=1\nroot_pid=1234\nroot_identity=1\nroot_in_job=1\nroot_exited=1\nroot_exit_code=1140850689\nchild_identity=1\nchild_verified=0\nattempt=echo_received\ndiag=job_query,24\nroot_stopped=1\njob_empty=0\nhandles_closed=1\n"
        guard = lab.RuleLifetimeGuard()
        with patch.object(lab,"inspect_local_identity",return_value=IDENTITY), patch.object(lab,"validate_effective_rule",return_value=True), patch.object(lab.subprocess,"run",return_value=Mock(returncode=0,stdout=output)):
            result = lab.run_account_probe(PLAN,str(Path("helper.exe").absolute()),(lab.ControlledEndpoint("tcp","::1",12345),),password="transient",guard=guard)
        self.assertEqual(result.status, "inconclusive")
        self.assertTrue(result.process_created)
        self.assertEqual(result.root_pid,1234)
        self.assertTrue(result.root_identity_verified)
        self.assertTrue(result.root_in_job)
        self.assertTrue(result.child_identity_verified)
        self.assertEqual(result.attempts, ("echo_received",))
        self.assertEqual(result.child_verified_indices, (0,))
        self.assertEqual(result.diagnostics, (("job_query",24),))
        self.assertIsNone(result.remaining_pids)
        self.assertFalse(result.cleanup_complete)
        self.assertFalse(guard.may_remove_rule)

    def test_stage_failure_reports_preserve_prior_facts(self):
        for stage, code, prefix in (
            ("process_create",1326,"report_version=2\n"),
            ("root_identity",0,"report_version=2\nprocess_created=1\n"),
            ("wait_timeout",0,"report_version=2\nprocess_created=1\nroot_identity=1\nroot_in_job=1\n"),
            ("exit_code",6,"report_version=2\nprocess_created=1\nroot_identity=1\nroot_in_job=1\nroot_exited=1\n"),
            ("job_query",24,"report_version=2\nprocess_created=1\nroot_identity=1\n"),
        ):
            with self.subTest(stage=stage):
                result=lab.parse_probe_report(prefix+f"diag={stage},{code}\njob_empty=0\n",SID,1)
                self.assertEqual(result.diagnostics,((stage,code),))
                self.assertEqual(result.process_created,"process_created=1" in prefix)
                self.assertEqual(result.root_identity_verified,"root_identity=1" in prefix)
                self.assertFalse(result.cleanup_complete)

    def test_malformed_diagnostics_never_export_raw_secrets_or_certify_cleanup(self):
        for line in ("diag=DO_NOT_LEAK,5", "diag=process_create,DO_NOT_LEAK", "root_identity=1\nroot_identity=0"):
            with self.subTest(line=line):
                result=lab.parse_probe_report("report_version=2\nroot_stopped=1\njob_empty=1\nhandles_closed=1\n"+line,SID,1)
                self.assertFalse(result.cleanup_complete)
                self.assertNotIn("DO_NOT_LEAK",repr(result))

    def test_timeout_stdout_retains_execution_but_never_cleanup(self):
        guard=lab.RuleLifetimeGuard()
        error=subprocess.TimeoutExpired("helper",1,output=b"process_created=1\nroot_identity=1\nroot_in_job=1\n")
        with patch.object(lab,"inspect_local_identity",return_value=IDENTITY), patch.object(lab,"validate_effective_rule",return_value=True), patch.object(lab.subprocess,"run",side_effect=error):
            result=lab.run_account_probe(PLAN,str(Path("helper.exe").absolute()),(lab.ControlledEndpoint("tcp","::1",12345),),password="transient",guard=guard)
        self.assertTrue(result.process_created)
        self.assertTrue(result.root_identity_verified)
        self.assertTrue(result.root_in_job)
        self.assertFalse(guard.may_remove_rule)

    def test_unverified_echo_and_incomplete_cleanup_never_prove_network_bypass(self):
        for identity, cleanup in ((False,True),(True,False),(False,False)):
            with self.subTest(identity=identity,cleanup=cleanup):
                self.assertEqual(lab.classify_attempts(("echo_received",),("echo_received",),("echo_received",),
                    effective_rule=True,identity_verified=identity,cleanup_complete=cleanup),"inconclusive")

    def test_review_runner_never_overrides_classification_from_listener_counts(self):
        import ast
        source=(Path(__file__).parents[1]/"tools/experimental/jarvis_sid_lab_runner_review.py").read_text(encoding="utf-8")
        tree=ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="outcome" for t in node.targets):
                self.assertTrue(isinstance(node.value,ast.Call) or
                    (isinstance(node.value,ast.Constant) and node.value.value=="inconclusive"))
        self.assertIn("result.diagnostics",source)


@unittest.skipUnless(os.name == "nt", "REAL WINDOWS CONTROL NOT EXECUTED")
class SIDFirewallRealControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler=Path(os.environ.get("WINDIR","C:/Windows"))/"Microsoft.NET/Framework64/v4.0.30319/csc.exe"
        if not compiler.is_file():
            raise unittest.SkipTest("OS C# compiler unavailable, no installation")
        cls.temp=tempfile.TemporaryDirectory(prefix="jarvis-sid-control-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.exe=str(Path(cls.temp.name)/"probe.exe")
        result=subprocess.run([str(compiler),"/nologo","/r:System.Management.dll","/out:"+cls.exe,str(Path(__file__).parent/"fixtures/sid_firewall_probe.cs")],capture_output=True,text=True)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    def test_real_unrestricted_tcp_udp_ipv4_ipv6_echo_controls(self):
        for family, address in ((socket.AF_INET,"127.0.0.1"),(socket.AF_INET6,"::1")):
            for protocol, kind in (("tcp",socket.SOCK_STREAM),("udp",socket.SOCK_DGRAM)):
                with self.subTest(protocol=protocol,address=address):
                    with socket.socket(family,kind) as listener:
                        listener.settimeout(3)
                        try: listener.bind((address,0))
                        except OSError:
                            if family==socket.AF_INET6: self.skipTest("IPv6 loopback unavailable")
                            raise
                        if protocol=="tcp": listener.listen(1)
                        received=[]; failures=[]
                        def echo():
                            try:
                                if protocol=="tcp":
                                    peer,_=listener.accept()
                                    with peer:
                                        peer.settimeout(3);data=peer.recv(64);received.append(data);peer.sendall(data)
                                else:
                                    data,peer=listener.recvfrom(64);received.append(data);listener.sendto(data,peer)
                            except Exception as error: failures.append(type(error).__name__)
                        thread=threading.Thread(target=echo);thread.start()
                        identity, attempts = lab.run_positive_controls(self.exe,
                            (lab.ControlledEndpoint(protocol,address,listener.getsockname()[1]),), SID)
                        thread.join(4)
                        self.assertFalse(thread.is_alive());self.assertEqual(failures,[])
                        self.assertNotEqual(identity,SID);self.assertEqual(attempts,("echo_received",))
                        self.assertEqual(received,[b"JARVIS-SID-LAB"])


if __name__ == "__main__": unittest.main()
