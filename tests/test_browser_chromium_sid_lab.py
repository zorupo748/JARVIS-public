"""Mocked launcher/error tests; no restricted credentials or browser fallback."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch,Mock

from jarvis.experimental import chromium_sid_lab as chromium
from jarvis.experimental.sid_firewall_lab import SIDLabError,LocalTestIdentity,RuleLifetimeGuard

REPORT=('chromium_report=1\nprocess_created=1\nroot_pid=123\nroot_identity=1\nroot_in_job=1\n'
        'root_exited=1\nroot_exit_code=0\nprocess=123,browser,1,1,0\nprocess=124,renderer,1,1,0\n'
        'sampled_peak_ws=123456\ncpu_ms=42\ninspection_failed=0\nroot_stopped=1\njob_empty=1\nhandles_closed=1\n')
DOM='<html><body data-js="ran"><span id="s">SID_CLICK_OK</span></body></html>'


class ChromiumSIDTests(unittest.TestCase):
    def test_preflight_fails_if_identity_or_rule_is_wrong(self):
        identity=LocalTestIdentity(chromium.ACCOUNT,chromium.SID,True,True)
        for value in (replace(identity,standard=False),replace(identity,enabled=False),replace(identity,sid='S-1-5-21-1-2-3-1001')):
            with patch.object(chromium,'inspect_local_identity',return_value=value),self.assertRaises(SIDLabError):
                chromium.preflight()
        with patch.object(chromium,'inspect_local_identity',return_value=identity),patch.object(chromium,'validate_effective_rule',return_value=False),self.assertRaises(SIDLabError):
            chromium.preflight()

    def test_mock_dom_requires_executed_attributes_and_text_not_source_strings(self):
        result=chromium.parse_chromium_report(REPORT,DOM)
        self.assertEqual(result.status,'dom_observed')
        self.assertTrue(result.javascript_observed);self.assertTrue(result.button_click_observed)
        self.assertFalse(result.playwright_executed)
        self.assertEqual(result.cpu_ms,42);self.assertEqual(result.sampled_peak_ws,123456)
        result=chromium.parse_chromium_report(REPORT,chromium.HTML)
        self.assertFalse(result.javascript_observed);self.assertFalse(result.button_click_observed)

    def test_children_escape_or_inspection_failure_never_certify_cleanup(self):
        for line in ('process=125,gpu,0,1,5\n','process=125,network,1,0,0\n','process=125,unknown,0,0,87\n'):
            with self.subTest(line=line):
                result=chromium.parse_chromium_report(REPORT+line,DOM)
                self.assertFalse(result.cleanup_complete)
                self.assertEqual(result.status,'inconclusive')

    def test_creation_failure_and_truncated_report_are_not_success(self):
        for text in ('chromium_report=1\ndiag=process_create,5\n',REPORT.replace('root_identity=1','root_identity=0'),REPORT.replace('job_empty=1','job_empty=0')):
            with self.subTest(text=text):
                self.assertEqual(chromium.parse_chromium_report(text,DOM).status,'inconclusive')

    def test_sensitive_raw_diagnostics_not_exported(self):
        result=chromium.parse_chromium_report(REPORT+'diag=DO_NOT_LEAK,secret\n',DOM)
        self.assertFalse(result.cleanup_complete)
        self.assertNotIn('DO_NOT_LEAK',repr(result))

    def test_mock_launch_uses_stdin_only_no_network_debug_or_other_identity(self):
        with tempfile.TemporaryDirectory(prefix='jarvis-sid-chromium-test-') as root:
            Path(root,'dom.txt').write_text(DOM,encoding='utf-8')
            guard=RuleLifetimeGuard()
            from jarvis.experimental import browser_run_environment as env
            with patch.object(chromium,'preflight'),patch.object(env,'allowed_paths',return_value=True),patch.object(env,'RunLayout'),patch.object(env,'effective_access_check'),patch.object(env,'verify_installed'),patch.object(env,'controller_sid'),patch.object(chromium.subprocess,'run',return_value=Mock(stdout=REPORT,returncode=0)) as execute:
                result=chromium.run_chromium_probe(str(Path(root,'launcher.exe')),str(Path(root,'chrome.exe')),root,password='DO_NOT_LEAK',guard=guard)
            self.assertTrue(result.cleanup_complete)
            self.assertTrue(guard.may_remove_rule)
            arguments=execute.call_args.args[0]
            self.assertEqual(arguments[2:4],[chromium.ACCOUNT,chromium.SID])
            self.assertNotIn('DO_NOT_LEAK',repr(arguments));self.assertNotIn('DO_NOT_LEAK',repr(result))
            self.assertFalse(any('remote-debugging-port' in v or 'no-sandbox' in v for v in arguments))

    def test_missing_rule_does_not_invoke_any_launcher(self):
        with patch.object(chromium,'preflight',side_effect=SIDLabError('effective_rule_not_verified')),patch.object(chromium.subprocess,'run') as execute:
            with self.assertRaises(SIDLabError):
                chromium.run_chromium_probe(str(Path('helper.exe').absolute()),str(Path('chrome.exe').absolute()),str(Path('work').absolute()),password='transient',guard=RuleLifetimeGuard())
            execute.assert_not_called()


if __name__=='__main__':unittest.main()
