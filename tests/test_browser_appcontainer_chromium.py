"""Real Chromium viability experiment; a reported startup block is NOT isolation."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from jarvis.experimental.appcontainer_probe import (
    _copy_chromium_dependencies, run_chromium_appcontainer_probe,
)
from jarvis.experimental.synthetic_browser import SyntheticBrowser


HTML = ('<!doctype html><html><body><p id="result">waiting</p><script>'
        'document.getElementById("result").textContent="JARVIS"+"-APPCONTAINER"+"-DOM-OK";'
        '</script></body></html>')


class ChromiumProbeInputTests(unittest.TestCase):
    def test_invalid_fixture_types_and_bounds_do_not_start_processes(self):
        for directory, html in ((None, HTML), ("unused", None), ("unused", ""), ("unused", "x" * 8193),
                                ("unused", "\ud800"), ("unused", "é" * 4097)):
            with self.subTest(directory_type=type(directory), html_type=type(html)), self.assertRaises(ValueError):
                run_chromium_appcontainer_probe(directory, html)


@unittest.skipUnless(os.name == "nt", "Windows AppContainer unavailable")
class ChromiumAppContainerRealTests(unittest.TestCase):
    def test_real_relocated_runtime_control_and_appcontainer_outcome(self):
        source = Path(os.environ.get("LOCALAPPDATA", ".")) / "ms-playwright/chromium-1208/chrome-win64"
        if not (source / "chrome.exe").is_file():
            self.skipTest("Chromium 145 cache unavailable; no downloads")
        cache = Path(__file__).resolve().parents[1] / ".cache"
        cache.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="chromium-runtime-control-", dir=cache) as temporary:
            root = Path(temporary).resolve()
            self.assertEqual(root.parent, cache.resolve())
            shutil.copyfile(source / "chrome.exe", root / "chrome.exe")
            _copy_chromium_dependencies(source, root, [])
            # Real positive DOM control uses the SAME relocated dependency set,
            # so missing copied DLLs/assets are not mistaken for a token block.
            with SyntheticBrowser(str(root / "chrome.exe")) as browser:
                browser.load_html("relocated-runtime-control", HTML)
                browser.wait_text("#result", "JARVIS-APPCONTAINER-DOM-OK")
                self.assertEqual(browser.read_text("#result"), "JARVIS-APPCONTAINER-DOM-OK")
        result = run_chromium_appcontainer_probe(str(source), HTML)
        self.assertTrue(result.cleanup_complete, result.remaining_resources)
        self.assertTrue(result.processes, result)
        root_process = result.processes[0]
        self.assertIs(root_process.appcontainer, True)
        self.assertEqual(root_process.sid, result.expected_sid)
        self.assertEqual(root_process.capabilities, 0)
        self.assertIs(root_process.in_job, True)
        self.assertGreater(result.sampled_peak_working_set_bytes, 0)
        self.assertIn(result.status, {"document_observed", "chromium_exit_failed", "document_not_observed", "chromium_timeout"})
        if result.document_observed:
            self.assertEqual(result.status, "document_observed")
            self.assertEqual(result.exit_code, 0)
        else:
            self.assertNotEqual(result.status, "document_observed")
        print("REAL_CHROMIUM_APPCONTAINER:", result.status, "exit=", result.exit_code,
              "document=", result.document_observed, "processes=", result.processes,
              "sampled_peak_ws_mib=", round(result.sampled_peak_working_set_bytes / 1048576, 2),
              "diagnostics=", result.diagnostics, "cleanup=", result.cleanup_complete)


if __name__ == "__main__":
    unittest.main()
