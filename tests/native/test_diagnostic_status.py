import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('sdk_diagnostics', ROOT/'scripts/run_tests_with_diagnostics.py')
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)


class DiagnosticStatusTests(unittest.TestCase):
    def test_successful_diagnostic_cannot_hide_primary_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'tests/net').mkdir(parents=True)
            (root/'tests/net/test_dtls.sn').write_text('unchanged source\n')
            results = [subprocess.CompletedProcess([], 7),
                subprocess.CompletedProcess([], 0, b'', b''),
                subprocess.CompletedProcess([], 0, b'', b'')]
            with patch.object(diagnostics, '__file__', str(root/'scripts/run_tests_with_diagnostics.py')), \
                 patch.object(sys, 'argv', ['diagnostics','--runner','runner','--compiler','compiler']), \
                 patch.object(diagnostics.subprocess, 'run', side_effect=results) as run:
                self.assertEqual(diagnostics.main(), 7)
                self.assertEqual(run.call_count, 3)
            report = json.loads((root/'.sn/dtls-failure-diagnostics/results.json').read_text())
            self.assertEqual(report['primary_runner_status'], 7)
            self.assertEqual(report['run_status'], 0)
            self.assertTrue(report['diagnostic_rerun_is_not_acceptance'])

    def test_successful_primary_runner_has_no_diagnostic_rerun(self):
        with patch.object(sys, 'argv', ['diagnostics','--runner','runner','--compiler','compiler']), \
             patch.object(diagnostics.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertEqual(diagnostics.main(), 0)
            self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
