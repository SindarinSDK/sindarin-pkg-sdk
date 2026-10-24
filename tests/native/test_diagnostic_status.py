import importlib.util
import json
from pathlib import Path
import subprocess
import shutil
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

    def test_tls_failure_keeps_stderr_original_status_and_source_when_output_is_pruned(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root/'tests/net/test_tls.sn'
            source.parent.mkdir(parents=True)
            original_source = b'unchanged TLS source\n'
            source.write_bytes(original_source)
            primary = b'  test_tls \x1b[0;31mFAIL\x1b[0m (exit code: 1)\r\n'
            output = root/'.sn/tls-failure-diagnostics'
            calls = []

            def invoke(command, **kwargs):
                calls.append(command)
                if len(calls) == 1:
                    return subprocess.CompletedProcess(command, 7, primary, b'runner stderr\n')
                if len(calls) == 2:
                    self.assertIn('--no-install', command)
                    self.assertIn('-O0', command)
                    self.assertIn(str(source), command)
                    shutil.rmtree(output)
                    return subprocess.CompletedProcess(command, 0, b'compiled\n', b'')
                return subprocess.CompletedProcess(command, 1, b'partial response\n', b'TLS read failed\n')

            with patch.object(diagnostics, '__file__', str(root/'scripts/run_tests_with_diagnostics.py')), \
                 patch.object(sys, 'argv', ['diagnostics', '--runner', 'runner', '--compiler', 'compiler']), \
                 patch.object(diagnostics.subprocess, 'run', side_effect=invoke):
                self.assertEqual(diagnostics.main(), 7)
            self.assertEqual(len(calls), 3)
            self.assertEqual(source.read_bytes(), original_source)
            self.assertFalse((root/'.sn/dtls-failure-diagnostics').exists())
            self.assertEqual((output/'primary.stdout').read_bytes(), primary)
            self.assertEqual((output/'primary.stderr').read_bytes(), b'runner stderr\n')
            self.assertEqual((output/'run.stderr').read_bytes(), b'TLS read failed\n')
            report = json.loads((output/'results.json').read_text())
            self.assertEqual(report['source'], 'tests/net/test_tls.sn')
            self.assertEqual(report['primary_runner_status'], 7)
            self.assertEqual(report['run_status'], 1)
            self.assertTrue(report['diagnostic_rerun_is_not_acceptance'])


if __name__ == '__main__':
    unittest.main()
