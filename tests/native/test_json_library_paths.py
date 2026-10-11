import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('json_native_check', ROOT / 'scripts/check_json_native.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class JsonLibraryPaths(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.compiler = self.root / 'bin/sn'

    def archive(self, relative):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'!<arch>\n')
        return path.resolve()

    def test_staged_archive_remains_preferred(self):
        staged = self.archive('bin/deps/lib/libjson-c.a')
        self.archive('.sn/sindarin-pkg-libs/libs/linux/lib/libjson-c.a')
        self.assertEqual(checker.json_library_path(self.compiler, 'Linux'), staged)

    def test_macos_installed_archive_without_staged_library(self):
        installed = self.archive('.sn/sindarin-pkg-libs/libs/darwin/lib/libjson-c.a')
        self.assertEqual(checker.json_library_path(self.compiler, 'Darwin'), installed)

    def test_windows_installed_archive_and_missing_dependency_diagnostic(self):
        installed = self.archive('.sn/sindarin-pkg-libs/libs/windows/lib/libjson-c.a')
        self.assertEqual(checker.json_library_path(self.compiler, 'Windows'), installed)
        with self.assertRaisesRegex(ValueError, 'json-c archive missing from compiler dependency locations'):
            checker.json_library_path(self.compiler, 'Linux')


if __name__ == '__main__':
    unittest.main()
