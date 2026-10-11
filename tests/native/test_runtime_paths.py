import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('bytes_check',ROOT/'scripts/check_bytes_native.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RuntimePathsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sn-sdk-install-layout-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.environment = patch.dict(os.environ)
        self.environment.start(); self.addCleanup(self.environment.stop)
        os.environ.pop('SN_SDK',None)

    def layout(self, folder, backend):
        (folder/'sn.cfg').parent.mkdir(parents=True,exist_ok=True)
        (folder/'sn.cfg').write_text('compiler config')
        archive = folder/'lib'/backend/'libsn_runtime_min.a'
        archive.parent.mkdir(parents=True); archive.write_bytes(b'archive')
        header = folder/'include/runtime/sn_array.h'
        header.parent.mkdir(parents=True); header.write_text('header')
        return archive,header.parent

    def test_windows_installed_binary_copy_uses_resource_root(self):
        resources = self.root/'lib/sindarin'
        wanted = self.layout(resources,'clang')
        # The exact v0.0.83 release contains only sn.windows.cfg, not sn.cfg.
        (resources/'sn.cfg').rename(resources/'sn.windows.cfg')
        compiler = self.root/'bin/sn.exe'
        compiler.parent.mkdir(); compiler.write_bytes(b'copied executable')
        self.assertEqual(module.runtime_paths(compiler,windows=True),wanted)

    def test_portable_build_layout_keeps_colocated_runtime(self):
        compiler = self.root/'bin/sn'
        wanted = self.layout(compiler.parent,'gcc')
        compiler.write_bytes(b'executable')
        self.assertEqual(module.runtime_paths(compiler,windows=False),wanted)

    def test_explicit_sdk_override_and_incomplete_installation(self):
        folder = self.root/'resources'
        wanted = self.layout(folder,'gcc')
        os.environ['SN_SDK'] = str(folder)
        self.assertEqual(module.runtime_paths(self.root/'bin/sn',windows=False),wanted)
        wanted[0].unlink()
        with self.assertRaisesRegex(ValueError,'installation is incomplete'):
            module.runtime_paths(self.root/'bin/sn',windows=False)


if __name__ == '__main__': unittest.main()
