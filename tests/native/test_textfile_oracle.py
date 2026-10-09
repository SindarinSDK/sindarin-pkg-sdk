import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('textfile_check', ROOT/'scripts/check_textfile_native.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class PlatformOracleTests(unittest.TestCase):
    def test_windows_checkout_and_crt_conversion_are_idempotent(self):
        authored = b'first\nsecond\n'
        checkout = b'first\r\nsecond\r\n'
        self.assertEqual(check.platform_text_oracle(authored, True), checkout)
        self.assertEqual(check.platform_text_oracle(checkout, True), checkout)

    def test_other_bytes_and_posix_oracle_are_preserved(self):
        data = b'\xff\r\nzero\x00\rbare\n'
        self.assertEqual(check.platform_text_oracle(data, False), data)
        self.assertEqual(check.platform_text_oracle(data, True), b'\xff\r\nzero\x00\rbare\r\n')


if __name__ == '__main__':
    unittest.main()
