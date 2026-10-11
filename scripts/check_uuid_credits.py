#!/usr/bin/env python3
"""Check SDK UUID namespace ownership and unchanged original callers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROBE = 'long long inspect_uuid_credit(__sn__UUID *value) { return value ? value->__rc__ : -1; }\n'
CONTROL = ('import "sindarin-pkg-sdk/src/core/uuid"\n@source "credits.c"\n'
    '@alias "inspect_uuid_credit"\nnative fn credit(value: UUID): int\n'
    'fn aliasCredit(value: UUID): int =>\n  var alias: UUID = value\n  return credit(alias)\n'
    'fn main(): void =>\n  var dns: UUID = UUID.namespaceDns()\n  println(credit(dns))\n'
    '  var url: UUID = UUID.namespaceUrl()\n  println(credit(url))\n'
    '  var oid: UUID = UUID.namespaceOid()\n  println(credit(oid))\n'
    '  var x500: UUID = UUID.namespaceX500()\n  println(credit(x500))\n'
    '  println(aliasCredit(dns))\n  println(credit(dns))\n'
    '  println(dns.toString()=="6ba7b810-9dad-11d1-80b4-00c04fd430c8")\n')


def checked(command, cwd):
    run = subprocess.run([str(value) for value in command], cwd=cwd, capture_output=True, timeout=180)
    if run.returncode:
        raise ValueError(f'{command!r}\nstdout: {run.stdout!r}\nstderr: {run.stderr!r}')
    return run


def verify(compiler):
    compiler = Path(compiler).resolve()
    cases = []
    source = ROOT / 'tests/core/test_uuid.sn'
    oracle = source.with_suffix('.expected')
    with tempfile.TemporaryDirectory(prefix='sn-sdk-uuid-credits-') as folder:
        app = Path(folder)
        package = app / '.sn/sindarin-pkg-sdk'
        shutil.copytree(ROOT / 'src', package / 'src')
        shutil.copyfile(ROOT / 'sn.yaml', package / 'sn.yaml')
        (app / 'credits.c').write_text(PROBE, encoding='utf-8')
        for name, program, expected in (
                ('namespace credits and alias lifetime', CONTROL.encode(), b'1\n1\n1\n1\n2\n1\ntrue\n'),
                ('original UUID caller', source.read_bytes(), oracle.read_bytes().replace(b'\r\n', b'\n'))):
            (app / 'main.sn').write_bytes(program)
            if os.name == 'nt':
                expected = expected.replace(b'\n', b'\r\n')
            for target in ('c', 'rust'):
                for opt in ('-O0', '-O1', '-O2'):
                    for mode in ('default', 'checked', 'unchecked'):
                        exe = app / 'client.exe'
                        command = [compiler, 'main.sn', '--no-install', '--target', target, opt, '-o', exe]
                        if mode != 'default':
                            command.append('--' + mode)
                        checked(command, app)
                        run = checked([exe], app)
                        if run.stdout != expected or run.stderr:
                            raise ValueError(f'{name}/{target}/{opt}/{mode}: {run.stdout!r} {run.stderr!r}')
                        cases.append({'case': name, 'target': target, 'opt': opt, 'mode': mode, 'passed': True})
    report = {'passed': True, 'cases': cases, 'compiler_sha256': hashlib.sha256(compiler.read_bytes()).hexdigest(),
              'original_source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
              'original_oracle_sha256': hashlib.sha256(oracle.read_bytes()).hexdigest()}
    (ROOT / '.sn').mkdir(exist_ok=True)
    suffix = '-sanitized' if 'sanitize' in os.environ.get('SN_CFLAGS', '') else ''
    (ROOT / '.sn' / ('uuid-credit-validation' + suffix + '.json')).write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {len(cases)} UUID ownership and original caller cases')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    args = parser.parse_args()
    verify(args.compiler)
