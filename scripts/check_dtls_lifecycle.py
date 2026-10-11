#!/usr/bin/env python3
"""Verify real DTLS listener teardown and unchanged source/oracles with both streams retained."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def checked(command, cwd):
    result = subprocess.run([str(v) for v in command], cwd=cwd, capture_output=True, timeout=180)
    if result.returncode:
        raise ValueError(f'{command!r}\nstdout: {result.stdout!r}\nstderr: {result.stderr!r}')
    return result


def verify(compiler, sanitize=False, targets=('c', 'rust')):
    compiler = Path(compiler).resolve()
    cc = shlex.split(os.environ.get('SN_CC') or ('clang' if os.name == 'nt' or platform.system() == 'Darwin' else 'gcc'))
    flags = ['-std=c11', '-D_GNU_SOURCE', '-UNDEBUG'] + shlex.split(os.environ.get('SN_CFLAGS', ''))
    flags += ['-I', compiler.parent/'include/runtime', '-I', compiler.parent/'deps/include']
    links = ['-L', compiler.parent/'deps/lib', '-lssl', '-lcrypto', '-pthread']
    if os.name == 'nt':
        links += ['-lws2_32', '-lcrypt32']
    elif platform.system() == 'Darwin':
        links += ['-framework', 'Security', '-framework', 'CoreFoundation']
    else:
        links += ['-ldl', '-lm']
    source = ROOT/'tests/net/test_dtls.sn'
    oracle = source.with_suffix('.expected')
    report = {'passed': False, 'compiler_sha256': hashlib.sha256(compiler.read_bytes()).hexdigest(),
        'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'oracle_sha256': hashlib.sha256(oracle.read_bytes()).hexdigest(), 'cases': []}
    output = ROOT/'.sn'/('dtls-lifecycle-sanitizers.json' if sanitize else 'dtls-lifecycle.json')
    output.parent.mkdir(exist_ok=True)
    def save():
        output.write_text(json.dumps(report, indent=2)+'\n')
    with tempfile.TemporaryDirectory(prefix='sn-dtls-lifecycle-') as folder:
        work = Path(folder)
        executable = work/'registry.exe'
        runtime = compiler.parent/'lib'/('clang' if os.name == 'nt' else 'gcc')/'libsn_runtime_min.a'
        runtime_inputs = [runtime]
        if sanitize:
            flags += ['-g', '-O0', '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            runtime_inputs = [compiler.parent.parent/'src/runtime'/name for name in ('sn_abi.c','sn_array.c','sn_string.c','sn_byte.c')]
        checked(cc + flags + [ROOT/'tests/native/dtls_listener_registry.c'] + runtime_inputs + links + ['-o', executable], ROOT)
        run = subprocess.run([str(executable)], cwd=ROOT, capture_output=True, timeout=180,
            env=dict(os.environ, **({'ASAN_OPTIONS':'detect_leaks=1:halt_on_error=1','UBSAN_OPTIONS':'halt_on_error=1'} if sanitize else {})))
        report['cases'].append({'case':'40 real listener bind/close/double-close registry cycles',
            'exit':run.returncode, 'stdout_hex':run.stdout.hex(), 'stderr_hex':run.stderr.hex()})
        save()
        if run.returncode or run.stdout or run.stderr:
            raise ValueError(f'listener registry lifecycle: {run.returncode} {run.stdout!r} {run.stderr!r}')
        if not sanitize:
            shutil.copytree(ROOT/'src', work/'.sn/sindarin-pkg-sdk/src')
            shutil.copyfile(ROOT/'sn.yaml', work/'.sn/sindarin-pkg-sdk/sn.yaml')
            shutil.copytree(ROOT/'tests/net', work/'tests/net')
            shutil.copyfile(source, work/'main.sn')
            expected = oracle.read_bytes().replace(b'\r\n', b'\n')
            if os.name == 'nt':
                expected = expected.replace(b'\n', b'\r\n')
            for target in targets:
                for opt in ('-O0', '-O1', '-O2'):
                    for mode in ('default', 'checked', 'unchecked'):
                        executable = work/'dtls.exe'
                        command = [compiler, 'main.sn', '--no-install', '--target', target, opt, '-o', executable]
                        if mode != 'default':
                            command.append('--'+mode)
                        checked(command, work)
                        run = subprocess.run([str(executable)], cwd=work, capture_output=True, timeout=60)
                        report['cases'].append({'case':'unchanged DTLS caller','target':target,'opt':opt,'mode':mode,
                            'exit':run.returncode,'stdout_hex':run.stdout.hex(),'stderr_hex':run.stderr.hex()})
                        save()
                        if run.returncode or run.stdout != expected or run.stderr:
                            raise ValueError(f'{target}/{opt}/{mode}: {run.returncode} stdout={run.stdout!r} stderr={run.stderr!r}')
    report['passed'] = True
    save()
    print(f'PASS: {len(report["cases"])} DTLS lifecycle cases')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--targets', nargs='+', choices=('c','rust'), default=['c','rust'])
    args = parser.parse_args()
    verify(args.compiler, args.sanitize, tuple(args.targets))
