#!/usr/bin/env python3
"""Preserve the original package-test result and retain direct DTLS failure streams."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True)
    parser.add_argument('--runner', type=Path, required=True)
    args = parser.parse_args()
    original = subprocess.run([str(args.runner.resolve()), '--verbose'])
    if original.returncode == 0:
        return 0
    compiler = Path(shutil.which(args.compiler) or args.compiler).resolve()
    root = Path(__file__).resolve().parents[1]
    output = root/'.sn/dtls-failure-diagnostics'
    output.mkdir(parents=True, exist_ok=True)
    source = root/'tests/net/test_dtls.sn'
    exe = output/('dtls.exe' if sys.platform == 'win32' else 'dtls')
    report = {'primary_runner_status': original.returncode,
        'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'diagnostic_rerun_is_not_acceptance': True}
    try:
        build = subprocess.run([str(compiler), str(source), '-o', str(exe)], cwd=root,
            capture_output=True, timeout=180)
        (output/'build.stdout').write_bytes(build.stdout)
        (output/'build.stderr').write_bytes(build.stderr)
        report['build_status'] = build.returncode
        if build.returncode == 0:
            run = subprocess.run([str(exe)], cwd=root, capture_output=True, timeout=60)
            (output/'run.stdout').write_bytes(run.stdout)
            (output/'run.stderr').write_bytes(run.stderr)
            report['run_status'] = run.returncode
            print(f'DTLS diagnostic exit: {run.returncode}', flush=True)
            sys.stdout.buffer.write(run.stdout)
            sys.stderr.buffer.write(run.stderr)
        else:
            sys.stderr.buffer.write(build.stderr)
    except (OSError, subprocess.TimeoutExpired) as error:
        report['diagnostic_error'] = str(error)
        print(f'DTLS diagnostic: {error}', file=sys.stderr)
    (output/'results.json').write_text(json.dumps(report, indent=2)+'\n')
    return original.returncode


if __name__ == '__main__':
    sys.exit(main())
