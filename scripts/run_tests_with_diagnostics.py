#!/usr/bin/env python3
"""Retain the failed SDK fixture's streams without changing primary acceptance."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True)
    parser.add_argument('--runner', type=Path, required=True)
    args = parser.parse_args()
    original = subprocess.run([str(args.runner.resolve()), '--verbose'], capture_output=True)
    stdout, stderr = original.stdout or b'', original.stderr or b''
    sys.stdout.buffer.write(stdout)
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(stderr)
    sys.stderr.buffer.flush()
    if original.returncode == 0:
        return 0
    compiler = Path(shutil.which(args.compiler) or args.compiler).resolve()
    root = Path(__file__).resolve().parents[1]
    plain = re.sub(rb'\x1b\[[0-9;]*m', b'', stdout)
    failed = set(name.decode() for name in re.findall(rb'^\s*(test_[A-Za-z0-9_]+)\s+FAIL\b', plain, re.M))
    sources = sorted(path for path in (root/'tests').rglob('*.sn') if path.stem in failed)
    if not sources:
        sources = [root/'tests/net/test_dtls.sn']
    for source in sources:
        label = source.stem.removeprefix('test_')
        output = root/'.sn'/(label+'-failure-diagnostics')
        output.mkdir(parents=True, exist_ok=True)
        exe = output/(label+'.exe' if sys.platform == 'win32' else label)
        report = {'primary_runner_status': original.returncode,
            'source': str(source.relative_to(root)),
            'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
            'diagnostic_rerun_is_not_acceptance': True}
        try:
            # Match the original runner's compile mode and preserve the exact
            # installed dependencies. Automatic installation can prune .sn's
            # diagnostics directory while the compiler is writing into it.
            command = [str(compiler), str(source), '--no-install', '-O0', '-l', '1', '-o', str(exe)]
            if sys.platform != 'win32':
                command.append('-g')
            report['compile_command'] = command
            build = subprocess.run(command, cwd=root, capture_output=True, timeout=180)
            output.mkdir(parents=True, exist_ok=True)
            (output/'build.stdout').write_bytes(build.stdout)
            (output/'build.stderr').write_bytes(build.stderr)
            report['build_status'] = build.returncode
            if build.returncode == 0:
                run = subprocess.run([str(exe)], cwd=root, capture_output=True, timeout=60)
                (output/'run.stdout').write_bytes(run.stdout)
                (output/'run.stderr').write_bytes(run.stderr)
                report['run_status'] = run.returncode
                print(f'{label.upper()} diagnostic exit: {run.returncode}', flush=True)
                sys.stdout.buffer.write(run.stdout)
                sys.stderr.buffer.write(run.stderr)
            else:
                sys.stderr.buffer.write(build.stderr)
        except (OSError, subprocess.TimeoutExpired) as error:
            report['diagnostic_error'] = str(error)
            print(f'{label.upper()} diagnostic: {error}', file=sys.stderr)
        output.mkdir(parents=True, exist_ok=True)
        (output/'primary.stdout').write_bytes(stdout)
        (output/'primary.stderr').write_bytes(stderr)
        (output/'results.json').write_text(json.dumps(report, indent=2)+'\n')
    return original.returncode


if __name__ == '__main__':
    sys.exit(main())
