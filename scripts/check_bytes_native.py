#!/usr/bin/env python3
"""Verify the original C Bytes decoder as a standalone canonical SDK module."""
import argparse
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def runtime_paths(compiler, windows=None):
    """Use the compiler's portable/install lookup; Windows bin/sn is a copy."""
    windows = os.name == 'nt' if windows is None else windows
    folder = Path(compiler).resolve().parent
    override = os.environ.get('SN_SDK')
    roots = [Path(override).resolve()] if override and Path(override).is_dir() else [folder,folder.parent/'lib/sindarin']
    for root in roots:
        runtime = root/'lib'/('clang' if windows else 'gcc')/'libsn_runtime_min.a'
        includes = root/'include/runtime'
        if runtime.is_file() and (includes/'sn_array.h').is_file():
            return runtime, includes
    raise ValueError('compiler runtime/header installation is incomplete; searched: '+', '.join(str(root) for root in roots))


def verify(compiler, sanitize=False, runtime_source=None, module='bytes'):
    labels = {'bytes': 'Bytes', 'binaryfile': 'BinaryFile'}
    label = labels[module]
    candidate = Path(compiler)
    compiler = (candidate if candidate.is_file() else Path(shutil.which(str(compiler)) or compiler)).resolve()
    runtime, includes = runtime_paths(compiler)
    cc = shlex.split(os.environ.get('SN_CC') or ('clang' if os.name == 'nt' or platform.system() == 'Darwin' else 'gcc'))
    with tempfile.TemporaryDirectory(prefix=f'sn-sdk-{module}-') as folder:
        work = Path(folder); executable = work/(module+'-client.exe')
        flags = ['-std=c11','-D_GNU_SOURCE','-UNDEBUG','-Wall','-Wextra','-Werror','-I',includes,'-I',ROOT/'src/io']
        sources = [ROOT/'tests/native'/(module+'_module.c'), ROOT/'src/io'/(module+'.native.c')]
        if sanitize:
            source = Path(runtime_source or compiler.parent.parent/'src/runtime').resolve()
            sources += [source/name for name in ('sn_abi.c','sn_array.c','sn_string.c','sn_byte.c')]
            flags += ['-g','-O0','-fsanitize=address,undefined','-fno-omit-frame-pointer']
        else:
            sources += [runtime]
        built = subprocess.run([str(v) for v in cc+flags+sources+['-pthread','-o',executable]],capture_output=True,timeout=180)
        if built.returncode: raise ValueError(built.stderr.decode(errors='replace'))
        run = subprocess.run([str(executable)],cwd=work,capture_output=True,timeout=15)
        if run.returncode or run.stdout.splitlines() != [f'SDK native {label}: pass'.encode()] or run.stderr:
            raise ValueError(f'{label} module mismatch: {run.returncode} {run.stdout!r} {run.stderr!r}')
        if module == 'binaryfile' and not sanitize:
            run = subprocess.run([str(executable),'nil-path'],cwd=work,capture_output=True,timeout=15)
            if run.returncode != 1 or run.stdout or run.stderr != b'SnBinaryFile.open: path is NULL\n':
                raise ValueError(f'BinaryFile error mismatch: {run.returncode} {run.stdout!r} {run.stderr!r}')
    return {'kind':('sanitized' if sanitize else 'independent')+f' C {label} module','passed':True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--runtime-source', type=Path)
    parser.add_argument('--module', choices=('bytes','binaryfile'), default='bytes')
    args = parser.parse_args()
    verify(args.compiler,args.sanitize,args.runtime_source,args.module)
    print('PASS: independent canonical C SDK '+{'bytes':'Bytes','binaryfile':'BinaryFile'}[args.module]+' module')
