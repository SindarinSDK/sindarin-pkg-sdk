#!/usr/bin/env python3
"""Build one canonical SDK C module and verify independent and legacy consumers."""
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


def checked(command, cwd, env=None):
    result = subprocess.run([str(a) for a in command], cwd=cwd, env=env,
                            capture_output=True, timeout=180)
    if result.returncode:
        raise ValueError(f'command failed ({result.returncode}): {command!r}\n' + result.stderr.decode(errors='replace') + result.stdout.decode(errors='replace'))
    return result


def platform_text_oracle(data, windows):
    # Git may already have converted the checkout to CRLF. Convert the authored
    # text oracle to CRT output exactly once, retaining every other byte.
    return data.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n') if windows else data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--runtime-source', type=Path)
    args = parser.parse_args()
    compiler = args.compiler.resolve()
    if os.name == 'nt' and not compiler.is_file() and compiler.with_suffix('.exe').is_file():
        compiler = compiler.with_suffix('.exe')
    runtime = compiler.parent / 'lib' / ('clang' if os.name == 'nt' else 'gcc') / 'libsn_runtime_min.a'
    includes = compiler.parent / 'include/runtime'
    cc = shlex.split(os.environ.get('SN_CC') or ('clang' if os.name == 'nt' or platform.system() == 'Darwin' else 'gcc'))
    rustc = shlex.split(os.environ.get('SN_RUSTC', 'rustc'))
    rustflags = shlex.split(os.environ.get('SN_RUSTFLAGS', ''))
    report = {'sources': {}, 'cases': [], 'complete_sdk_package': False}
    for path in (ROOT/'src/io/textfile.sn', ROOT/'src/io/textfile.sn.c', ROOT/'src/io/textfile.native.c', ROOT/'src/io/textfile.native.h'):
        report['sources'][path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='sn-sdk-textfile-') as folder:
        work = Path(folder)
        if args.sanitize:
            executable = work / 'sanitizer'
            runtime_root = (args.runtime_source or compiler.parent.parent/'src/runtime').resolve()
            runtime_sources = [runtime_root/name for name in
                               ('sn_abi.c','sn_array.c','sn_string.c','sn_byte.c')]
            # Source instrumentation is required; an uninstrumented prebuilt
            # runtime does not prove field/payload lifetimes under sanitizers.
            if not all(p.is_file() for p in runtime_sources):
                raise ValueError('sanitizer mode requires compiler runtime sources (--runtime-source)')
            checked(cc + ['-std=c11','-D_GNU_SOURCE','-g','-O0','-fsanitize=address,undefined',
                           '-fno-omit-frame-pointer','-I',includes,'-I',ROOT/'src/io',
                           ROOT/'tests/native/textfile_resource.c',ROOT/'src/io/textfile.native.c'] +
                    runtime_sources + ['-pthread','-o',executable], work)
            run=checked([executable],work)
            assert run.stdout.splitlines()==[b'SDK native TextFile: pass'] and not run.stderr
            report['cases'].append({'kind':'sanitized C module/resources','passed':True})
        else:
            package=work/'package'
            shutil.copytree(ROOT/'src',package/'src')
            declarations='src/io/textfile.sn'
            (package/'sn.yaml').write_text('name: sdk-textfile-native\nruntime: C\nnative:\n  abi: 1.0\n'
                f'  declarations: [{declarations}]\n  builds:\n    - name: textfile\n      language: C\n'
                '      sources: [src/io/textfile.native.c]\n  bindings:\n'
                '    - declaration: src/io/textfile.sn::sn_text_file_open\n      build: textfile\n'
                '      symbol: sn_text_file_open\n      convention: C\n      failure: abort\n'
                '      ownership: {parameters: {path: borrowed}, result: owned}\n')
            built=checked([compiler,'--build-native',package/'sn.yaml','-o',work/'artifacts'],work)
            summary=json.loads(built.stdout)
            metadata=json.loads(Path(summary['assembly']).read_text())
            archive=Path(summary['assembly']).parent/metadata['units'][0]['archive']
            executable=work/'c-client.exe'
            checked(cc + ['-std=c11','-D_GNU_SOURCE','-I',includes,'-I',ROOT/'src/io',
                          ROOT/'tests/native/textfile_resource.c',archive,runtime,'-pthread','-o',executable],work)
            run=checked([executable],work)
            assert run.stdout.splitlines()==[b'SDK native TextFile: pass'] and not run.stderr
            report['cases'].append({'kind':'independent C client/resource/array/field layout','passed':True})
            failed=subprocess.run([str(executable),'--nil-open'],cwd=work,capture_output=True,timeout=20)
            expected_error=b'SnTextFile.open: path is NULL\r\n' if os.name=='nt' else b'SnTextFile.open: path is NULL\n'
            assert failed.returncode==1 and failed.stdout==b'' and failed.stderr==expected_error
            report['cases'].append({'kind':'original native nil-path error and exit','passed':True})
            executable=work/'rust-client.exe'
            checked(rustc+['--edition=2021',ROOT/'tests/native/textfile_resource.rs','-L',archive.parent,
                           '-l','static='+archive.stem.removeprefix('lib'),'-L',runtime.parent,
                           '-l','static=sn_runtime_min','-o',executable]+rustflags,work)
            run=checked([executable],work)
            assert run.stdout.splitlines()==[b'SDK native TextFile: pass'] and not run.stderr
            report['cases'].append({'kind':'independent Rust client/shared runtime path/lifetimes','passed':True})
            go_project=work/'go-client'
            shutil.copytree(ROOT/'tests/native/textfile_go',go_project)
            # Local headers are included in Go's package input tracking.
            shutil.copyfile(ROOT/'src/io/textfile.native.h',go_project/'textfile.native.h')
            env=os.environ.copy()
            env['CC']=shlex.join(cc)
            env['CGO_ENABLED']='1'
            env['GOTOOLCHAIN']='local'
            env['GOEXPERIMENT']='cgocheck2'
            env['CGO_CPPFLAGS']=shlex.join(['-D_GNU_SOURCE','-I'+str(includes)])
            env['CGO_LDFLAGS']=shlex.join([str(archive),str(runtime)])
            executable=work/'go-client.exe'
            checked(['go','build','-o',executable,'.'],go_project,env)
            run=checked([executable],work,env)
            assert run.stdout.splitlines()==[b'SDK native TextFile: pass'] and not run.stderr
            report['cases'].append({'kind':'independent Go client/shared runtime/GC-safe ownership','passed':True})
            project=work/'legacy'
            shutil.copytree(ROOT/'src',project/'.sn/sindarin-pkg-sdk/src')
            shutil.copyfile(ROOT/'sn.yaml',project/'.sn/sindarin-pkg-sdk/sn.yaml')
            source=project/'test_textfile.sn'
            shutil.copyfile(ROOT/'tests/io/test_textfile.sn',source)
            expected=(ROOT/'tests/io/test_textfile.expected').read_bytes()
            expected=platform_text_oracle(expected, os.name=='nt')
            for target in ('c','rust'):
                for opt in ('-O0','-O1','-O2'):
                    for mode in ('default','checked','unchecked'):
                        executable=project/'legacy.exe'
                        command=[compiler,'test_textfile.sn','--no-install','--target',target,opt,'-o',executable]
                        if mode!='default': command.append('--'+mode)
                        checked(command,project)
                        run=checked([executable],project)
                        assert run.stdout==expected,(target,opt,mode,run.stdout)
                        report['cases'].append({'kind':'unchanged SDK Sindarin fixture','target':target,'opt':opt,'mode':mode,'passed':True})
            fields=project/'textfile_fields.sn'
            shutil.copyfile(ROOT/'tests/native/textfile_fields.sn.raw',fields)
            field_expected=(ROOT/'tests/native/textfile_fields.expected').read_bytes()
            field_expected=platform_text_oracle(field_expected, os.name=='nt')
            for target in ('c','rust'):
                executable=project/'fields.exe'
                checked([compiler,'textfile_fields.sn','--no-install','--target',target,'-o',executable],project)
                run=checked([executable],project)
                assert run.stdout==field_expected,(target,run.stdout)
                report['cases'].append({'kind':'public fields, alias mutation and sizeof','target':target,'passed':True})
        report['passed']=all(c['passed'] for c in report['cases'])
        destination=ROOT/'.sn'/('textfile-native-sanitizers.json' if args.sanitize else 'textfile-native-validation.json')
        destination.parent.mkdir(exist_ok=True)
        destination.write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: {len(report["cases"])} canonical SDK TextFile checks')


if __name__=='__main__':
    main()
