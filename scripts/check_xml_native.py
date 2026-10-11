#!/usr/bin/env python3
"""Check reusable canonical Xml module and unchanged legacy SDK callers."""
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

ROOT=Path(__file__).resolve().parents[1]


def checked(command,cwd,env=None):
    run=subprocess.run([str(a) for a in command],cwd=cwd,env=env,capture_output=True,timeout=180)
    if run.returncode:raise ValueError(f'{command!r}\nstdout: {run.stdout!r}\nstderr: {run.stderr!r}')
    return run


def xml_library_path(compiler, system=None):
    system = system or platform.system()
    platform_dir = {'Linux': 'linux', 'Darwin': 'darwin', 'Windows': 'windows'}[system]
    root = compiler.parent.parent
    candidates = [compiler.parent/'deps/lib/libxml2.a',
                  root/'.sn/sindarin-pkg-libs/libs'/platform_dir/'lib/libxml2.a',
                  root/'libs/libs'/platform_dir/'lib/libxml2.a']
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise ValueError('xml2 archive missing from compiler dependency locations: ' + ', '.join(str(p) for p in candidates))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler',type=Path,required=True)
    parser.add_argument('--sanitize',action='store_true')
    parser.add_argument('--quick',action='store_true')
    args=parser.parse_args();compiler=args.compiler.resolve()
    if os.name=='nt' and not compiler.is_file():compiler=compiler.with_suffix('.exe')
    include=compiler.parent/'include/runtime'
    runtime=compiler.parent/'lib'/('clang' if os.name=='nt' else 'gcc')/'libsn_runtime_min.a'
    cc=shlex.split(os.environ.get('SN_CC') or ('clang' if os.name=='nt' or platform.system()=='Darwin' else 'gcc'))
    ar=shlex.split(os.environ.get('SN_AR') or ('llvm-ar' if shutil.which('llvm-ar') else 'ar'))
    cases=[]
    with tempfile.TemporaryDirectory(prefix='sn-sdk-xml-') as folder:
        work=Path(folder);flags=['-std=c11','-D_GNU_SOURCE','-UNDEBUG','-Werror=implicit-function-declaration','-I',ROOT/'src/encoding','-I',include]
        flags+=shlex.split(os.environ.get('SN_CFLAGS',''))
        deps=compiler.parent/'deps';flags+=['-I',deps/'include','-I',deps/'include/libxml2'];xml_library=xml_library_path(compiler)
        platform_dir={'Linux':'linux','Darwin':'darwin','Windows':'windows'}[platform.system()]
        zlib_dirs=[deps/'lib',compiler.parent.parent/'.sn/sindarin-pkg-libs/libs'/platform_dir/'lib']
        zlib=next((directory/name for directory in zlib_dirs for name in ('libz.a','libzlib.a','zlib.a','libzs.a') if (directory/name).is_file()),None)
        if zlib is None:raise ValueError('No supported compiler zlib archive')
        caller_env=dict(os.environ)
        # Original callers retain @link xml2; add the resolved archive's
        # directory to both C and Rust sidecar linker search paths.
        caller_env['SN_LDFLAGS']=(caller_env.get('SN_LDFLAGS','')+' -L"'+xml_library.parent.as_posix()+'"').strip()
        modules=[ROOT/'src/encoding'/name for name in ('xml.native.c',)]
        executable=work/'c-client.exe'
        if args.sanitize:
            root=compiler.parent.parent/'src/runtime'
            runtime_sources=[root/name for name in ('sn_abi.c','sn_array.c','sn_string.c','sn_byte.c')]
            checked(cc+flags+['-g','-O0','-fsanitize=address,undefined','-fno-omit-frame-pointer',ROOT/'tests/native/xml.c']+modules+runtime_sources+[xml_library,zlib,'-pthread','-lm']+(['-lbcrypt'] if os.name=='nt' else [])+['-o',executable],work)
            run=checked([executable],work,dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
            assert run.stdout.splitlines()==[b'SDK canonical Xml: pass'] and not run.stderr
            cases.append({'kind':'C modules and actual runtime address/undefined/leak','passed':True})
        else:
            archives=[]
            for module in modules:
                obj=work/(module.stem+'.o');archive=work/('lib'+module.stem+'.a')
                checked(cc+flags+['-c',module,'-o',obj],work);checked(ar+['rcs',archive,obj],work);archives.append(archive)
            checked(cc+flags+[ROOT/'tests/native/xml.c']+archives+[runtime,xml_library,zlib,'-pthread','-lm']+(['-lbcrypt'] if os.name=='nt' else [])+['-o',executable],work)
            run=checked([executable],work);assert run.stdout.splitlines()==[b'SDK canonical Xml: pass'] and not run.stderr
            cases.append({'kind':'C independent archives','passed':True})
            rustc=shlex.split(os.environ.get('SN_RUSTC','rustc'))
            links=[arg for archive in archives for arg in ('-C','link-arg='+str(archive))]
            links+=['-C','link-arg='+str(runtime),'-C','link-arg='+str(xml_library),'-C','link-arg='+str(zlib),'-C','link-arg=-lm']
            if os.name!='nt':links+=['-C','link-arg=-pthread']
            else:links+=['-C','link-arg=-pthread','-C','link-arg=-lbcrypt']
            checked(rustc+['--edition=2021','-C','default-linker-libraries=yes',ROOT/'tests/native/xml.rs','-o',work/'rust-client.exe']+links+shlex.split(os.environ.get('SN_RUSTFLAGS','')),work)
            run=checked([work/'rust-client.exe'],work);assert run.stdout.splitlines()==[b'SDK canonical Xml Rust: pass'] and not run.stderr
            cases.append({'kind':'Rust independent C archives','passed':True})
            shutil.copytree(ROOT/'src',work/'.sn/sindarin-pkg-sdk/src');shutil.copyfile(ROOT/'sn.yaml',work/'.sn/sindarin-pkg-sdk/sn.yaml')
            modes=[('-O0','default')] if args.quick else [(o,m) for o in ('-O0','-O1','-O2') for m in ('default','checked','unchecked')]
            for stem in ('xml',):
                source=ROOT/'tests/encoding'/('test_'+stem+'.sn');shutil.copyfile(source,work/'main.sn')
                expected=source.with_suffix('.expected').read_bytes().replace(b'\r\n',b'\n')
                if os.name=='nt':expected=expected.replace(b'\n',b'\r\n')
                for opt,mode in modes:
                    for target in ('c','rust'):
                        command=[compiler,'main.sn','--no-install','--target',target,opt,'-o',executable]
                        if mode!='default':command.append('--'+mode)
                        checked(command,work,caller_env);run=checked([executable],work)
                        if run.stdout!=expected or run.stderr:raise ValueError(f'{stem}/{target}/{opt}/{mode}: {run.stdout!r} {run.stderr!r}')
                        cases.append({'module':stem,'target':target,'opt':opt,'mode':mode,'passed':True})
    paths=[p for p in (ROOT/'src/encoding').glob('*') if p.is_file()]
    paths += [ROOT/'tests/encoding'/name for name in ('test_xml.sn','test_xml.expected')]
    report={'passed':True,'cases':cases,'complete_sdk_package':False,
        'compiler_sha256':hashlib.sha256(compiler.read_bytes()).hexdigest(),
        'platform':platform.system(),
        'sources':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
        'scope':'Canonical C Xml storage and unchanged legacy callers; hosted compiler artifact adapters and broader SDK migration remain required'}
    (ROOT/'.sn').mkdir(exist_ok=True);(ROOT/'.sn'/('xml-sanitizers.json' if args.sanitize else 'xml-native.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: {len(cases)} Xml native and legacy caller cases')


if __name__=='__main__':main()
