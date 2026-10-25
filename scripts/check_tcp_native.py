#!/usr/bin/env python3
"""Check reusable canonical TCP module and unchanged legacy SDK callers."""
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



def layout_probe(include, stream, listener):
    expressions=[]
    for record,fields in ((stream,('__rc__','socket_fd','remote_addr','internal')),
                          (listener,('__rc__','socket_fd','bound_port'))):
        expressions += ['sizeof('+record+')','_Alignof('+record+')']
        for field in fields:
            expressions += ['offsetof('+record+','+field+')','sizeof((('+record+' *)0)->'+field+')']
    return '#include <stddef.h>\n#include <stdio.h>\n#include "'+include+'"\nint main(void) { printf("'+(' '.join(['%zu']*len(expressions)))+'\\n",'+','.join(expressions)+'); return 0; }\n'


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
    cases=[];legacy_layout=None
    with tempfile.TemporaryDirectory(prefix='sn-sdk-tcp-') as folder:
        work=Path(folder);flags=['-std=c11','-D_GNU_SOURCE','-UNDEBUG','-Werror=implicit-function-declaration','-I',ROOT/'src/net','-I',include]
        flags+=shlex.split(os.environ.get('SN_CFLAGS',''))
        modules=[ROOT/'src/net'/name for name in ('tcp.native.c',)]
        executable=work/'c-client.exe'
        if args.sanitize:
            root=compiler.parent.parent/'src/runtime'
            runtime_sources=[root/name for name in ('sn_abi.c','sn_array.c','sn_string.c','sn_byte.c')]
            checked(cc+flags+['-g','-O0','-fsanitize=address,undefined','-fno-omit-frame-pointer',ROOT/'tests/native/tcp.c']+modules+runtime_sources+['-pthread','-lm']+(['-lbcrypt','-lws2_32'] if os.name=='nt' else [])+['-o',executable],work)
            run=checked([executable],work,dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
            assert run.stdout.splitlines()==[b'SDK canonical TCP: pass'] and not run.stderr
            cases.append({'kind':'C modules and actual runtime address/undefined/leak','passed':True})
        else:
            archives=[]
            for module in modules:
                obj=work/(module.stem+'.o');archive=work/('lib'+module.stem+'.a')
                checked(cc+flags+['-c',module,'-o',obj],work);checked(ar+['rcs',archive,obj],work);archives.append(archive)
            checked(cc+flags+[ROOT/'tests/native/tcp.c']+archives+[runtime,'-pthread','-lm']+(['-lbcrypt','-lws2_32'] if os.name=='nt' else [])+['-o',executable],work)
            run=checked([executable],work);assert run.stdout.splitlines()==[b'SDK canonical TCP: pass'] and not run.stderr
            cases.append({'kind':'C independent archives','passed':True})
            rustc=shlex.split(os.environ.get('SN_RUSTC','rustc'))
            links=[arg for archive in archives for arg in ('-C','link-arg='+str(archive))]
            links+=['-C','link-arg='+str(runtime),'-C','link-arg=-lm']
            if os.name=='nt':links+=['-C','link-arg=-lws2_32']
            if os.name!='nt':links+=['-C','link-arg=-pthread']
            else:links+=['-C','link-arg=-lbcrypt']
            checked(rustc+['--edition=2021','-C','default-linker-libraries=yes',ROOT/'tests/native/tcp.rs','-o',work/'rust-client.exe']+links+shlex.split(os.environ.get('SN_RUSTFLAGS','')),work)
            run=checked([work/'rust-client.exe'],work);assert run.stdout.splitlines()==[b'SDK canonical TCP Rust: pass'] and not run.stderr
            cases.append({'kind':'Rust independent C archives','passed':True})
            # Compare independently generated original Sindarin storage with
            # the canonical header, including alignment and every field width.
            legacy=work/'legacy-layout.c'
            checked([compiler,ROOT/'src/net/tcp.sn','--no-install','--package-body','--target','c','--emit-c','-o',legacy],work)
            layouts={};probe_sources={}
            for kind,header,stream,listener in (
                ('legacy',legacy.as_posix(),'__sn__TcpStream','__sn__TcpListener'),
                ('canonical','tcp.native.h','SnSdkTcpStreamRecord','SnSdkTcpListenerRecord')):
                probe=work/(kind+'-probe.c');code=layout_probe(header,stream,listener);probe.write_text(code);probe_sources[kind]=code
                output=work/(kind+'-probe.exe')
                checked(cc+flags+[probe,runtime,'-pthread','-lm']+(['-lbcrypt','-lws2_32'] if os.name=='nt' else [])+['-o',output],work)
                result=checked([output],work);assert not result.stderr
                layouts[kind]=[int(value) for value in result.stdout.split()]
                assert len(layouts[kind])==18
            assert layouts['legacy']==layouts['canonical'],layouts
            legacy_layout={'values':layouts,'probe_sources':probe_sources,'generated_legacy_C':legacy.read_text(),
                'source_sha256':hashlib.sha256((ROOT/'src/net/tcp.sn').read_bytes()).hexdigest()}
            cases.append({'kind':'Original Sindarin C layout versus canonical storage, alignment and all field widths/offsets','passed':True})
            shutil.copytree(ROOT/'src',work/'src');shutil.copyfile(ROOT/'sn.yaml',work/'sn.yaml')
            (work/'tests/net').mkdir(parents=True)
            modes=[('-O0','default')] if args.quick else [(o,m) for o in ('-O0','-O1','-O2') for m in ('default','checked','unchecked')]
            for stem in ('tcp',):
                source=ROOT/'tests/net'/('test_'+stem+'.sn');staged=work/'tests/net'/source.name;shutil.copyfile(source,staged)
                assert staged.read_bytes()==source.read_bytes()
                expected=source.with_suffix('.expected').read_bytes().replace(b'\r\n',b'\n')
                if os.name=='nt':expected=expected.replace(b'\n',b'\r\n')
                for opt,mode in modes:
                    for target in ('c','rust'):
                        command=[compiler,staged,'--no-install','--target',target,opt,'-o',executable]
                        if mode!='default':command.append('--'+mode)
                        checked(command,work);run=checked([executable],work)
                        if run.stdout!=expected or run.stderr:raise ValueError(f'{stem}/{target}/{opt}/{mode}: {run.stdout!r} {run.stderr!r}')
                        cases.append({'module':stem,'target':target,'opt':opt,'mode':mode,'passed':True})
    paths=[p for p in (ROOT/'src/net').glob('*') if p.is_file()]
    paths += [ROOT/'tests/net'/name for name in ('test_tcp.sn','test_tcp.expected')]
    report={'passed':True,'cases':cases,'complete_sdk_package':False,
        'compiler_sha256':hashlib.sha256(compiler.read_bytes()).hexdigest(),
        'platform':platform.system(),
        'legacy_layout':legacy_layout,
        'client_sha256':{name:hashlib.sha256((ROOT/'tests/native'/name).read_bytes()).hexdigest() for name in (('tcp.c',) if args.sanitize else ('tcp.c','tcp.rs'))},
        'runtime_archive_sha256':hashlib.sha256(runtime.read_bytes()).hexdigest(),
        'runtime_header_sha256':{str(p.relative_to(include)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(include.rglob('*.h'))},
        'runtime_source_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in runtime_sources} if args.sanitize else {},
        'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'environment':{n:os.environ.get(n) for n in ('SN_CC','SN_CFLAGS','SN_RUSTFLAGS','ASAN_OPTIONS','UBSAN_OPTIONS')},
        'sources':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
        'scope':'Canonical C TCP storage and unchanged legacy callers; hosted compiler artifact adapters and broader SDK migration remain required'}
    (ROOT/'.sn').mkdir(exist_ok=True);(ROOT/'.sn'/('tcp-sanitizers.json' if args.sanitize else 'tcp-native.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: {len(cases)} TCP native and legacy caller cases')


if __name__=='__main__':main()
