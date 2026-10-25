#!/usr/bin/env python3
"""Check reusable canonical TLS module and unchanged legacy SDK callers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading

ROOT=Path(__file__).resolve().parents[1]


def checked(command,cwd,env=None):
    run=subprocess.run([str(a) for a in command],cwd=cwd,env=env,capture_output=True,timeout=180)
    if run.returncode:raise ValueError(f'{command!r}\nstdout: {run.stdout!r}\nstderr: {run.stderr!r}')
    return run



def layout_probe(include, stream, listener):
    expressions=[]
    for record,fields in ((stream,('__rc__','socket_fd','ssl_ptr','remote_addr')),
                          (listener,('__rc__','socket_fd','bound_port'))):
        expressions += ['sizeof('+record+')','_Alignof('+record+')']
        for field in fields:
            expressions += ['offsetof('+record+','+field+')','sizeof((('+record+' *)0)->'+field+')']
    return '#include <stddef.h>\n#include <stdio.h>\n#include "'+include+'"\nint main(void) { printf("'+(' '.join(['%zu']*len(expressions)))+'\\n",'+','.join(expressions)+'); return 0; }\n'


def error_checks(cc,flags,libraries,runtime,archives,legacy,work,generator,certificate,key):
    """Compare fatal error contracts with original generated C, including trust."""
    other=work/'other-certificate.pem';other_key=work/'other-key.pem'
    checked([generator,other,other_key],work)
    clients={}
    for kind in ('legacy','canonical'):
        output=work/(kind+'-errors.exe')
        backing=['-DTLS_LEGACY_HEADER="'+legacy.as_posix()+'"'] if kind=='legacy' else archives
        checked(cc+flags+[ROOT/'tests/native/tls_errors.c']+backing+[runtime]+libraries+['-o',output],work)
        clients[kind]=output
    contracts=[('null-connect',b'TlsStream.connect: NULL address'),
        ('invalid-connect',b'TlsStream.connect: invalid address format'),
        ('null-bind',b'TlsListener.bind: NULL argument'),
        ('invalid-bind',b'TlsListener.bind: invalid address format'),
        ('missing-certificate',b'TlsListener.bind: failed to load certificate'),
        ('missing-key',b'TlsListener.bind: failed to load private key')]
    results=[]
    for name,prefix in contracts:
        pair={}
        for kind,executable in clients.items():
            command=[str(executable),name]+([str(certificate)] if name=='missing-key' else [])
            run=subprocess.run(command,cwd=work,capture_output=True,timeout=20)
            assert (run.returncode,run.stdout)==(1,b'') and run.stderr.startswith(prefix),(name,kind,run)
            pair[kind]={'exit':run.returncode,'stderr_hex':run.stderr.hex()}
        results.append({'contract':name,'results':pair,'passed':True})
    for name in ('untrusted-certificate','hostname-mismatch'):
        pair={}
        for kind,executable in clients.items():
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(certificate,key)
            server=socket.socket();server.bind(('127.0.0.1',0));server.listen(1);server.settimeout(15)
            failures=[]
            def handshake():
                try:
                    connection,_=server.accept()
                    with connection:
                        connection.settimeout(15)
                        try:
                            with context.wrap_socket(connection,server_side=True):
                                failures.append('Client unexpectedly accepted the certificate')
                        except ssl.SSLError:
                            pass
                except Exception as error:
                    failures.append(repr(error))
            thread=threading.Thread(target=handshake,daemon=True);thread.start()
            host='localhost' if name=='untrusted-certificate' else '127.0.0.1'
            environment=dict(os.environ,SN_CERTS=str(other if name=='untrusted-certificate' else certificate))
            try:
                run=subprocess.run([str(executable),'connect',f'{host}:{server.getsockname()[1]}'],cwd=work,env=environment,capture_output=True,timeout=20)
                thread.join(20)
                assert not thread.is_alive() and not failures,failures
                assert (run.returncode,run.stdout)==(1,b'') and run.stderr.startswith(b'TlsStream.connect: TLS handshake failed'),(name,kind,run)
                pair[kind]={'exit':run.returncode,'stderr_hex':run.stderr.hex()}
            finally:
                server.close()
        results.append({'contract':name,'results':pair,'passed':True})
    return results


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
    cases=[];legacy_layout=None;errors=[]
    with tempfile.TemporaryDirectory(prefix='sn-sdk-tls-') as folder:
        work=Path(folder);flags=['-std=c11','-D_GNU_SOURCE','-UNDEBUG','-Werror=implicit-function-declaration','-I',ROOT/'src/net','-I',include]
        flags+=shlex.split(os.environ.get('SN_CFLAGS',''))
        flags+=['-I',compiler.parent/'deps/include']
        libraries=['-L',compiler.parent/'deps/lib','-lssl','-lcrypto','-pthread','-lm']
        if os.name=='nt':libraries+=['-lbcrypt','-lws2_32','-lcrypt32']
        if platform.system()=='Darwin':libraries+=['-framework','Security','-framework','CoreFoundation']
        elif os.name!='nt':libraries+=['-ldl']
        certificate=work/'certificate.pem';key=work/'key.pem'
        generator=work/'certificate.exe'
        checked(cc+flags+[ROOT/'tests/native/tls_certificate.c']+libraries+['-o',generator],work)
        checked([generator,certificate,key],work)
        client_env=dict(os.environ,SN_CERTS=str(certificate))
        modules=[ROOT/'src/net'/name for name in ('tls.native.c',)]
        executable=work/'c-client.exe'
        if args.sanitize:
            root=compiler.parent.parent/'src/runtime'
            runtime_sources=[root/name for name in ('sn_abi.c','sn_array.c','sn_string.c','sn_byte.c')]
            checked(cc+flags+['-g','-O0','-fsanitize=address,undefined','-fno-omit-frame-pointer',ROOT/'tests/native/tls.c']+modules+runtime_sources+libraries+['-o',executable],work)
            run=checked([executable,certificate,key],work,dict(client_env,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
            assert run.stdout.splitlines()==[b'SDK canonical TLS: pass'] and not run.stderr
            cases.append({'kind':'C modules and actual runtime address/undefined/leak','passed':True})
        else:
            archives=[]
            for module in modules:
                obj=work/(module.stem+'.o');archive=work/('lib'+module.stem+'.a')
                checked(cc+flags+['-c',module,'-o',obj],work);checked(ar+['rcs',archive,obj],work);archives.append(archive)
            checked(cc+flags+[ROOT/'tests/native/tls.c']+archives+[runtime]+libraries+['-o',executable],work)
            run=checked([executable,certificate,key],work,client_env);assert run.stdout.splitlines()==[b'SDK canonical TLS: pass'] and not run.stderr
            cases.append({'kind':'C independent archives','passed':True})
            rustc=shlex.split(os.environ.get('SN_RUSTC','rustc'))
            links=[arg for archive in archives for arg in ('-C','link-arg='+str(archive))]
            links+=['-C','link-arg='+str(runtime)]
            links += [arg for library in libraries for arg in ('-C','link-arg='+str(library))]
            checked(rustc+['--edition=2021','-C','default-linker-libraries=yes',ROOT/'tests/native/tls.rs','-o',work/'rust-client.exe']+links+shlex.split(os.environ.get('SN_RUSTFLAGS','')),work)
            run=checked([work/'rust-client.exe',certificate,key],work,client_env);assert run.stdout.splitlines()==[b'SDK canonical TLS Rust: pass'] and not run.stderr
            cases.append({'kind':'Rust independent C archives','passed':True})
            # Compare independently generated original Sindarin storage with
            # the canonical header, including alignment and every field width.
            legacy=work/'legacy-layout.c'
            checked([compiler,ROOT/'src/net/tls.sn','--no-install','--package-body','--target','c','--emit-c','-o',legacy],work)
            layouts={};probe_sources={}
            for kind,header,stream,listener in (
                ('legacy',legacy.as_posix(),'__sn__TlsStream','__sn__TlsListener'),
                ('canonical','tls.native.h','SnSdkTlsStreamRecord','SnSdkTlsListenerRecord')):
                probe=work/(kind+'-probe.c');code=layout_probe(header,stream,listener);probe.write_text(code);probe_sources[kind]=code
                output=work/(kind+'-probe.exe')
                checked(cc+flags+[probe,runtime]+libraries+['-o',output],work)
                result=checked([output],work);assert not result.stderr
                layouts[kind]=[int(value) for value in result.stdout.split()]
                assert len(layouts[kind])==18
            assert layouts['legacy']==layouts['canonical'],layouts
            legacy_layout={'values':layouts,'probe_sources':probe_sources,'generated_legacy_C':legacy.read_text(),
                'source_sha256':hashlib.sha256((ROOT/'src/net/tls.sn').read_bytes()).hexdigest()}
            cases.append({'kind':'Original Sindarin C layout versus canonical storage, alignment and all field widths/offsets','passed':True})
            errors=error_checks(cc,flags,libraries,runtime,archives,legacy,work,generator,certificate,key)
            package=work/'.sn/sindarin-pkg-sdk'
            shutil.copytree(ROOT/'src',package/'src');shutil.copyfile(ROOT/'sn.yaml',package/'sn.yaml')
            (work/'tests/net').mkdir(parents=True)
            modes=[('-O0','default')] if args.quick else [(o,m) for o in ('-O0','-O1','-O2') for m in ('default','checked','unchecked')]
            for stem in ('tls',):
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
    paths += [ROOT/'tests/net'/name for name in ('test_tls.sn','test_tls.expected')]
    report={'passed':True,'cases':cases,'complete_sdk_package':False,
        'compiler_sha256':hashlib.sha256(compiler.read_bytes()).hexdigest(),
        'platform':platform.system(),
        'legacy_layout':legacy_layout,'fatal_error_contracts':errors,
        'client_sha256':{name:hashlib.sha256((ROOT/'tests/native'/name).read_bytes()).hexdigest() for name in (('tls.c','tls_certificate.c') if args.sanitize else ('tls.c','tls.rs','tls_certificate.c','tls_errors.c'))},
        'runtime_archive_sha256':hashlib.sha256(runtime.read_bytes()).hexdigest(),
        'runtime_header_sha256':{str(p.relative_to(include)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(include.rglob('*.h'))},
        'runtime_source_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in runtime_sources} if args.sanitize else {},
        'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'environment':{n:os.environ.get(n) for n in ('SN_CC','SN_CFLAGS','SN_RUSTFLAGS','ASAN_OPTIONS','UBSAN_OPTIONS')},
        'sources':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
        'credentials':'Ephemeral localhost-only self-signed certificate generated with linked OpenSSL; only native loopback clients use its SN_CERTS. Original external SDK caller retains system trust.',
        'scope':'Canonical C TLS storage and unchanged legacy callers; hosted compiler artifact adapters and broader SDK migration remain required'}
    (ROOT/'.sn').mkdir(exist_ok=True);(ROOT/'.sn'/('tls-sanitizers.json' if args.sanitize else 'tls-native.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: {len(cases)} TLS native and legacy caller cases; {len(errors)} separate fatal error contracts')


if __name__=='__main__':main()
