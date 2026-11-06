"""Native wrapper build/leak validation; missing checks are hard failures.

Receipts contain hashes and bounded status codes, never raw diagnostics or keys.
This component validation neither adopts trust nor qualifies deployment authority.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
LIMIT=1024*1024
LAUNCHER=(
    'import os,resource,sys;os.umask(0o077);'
    'resource.setrlimit(resource.RLIMIT_CORE,(0,0));'
    'resource.setrlimit(resource.RLIMIT_CPU,(5,5));'
    'resource.setrlimit(resource.RLIMIT_FSIZE,(1048576,1048576));'
    'resource.setrlimit(resource.RLIMIT_NOFILE,(64,64));'
    'os.execve(sys.argv[1],sys.argv[1:],dict(os.environ))'
)


def sha(value):return hashlib.sha256(value).hexdigest()


def run_case(binary, args, cwd, *, expected):
    # ASan requires a large virtual-address reservation, so the production
    # verifier's address-space limit is not used for this sanitizer-only job.
    env={'LC_ALL':'C','ASAN_OPTIONS':'detect_leaks=1:abort_on_error=1',
         'UBSAN_OPTIONS':'halt_on_error=1','OPENSSL_CONF':str(cwd/'openssl.cnf')}
    try:
        with tempfile.TemporaryFile() as diagnostic:
            completed=subprocess.run([sys.executable,'-I','-S','-c',LAUNCHER,str(binary),*map(str,args)],
                cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                stderr=diagnostic,timeout=10,check=False,close_fds=True)
            diagnostic.seek(0);data=diagnostic.read(LIMIT+1)
        unsupported=(b'LeakSanitizer has encountered a fatal error' in data
                     and b'ptrace' in data)
        passed=completed.returncode==expected and not data
        return {'status':'PASS' if passed else 'FAIL','exit_code':completed.returncode,
                'expected_exit_code':expected,'diagnostic_sha256':sha(data),
                'reason':'NATIVE_LEAK_ENVIRONMENT_UNSUPPORTED' if unsupported else
                         ('NATIVE_DIAGNOSTIC_LIMIT' if len(data)>LIMIT else
                          ('OK' if passed else 'NATIVE_SANITIZER_FAILED'))}
    except subprocess.TimeoutExpired:
        return {'status':'FAIL','reason':'NATIVE_SANITIZER_TIMEOUT'}
    except OSError:
        return {'status':'FAIL','reason':'NATIVE_SANITIZER_UNAVAILABLE'}


def validate(output: Path) -> dict:
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if output.exists() or output.is_symlink() or output.parent.resolve(strict=True)!=output.parent:
        raise ValueError('NATIVE_OUTPUT_EXISTS_OR_ALIASED')
    output.mkdir(mode=0o700)
    receipt={'schema':'usbay.native_memory_validation.v1','status':'FAIL',
             'scope':'LOCAL_C_WRAPPERS_WITH_LINKED_OPENSSL_NOT_REBUILT',
             'leak_detection_required':True,'production_authority_granted':False,
             'source_sha256':{},'binary_sha256':{},'cases':[]}
    try:
        for name,source in [('rfc3161_info','audit/rfc3161_info.c'),
                            ('make_memory_tsa_vectors','validation/rfc3161/tests/make_memory_tsa_vectors.c')]:
            receipt['source_sha256'][source]=sha((ROOT/source).read_bytes())
            command=['/usr/bin/cc','-std=c11','-Wall','-Wextra','-Werror','-O1','-g',
                     '-fsanitize=address,undefined','-fno-omit-frame-pointer',
                     str(ROOT/source),'-lcrypto','-o',str(output/name)]
            build=subprocess.run(command,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                timeout=30,check=False)
            if build.returncode:raise ValueError('NATIVE_SANITIZER_BUILD_FAILED')
            receipt['binary_sha256'][name]=sha((output/name).read_bytes())
        with tempfile.TemporaryDirectory(prefix='usbay-leak-check-') as temporary:
            folder=Path(temporary);(folder/'openssl.cnf').write_bytes(b'')
            generator=run_case(output/'make_memory_tsa_vectors',[],folder,expected=0)
            receipt['cases'].append({'name':'memory_only_test_key_lifecycle',**generator})
            if generator['status']!='PASS':raise ValueError(generator['reason'])
            # A second matching-chain input path covers the explicit imprint
            # branch, retaining only public artifacts inside another private dir.
            extra=folder/'explicit';extra.mkdir();(extra/'openssl.cnf').write_bytes(b'')
            case=run_case(output/'make_memory_tsa_vectors',['a'*64],extra,expected=0)
            receipt['cases'].append({'name':'explicit_imprint_test_key_lifecycle',**case})
            if case['status']!='PASS':raise ValueError(case['reason'])
            valid=(ROOT/'fixtures/sigstage/response-sha256.tsr').read_bytes()
            for index,raw in enumerate((valid,valid[:1],valid[:30],valid+b'canary',b'not-der')):
                incoming=folder/f'input-{index}';outgoing=folder/f'output-{index}'
                incoming.write_bytes(raw)
                case=run_case(output/'rfc3161_info',[incoming,outgoing],folder,expected=0 if index==0 else 1)
                receipt['cases'].append({'name':f'structured_timestamp_decode_{index}',**case})
                if case['status']!='PASS':raise ValueError(case['reason'])
        receipt['status']='PASS';receipt['reason']='ALL_REQUIRED_SANITIZERS_PASSED'
    except ValueError as error:receipt['reason']=str(error)
    except Exception:receipt['reason']='NATIVE_MEMORY_VALIDATION_FAILED'
    (output/'native-memory-validation.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    return receipt


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);args=parser.parse_args()
    try:
        receipt=validate(Path(args.output).absolute())
        print(json.dumps({'status':receipt['status'],'reason':receipt['reason'],'cases':len(receipt['cases'])}))
        return 0 if receipt['status']=='PASS' else 1
    except Exception:
        print(json.dumps({'status':'FAIL','reason':'NATIVE_MEMORY_SETUP_FAILED'}));return 1


if __name__=='__main__':raise SystemExit(main())
