"""Project exact immutable Git blobs for standalone component validation.

No application import, working-tree copy, source execution or authority issuance.
The receipt binds bytes to the requested commit/tree; it is not an attestation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

GIT = '/usr/bin/git'
MANIFEST = 'validation/rfc3161/candidate-files.json'
MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024


class ProjectionError(RuntimeError):
    pass


def _git(root: Path, *args: str) -> bytes:
    try:
        result=subprocess.run([GIT,*args],cwd=root,
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1',
                 'GIT_CONFIG_GLOBAL':os.devnull,'GIT_CONFIG_SYSTEM':os.devnull},
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            timeout=10,check=False)
        if result.returncode:raise ProjectionError('SOURCE_GIT_FAILED')
        return result.stdout
    except (OSError,subprocess.TimeoutExpired):
        raise ProjectionError('SOURCE_GIT_UNAVAILABLE') from None


def _blob(root: Path, sha: str) -> bytes:
    size=_git(root,'cat-file','-s',sha).strip()
    if not re.fullmatch(rb'[0-9]{1,9}',size) or int(size)>MAX_FILE:
        raise ProjectionError('SOURCE_FILE_TOO_LARGE')
    raw=_git(root,'cat-file','blob',sha)
    if len(raw)!=int(size) or hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=sha:
        raise ProjectionError('SOURCE_BLOB_MISMATCH')
    return raw


def _entries(root: Path, commit: str, paths: list[str]) -> dict:
    values={}
    for raw in _git(root,'ls-tree','-r','-z','--full-tree',commit,'--',*paths).split(b'\0'):
        if not raw:continue
        try:
            metadata,name=raw.split(b'\t',1);mode,kind,sha=metadata.split(b' ')
            path=name.decode('ascii');blob=sha.decode('ascii')
        except (ValueError,UnicodeError):raise ProjectionError('SOURCE_TREE_INVALID') from None
        if (path in values or mode not in {b'100644',b'100755'} or kind!=b'blob'
                or not re.fullmatch(r'[0-9a-f]{40}',blob)):
            raise ProjectionError('SOURCE_FILE_TYPE_INVALID')
        values[path]=blob
    if set(values)!=set(paths):raise ProjectionError('SOURCE_FILE_MISSING')
    return values


def _strict_pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ProjectionError('SOURCE_MANIFEST_INVALID')
        result[key]=value
    return result


def project(source: Path | str, destination: Path | str, *, commit: str, tree: str) -> dict:
    if any(type(x) is not str or not re.fullmatch(r'[0-9a-f]{40}',x) for x in (commit,tree)):
        raise ProjectionError('SOURCE_REFERENCE_INVALID')
    root=Path(source).absolute();target=Path(destination).absolute()
    if (not root.is_dir() or root.resolve(strict=True)!=root or
            _git(root,'rev-parse','--show-toplevel').decode().strip()!=str(root)):
        raise ProjectionError('SOURCE_ROOT_INVALID')
    if _git(root,'rev-parse','HEAD').decode().strip()!=commit or _git(root,'rev-parse','HEAD^{tree}').decode().strip()!=tree:
        raise ProjectionError('SOURCE_IDENTITY_MISMATCH')
    if (target.exists() or target.is_symlink() or target==root or root in target.parents
            or not target.parent.is_dir() or target.parent.resolve(strict=True)!=target.parent):
        raise ProjectionError('PROJECTION_DESTINATION_INVALID')
    manifest_blob=_entries(root,commit,[MANIFEST])[MANIFEST]
    try:
        manifest=json.loads(_blob(root,manifest_blob),object_pairs_hook=_strict_pairs)
    except ProjectionError:raise
    except Exception:raise ProjectionError('SOURCE_MANIFEST_INVALID') from None
    if (type(manifest) is not dict or set(manifest)!={'schema','files'}
            or manifest['schema']!='usbay.native_component_projection.v1'
            or type(manifest['files']) is not list or not 1<=len(manifest['files'])<=100):
        raise ProjectionError('SOURCE_MANIFEST_INVALID')
    paths=manifest['files']
    if any(type(x) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*',x)
           or any(part in {'.','..'} for part in x.split('/')) for x in paths):
        raise ProjectionError('SOURCE_PATH_INVALID')
    if len(set(paths))!=len(paths) or MANIFEST not in paths or 'component-projection-receipt.json' in paths:
        raise ProjectionError('SOURCE_MANIFEST_INVALID')
    entries=_entries(root,commit,paths);payloads={};total=0
    for name,blob in entries.items():
        payloads[name]=_blob(root,blob);total+=len(payloads[name])
        if total>MAX_TOTAL:raise ProjectionError('SOURCE_TOTAL_TOO_LARGE')
    target.mkdir(mode=0o700)
    for name,raw in payloads.items():
        file=target/name;file.parent.mkdir(parents=True,exist_ok=True)
        descriptor=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(descriptor,'wb') as stream:stream.write(raw)
    if _git(root,'rev-parse','HEAD').decode().strip()!=commit or _git(root,'rev-parse','HEAD^{tree}').decode().strip()!=tree:
        raise ProjectionError('SOURCE_CHANGED_DURING_PROJECTION')
    receipt={'schema':'usbay.native_component_projection_receipt.v1',
        'status':'PROJECTED_FOR_COMPONENT_TESTS','commit':commit,'tree':tree,
        'manifest_git_blob':manifest_blob,
        'files':{name:{'git_blob':entries[name],'sha256':hashlib.sha256(raw).hexdigest(),
                        'bytes':len(raw)} for name,raw in sorted(payloads.items())},
        'scope':'EXACT_SOURCE_BYTES_ONLY_NOT_AUTHORITY_OR_DEPLOYMENT'}
    (target/'component-projection-receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    return receipt


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source',required=True)
    parser.add_argument('--destination',required=True);parser.add_argument('--commit',required=True);parser.add_argument('--tree',required=True)
    parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    try:
        operation=verify_projection if args.verify else project
        result=operation(args.source,args.destination,commit=args.commit,tree=args.tree)
        print(json.dumps({'status':result['status'],'commit':result['commit'],'tree':result['tree'],'files':len(result['files'])}))
        return 0
    except ProjectionError as error:reason=str(error)
    except Exception:reason='PROJECTION_FAILED'
    print(json.dumps({'status':'FAIL','reason':reason}));return 1


def verify_projection(source, destination, *, commit, tree):
    target=Path(destination).absolute()
    if not target.is_dir() or target.resolve(strict=True)!=target:
        raise ProjectionError('PROJECTION_ROOT_INVALID')
    with tempfile.TemporaryDirectory(prefix='usbay-source-recheck-') as temporary:
        expected=project(source,Path(temporary)/'expected',commit=commit,tree=tree)
    for name,identity in expected['files'].items():
        file=target/name
        if file.parent.resolve(strict=True)!=file.parent:
            raise ProjectionError('PROJECTED_SOURCE_CHANGED')
        before=file.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>MAX_FILE:
            raise ProjectionError('PROJECTED_SOURCE_CHANGED')
        descriptor=os.open(file,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(descriptor,'rb') as stream:
            selected=os.fstat(stream.fileno());raw=stream.read(MAX_FILE+1);after=os.fstat(stream.fileno())
        named=file.lstat()
        stamp=lambda value:(value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
        if (stamp(before)!=stamp(selected) or stamp(before)!=stamp(after) or stamp(before)!=stamp(named)
                or len(raw)!=identity['bytes'] or hashlib.sha256(raw).hexdigest()!=identity['sha256']):
            raise ProjectionError('PROJECTED_SOURCE_CHANGED')
    expected['status']='PROJECTED_SOURCE_REVERIFIED'
    return expected


if __name__=='__main__':raise SystemExit(main())
