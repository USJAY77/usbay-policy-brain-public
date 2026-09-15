#!/bin/zsh -f
# Save as: $HOME/usbay-age-preservation.zsh
# Review/test: /bin/chmod 700 "$HOME/usbay-age-preservation.zsh" && /bin/zsh -f "$HOME/usbay-age-preservation.zsh" --self-test
# Authorized run only: USBAY_RECOVERY_SETUP_AUTHORIZED=YES /bin/zsh -f "$HOME/usbay-age-preservation.zsh"
exec /usr/bin/python3 - "$@" <<'PY'
import copy, hashlib, json, os, plistlib, secrets, signal, stat, subprocess, sys, tempfile, time
from pathlib import Path

AGE_VERSION='1.3.2'; MIN_FREE=1<<30; WHOLE_MIN=490_000_000_000; WHOLE_MAX=500_000_000_000
VOL_NOM=494_110_000_000; VOL_TOL=.03; TIMEOUT=60; INSTALL_TIMEOUT=600; INTERACTIVE_TIMEOUT=300
EXPECTED=['RECOVERY-INSTRUCTIONS.txt','manifest.txt','usbay-preservation-identity.txt.age','usbay-preservation-recipient.txt']
BOTTLES={'arm64_sonoma':'48bbd797cd00ab11ec496717f51205ba07f4f7fdc7c8a939c5f4b7b6a11d5287','arm64_sequoia':'48bbd797cd00ab11ec496717f51205ba07f4f7fdc7c8a939c5f4b7b6a11d5287','arm64_tahoe':'48bbd797cd00ab11ec496717f51205ba07f4f7fdc7c8a939c5f4b7b6a11d5287','arm64_golden_gate':'ab6acf805fc7c3bd78da358bd3e4b3d4df3cabf6d070e5cc86745643012a4ee0'}
class Stop(RuntimeError): pass

def trace_event(trace,event,**details):
    if trace is not None:
        item={'event':event,**details}
        if event!='group-state' or not trace or trace[-1]!=item:trace.append(item)

def print_supervisor_diagnostic(name,actual,expected,events,**details):
    bounded_result=next((e for e in reversed(events) if e['event']=='bounded-result'),None)
    cleanup=next((e for e in reversed(events) if e['event']=='cleanup-result'),None)
    report={
        'test':name,
        'actual':actual,
        'expected':expected,
        'bounded_result_reason':None if bounded_result is None else bounded_result.get('reason'),
        'group_transitions':[{'phase':e['phase'],'state':e['state']} for e in events if e['event']=='group-state'],
        'signal_outcomes':[{'phase':e['phase'],'signal':e['signal'],'outcome':e['outcome']} for e in events if e['event']=='group-signal'],
        'cleanup_outcome':None if cleanup is None else cleanup.get('outcome'),
        'cleanup_reason':None if cleanup is None else cleanup.get('reason'),
        'direct_child_reaped':None if cleanup is None else cleanup.get('direct_child_reaped'),
        'direct_child_status':None if cleanup is None else cleanup.get('direct_child_status'),
        'events':events,
        **details,
    }
    print('SYNTHETIC_DIAGNOSTIC='+json.dumps(report,separators=(',',':'),sort_keys=True),flush=True)

def req(d,k,w,t=None):
    if k not in d: raise Stop(f'{w}: missing {k}')
    v=d[k]
    if t and (isinstance(v,bool) if t is int else not isinstance(v,t)): raise Stop(f'{w}: invalid {k}')
    return v

def no_symlink_components(path, allow_missing=True):
    p=Path(path).expanduser().absolute(); cur=Path(p.anchor)
    for part in p.parts[1:]:
        cur/=part
        try: st=cur.lstat()
        except FileNotFoundError:
            if allow_missing: continue
            raise Stop(f'missing path: {cur}')
        if stat.S_ISLNK(st.st_mode): raise Stop(f'symlink path component: {cur}')
    return p

def create_dir_exclusive(path,mode=0o700):
    p=no_symlink_components(path)
    os.mkdir(p,mode); return p

def write_exclusive(path,data,mode=0o600):
    p=no_symlink_components(path)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),mode)
    try:
        b=data.encode() if isinstance(data,str) else data
        n=os.write(fd,b)
        if n!=len(b): raise Stop(f'short write: {p}')
        os.fsync(fd)
    finally: os.close(fd)

def append_checked(path,line):
    if not line: raise Stop('empty evidence line')
    with open(path,'a',encoding='utf-8') as f:
        n=f.write(line+'\n'); f.flush(); os.fsync(f.fileno())
        if n!=len(line)+1: raise Stop('short evidence write')

def publish_staged_file(staged,destination,mode=0o600,interrupt_before_link=False):
    staged=no_symlink_components(staged,False); destination=no_symlink_components(destination)
    parent=no_symlink_components(destination.parent,False)
    if not parent.is_dir() or parent.is_symlink(): raise Stop('unsafe publication parent')
    if parent.stat().st_uid!=os.getuid(): raise Stop('publication parent not owner-controlled')
    if destination.exists() or destination.is_symlink(): raise Stop('publication destination exists or is symlink')
    if not staged.is_file() or staged.is_symlink(): raise Stop('unsafe staged file')
    if staged.stat().st_dev!=parent.stat().st_dev: raise Stop('staging and destination filesystems differ')
    os.chmod(staged,mode)
    with open(staged,'rb') as f: os.fsync(f.fileno())
    if interrupt_before_link: raise KeyboardInterrupt('synthetic publication interruption')
    try: os.link(staged,destination,follow_symlinks=False)
    except FileExistsError: raise Stop('publication destination appeared before link')
    os.chmod(destination,mode)
    fd=os.open(parent,os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)
    if destination.is_symlink() or not destination.is_file(): raise Stop('published path is not a regular file')
    if stat.S_IMODE(destination.stat().st_mode)!=mode: raise Stop('published mode mismatch')

def cleanup_private_staging(stage_dir,staged_file):
    # Called only with a unique staging directory created by this invocation.
    try:
        if staged_file.exists() and not staged_file.is_symlink(): staged_file.unlink()
    finally:
        if stage_dir.exists() and not stage_dir.is_symlink(): stage_dir.rmdir()

def sha256(path):
    p=no_symlink_components(path,False)
    if not p.is_file(): raise Stop(f'not a file: {p}')
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for block in iter(lambda:f.read(1<<20),b''): h.update(block)
    d=h.hexdigest()
    if len(d)!=64: raise Stop(f'hash failed: {p}')
    return d

def group_state(pgid,trace=None,phase='probe'):
    try: os.killpg(pgid,0); state='present'
    except ProcessLookupError: state='absent'
    except PermissionError: state='denied'
    trace_event(trace,'group-state',phase=phase,state=state)
    return state

def wait_group_clean(pgid,child,seconds,trace=None,phase='wait'):
    end=time.monotonic()+seconds
    while True:
        if child is not None: child.poll()
        state=group_state(pgid,trace,phase)
        if state=='absent' and (child is None or child.poll() is not None):
            trace_event(trace,'group-wait',phase=phase,outcome='clean')
            return 'clean'
        if state=='denied':
            trace_event(trace,'group-wait',phase=phase,outcome='denied')
            return 'denied'
        if time.monotonic()>=end:
            trace_event(trace,'group-wait',phase=phase,outcome='timeout')
            return 'timeout'
        time.sleep(min(.02,max(0,end-time.monotonic())))

def signal_group(pgid,sig,trace=None,phase='signal'):
    try: os.killpg(pgid,sig); outcome='sent'
    except ProcessLookupError: outcome='absent'
    except PermissionError: outcome='denied'
    trace_event(trace,'group-signal',phase=phase,signal=int(sig),outcome=outcome)
    return outcome

def terminate_group(pgid,child=None,term_wait=2,kill_wait=2,trace=None):
    def finish(ok,reason):
        child_status=None if child is None else child.poll()
        trace_event(trace,'cleanup-result',outcome='clean' if ok else 'unproven',reason=reason,direct_child_reaped=child is None or child_status is not None,direct_child_status=child_status)
        return ok
    first=signal_group(pgid,signal.SIGTERM,trace,'term')
    if first=='absent': return finish(child is None or reap_child(child,term_wait),'term-group-absent')
    denied=first=='denied'
    if first!='denied':
        phase=wait_group_clean(pgid,child,term_wait,trace,'term-wait')
        if phase=='clean': return finish(True,'term-clean')
        denied=phase=='denied'
    second=signal_group(pgid,signal.SIGKILL,trace,'kill')
    denied=denied or second=='denied'
    if second=='absent':
        direct_ok=child is None or reap_child(child,kill_wait)
        return finish(direct_ok and not denied,'kill-group-absent')
    if second=='denied':
        if child is not None: terminate_child(child,term_wait,kill_wait)
        return finish(False,'kill-denied')
    phase=wait_group_clean(pgid,child,kill_wait,trace,'kill-wait')
    denied=denied or phase=='denied'
    if phase!='clean' and child is not None: terminate_child(child,term_wait,kill_wait)
    return finish(phase=='clean' and not denied,'kill-'+phase)

def reap_child(p,seconds=2):
    if p.poll() is not None: return True
    try:p.wait(timeout=seconds);return True
    except subprocess.TimeoutExpired:pass
    try:p.kill()
    except ProcessLookupError:pass
    except PermissionError:return False
    try:p.wait(timeout=seconds);return True
    except subprocess.TimeoutExpired:return False

def terminate_child(p,term_wait=2,kill_wait=2):
    try:p.terminate()
    except ProcessLookupError:return reap_child(p,term_wait)
    except PermissionError:return False
    try:p.wait(timeout=term_wait);return True
    except subprocess.TimeoutExpired:pass
    try:p.kill()
    except ProcessLookupError:return reap_child(p,kill_wait)
    except PermissionError:return False
    try:p.wait(timeout=kill_wait);return True
    except subprocess.TimeoutExpired:return False

def restore_child_signal_mask(mask):
    def restore():
        signal.pthread_sigmask(signal.SIG_SETMASK,mask)
    return restore

def bounded(argv,seconds=TIMEOUT,stdout=None,stderr=None,test_interrupt=False,env=None,diagnostics=None):
    watched=(signal.SIGINT,signal.SIGTERM,signal.SIGHUP)
    prior_mask=signal.pthread_sigmask(signal.SIG_BLOCK,watched)
    p=None;old={};timers=[]
    class WaitInterrupted(Exception):pass
    interrupted=[None]
    def handler(sig,frame):
        if interrupted[0] is None:interrupted[0]=sig
        trace_event(diagnostics,'signal-delivery',signal=int(sig),stage='raising-handler')
        raise WaitInterrupted()
    def latch(sig,frame):
        if interrupted[0] is None:interrupted[0]=sig
        trace_event(diagnostics,'signal-delivery',signal=int(sig),stage='cleanup-latch')
    def finish(code,reason):
        trace_event(diagnostics,'bounded-result',actual=code,reason=reason)
        return code
    try:
        try:
            p=subprocess.Popen(argv,start_new_session=True,stdout=stdout,stderr=stderr,env=env,preexec_fn=restore_child_signal_mask(prior_mask))
            trace_event(diagnostics,'child-spawned',pid=p.pid,prior_mask=sorted(int(s) for s in prior_mask if s in watched))
            old={s:signal.signal(s,handler) for s in watched}
            trace_event(diagnostics,'handlers-installed',signals=[int(s) for s in watched])
            if test_interrupt:
                import threading
                if test_interrupt=='setup':
                    os.kill(os.getpid(),signal.SIGTERM)
                    trace_event(diagnostics,'setup-signal-queued',signal=int(signal.SIGTERM))
                else:
                    timers.append(threading.Timer(.1,lambda:os.kill(os.getpid(),signal.SIGTERM)))
                    if test_interrupt=='repeat':timers.append(threading.Timer(.15,lambda:os.kill(os.getpid(),signal.SIGTERM)))
                    for timer in timers:timer.start()
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK,prior_mask)
                try: rc=p.wait(timeout=seconds)
                except subprocess.TimeoutExpired:
                    return finish(124,'timeout-clean') if terminate_group(p.pid,p,trace=diagnostics) else finish(125,'timeout-cleanup-unproven')
                if test_interrupt=='after-wait':os.kill(os.getpid(),signal.SIGTERM)
                state=group_state(p.pid,diagnostics,'post-wait')
                if state!='absent':
                    if not terminate_group(p.pid,p,trace=diagnostics): return finish(125,'post-wait-cleanup-unproven')
                    if interrupted[0]: return finish(128+interrupted[0],'interrupted-clean')
                    return finish(125,'descendant-cleaned')
                if interrupted[0]: return finish(128+interrupted[0],'interrupted-clean')
                return finish(rc,'child-exit')
            except WaitInterrupted:
                signal.pthread_sigmask(signal.SIG_BLOCK,watched)
                for sig in watched:signal.signal(sig,latch)
                signal.pthread_sigmask(signal.SIG_SETMASK,prior_mask)
                trace_event(diagnostics,'interruption-caught',signal=int(interrupted[0]))
                return finish(128+interrupted[0],'interrupted-clean') if terminate_group(p.pid,p,trace=diagnostics) else finish(125,'interrupted-cleanup-unproven')
        except BaseException:
            signal.pthread_sigmask(signal.SIG_BLOCK,watched)
            if old:
                for sig in watched:signal.signal(sig,latch)
            if p is not None:terminate_group(p.pid,p)
            raise
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK,watched)
        for timer in timers:timer.cancel()
        for s,h in old.items(): signal.signal(s,h)
        signal.pthread_sigmask(signal.SIG_SETMASK,prior_mask)
        current_mask=signal.pthread_sigmask(signal.SIG_BLOCK,())
        trace_event(diagnostics,'restoration',mask_restored=all((s in current_mask)==(s in prior_mask) for s in watched),handlers_restored=all(signal.getsignal(s)==old[s] for s in old))

def capture_bounded(argv,seconds=TIMEOUT,env=None):
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        rc=bounded(argv,seconds,stdout=out,stderr=err,env=env)
        out.seek(0);err.seek(0);stdout=out.read();stderr=err.read()
    if rc: raise Stop(f'command failed or timed out ({rc}): {argv[0]}: '+stderr.decode(errors='replace')[:500])
    return stdout

def run_bounded_checked(argv,seconds=TIMEOUT,env=None):
    rc=bounded(argv,seconds,env=env)
    if rc: raise Stop(f'command failed or timed out ({rc}): {argv[0]}')

def interactive_age(argv,seconds,env=None):
    # One overall timeout includes the hidden passphrase prompt; age exposes no accepted-passphrase event.
    with open('/dev/tty','rb',buffering=0) as inp, open('/dev/tty','wb',buffering=0) as out:
        watched=(signal.SIGINT,signal.SIGTERM,signal.SIGHUP)
        prior_mask=signal.pthread_sigmask(signal.SIG_BLOCK,watched)
        p=None;old={}
        class WaitInterrupted(Exception):pass
        interrupted=[None]
        def handler(sig,frame):
            if interrupted[0] is None:interrupted[0]=sig
            raise WaitInterrupted()
        def latch(sig,frame):
            if interrupted[0] is None:interrupted[0]=sig
        try:
            try:
                p=subprocess.Popen(argv,stdin=inp,stdout=out,stderr=out,env=env,preexec_fn=restore_child_signal_mask(prior_mask))
                old={s:signal.signal(s,handler) for s in watched}
                try:
                    signal.pthread_sigmask(signal.SIG_SETMASK,prior_mask)
                    try:rc=p.wait(timeout=seconds)
                    except subprocess.TimeoutExpired:
                        return 124 if terminate_child(p) else 125
                    if interrupted[0]:return 128+interrupted[0]
                    return rc
                except WaitInterrupted:
                    signal.pthread_sigmask(signal.SIG_BLOCK,watched)
                    for sig in watched:signal.signal(sig,latch)
                    signal.pthread_sigmask(signal.SIG_SETMASK,prior_mask)
                    return 128+interrupted[0] if terminate_child(p) else 125
            except BaseException:
                signal.pthread_sigmask(signal.SIG_BLOCK,watched)
                if old:
                    for sig in watched:signal.signal(sig,latch)
                if p is not None:terminate_child(p)
                raise
        finally:
            signal.pthread_sigmask(signal.SIG_BLOCK,watched)
            for s,h in old.items():signal.signal(s,h)
            signal.pthread_sigmask(signal.SIG_SETMASK,prior_mask)

def tty_confirm(text):
    # Deliberately no command deadline: this is an owner-controlled confirmation wait.
    with open('/dev/tty','r',encoding='utf-8') as i,open('/dev/tty','w',encoding='utf-8') as o:
        o.write(text+' Type YES: ');o.flush();return i.readline().rstrip('\n')=='YES'

def parse_usb(listing,infos,expected_uuid=None,recovery_name=None,check_fs=False):
    rows=req(listing,'AllDisksAndPartitions','diskutil list',list); idx={req(x,'DeviceIdentifier','info',str):x for x in infos}; matches=[]; errs=[]
    for row in rows:
        wid=req(row,'DeviceIdentifier','disk row',str); wi=idx.get(wid)
        if not wi: continue
        protocol=wi.get('BusProtocol',wi.get('Protocol','')); media=str(wi.get('MediaName',wi.get('DeviceModel','')))
        if str(protocol).upper()!='USB' or 'sandisk' not in media.lower(): continue
        try:
            if req(row,'Content',wid,str)!='FDisk_partition_scheme':raise Stop('partition map mismatch')
            if not (WHOLE_MIN<=req(wi,'TotalSize',wid,int)<=WHOLE_MAX):raise Stop('whole size mismatch')
            parts=req(row,'Partitions',wid,list)
            if len(parts)!=1:raise Stop('partition count mismatch')
            vid=req(parts[0],'DeviceIdentifier','partition',str);vi=idx.get(vid)
            if not vi:raise Stop('missing volume info')
            if vi.get('ParentWholeDisk',vi.get('PartOfWhole'))!=wid:raise Stop('parent mismatch')
            fs=vi.get('FilesystemName',vi.get('FileSystemPersonality'))
            if str(fs).lower()!='exfat':raise Stop('filesystem mismatch')
            if not req(vi,'Mounted',vid,bool) or not req(vi,'Writable',vid,bool):raise Stop('not mounted/writable')
            if vi.get('ReadOnlyVolume',False) or vi.get('ReadOnlyMedia',False):raise Stop('read-only')
            uuid=req(vi,'VolumeUUID',vid,str);mount=Path(req(vi,'MountPoint',vid,str))
            if expected_uuid and uuid!=expected_uuid:raise Stop('UUID mismatch')
            size=req(vi,'TotalSize',vid,int);free=req(vi,'FreeSpace',vid,int)
            if abs(size-VOL_NOM)>VOL_NOM*VOL_TOL:raise Stop('volume size mismatch')
            if free<MIN_FREE:raise Stop('insufficient free space')
            if check_fs:
                no_symlink_components(mount,False)
                root=mount/recovery_name
                if root.is_symlink() or not root.is_dir():raise Stop('recovery directory mismatch')
                if sorted(p.name for p in root.iterdir())!=EXPECTED:raise Stop('recovery contents mismatch')
            matches.append({'whole':wid,'volume':vid,'uuid':uuid,'mount':str(mount),'media':media,'whole_size':wi['TotalSize'],'volume_size':size,'free':free})
        except Stop as e:errs.append(str(e))
    if len(matches)>1:raise Stop('ambiguous matching USB devices')
    if len(matches)!=1:raise Stop('no unique matching USB: '+';'.join(errs))
    return matches[0]

def collect_usb(diskutil,seconds=TIMEOUT):
    raw=capture_bounded([diskutil,'list','-plist','external','physical'],seconds); listing=plistlib.loads(raw); ids=[]
    for row in req(listing,'AllDisksAndPartitions','diskutil list',list):
        if isinstance(row,dict) and row.get('DeviceIdentifier'):
            ids.append(row['DeviceIdentifier']);ids += [p.get('DeviceIdentifier') for p in row.get('Partitions',[]) if p.get('DeviceIdentifier')]
    infos=[]
    for ident in ids: infos.append(plistlib.loads(capture_bounded([diskutil,'info','-plist','/dev/'+ident],seconds)))
    return listing,infos

def reidentify_usb(listing,infos,baseline,recovery_name=None,require_empty=False,check_fs=False):
    current=parse_usb(listing,infos,baseline['uuid'],recovery_name,check_fs)
    for key in ('whole','volume','uuid','mount','media','whole_size','volume_size'):
        if current[key]!=baseline[key]: raise Stop('USB identity, destination, or physical characteristics changed: '+key)
    mount=no_symlink_components(current['mount'],False)
    if not mount.is_dir(): raise Stop('current USB mount is not a directory')
    if recovery_name and require_empty:
        root=mount/recovery_name
        if root.is_symlink() or not root.is_dir(): raise Stop('recovery directory unavailable after reidentification')
        if any(root.iterdir()): raise Stop('recovery directory is not empty before encrypted identity write')
    return current

def validate_install_receipt(receipt):
    formulae=req(receipt,'formulae','Homebrew installed receipt',list)
    if len(formulae)!=1: raise Stop('Homebrew installed receipt formula count mismatch')
    formula=formulae[0]
    if formula.get('name')!='age' or formula.get('versions',{}).get('stable')!=AGE_VERSION: raise Stop('post-install age formula version mismatch')
    installed=req(formula,'installed','Homebrew installed receipt formula',list)
    matches=[x for x in installed if isinstance(x,dict) and x.get('version')==AGE_VERSION]
    if len(matches)!=1: raise Stop('post-install installed age version mismatch')
    if matches[0].get('poured_from_bottle') is not True: raise Stop('post-install receipt does not prove bottle installation')
    return {'formula_version':formula['versions']['stable'],'installed_version':matches[0]['version'],'poured_from_bottle':True}

def preflight_summary(evidence_root,usb,entries,tag):
    lines=['Evidence directory: '+str(evidence_root),'USB mount: '+usb['mount'],'USB volume UUID: '+usb['uuid'],'USB media: '+usb['media'],'USB whole disk: '+usb['whole'],'USB volume: '+usb['volume'],'USB whole bytes: '+str(usb['whole_size']),'USB volume bytes: '+str(usb['volume_size']),'USB free bytes: '+str(usb['free']),'Reviewed age version: '+AGE_VERSION,'Reviewed bottle tag: '+tag,'Reviewed bottle SHA-256: '+BOTTLES[tag],'USB top-level names/types:']
    lines += ['  '+json.dumps(e,separators=(',',':')) for e in entries]
    return '\n'.join(lines)

def fixture(d='disk9',u='VOL-9',mount='/tmp/SYNTHETIC'):
    L={'AllDisksAndPartitions':[{'DeviceIdentifier':d,'Content':'FDisk_partition_scheme','Partitions':[{'DeviceIdentifier':d+'s1'}]}]}
    W={'DeviceIdentifier':d,'BusProtocol':'USB','MediaName':'USB SanDisk 3.2Gen1 Media','TotalSize':494_130_000_000}
    V={'DeviceIdentifier':d+'s1','ParentWholeDisk':d,'VolumeUUID':u,'FilesystemName':'ExFAT','Mounted':True,'Writable':True,'ReadOnlyVolume':False,'ReadOnlyMedia':False,'MountPoint':mount,'TotalSize':493_900_000_000,'FreeSpace':493_000_000_000}
    return L,W,V

def selftest():
    passed=[]; L,W,V=fixture(); parse_usb(L,[W,V]);passed.append('usb-valid')
    cases=[]
    v=copy.deepcopy(V);del v['VolumeUUID'];cases.append(('usb-missing',L,[W,v],None))
    L2,W2,V2=fixture('disk10','VOL-10');a={'AllDisksAndPartitions':L['AllDisksAndPartitions']+L2['AllDisksAndPartitions']};cases.append(('usb-ambiguous',a,[W,V,W2,V2],None))
    v=copy.deepcopy(V);v['ParentWholeDisk']='disk8';cases.append(('usb-parent',L,[W,v],None))
    l=copy.deepcopy(L);l['AllDisksAndPartitions'][0]['Content']='GUID_partition_scheme';cases.append(('usb-map',l,[W,V],None))
    v=copy.deepcopy(V);v['FreeSpace']=1;cases.append(('usb-free',L,[W,v],None))
    cases.append(('usb-uuid',L,[W,V],'OTHER'))
    for name,l,ii,u in cases:
        try:parse_usb(l,ii,u);raise AssertionError(name)
        except Stop:passed.append(name)
    with tempfile.TemporaryDirectory() as t:
        L,W,V=fixture(mount=t);root=Path(t)/'USBAY-Recovery-X';root.mkdir()
        for n in EXPECTED:(root/n).touch()
        parse_usb(L,[W,V],'VOL-9',root.name,True);passed.append('usb-reconnect')
        (root/'extra').touch()
        try:parse_usb(L,[W,V],'VOL-9',root.name,True);raise AssertionError('usb-reconnect-extra')
        except Stop:passed.append('usb-reconnect-extra')
    tests=[
        ('supervisor-normal',['/bin/sh','-c','sleep .02'],1,False,0),
        ('supervisor-timeout',['/bin/sh','-c','sleep 5 & wait'],.05,False,124),
        ('supervisor-orphan',['/bin/sh','-c','sleep 5 &'],1,False,125),
        ('supervisor-interrupt',['/bin/sh','-c','sleep 5 & wait'],1,True,143),
    ]
    for n,argv,seconds,test_interrupt,e in tests:
        diagnostics=[]
        a=bounded(argv,seconds,test_interrupt=test_interrupt,diagnostics=diagnostics)
        print_supervisor_diagnostic(n,a,e,diagnostics)
        if a!=e:raise AssertionError(f'{n}:{a}!={e}')
        passed.append(n)
    watched=(signal.SIGHUP,signal.SIGINT,signal.SIGTERM)
    parent_mask=signal.pthread_sigmask(signal.SIG_BLOCK,())
    expected_mask={s.name:s in parent_mask for s in watched}
    with tempfile.TemporaryFile() as output:
        code='import json,signal;watched=(signal.SIGHUP,signal.SIGINT,signal.SIGTERM);mask=signal.pthread_sigmask(signal.SIG_BLOCK,());print(json.dumps({s.name:s in mask for s in watched},sort_keys=True))'
        rc=bounded([sys.executable,'-c',code],1,stdout=output)
        output.seek(0);observed_mask=json.loads(output.read().decode())
    if rc or observed_mask!=expected_mask:raise AssertionError(f'supervisor-child-signal-mask:{observed_mask}!={expected_mask}')
    passed.append('supervisor-child-signal-mask')
    rc=bounded([sys.executable,'-c','pass'],1,test_interrupt='after-wait')
    if rc!=143:raise AssertionError('supervisor-interrupt-after-wait')
    passed.append('supervisor-interrupt-after-wait')
    with tempfile.TemporaryDirectory() as t:
        pidfile=Path(t)/'pid'
        started=time.monotonic()
        rc=bounded([sys.executable,'-c','import os,signal,sys,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);open(sys.argv[1],"w").write(str(os.getpid()));time.sleep(5)',str(pidfile)],4,test_interrupt='repeat')
        elapsed=time.monotonic()-started
        if rc!=143 or elapsed>3:raise AssertionError('supervisor-interrupt-repeat-status')
        pid=int(pidfile.read_text())
        try:os.kill(pid,0);raise AssertionError('supervisor-interrupt-repeat-leaked')
        except ProcessLookupError:pass
    passed.append('supervisor-interrupt-repeat-cleanup')
    with tempfile.TemporaryDirectory() as t:
        pidfile=Path(t)/'pid';diagnostics=[]
        rc=bounded([sys.executable,'-c','import os,sys,time;open(sys.argv[1],"w").write(str(os.getpid()));time.sleep(5)',str(pidfile)],4,test_interrupt='setup',diagnostics=diagnostics)
        spawned=next((e['pid'] for e in diagnostics if e['event']=='child-spawned'),None)
        direct_alive=None
        if spawned is not None:
            try:os.kill(spawned,0);direct_alive=True
            except ProcessLookupError:direct_alive=False
            except PermissionError:direct_alive='denied'
        print_supervisor_diagnostic('supervisor-interrupt-setup',rc,143,diagnostics,pidfile_created=pidfile.exists(),direct_child_alive=direct_alive)
        if rc!=143:raise AssertionError(f'supervisor-interrupt-setup-status actual={rc} expected=143')
        if pidfile.exists():
            pid=int(pidfile.read_text())
            try:os.kill(pid,0);raise AssertionError('supervisor-interrupt-setup-leaked')
            except ProcessLookupError:pass
    passed.append('supervisor-interrupt-setup-cleanup')
    original_killpg=os.killpg
    try:
        def denied_killpg(pgid,sig):raise PermissionError('synthetic permission denial')
        os.killpg=denied_killpg
        if group_state(999999)!='denied':raise AssertionError('supervisor-permission-probe')
        started=time.monotonic()
        if terminate_group(999999,term_wait=.01,kill_wait=.01):raise AssertionError('supervisor-permission-cleanup')
        if time.monotonic()-started>.25:raise AssertionError('supervisor-permission-cleanup-unbounded')
    finally:os.killpg=original_killpg
    passed.append('supervisor-permission-denied')
    class UnreapableChild:
        def poll(self):return None
        def wait(self,timeout=None):raise subprocess.TimeoutExpired(['synthetic'],timeout)
        def kill(self):raise PermissionError('synthetic child kill denial')
    started=time.monotonic()
    if reap_child(UnreapableChild(),.01):raise AssertionError('supervisor-reap-permission')
    if time.monotonic()-started>.25:raise AssertionError('supervisor-reap-unbounded')
    passed.append('supervisor-reap-permission-denied')
    class UnstoppableChild:
        def terminate(self):raise PermissionError('synthetic child terminate denial')
    started=time.monotonic()
    if terminate_child(UnstoppableChild(),.01,.01):raise AssertionError('supervisor-direct-permission')
    if time.monotonic()-started>.25:raise AssertionError('supervisor-direct-unbounded')
    passed.append('supervisor-direct-permission-denied')
    with tempfile.TemporaryDirectory() as t:
        pidfile=Path(t)/'pid'
        original_killpg=os.killpg
        try:
            os.killpg=denied_killpg
            started=time.monotonic()
            rc=bounded([sys.executable,'-c','import os,sys,time;open(sys.argv[1],"w").write(str(os.getpid()));time.sleep(5)',str(pidfile)],.1)
            elapsed=time.monotonic()-started
        finally:os.killpg=original_killpg
        if rc!=125 or elapsed>1:raise AssertionError('supervisor-real-child-permission-status')
        pid=int(pidfile.read_text())
        try:os.kill(pid,0);raise AssertionError('supervisor-real-child-leaked')
        except ProcessLookupError:pass
    passed.append('supervisor-real-child-permission-denied')
    controls={'HOMEBREW_NO_AUTO_UPDATE':'1','HOMEBREW_NO_INSTALL_CLEANUP':'1','HOMEBREW_NO_INSTALL_UPGRADE':'1'}
    child_env=os.environ.copy();child_env.update(controls)
    with tempfile.TemporaryFile() as output:
        rc=bounded([sys.executable,'-c','import json,os;print(json.dumps({k:os.environ.get(k) for k in '+repr(tuple(controls))+'}))'],1,stdout=output,env=child_env)
        output.seek(0); observed=json.loads(output.read().decode())
    if rc!=0 or observed!=controls:raise AssertionError('homebrew-child-environment')
    passed.append('homebrew-child-environment')
    with tempfile.TemporaryDirectory() as t:
        root=Path(t);os.chmod(root,0o700)
        def staged(name,data=b'harmless synthetic identity\n'):
            d=Path(tempfile.mkdtemp(prefix='.stage-',dir=root));os.chmod(d,0o700);f=d/'identity';write_exclusive(f,data,0o600);return d,f
        d,f=staged('success');dest=root/'published';publish_staged_file(f,dest);cleanup_private_staging(d,f)
        if dest.read_bytes()!=b'harmless synthetic identity\n' or stat.S_IMODE(dest.stat().st_mode)!=0o600:raise AssertionError('publication-success')
        passed.append('publication-success')
        existing=root/'existing';write_exclusive(existing,b'pre-existing',0o600);d,f=staged('existing')
        try:publish_staged_file(f,existing);raise AssertionError('publication-existing')
        except Stop:pass
        finally:cleanup_private_staging(d,f)
        if existing.read_bytes()!=b'pre-existing':raise AssertionError('existing-destination-modified')
        passed.append('publication-existing-preserved')
        target=root/'target';write_exclusive(target,b'target',0o600);link=root/'conflict';link.symlink_to(target);d,f=staged('symlink')
        try:publish_staged_file(f,link);raise AssertionError('publication-symlink')
        except Stop:pass
        finally:cleanup_private_staging(d,f)
        if not link.is_symlink() or target.read_bytes()!=b'target':raise AssertionError('conflicting-symlink-modified')
        passed.append('publication-symlink-preserved')
        interrupted=root/'interrupted';d,f=staged('interrupt')
        try:publish_staged_file(f,interrupted,interrupt_before_link=True);raise AssertionError('publication-interrupt')
        except KeyboardInterrupt:pass
        finally:cleanup_private_staging(d,f)
        if interrupted.exists() or interrupted.is_symlink() or d.exists():raise AssertionError('publication-interrupt-cleanup')
        passed.append('publication-interrupt-cleanup')
    with tempfile.TemporaryFile() as output:
        rc=bounded([sys.executable,'-c','print("bounded-capture")'],1,stdout=output)
        output.seek(0)
        if rc or output.read()!=b'bounded-capture\n':raise AssertionError('bounded-capture-normal')
    passed.append('bounded-capture-normal')
    try:capture_bounded([sys.executable,'-c','import time;time.sleep(5)'],.05);raise AssertionError('bounded-capture-timeout')
    except Stop as e:
        if '(124)' not in str(e):raise
    passed.append('bounded-capture-timeout')
    try:run_bounded_checked([sys.executable,'-c','import time;time.sleep(5)'],.05);raise AssertionError('bounded-checked-timeout')
    except Stop as e:
        if '(124)' not in str(e):raise
    passed.append('bounded-checked-timeout')
    with tempfile.TemporaryDirectory() as fakebin:
        fake=Path(fakebin)/'diskutil';write_exclusive(fake,b'#!/bin/sh\nsleep 5\n',0o700)
        try:collect_usb(str(fake),.05);raise AssertionError('collect-usb-timeout')
        except Stop as e:
            if '(124)' not in str(e):raise
        passed.append('collect-usb-timeout')
    with tempfile.TemporaryDirectory() as current_mount:
        L,W,V=fixture(mount=current_mount);base=parse_usb(L,[W,V]);current=reidentify_usb(L,[W,V],base)
        if current['mount']!=current_mount:raise AssertionError('usb-reidentify-valid')
        passed.append('usb-reidentify-valid')
        v=copy.deepcopy(V);v['VolumeUUID']='CHANGED'
        try:reidentify_usb(L,[W,v],base);raise AssertionError('usb-reidentify-uuid')
        except Stop:passed.append('usb-reidentify-uuid')
        v=copy.deepcopy(V);v['ParentWholeDisk']='disk8'
        try:reidentify_usb(L,[W,v],base);raise AssertionError('usb-reidentify-parent')
        except Stop:passed.append('usb-reidentify-parent')
    with tempfile.TemporaryDirectory() as changed_mount:
        Lc,Wc,Vc=fixture(mount=changed_mount);base_mount=parse_usb(Lc,[Wc,Vc]);v=copy.deepcopy(Vc);v['MountPoint']=changed_mount+'-changed'
        try:reidentify_usb(Lc,[Wc,v],base_mount);raise AssertionError('usb-reidentify-mount')
        except Stop:passed.append('usb-reidentify-mount')
    with tempfile.TemporaryDirectory() as t:
        L,W,V=fixture(mount=t);base=parse_usb(L,[W,V]);r=Path(t)/'RECOVERY';r.mkdir();reidentify_usb(L,[W,V],base,'RECOVERY',True)
        (r/'unexpected').touch()
        try:reidentify_usb(L,[W,V],base,'RECOVERY',True);raise AssertionError('usb-reidentify-empty')
        except Stop:passed.append('usb-reidentify-empty')
    good={'formulae':[{'name':'age','versions':{'stable':AGE_VERSION},'installed':[{'version':AGE_VERSION,'poured_from_bottle':True}]}]}
    if validate_install_receipt(good)['installed_version']!=AGE_VERSION:raise AssertionError('receipt-valid')
    passed.append('receipt-valid')
    for name,mutate in [('receipt-version',lambda x:x['formulae'][0]['versions'].__setitem__('stable','0.0.0')),('receipt-not-bottle',lambda x:x['formulae'][0]['installed'][0].__setitem__('poured_from_bottle',False))]:
        bad=copy.deepcopy(good);mutate(bad)
        try:validate_install_receipt(bad);raise AssertionError(name)
        except Stop:passed.append(name)
    summary=preflight_summary(Path('/safe/evidence'),base,[{'name':'visible','type':'file'}],'arm64_sonoma')
    if 'Evidence directory: /safe/evidence' not in summary or 'USB volume UUID: VOL-9' not in summary or 'visible' not in summary:raise AssertionError('preflight-summary')
    passed.append('preflight-summary')
    print('fixture_kind=SYNTHETIC_NOT_OWNER_DEVICE_EVIDENCE')
    for n in passed:print(n+'=PASS')

def main():
    if sys.argv[1:]==['--self-test']:selftest();return
    if sys.argv[1:]:raise Stop('usage: script [--self-test]')
    if os.environ.get('USBAY_RECOVERY_SETUP_AUTHORIZED')!='YES':raise Stop('authorization gate missing')
    if sys.platform!='darwin':raise Stop('macOS required')
    home=no_symlink_components(Path.home(),False); config=home/'.config'; age_dir=config/'age'
    primary=age_dir/'usbay-preservation-identity.txt';recipient=age_dir/'usbay-preservation-recipient.txt'
    for p in (primary,recipient):
        no_symlink_components(p)
        if p.exists() or p.is_symlink():raise Stop(f'existing destination: {p}')
    if config.exists() and (not config.is_dir() or config.is_symlink()):raise Stop('unsafe ~/.config')
    if not config.exists() and not tty_confirm('~/.config is missing and would be created mode 700. Continue?'):raise Stop('owner declined ~/.config creation')
    if age_dir.exists() and (not age_dir.is_dir() or age_dir.is_symlink()):raise Stop('unsafe age directory')
    diskutil='/usr/sbin/diskutil';listing,infos=collect_usb(diskutil);usb=parse_usb(listing,infos)
    mount=no_symlink_components(usb['mount'],False)
    entries=[]
    for p in mount.iterdir(): entries.append({'name':p.name,'type':'symlink' if p.is_symlink() else 'directory' if p.is_dir() else 'file' if p.is_file() else 'other'})
    brew=next((p for p in ['/opt/homebrew/bin/brew','/usr/local/bin/brew'] if os.path.isfile(p) and os.access(p,os.X_OK)),None)
    if not brew:raise Stop('Homebrew missing')
    with tempfile.TemporaryFile() as dn:
        existing_age_rc=bounded([brew,'list','--formula','age'],TIMEOUT,stdout=dn,stderr=dn)
    if existing_age_rc==0:raise Stop('existing age provenance not established; refusing')
    if existing_age_rc!=1:raise Stop('Homebrew existing-age query failed or timed out: '+str(existing_age_rc))
    arch=capture_bounded(['/usr/bin/uname','-m'],TIMEOUT).decode().strip();major=int(capture_bounded(['/usr/bin/sw_vers','-productVersion'],TIMEOUT).decode().split('.')[0]);tag={( 'arm64',14):'arm64_sonoma',('arm64',15):'arm64_sequoia',('arm64',26):'arm64_tahoe',('arm64',27):'arm64_golden_gate'}.get((arch,major))
    if not tag:raise Stop('unreviewed macOS/architecture')
    formula=json.loads(capture_bounded(['/usr/bin/curl','-fsSL','https://formulae.brew.sh/api/formula/age.json'],TIMEOUT))
    bottle=formula.get('bottle',{}).get('stable',{}).get('files',{}).get(tag)
    if formula.get('name')!='age' or formula.get('tap')!='homebrew/core' or formula.get('versions',{}).get('stable')!=AGE_VERSION or formula.get('dependencies') or not bottle or bottle.get('sha256')!=BOTTLES[tag]:raise Stop('formula metadata differs from reviewed lock')
    evidence_root=create_dir_exclusive(home/'USBAY-Preservation-Evidence'/('recovery-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'-'+secrets.token_hex(8))) if (home/'USBAY-Preservation-Evidence').exists() else None
    if evidence_root is None:
        parent=home/'USBAY-Preservation-Evidence';create_dir_exclusive(parent);evidence_root=create_dir_exclusive(parent/('recovery-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'-'+secrets.token_hex(8)))
    evidence=evidence_root/'results.txt';write_exclusive(evidence,'FORMAT=USBAY-recovery-v1\n')
    rec=lambda x:append_checked(evidence,x)
    for k,v in usb.items():rec('USB_INITIAL_'+k.upper()+'='+str(v))
    for e in entries:rec('USB_TOP_LEVEL='+json.dumps(e,separators=(',',':')))
    rec('FORMULA_VERSION='+AGE_VERSION);rec('BOTTLE_TAG='+tag);rec('BOTTLE_SHA256='+BOTTLES[tag]);rec('PROVENANCE_LIMIT=official Homebrew/core metadata lock + force-bottle result + verified post-install bottle receipt; installed-byte equality not claimed')
    print(preflight_summary(evidence_root,usb,entries,tag),flush=True)
    if not tty_confirm('Review evidence preflight and accept listed USB top-level names/types before any install or key creation. Continue?'):raise Stop('owner declined preflight')
    env=os.environ.copy();env.update(HOMEBREW_NO_AUTO_UPDATE='1',HOMEBREW_NO_INSTALL_CLEANUP='1',HOMEBREW_NO_INSTALL_UPGRADE='1')
    out=open(evidence_root/'brew-install.stdout','xb');err=open(evidence_root/'brew-install.stderr','xb');rc=bounded([brew,'install','--formula','--force-bottle','age'],INSTALL_TIMEOUT,out,err,env=env);out.close();err.close();rec('BREW_INSTALL_STATUS='+str(rc))
    if rc:raise Stop('brew install failed')
    age_prefix=capture_bounded([brew,'--prefix','age'],TIMEOUT).decode().strip();age=age_prefix+'/bin/age';keygen=age_prefix+'/bin/age-keygen'
    receipt_bytes=capture_bounded([brew,'info','--json=v2','--installed','age'],TIMEOUT);write_exclusive(evidence_root/'homebrew-installed-receipt.json',receipt_bytes);rec('HOMEBREW_RECEIPT_SHA256='+sha256(evidence_root/'homebrew-installed-receipt.json'))
    receipt=json.loads(receipt_bytes);receipt_check=validate_install_receipt(receipt);rec('POST_INSTALL_FORMULA_VERSION='+receipt_check['formula_version']);rec('POST_INSTALL_INSTALLED_VERSION='+receipt_check['installed_version']);rec('POST_INSTALL_POURED_FROM_BOTTLE=YES')
    # Harmless tooling round trip before the real identity.
    with tempfile.TemporaryDirectory(prefix='tooling-',dir=evidence_root) as t:
        t=Path(t);plain=t/'plain';key=t/'key';pub=t/'pub';cipher=t/'cipher';recovered=t/'recovered';write_exclusive(plain,b'USBAY harmless tooling round trip\n')
        with open(os.devnull,'wb') as dn:
            if bounded([keygen,'-o',str(key)],30,stderr=dn):raise Stop('harmless keygen failed')
        with open(pub,'xb') as o:
            if bounded([keygen,'-y',str(key)],30,stdout=o):raise Stop('harmless recipient failed')
        pv=pub.read_text().strip()
        if bounded([age,'-r',pv,'-o',str(cipher),str(plain)],30) or bounded([age,'-d','-i',str(key),'-o',str(recovered),str(cipher)],30) or plain.read_bytes()!=recovered.read_bytes():raise Stop('harmless tooling round trip failed')
        rec('HARMLESS_TOOLING_ROUNDTRIP=PASS')
    if not tty_confirm('Preflight, install receipt, and harmless tooling test passed. Generate the real primary identity?'):raise Stop('owner declined key creation')
    if not config.exists():os.mkdir(config,0o700)
    if not age_dir.exists():os.mkdir(age_dir,0o700)
    # Existing directory modes are never changed.
    if stat.S_IMODE(age_dir.stat().st_mode)!=0o700:raise Stop('existing age directory must already be mode 700')
    stage_dir=Path(tempfile.mkdtemp(prefix='.primary-staging-',dir=age_dir));os.chmod(stage_dir,0o700);staged_primary=stage_dir/'identity'
    try:
        with open(os.devnull,'wb') as dn:
            if bounded([keygen,'-o',str(staged_primary)],30,stderr=dn):raise Stop('primary keygen failed')
        publish_staged_file(staged_primary,primary,0o600)
    finally:
        cleanup_private_staging(stage_dir,staged_primary)
    with open(recipient,'xb') as o:
        if bounded([keygen,'-y',str(primary)],30,stdout=o):raise Stop('recipient derivation failed')
    public=recipient.read_text().strip();rec('PRIMARY_IDENTITY_CREATED=YES');rec('PRIVATE_IDENTITY_LOGGED=NO')
    listing_write,infos_write=collect_usb(diskutil);usb_write=reidentify_usb(listing_write,infos_write,usb);rec('USB_PRE_DIRECTORY_REIDENTIFICATION=PASS');mount=no_symlink_components(usb_write['mount'],False)
    recovery_name='USBAY-Recovery-'+secrets.token_hex(16);recovery=create_dir_exclusive(mount/recovery_name)
    encrypted=recovery/EXPECTED[2];usbpub=recovery/EXPECTED[3];instructions=recovery/EXPECTED[0];manifest=recovery/EXPECTED[1]
    with open('/dev/tty','w') as tty:tty.write('Use the already selected paper custody: create a fresh passphrase of at least seven independently selected Diceware words, write it directly on paper, and store it locked and physically separate from the USB. Never enter it in chat, arguments, files, or logs.\n')
    if not tty_confirm('Confirm the paper passphrase has been created and stored as selected, then encrypt the recovery copy?'):raise Stop('owner declined passphrase step')
    listing_encrypt,infos_encrypt=collect_usb(diskutil);usb_encrypt=reidentify_usb(listing_encrypt,infos_encrypt,usb,recovery_name,True);rec('USB_PRE_ENCRYPTION_REIDENTIFICATION=PASS');recovery=Path(usb_encrypt['mount'])/recovery_name;encrypted=recovery/EXPECTED[2];usbpub=recovery/EXPECTED[3];instructions=recovery/EXPECTED[0];manifest=recovery/EXPECTED[1]
    rc=interactive_age([age,'-p','-o',str(encrypted),str(primary)],INTERACTIVE_TIMEOUT);rec('USB_ENCRYPTION_STATUS='+str(rc))
    if rc:raise Stop('USB identity encryption failed')
    write_exclusive(usbpub,(public+'\n').encode(),0o644);write_exclusive(instructions,'Encrypted copy of the primary age identity. Passphrase is held separately on paper.\n',0o644)
    hashes={p.name:sha256(p) for p in (encrypted,usbpub,instructions)};write_exclusive(manifest,''.join(f'{n}.sha256={h}\n' for n,h in sorted(hashes.items())),0o644);hashes[manifest.name]=sha256(manifest)
    for n,h in hashes.items():rec('USB_'+n+'_SHA256='+h)
    os.sync();run_bounded_checked([diskutil,'eject','/dev/'+usb_encrypt['whole']],TIMEOUT)
    if not tty_confirm('Reconnect the same USB and wait for macOS to mount it. Continue with verification?'):raise Stop('owner declined reconnect')
    listing2,infos2=collect_usb(diskutil);usb2=reidentify_usb(listing2,infos2,usb,recovery_name,False,True);root=Path(usb2['mount'])/recovery_name
    if (root/EXPECTED[3]).read_bytes()!=recipient.read_bytes():raise Stop('public recipient mismatch')
    for n,h in hashes.items():
        if sha256(root/n)!=h:raise Stop('reconnect hash mismatch: '+n)
    rec('USB_RECONNECT_PARENT_RELATIONSHIP=PASS');rec('USB_RECONNECT_EXACT_CONTENTS=PASS')
    test=create_dir_exclusive(evidence_root/'synthetic-recovery-test');plain=test/'plain';cipher=test/'challenge.age';recovered=test/'recovered';write_exclusive(plain,b'USBAY synthetic recovery challenge\n')
    if bounded([age,'-r',public,'-o',str(cipher),str(plain)],30):raise Stop('challenge encryption failed')
    clean={'HOME':str(home),'PATH':'/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin','TMPDIR':os.environ.get('TMPDIR','/tmp')}
    rc=interactive_age([age,'-d','-i',str(root/EXPECTED[2]),'-o',str(recovered),str(cipher)],INTERACTIVE_TIMEOUT,clean);rec('RECOVERY_STATUS='+str(rc))
    if rc or recovered.read_bytes()!=plain.read_bytes():raise Stop('synthetic recovery failed')
    for p in (plain,cipher,recovered):rec('SYNTHETIC_'+p.name.upper()+'_SHA256='+sha256(p))
    rec('RECOVERY_IDENTITY_ARGUMENTS=1');rec('RECOVERY_IDENTITY_SOURCE=USB_EXPLICIT');rec('PRIMARY_IDENTITY_REFERENCED=NO');rec('BOUNDED_CLAIM=Recovery succeeded using the USB recovery identity without referencing the primary identity.');rec('RESULT=PASS')
    os.sync()
    for p in (plain,cipher,recovered):p.unlink()
    test.rmdir();rec('SYNTHETIC_CLEANUP=PASS')
    print('PASS evidence='+str(evidence))
try:main()
except AssertionError as e:
    print('SELFTEST_FAILED: '+str(e),file=sys.stderr);sys.exit(1)
except (Stop,subprocess.CalledProcessError,OSError,ValueError,KeyError) as e:
    print('BLOCKED: '+str(e),file=sys.stderr);sys.exit(1)
PY
