import base64
import hashlib
import json
import os
import plistlib
import signal
import subprocess
import sys
import tempfile
import time

COMMAND=['/usr/sbin/diskutil','list','-plist','external','physical']
DEADLINE_SECONDS=15
TERM_WAIT_SECONDS=2
KILL_WAIT_SECONDS=2
AUTH_ENV='USBAY_FDA_DIAGNOSTIC_AUTHORIZED'

def emit(key,value):
    if isinstance(value,bool):
        value='YES' if value else 'NO'
    print(f'{key}={value}',flush=True)

def trace_event(trace,event,**details):
    item={'event':event,**details}
    if event!='group-state' or not trace or trace[-1]!=item:
        trace.append(item)

def reap_child(child,seconds=2):
    if child.poll() is not None:
        return True
    try:
        child.wait(timeout=seconds)
        return True
    except subprocess.TimeoutExpired:
        pass
    try:
        child.kill()
    except ProcessLookupError:
        pass
    except PermissionError:
        return False
    try:
        child.wait(timeout=seconds)
        return True
    except subprocess.TimeoutExpired:
        return False

def terminate_child(child,term_wait=2,kill_wait=2):
    try:
        child.terminate()
    except ProcessLookupError:
        return reap_child(child,term_wait)
    except PermissionError:
        return False
    try:
        child.wait(timeout=term_wait)
        return True
    except subprocess.TimeoutExpired:
        pass
    try:
        child.kill()
    except ProcessLookupError:
        return reap_child(child,kill_wait)
    except PermissionError:
        return False
    try:
        child.wait(timeout=kill_wait)
        return True
    except subprocess.TimeoutExpired:
        return False

def group_state(pgid,trace,phase,child_status=None):
    details={'phase':phase,'child_status_at_probe':child_status}
    try:
        os.killpg(pgid,0)
        state='present'
    except ProcessLookupError:
        state='absent'
    except PermissionError as error:
        state='denied'
        details['errno']=error.errno
        try:
            details['leader_pgid']=os.getpgid(pgid)
            details['leader_state']='present'
        except ProcessLookupError:
            details['leader_state']='absent'
        except PermissionError as leader_error:
            details['leader_state']='denied'
            details['leader_errno']=leader_error.errno
        except OSError as leader_error:
            details['leader_state']='error'
            details['leader_errno']=leader_error.errno
    trace_event(trace,'group-state',state=state,**details)
    return state

def wait_group_clean(pgid,child,seconds,trace,phase):
    end=time.monotonic()+seconds
    denied_observed=False
    while True:
        child_status=child.poll()
        state=group_state(pgid,trace,phase,child_status)
        if state=='absent' and child.poll() is not None:
            trace_event(
                trace,
                'group-wait',
                phase=phase,
                outcome='clean',
                denied_observed=denied_observed,
            )
            return 'clean'
        if state=='denied':
            if not denied_observed:
                trace_event(trace,'group-denial-observed',phase=phase)
            denied_observed=True
        if time.monotonic()>=end:
            outcome='denied' if state=='denied' else 'timeout'
            trace_event(
                trace,
                'group-wait',
                phase=phase,
                outcome=outcome,
                denied_observed=denied_observed,
            )
            return outcome
        time.sleep(min(.02,max(0,end-time.monotonic())))

def signal_group(pgid,sig,trace,phase):
    try:
        os.killpg(pgid,sig)
        outcome='sent'
    except ProcessLookupError:
        outcome='absent'
    except PermissionError:
        outcome='denied'
    trace_event(
        trace,
        'group-signal',
        phase=phase,
        signal=int(sig),
        outcome=outcome,
    )
    return outcome

def terminate_group(
    pgid,
    child,
    trace,
    term_wait=TERM_WAIT_SECONDS,
    kill_wait=KILL_WAIT_SECONDS,
):
    def finish(ok,reason):
        child_status=child.poll()
        trace_event(
            trace,
            'cleanup-result',
            outcome='clean' if ok else 'unproven',
            reason=reason,
            direct_child_reaped=child_status is not None,
            direct_child_status=child_status,
        )
        return ok

    first=signal_group(pgid,signal.SIGTERM,trace,'term')
    if first=='absent':
        return finish(reap_child(child,term_wait),'term-group-absent')

    denied=first=='denied'
    if first!='denied':
        phase=wait_group_clean(pgid,child,term_wait,trace,'term-wait')
        if phase=='clean':
            return finish(True,'term-clean')
        denied=phase=='denied'

    second=signal_group(pgid,signal.SIGKILL,trace,'kill')
    denied=denied or second=='denied'
    if second=='absent':
        direct_ok=reap_child(child,kill_wait)
        return finish(direct_ok and not denied,'kill-group-absent')
    if second=='denied':
        terminate_child(child,term_wait,kill_wait)
        return finish(False,'kill-denied')

    phase=wait_group_clean(pgid,child,kill_wait,trace,'kill-wait')
    denied=denied or phase=='denied'
    if phase!='clean':
        terminate_child(child,term_wait,kill_wait)
    return finish(phase=='clean' and not denied,'kill-'+phase)

def restore_child_signal_mask(mask):
    def restore():
        signal.pthread_sigmask(signal.SIG_SETMASK,mask)
    return restore

def bounded(argv,seconds,stdout,stderr,trace):
    watched=(signal.SIGINT,signal.SIGTERM,signal.SIGHUP)
    prior_mask=signal.pthread_sigmask(signal.SIG_BLOCK,watched)
    child=None

    class WaitInterrupted(Exception):
        pass

    interrupted=[None]

    def handler(sig,frame):
        if interrupted[0] is None:
            interrupted[0]=sig
        trace_event(trace,'signal-delivery',signal=int(sig),stage='raising-handler')
        raise WaitInterrupted()

    def latch(sig,frame):
        if interrupted[0] is None:
            interrupted[0]=sig
        trace_event(trace,'signal-delivery',signal=int(sig),stage='cleanup-latch')

    def enter_cleanup_mode():
        signal.pthread_sigmask(signal.SIG_BLOCK,watched)
        for sig in watched:
            signal.signal(sig,latch)
        trace_event(trace,'cleanup-signal-mode',watched=[int(sig) for sig in watched])

    def safe_child_poll(phase):
        if child is None:
            return None,True
        try:
            return child.poll(),True
        except BaseException as poll_error:
            trace_event(
                trace,
                'child-poll-exception',
                phase=phase,
                exception_type=type(poll_error).__name__,
            )
            return None,False

    def drain_pending():
        try:
            pending=set(signal.sigpending())
            for sig in watched:
                if sig in pending:
                    received=signal.sigwait({sig})
                    if interrupted[0] is None:
                        interrupted[0]=received
                    trace_event(
                        trace,
                        'signal-delivery',
                        signal=int(received),
                        stage='cleanup-pending-drain',
                    )
                    pending=set(signal.sigpending())
            return True
        except BaseException as drain_error:
            trace_event(
                trace,
                'pending-signal-drain-exception',
                exception_type=type(drain_error).__name__,
            )
            return False

    def safe_cleanup():
        if child is None:
            trace_event(
                trace,
                'cleanup-result',
                outcome='not-needed',
                reason='child-not-spawned',
                direct_child_reaped=True,
                direct_child_status=None,
            )
            return True
        try:
            return terminate_group(child.pid,child,trace)
        except BaseException as cleanup_error:
            trace_event(
                trace,
                'cleanup-exception',
                exception_type=type(cleanup_error).__name__,
            )
            try:
                direct_child_reaped=terminate_child(
                    child,
                    TERM_WAIT_SECONDS,
                    KILL_WAIT_SECONDS,
                )
            except BaseException as direct_error:
                direct_child_reaped=False
                trace_event(
                    trace,
                    'direct-child-cleanup-exception',
                    exception_type=type(direct_error).__name__,
                )
            direct_child_status,poll_ok=safe_child_poll(
                'cleanup-exception-fallback',
            )
            trace_event(
                trace,
                'cleanup-result',
                outcome='unproven',
                reason=(
                    'cleanup-exception'
                    if poll_ok
                    else 'cleanup-exception-child-status-unavailable'
                ),
                direct_child_reaped=direct_child_reaped and poll_ok,
                direct_child_status=direct_child_status,
            )
            return False

    def finish(code,reason):
        drain_ok=drain_pending()
        if not drain_ok:
            code=125
            reason='pending-signal-drain-cleanup-unproven'
        elif interrupted[0] is not None and code!=125:
            code=128+interrupted[0]
            reason='interrupted-clean'
        trace_event(trace,'bounded-result',actual=code,reason=reason)
        return code,reason

    try:
        child=subprocess.Popen(
            argv,
            start_new_session=True,
            stdout=stdout,
            stderr=stderr,
            preexec_fn=restore_child_signal_mask(prior_mask),
        )
        trace_event(
            trace,
            'child-spawned',
            pid=child.pid,
            prior_mask=sorted(int(sig) for sig in prior_mask if sig in watched),
        )
        for sig in watched:
            signal.signal(sig,handler)
        trace_event(trace,'handlers-installed',signals=[int(sig) for sig in watched])
        signal.pthread_sigmask(signal.SIG_SETMASK,prior_mask)
        try:
            child_rc=child.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            enter_cleanup_mode()
            if safe_cleanup():
                return finish(124,'timeout-clean')
            return finish(125,'timeout-cleanup-unproven')
        except WaitInterrupted:
            enter_cleanup_mode()
            trace_event(
                trace,
                'interruption-caught',
                signal=int(interrupted[0]),
            )
            if safe_cleanup():
                return finish(128+interrupted[0],'interrupted-clean')
            return finish(125,'interrupted-cleanup-unproven')

        enter_cleanup_mode()
        try:
            state=group_state(child.pid,trace,'post-wait',child.poll())
        except BaseException as probe_error:
            trace_event(
                trace,
                'post-wait-probe-exception',
                exception_type=type(probe_error).__name__,
            )
            if safe_cleanup():
                return finish(70,'post-wait-probe-exception-clean')
            return finish(125,'post-wait-probe-cleanup-unproven')
        if state!='absent':
            if not safe_cleanup():
                return finish(125,'post-wait-cleanup-unproven')
            return finish(125,'descendant-cleaned')
        return finish(child_rc,'child-exit')
    except BaseException as error:
        enter_cleanup_mode()
        trace_event(
            trace,
            'bounded-exception',
            exception_type=type(error).__name__,
            interrupted_signal=(
                None if interrupted[0] is None else int(interrupted[0])
            ),
        )
        cleanup_ok=safe_cleanup()
        if interrupted[0] is not None and cleanup_ok:
            return finish(128+interrupted[0],'interrupted-exception-clean')
        if cleanup_ok:
            return finish(70,'launcher-exception-clean')
        return finish(125,'launcher-exception-cleanup-unproven')

def main():
    if sys.argv[1:]:
        emit('DIAGNOSTIC_RESULT','BLOCKED')
        emit('DIAGNOSTIC_REASON','arguments-not-accepted')
        return 64
    if os.environ.get(AUTH_ENV)!='YES':
        emit('DIAGNOSTIC_RESULT','BLOCKED')
        emit('DIAGNOSTIC_REASON','technical-authorization-gate-missing')
        return 77
    if sys.platform!='darwin':
        emit('DIAGNOSTIC_RESULT','BLOCKED')
        emit('DIAGNOSTIC_REASON','macOS-required')
        return 69
    if not os.path.isfile(COMMAND[0]) or not os.access(COMMAND[0],os.X_OK):
        emit('DIAGNOSTIC_RESULT','BLOCKED')
        emit('DIAGNOSTIC_REASON','diskutil-unavailable')
        return 69

    trace=[]
    start_wall=time.time()
    start_mono=time.monotonic()
    emit('DIAGNOSTIC_COMMAND',json.dumps(COMMAND,separators=(',',':')))
    emit('DIAGNOSTIC_DEADLINE_SECONDS',DEADLINE_SECONDS)
    emit('DIAGNOSTIC_START_UTC',time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(start_wall)))

    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        status,reason=bounded(
            COMMAND,
            DEADLINE_SECONDS,
            stdout_file,
            stderr_file,
            trace,
        )
        elapsed_ms=round((time.monotonic()-start_mono)*1000)
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout_bytes=stdout_file.read()
        stderr_bytes=stderr_file.read()

    end_wall=time.time()
    emit('DIAGNOSTIC_END_UTC',time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(end_wall)))
    emit('DIAGNOSTIC_ELAPSED_MS',elapsed_ms)
    emit('DIAGNOSTIC_INTERNAL_STATUS',status)
    emit('DIAGNOSTIC_BOUNDED_REASON',reason)
    emit('DISKUTIL_STDOUT_BYTES',len(stdout_bytes))
    emit('DISKUTIL_STDOUT_SHA256',hashlib.sha256(stdout_bytes).hexdigest())
    emit('DISKUTIL_STDOUT_BASE64',base64.b64encode(stdout_bytes).decode('ascii'))
    emit('DISKUTIL_STDERR_BYTES',len(stderr_bytes))
    emit('DISKUTIL_STDERR_SHA256',hashlib.sha256(stderr_bytes).hexdigest())
    emit('DISKUTIL_STDERR_BASE64',base64.b64encode(stderr_bytes).decode('ascii'))

    bounded_result=next(
        (event for event in reversed(trace) if event['event']=='bounded-result'),
        None,
    )
    cleanup=next(
        (event for event in reversed(trace) if event['event']=='cleanup-result'),
        None,
    )
    report={
        'bounded_result_reason':None if bounded_result is None else bounded_result.get('reason'),
        'cleanup_outcome':'not-needed' if cleanup is None else cleanup.get('outcome'),
        'cleanup_reason':None if cleanup is None else cleanup.get('reason'),
        'direct_child_reaped':(
            status is not None if cleanup is None
            else cleanup.get('direct_child_reaped')
        ),
        'direct_child_status':None if cleanup is None else cleanup.get('direct_child_status'),
        'events':trace,
    }
    emit('SUPERVISOR_DIAGNOSTIC',json.dumps(report,separators=(',',':'),sort_keys=True))

    if status!=0:
        emit('PLIST_VALID','NOT_EVALUATED')
        emit('ALL_DISKS_AND_PARTITIONS','NOT_EVALUATED')
        if status==125 and reason=='descendant-cleaned':
            result='BLOCKED_DESCENDANT_DETECTED_AND_CLEANED'
        elif status==125 and 'cleanup-unproven' in reason:
            result='BLOCKED_CLEANUP_UNPROVEN'
        elif status==125 and reason=='child-exit':
            result='FAILED_CHILD_EXIT_125'
        elif status==125:
            result='BLOCKED_STATUS_125_UNCLASSIFIED'
        else:
            result='FAILED'
        emit('DIAGNOSTIC_RESULT',result)
        return status

    try:
        parsed=plistlib.loads(stdout_bytes)
    except Exception as error:
        emit('PLIST_VALID','NO')
        emit('PLIST_ERROR_TYPE',type(error).__name__)
        emit('ALL_DISKS_AND_PARTITIONS','NOT_EVALUATED')
        emit('DIAGNOSTIC_RESULT','FAILED_OUTPUT_VALIDATION')
        return 2

    emit('PLIST_VALID','YES')
    rows=parsed.get('AllDisksAndPartitions') if isinstance(parsed,dict) else None
    if not isinstance(rows,list):
        emit('ALL_DISKS_AND_PARTITIONS','NO')
        emit('DIAGNOSTIC_RESULT','FAILED_OUTPUT_VALIDATION')
        return 2

    identifiers=[
        row.get('DeviceIdentifier')
        for row in rows
        if isinstance(row,dict) and isinstance(row.get('DeviceIdentifier'),str)
    ]
    emit('ALL_DISKS_AND_PARTITIONS','YES')
    emit('EXTERNAL_PHYSICAL_DISK_COUNT',len(rows))
    emit('DEVICE_IDENTIFIERS',json.dumps(identifiers,separators=(',',':')))
    emit('DIAGNOSTIC_RESULT','COMMAND_SUCCEEDED')
    return 0
