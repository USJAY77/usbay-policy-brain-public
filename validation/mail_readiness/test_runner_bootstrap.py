"""Pure and disposable-file tests; never invoke sudo, namespaces or /etc writes."""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import runner_bootstrap as b
from result_contract import namespace_identity_pass, fresh_identity_pass


class PolicyTests(unittest.TestCase):
    def test_bootstrap_error_reason_does_not_expose_input(self):
        self.assertEqual(b.safe_reason(RuntimeError('PRIVATE_CANARY')), 'BOOTSTRAP_ERROR')
        self.assertEqual(b.safe_reason(RuntimeError('MAPPING_POLICY_CHANGED')), 'MAPPING_POLICY_CHANGED')

    def test_append_only_exact_single_id(self):
        original=b'# preserved\nrunner:100000:65536\n'
        self.assertEqual(b.policy_extension(original,1001),original+b'root:1001:1\n')

    def test_exact_existing_grant_is_unchanged(self):
        raw=b'root:1001:1\n'
        self.assertEqual(b.policy_extension(raw,1001),raw)

    def test_missing_final_newline_preserved_with_separator(self):
        self.assertEqual(b.policy_extension(b'runner:100000:65536',1001),b'runner:100000:65536\nroot:1001:1\n')

    def test_root_ids_and_ambiguous_ids_rejected(self):
        for value in (0,-1,True,'1001','*',2147483648):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                b.policy_extension(b'',value)

    def test_malformed_policy_rejected(self):
        for raw in (b'\xff',b'root:*:1',b'root:0:1',b'root:1001:0',b'root:1:4294967295',b'broken',b'x'*1048577):
            with self.subTest(raw_size=len(raw)),self.assertRaises(RuntimeError):
                b.policy_extension(raw,1001)

    def test_broad_overlapping_root_grant_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'AMBIGUOUS'):
            b.policy_extension(b'root:1000:10\n',1001)

    def test_duplicate_root_grant_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'AMBIGUOUS'):
            b.policy_extension(b'root:1001:1\nroot:1001:1\n',1001)

    def test_numeric_root_alias_rejected_for_target(self):
        with self.assertRaisesRegex(RuntimeError,'AMBIGUOUS'):
            b.policy_extension(b'0:1001:1\n',1001)

    def test_existing_unrelated_policy_is_preserved(self):
        raw=b'root:2000:1\nrunner:100000:65536\n'
        self.assertEqual(b.policy_extension(raw,1001),raw+b'root:1001:1\n')


class PolicyTransactionTests(unittest.TestCase):
    def setUp(self):
        self.state={Path('/etc/subuid'):b'runner:100000:65536\n',Path('/etc/subgid'):b'runner:100000:65536\n'}
        self.original=copy.deepcopy(self.state)
        self.serial=0

    def snapshot(self,path):
        return (self.serial,self.state[path])

    def replace(self,path,old,new):
        if self.state[path]!=old[1]:raise RuntimeError('MAPPING_POLICY_CHANGED')
        self.state[path]=new
        self.serial+=1
        return self.snapshot(path)

    def test_callback_runs_only_after_both_grants_and_restores(self):
        def callback():
            self.assertTrue(all(b'root:1001:1' in x for x in self.state.values()))
            return 7
        with patch.object(b,'snapshot',self.snapshot),patch.object(b,'atomic_replace',self.replace):
            self.assertEqual(b.run_with_policy(1001,1001,callback),7)
        self.assertEqual(self.state,self.original)

    def test_callback_failure_restores_both(self):
        def callback():raise RuntimeError('SYNTHETIC_FAILURE')
        with patch.object(b,'snapshot',self.snapshot),patch.object(b,'atomic_replace',self.replace):
            with self.assertRaisesRegex(RuntimeError,'SYNTHETIC_FAILURE'):
                b.run_with_policy(1001,1001,callback)
        self.assertEqual(self.state,self.original)

    def test_second_write_failure_prevents_launch_and_restores_first(self):
        launched=[]
        def replace(path,old,new):
            if path.name=='subgid':raise RuntimeError('SECOND_WRITE_FAILED')
            return self.replace(path,old,new)
        with patch.object(b,'snapshot',self.snapshot),patch.object(b,'atomic_replace',replace):
            with self.assertRaisesRegex(RuntimeError,'SECOND_WRITE_FAILED'):
                b.run_with_policy(1001,1001,lambda:launched.append(True))
        self.assertEqual(launched,[])
        self.assertEqual(self.state,self.original)

    def test_concurrent_mutation_is_not_overwritten_during_restore(self):
        def callback():self.state[Path('/etc/subgid')]=b'changed-by-other\n'
        with patch.object(b,'snapshot',self.snapshot),patch.object(b,'atomic_replace',self.replace):
            with self.assertRaisesRegex(RuntimeError,'RESTORE_FAILED'):
                b.run_with_policy(1001,1001,callback)
        self.assertEqual(self.state[Path('/etc/subgid')],b'changed-by-other\n')
        self.assertEqual(self.state[Path('/etc/subuid')],self.original[Path('/etc/subuid')])

    def test_invalid_second_policy_stops_before_any_write(self):
        self.state[Path('/etc/subgid')]=b'invalid'
        with patch.object(b,'snapshot',self.snapshot),patch.object(b,'atomic_replace') as writer:
            with self.assertRaises(RuntimeError):b.run_with_policy(1001,1001,lambda:None)
            writer.assert_not_called()

    def test_changed_snapshot_stops_atomic_replace(self):
        with patch.object(b,'snapshot',return_value=(SimpleNamespace(),b'changed')):
            with patch.object(b,'signature',return_value=1):
                with self.assertRaisesRegex(RuntimeError,'CHANGED'):
                    b.atomic_replace(Path('/unused'),(SimpleNamespace(),b'original'),b'new')

    def test_symlink_policy_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'target';target.write_bytes(b'')
            link=Path(tmp)/'link';link.symlink_to(target)
            with self.assertRaises(OSError):b.snapshot(link)


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.value={'uids':[0,0,0],'gids':[0,0,0],'groups':[], 'setgroups_denied':True,
                    'uid_map':[[0,1001,1]],'gid_map':[[0,1002,1]]}

    def test_exact_identity_passes(self):
        self.assertTrue(namespace_identity_pass(self.value,1001,1002))

    def test_wrong_or_broadened_mapping_fails(self):
        for key,mapping in (('uid_map',[[0,0,1]]),('gid_map',[[0,1002,2]]),('uid_map',[[0,1001,1],[1,2000,1]]),('uid_map',[[False,1001,1]])):
            value=copy.deepcopy(self.value);value[key]=mapping
            self.assertFalse(namespace_identity_pass(value,1001,1002))

    def test_inherited_groups_or_enabled_setgroups_fail(self):
        for key,val in (('groups',[1001]),('setgroups_denied',False),('uids',[0,0,1001]),('gids',[0,0,True])):
            value=copy.deepcopy(self.value);value[key]=val
            self.assertFalse(namespace_identity_pass(value,1001,1002))

    def test_missing_and_extra_identity_evidence_fail(self):
        value=copy.deepcopy(self.value);value.pop('uid_map')
        self.assertFalse(namespace_identity_pass(value,1001,1002))
        value=copy.deepcopy(self.value);value['extra']=True
        self.assertFalse(namespace_identity_pass(value,1001,1002))

    def test_fresh_child_requires_denied_setgroups(self):
        value={k:self.value[k] for k in ('uids','gids','groups','setgroups_denied')}
        self.assertTrue(fresh_identity_pass(value))
        value['setgroups_denied']=1
        self.assertFalse(fresh_identity_pass(value))


if __name__=='__main__':unittest.main()


class LauncherDiagnosticsTests(unittest.TestCase):
    def test_setgroups_write_failure_has_only_fixed_categories(self):
        result=b.launcher_diagnostics(b'', b'unshare: write failed /proc/self/setgroups: Permission denied PRIVATE_CANARY',1)
        self.assertEqual(result['launcher_categories'],['PERMISSION_DENIED','WRITE_FAILED','SETGROUPS_PATH'])
        self.assertNotIn('PRIVATE_CANARY',str(result))
        self.assertTrue(result['mapping_policy_restored'])

    def test_unknown_output_is_not_echoed(self):
        result=b.launcher_diagnostics(b'{"stage":"PRIVATE_CANARY","error":"PRIVATE_CANARY","errno":true}',b'PRIVATE_CANARY',2)
        self.assertEqual(result['stage'],'NAMESPACE_LAUNCH')
        self.assertIsNone(result['errno'])
        self.assertEqual(result['launcher_exit'],2)
        self.assertNotIn('PRIVATE_CANARY',str(result))

    def test_signal_exit_is_preserved(self):
        self.assertEqual(b.launcher_diagnostics(b'',b'',-11)['launcher_exit'],-11)

    def test_child_stage_is_preserved(self):
        result=b.launcher_diagnostics(b'{"stage":"CHROOT","error":"PermissionError","errno":13}',b'',2)
        self.assertEqual((result['stage'],result['error'],result['errno']),('CHROOT','PermissionError',13))

    def test_oversized_unknown_stdout_cannot_inject_fields(self):
        result=b.launcher_diagnostics(b'x'*16385,b'',1)
        self.assertEqual(result['stage'],'NAMESPACE_LAUNCH')
