import unittest
from gidmap_guard import apply_group_map, mapping_text, target_binding


class GidMapOrderTests(unittest.TestCase):
    def setUp(self):
        self.state={'uid_map':b'0 1001 1\n','gid_map':b'','setgroups':b'allow\n'}
        self.events=[]

    def write(self,name,data):
        # Simulate the documented kernel rule: deny after gid_map is forbidden.
        if name=='setgroups' and self.state['gid_map']:
            raise PermissionError('KERNEL_DENY_AFTER_GID_MAP')
        if name=='gid_map' and self.state['setgroups'].strip()!=b'deny':
            raise PermissionError('GROUPS_NOT_DENIED')
        self.events.append(name);self.state[name]=data

    def test_denial_precedes_gid_mapping_and_final_state_is_exact(self):
        apply_group_map(self.state.__getitem__,self.write,1001,1002)
        self.assertEqual(self.events,['setgroups','gid_map'])
        self.assertEqual(self.state['gid_map'],b'0 1002 1\n')

    def test_existing_denial_is_not_written_again(self):
        self.state['setgroups']=b'deny\n'
        apply_group_map(self.state.__getitem__,self.write,1001,1002)
        self.assertEqual(self.events,['gid_map'])

    def test_denial_write_failure_never_publishes_gid_map(self):
        def fail(name,data):raise PermissionError('DENIED')
        with self.assertRaises(PermissionError):apply_group_map(self.state.__getitem__,fail,1001,1002)
        self.assertEqual(self.state['gid_map'],b'')

    def test_ineffective_denial_never_publishes_gid_map(self):
        with self.assertRaisesRegex(RuntimeError,'DENIAL_NOT_PROVEN'):
            apply_group_map(self.state.__getitem__,lambda name,data:None,1001,1002)
        self.assertEqual(self.state['gid_map'],b'')

    def test_existing_gid_map_is_not_overwritten(self):
        self.state['gid_map']=b'0 2000 1\n'
        with self.assertRaises(RuntimeError):apply_group_map(self.state.__getitem__,self.write,1001,1002)
        self.assertEqual(self.events,[])

    def test_wrong_uid_binding_blocks_both_writes(self):
        self.state['uid_map']=b'0 2000 1\n'
        with self.assertRaises(RuntimeError):apply_group_map(self.state.__getitem__,self.write,1001,1002)
        self.assertEqual(self.events,[])

    def test_missing_setgroups_state_blocks_mapping(self):
        self.state['setgroups']=b''
        with self.assertRaises(RuntimeError):apply_group_map(self.state.__getitem__,self.write,1001,1002)
        self.assertEqual(self.events,[])

    def test_short_or_wrong_mapping_is_not_success(self):
        def write(name,data):self.state[name]=b'deny\n' if name=='setgroups' else b'0 1002 2\n'
        with self.assertRaisesRegex(RuntimeError,'FINAL_STATE_INVALID'):
            apply_group_map(self.state.__getitem__,write,1001,1002)

    def test_root_and_untyped_ids_are_rejected(self):
        for uid,gid in ((0,1001),(1001,0),(True,1001),(1001,'1002')):
            with self.subTest(uid=uid,gid=gid),self.assertRaises(RuntimeError):mapping_text(uid,gid)


class GidMapTargetTests(unittest.TestCase):
    def test_exact_parent_and_single_gid_binding(self):
        self.assertEqual(target_binding(['123','0','1002','1'],123,1002),123)

    def test_other_pid_rejected(self):
        with self.assertRaises(RuntimeError):target_binding(['124','0','1002','1'],123,1002)

    def test_root_broad_and_changed_inner_mapping_rejected(self):
        for fields in (['123','0','0','1'],['123','0','1002','2'],['123','1','1002','1']):
            with self.subTest(fields=fields),self.assertRaises(RuntimeError):target_binding(fields,123,1002)

    def test_malformed_or_extra_argument_rejected(self):
        for fields in (['123','0','1002'],['123','0','1002','1','extra'],['123','0','*','1'],['9'*11,'0','1002','1']):
            with self.subTest(fields=fields),self.assertRaises(RuntimeError):target_binding(fields,123,1002)

    def test_init_pid_or_invalid_parent_is_rejected(self):
        for target,parent in (('1',1),('0',0),('123',True)):
            with self.subTest(target=target,parent=parent),self.assertRaises(RuntimeError):target_binding([target,'0','1002','1'],parent,1002)
