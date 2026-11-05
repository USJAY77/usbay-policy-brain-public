"""Pure inert harness tests. Never import product, crypto or native case driver."""
import ast
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import runtime_dependencies as d
import runtime_artifact_contract as c


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.source = 'a'*64
        self.dependencies = 'b'*64
        self.value = {'schema': c.SCHEMA, 'source_binding': self.source,
                      'dependency_binding': self.dependencies,
                      'reports': dict.fromkeys(c.CASE_NAMES, 'passed'),
                      'tests_run': len(c.CASE_NAMES), 'execution_authorized': False}

    def test_exact_complete_report(self):
        self.assertTrue(c.result_pass(self.value, self.source, self.dependencies))

    def test_neither_source_nor_dependency_binding_optional(self):
        for source, dependencies in [('',self.dependencies),(self.source,''),('c'*64,self.dependencies),(self.source,'c'*64)]:
            self.assertFalse(c.result_pass(self.value, source, dependencies))

    def test_unknown_failed_missing_and_extra_cases_rejected(self):
        for outcome in ['UNKNOWN', 'skipped', 'failed', 'error', True]:
            value = copy.deepcopy(self.value)
            value['reports'][c.CASE_NAMES[0]] = outcome
            self.assertFalse(c.result_pass(value,self.source,self.dependencies))
        value = copy.deepcopy(self.value)
        value['reports'].pop(c.CASE_NAMES[0])
        self.assertFalse(c.result_pass(value,self.source,self.dependencies))
        value['reports']['arbitrary_test'] = 'passed'
        self.assertFalse(c.result_pass(value,self.source,self.dependencies))

    def test_authority_boolean_count_and_extra_data_rejected(self):
        for change in [{'execution_authorized':True},{'tests_run':True},{'raw':'PRIVATE_CANARY'}]:
            self.assertFalse(c.result_pass(self.value|change,self.source,self.dependencies))

    def test_bounded_diagnostic_drops_raw_values(self):
        value = copy.deepcopy(self.value)
        value['raw'] = 'PRIVATE_CANARY'
        value['reports'][c.CASE_NAMES[0]] = 'PRIVATE_CANARY'
        self.assertNotIn('PRIVATE_CANARY',json.dumps(c.bounded_result(value)))
        self.assertEqual(c.bounded_result(None),{'reported_tests_run':None,'reports':{}})

    def test_complete_failure_proves_execution_only(self):
        value = copy.deepcopy(self.value)
        value['reports'][c.CASE_NAMES[0]] = 'failed'
        self.assertTrue(c.result_structure_pass(value,self.source,self.dependencies))
        self.assertFalse(c.result_pass(value,self.source,self.dependencies))

    def test_native_driver_selection_is_exact_without_import(self):
        tree = ast.parse(Path(__file__).with_name('runtime_artifact_cases.py').read_bytes())
        cls = next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='RuntimeArtifactCases')
        names = [n.name for n in cls.body if isinstance(n,ast.FunctionDef) and n.name.startswith('test_')]
        self.assertEqual(set(names),set(c.CASE_NAMES))
        self.assertEqual(len(names),len(c.CASE_NAMES))
        self.assertEqual(len(c.CASE_NAMES),len(set(c.CASE_NAMES)))
        self.assertFalse(any(n.split('.')[0] in {'security','cryptography','cffi','pycparser','_cffi_backend','runtime_artifact_cases'} for n in sys.modules))

    def test_source_export_covers_native_modules(self):
        import offline_mail_contract as mail
        for name in ['runtime_artifact_cases.py','runtime_artifact_contract.py','runtime_dependencies.py','runtime_crypto.lock',
                     'security/__init__.py','security/runtime_artifact_provenance.py','security/runtime_artifact_authority.py']:
            self.assertIn(name,mail.SOURCE_MAP)


class DependencyTests(unittest.TestCase):
    def wheel(self, files=None, metadata=None):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream,'w') as out:
            out.writestr('cryptography-50.0.2.dist-info/METADATA',metadata or b'Name: cryptography\nVersion: 50.0.2\n')
            for name, data in (files or {'cryptography/__init__.py': b'# inert\n'}).items():
                out.writestr(name,data)
        raw=stream.getvalue()
        profile={'cryptography':{'version':'50.0.2','hashes':{hashlib.sha256(raw).hexdigest()}}}
        return raw,profile

    def test_existing_profile_exact_hash_and_pins(self):
        raw=Path(__file__).with_name('runtime_crypto.lock').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),d.PROFILE_SHA256)
        self.assertEqual({k:v['version'] for k,v in d.profile_packages(raw).items()},d.PACKAGES)

    def test_profile_must_be_subset_of_existing_lock(self):
        raw=Path(__file__).with_name('runtime_crypto.lock').read_bytes()
        full=Path(__file__).resolve().parents[2].joinpath('staging/requirements-python311.lock').read_bytes()
        for name,item in d.profile_packages(raw).items():
            self.assertIn((name+'=='+item['version']).encode(),full)
            for digest in item['hashes']:
                self.assertIn(('--hash=sha256:'+digest).encode(),full)

    def test_missing_unknown_or_option_profile_fails(self):
        for raw in [b'',b'--index-url https://invalid\n',b'cryptography==0.0\n',b'other==1.0\n', b'cryptography==50.0.2\n']:
            with self.assertRaises(RuntimeError):d.profile_packages(raw)

    def test_duplicate_pin_rejected(self):
        raw=Path(__file__).with_name('runtime_crypto.lock').read_bytes()
        with self.assertRaises(RuntimeError):d.profile_packages(raw+b'\ncryptography==50.0.2\n')

    def test_archive_hash_required_before_zip_parsing(self):
        with self.assertRaises(RuntimeError):d.wheel_members(b'not a zip',{})

    def test_exact_inert_wheel_passes(self):
        raw,profile=self.wheel()
        name,members=d.wheel_members(raw,profile)
        self.assertEqual(name,'cryptography')
        self.assertEqual(members['cryptography/__init__.py'],b'# inert\n')

    def test_traversal_hooks_unknown_roots_and_controls_rejected(self):
        for name in ['../escape','/escape','cryptography/../escape','cryptography//escape','cryptography/./escape',
                     'cryptography/back\\slash','cryptography/a.pth','cryptography/a.pyc','unknown/file','cryptography/a\nfile']:
            raw,profile=self.wheel({name:b'inert'})
            with self.assertRaises(RuntimeError):d.wheel_members(raw,profile)

    def test_metadata_mismatch_rejected(self):
        for meta in [b'Name: other\nVersion: 50.0.2\n',b'Name: cryptography\nVersion: 0\n',b'Name: cryptography\nName: other\nVersion: 50.0.2\n']:
            raw,profile=self.wheel(metadata=meta)
            with self.assertRaises(RuntimeError):d.wheel_members(raw,profile)

    def test_symlink_and_special_members_rejected(self):
        for mode in [stat.S_IFLNK|0o777,stat.S_IFIFO|0o600,stat.S_IFREG|0o4600]:
            stream=io.BytesIO()
            with zipfile.ZipFile(stream,'w') as out:
                item=zipfile.ZipInfo('cryptography/item');item.external_attr=mode<<16
                out.writestr(item,b'inert')
            raw=stream.getvalue()
            with self.assertRaises(RuntimeError):d.wheel_members(raw,{'cryptography':{'hashes':{hashlib.sha256(raw).hexdigest()}}})

    def test_duplicate_zip_member_rejected(self):
        import warnings
        stream=io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore',UserWarning)
            with zipfile.ZipFile(stream,'w') as out:
                out.writestr('cryptography/file',b'inert')
                out.writestr('cryptography/file',b'inert')
        raw=stream.getvalue()
        with self.assertRaises(RuntimeError):d.wheel_members(raw,{'cryptography':{'hashes':{hashlib.sha256(raw).hexdigest()}}})

    def test_archive_limits_enforced(self):
        raw,profile=self.wheel()
        with patch.object(d,'MAX_ARCHIVE',1),self.assertRaises(RuntimeError):d.wheel_members(raw,profile)
        with patch.object(d,'MAX_FILES',1),self.assertRaises(RuntimeError):d.wheel_members(raw,profile)
        with patch.object(d,'MAX_TOTAL',1),self.assertRaises(RuntimeError):d.wheel_members(raw,profile)

    def tree(self):
        temporary=tempfile.TemporaryDirectory(prefix='inert-dependency-tree-')
        self.addCleanup(temporary.cleanup)
        root=Path(temporary.name)
        files={'cryptography/__init__.py':b'# inert\n'}
        manifest=d.dependency_manifest(files,dict.fromkeys(d.PACKAGES,'a'*64))
        (root/'cryptography').mkdir(mode=0o700)
        for name,raw in files.items():(root/name).write_bytes(raw)
        (root/'.usbay-dependencies.json').write_bytes(d.canonical(manifest))
        return root,manifest

    def test_exact_inert_tree_passes(self):
        root,manifest=self.tree()
        d.verify_tree(root,manifest,(os.getuid(),os.getgid()))

    def test_changed_missing_extra_and_symlink_tree_fail(self):
        for mutation in ['changed','missing','extra','symlink','extra_directory','writable']:
            root,manifest=self.tree()
            p=root/'cryptography/__init__.py'
            if mutation=='changed':p.write_bytes(b'changed')
            elif mutation=='missing':p.unlink()
            elif mutation=='extra':(root/'extra').write_bytes(b'inert')
            elif mutation=='extra_directory':(root/'extra').mkdir()
            elif mutation=='writable':p.chmod(0o666)
            else:
                p.unlink();p.symlink_to('/nonexistent')
            with self.assertRaises((RuntimeError,FileNotFoundError)):d.verify_tree(root,manifest)

    def test_manifest_shape_and_traversal_rejected(self):
        root,manifest=self.tree()
        for change in [{'files':{'../escape':'a'*64}}, {'archives':{}}, {'packages':{}}, {'extra':True}, {'python':[3,11]}, {'files':None}]:
            with self.assertRaises(RuntimeError):d.verify_tree(root,manifest|change)

    def test_hardlink_file_rejected(self):
        root,manifest=self.tree()
        os.link(root/'cryptography/__init__.py',root/'linked')
        with self.assertRaises(RuntimeError):d.verify_tree(root,manifest)

    def test_wheel_set_must_have_exact_three(self):
        with tempfile.TemporaryDirectory() as name:
            base=Path(name);(base/'wheels').mkdir()
            with self.assertRaises(RuntimeError):d.expected_from_wheels(base,{})

    def test_wrong_owner_rejected(self):
        root,manifest=self.tree()
        with self.assertRaises(RuntimeError):d.verify_tree(root,manifest,(os.getuid()+1,os.getgid()))

    def test_root_context_stops_before_download(self):
        with patch.object(d.os,'geteuid',return_value=0),patch.object(d.subprocess,'run') as run:
            with self.assertRaises(RuntimeError):d.prepare_dependencies(Path('/unused'))
            run.assert_not_called()

    def test_wrong_python_stops_before_download(self):
        with patch.object(d.os,'geteuid',return_value=1001),patch.object(d.sys,'version_info',(3,11)),patch.object(d.subprocess,'run') as run:
            with self.assertRaises(RuntimeError):d.prepare_dependencies(Path('/unused'))
            run.assert_not_called()


class IntegrationBoundaryTests(unittest.TestCase):
    def test_fresh_child_orders_gates_and_bindings_before_product_import(self):
        tree=ast.parse(Path(__file__).with_name('isolation_preflight.py').read_bytes())
        inside=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='inside')
        probe=next(n.value.value for n in ast.walk(inside)
                   if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='probe' for t in n.targets))
        ast.parse(probe)
        # Check actual fresh-child sequence rather than importing the native driver.
        required=['fresh_exec_gate = install_no_exec()', 'if not preconditions_pass(',
                  'binding = verify_payload(', 'dependency_evidence = activate_dependencies(',
                  'from runtime_artifact_cases import run', 'runtime_artifact_result = run_runtime(']
        offsets=[probe.index(value) for value in required]
        self.assertEqual(offsets,sorted(offsets))
        self.assertIn("verify_tree(pathlib.Path('/dependencies'), json.loads(dependency_raw))",probe)

    def test_download_command_has_no_install_build_or_dependency_resolution(self):
        profile=Path(__file__).with_name('runtime_crypto.lock').read_bytes()
        with tempfile.TemporaryDirectory() as name:
            base=Path(name);(base/'source').mkdir();(base/'source/runtime_crypto.lock').write_bytes(profile)
            with patch.object(d.os,'geteuid',return_value=1001),patch.object(d.sys,'version_info',(3,12)), \
                 patch.object(d.subprocess,'run') as run:
                run.return_value.returncode=1
                with self.assertRaisesRegex(RuntimeError,'RUNTIME_DEPENDENCY_DOWNLOAD_FAILED'):
                    d.prepare_dependencies(base)
                argv=run.call_args.args[0]
                self.assertEqual(argv[:6],[sys.executable,'-I','-B','-m','pip','download'])
                for flag in ['--only-binary=:all:','--no-deps','--require-hashes','--no-cache-dir']:
                    self.assertIn(flag,argv)
                self.assertEqual(argv[argv.index('--index-url')+1],'https://pypi.org/simple')
                self.assertNotIn('install',argv)
                self.assertEqual(run.call_args.kwargs['env']['PIP_CONFIG_FILE'],'/dev/null')
                self.assertEqual(run.call_args.kwargs['timeout'],120)

    def test_diagnostics_never_include_wheel_output(self):
        tree=ast.parse(Path(__file__).with_name('runtime_dependencies.py').read_bytes())
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
               and isinstance(n.func.value,ast.Name) and n.func.value.id=='subprocess' and n.func.attr=='run']
        self.assertEqual(len(calls),1)
        keywords={k.arg:ast.unparse(k.value) for k in calls[0].keywords}
        self.assertEqual(keywords['stdout'],'subprocess.DEVNULL')
        self.assertEqual(keywords['stderr'],'subprocess.DEVNULL')


class SymlinkFixtureConstructionTests(unittest.TestCase):
    def test_symlink_fixtures_require_no_cross_directory_rename(self):
        # Execute only inert path-construction prefixes: no product or crypto imports,
        # no signature creation, verification, native filter or privileged operation.
        from types import SimpleNamespace
        tree=ast.parse(Path(__file__).with_name('runtime_artifact_cases.py').read_bytes())
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='RuntimeArtifactCases')
        for name in ['test_file_symlink','test_parent_symlink']:
            method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name==name)
            calls=[n for n in ast.walk(method) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)]
            self.assertFalse(any(n.func.attr in {'rename','replace','link_to','hardlink_to'} for n in calls))
            prefix=[]
            for node in method.body:
                if (isinstance(node,ast.Expr) and isinstance(node.value,ast.Call)
                        and isinstance(node.value.func,ast.Attribute) and node.value.func.attr=='reject'):
                    break
                if isinstance(node,ast.Assign) and any(isinstance(n,ast.Attribute) and n.attr=='manifest'
                                                       for n in ast.walk(node.targets[0])):
                    break
                prefix.append(node)
            with tempfile.TemporaryDirectory(prefix='inert-symlink-fixture-') as temporary:
                base=Path(temporary);root=base/'package';root.mkdir()
                file=root/'application.py';raw=b'# inert fixture bytes\n';file.write_bytes(raw)
                fixture=SimpleNamespace(base=base,root=root,file=file)
                exec(compile(ast.Module(body=prefix,type_ignores=[]),'<inert-fixture-prefix>','exec'),{'self':fixture})
                link=file if name=='test_file_symlink' else root/'linked'
                target=file if name=='test_file_symlink' else root/'linked/application.py'
                self.assertTrue(link.is_symlink())
                self.assertEqual(target.read_bytes(),raw)
                self.assertFalse(any(n.split('.')[0] in {'security','cryptography','cffi','runtime_artifact_cases'} for n in sys.modules))
