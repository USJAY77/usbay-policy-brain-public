"""Immutable-source projection tests use only disposable synthetic Git repos."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
SPEC=importlib.util.spec_from_file_location('usbay_component_projection',ROOT/'validation/rfc3161/project_source.py')
projection=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(projection)


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.base=Path(self.temporary.name);self.source=self.base/'source';self.source.mkdir()
        self.target=self.base/'projected'
        self.git('init','--initial-branch=fixture')
        self.file=self.source/'audit/public.py';self.file.parent.mkdir();self.file.write_bytes(b'PUBLIC_COMMITTED_SOURCE\n')
        self.manifest=self.source/projection.MANIFEST;self.manifest.parent.mkdir(parents=True)
        self.write_manifest([projection.MANIFEST,'audit/public.py']);self.commit()

    def git(self,*args):
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1',
             'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null'}
        proc=subprocess.run(['/usr/bin/git','-c','user.name=USBAY Test Fixture',
            '-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false',*args],
            cwd=self.source,env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True)
        return proc.stdout.decode().strip()

    def write_manifest(self,files):
        self.manifest.write_text(json.dumps({'schema':'usbay.native_component_projection.v1','files':files}))

    def commit(self):
        self.git('add','.');self.git('commit','-m','Synthetic source projection fixture')
        self.sha=self.git('rev-parse','HEAD');self.tree=self.git('rev-parse','HEAD^{tree}')

    def project(self,**changes):
        args={'commit':self.sha,'tree':self.tree};args.update(changes)
        return projection.project(self.source,self.target,**args)

    def reject(self,code,**changes):
        with self.assertRaises(projection.ProjectionError) as raised:self.project(**changes)
        self.assertEqual(str(raised.exception),code)

    def test_exact_committed_bytes_and_receipt(self):
        result=self.project();self.assertEqual(result['commit'],self.sha)
        self.assertEqual((self.target/'audit/public.py').read_bytes(),b'PUBLIC_COMMITTED_SOURCE\n')
        self.assertEqual(set(result['files']),{projection.MANIFEST,'audit/public.py'})
        self.assertNotIn('authority',result)

    def test_working_tree_changes_are_not_projected(self):
        self.file.write_bytes(b'UNCOMMITTED_OVERRIDE')
        self.project();self.assertEqual((self.target/'audit/public.py').read_bytes(),b'PUBLIC_COMMITTED_SOURCE\n')
        self.assertEqual(self.file.read_bytes(),b'UNCOMMITTED_OVERRIDE')

    def test_untracked_data_is_not_projected(self):
        (self.source/'untracked-data').write_bytes(b'UNTRACKED_CANARY')
        self.project();self.assertFalse((self.target/'untracked-data').exists())

    def test_wrong_commit(self):self.reject('SOURCE_IDENTITY_MISMATCH',commit='0'*40)

    def test_wrong_tree(self):self.reject('SOURCE_IDENTITY_MISMATCH',tree='0'*40)

    def test_nonhex_reference(self):self.reject('SOURCE_REFERENCE_INVALID',commit='HEAD; injected')

    def test_duplicate_paths(self):
        self.write_manifest([projection.MANIFEST,'audit/public.py','audit/public.py']);self.commit()
        self.reject('SOURCE_MANIFEST_INVALID')

    def test_path_traversal(self):
        self.write_manifest([projection.MANIFEST,'../outside']);self.commit();self.reject('SOURCE_PATH_INVALID')

    def test_receipt_path_cannot_overwrite_source(self):
        self.write_manifest([projection.MANIFEST,'component-projection-receipt.json']);self.commit()
        self.reject('SOURCE_MANIFEST_INVALID')

    def test_missing_tracked_file(self):
        self.write_manifest([projection.MANIFEST,'audit/missing.py']);self.commit();self.reject('SOURCE_FILE_MISSING')

    def test_symlink_is_not_a_regular_source_file(self):
        self.file.unlink();self.file.symlink_to('../outside');self.commit();self.reject('SOURCE_FILE_TYPE_INVALID')

    def test_existing_destination_is_not_overwritten(self):
        self.target.mkdir();marker=self.target/'keep';marker.write_bytes(b'PRESERVE')
        self.reject('PROJECTION_DESTINATION_INVALID');self.assertEqual(marker.read_bytes(),b'PRESERVE')

    def test_destination_cannot_be_inside_source(self):
        self.target=self.source/'new-output';self.reject('PROJECTION_DESTINATION_INVALID')

    def test_oversized_committed_blob(self):
        self.file.write_bytes(b'x'*(projection.MAX_FILE+1));self.commit();self.reject('SOURCE_FILE_TOO_LARGE')

    def test_duplicate_manifest_key(self):
        self.manifest.write_text('{"schema":"usbay.native_component_projection.v1","files":[],"files":[]}')
        self.commit();self.reject('SOURCE_MANIFEST_INVALID')

    def test_source_change_during_projection_is_rejected(self):
        actual=projection._git;changed=False
        def git_then_mutate(root,*args):
            nonlocal changed
            if self.target.exists() and not changed and args==('rev-parse','HEAD'):
                changed=True;self.file.write_bytes(b'CONCURRENT_COMMIT');self.commit()
            return actual(root,*args)
        with patch.object(projection,'_git',side_effect=git_then_mutate):
            self.reject('SOURCE_CHANGED_DURING_PROJECTION')
        self.assertFalse((self.target/'component-projection-receipt.json').exists())

    def test_projected_source_reverification(self):
        self.project();result=projection.verify_projection(self.source,self.target,commit=self.sha,tree=self.tree)
        self.assertEqual(result['status'],'PROJECTED_SOURCE_REVERIFIED')

    def test_projected_source_tampering_is_rejected(self):
        self.project();(self.target/'audit/public.py').write_bytes(b'REPLACED')
        with self.assertRaises(projection.ProjectionError) as raised:
            projection.verify_projection(self.source,self.target,commit=self.sha,tree=self.tree)
        self.assertEqual(str(raised.exception),'PROJECTED_SOURCE_CHANGED')


if __name__=='__main__':unittest.main()
