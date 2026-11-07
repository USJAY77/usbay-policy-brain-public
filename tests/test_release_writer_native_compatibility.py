"""Actual unchanged release verifier in a minimal-environment child process.

Only task-owned synthetic files and ephemeral HMAC material; no Gateway import,
Git process, environment inheritance, operational authority or publication.
"""
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest

from tests import test_release_transaction_writer as transaction_fixtures
from security.runtime_artifact_provenance import canonical_bytes

OBSERVATIONS=[]
CONSUMER_FILES=("security/deployment_attestation.py","security/node_identity.py","security/tenant_context.py",
                "security/runtime_artifact_authority.py","security/runtime_artifact_provenance.py")


CHILD = r'''
import sys,json,hashlib
from pathlib import Path
from datetime import datetime
def no_transport(event,args):
    if event.startswith("subprocess.") or event in ("os.system","os.exec","socket.connect","socket.connect_ex","socket.bind"):
        raise RuntimeError("FORBIDDEN_CHILD_EFFECT")
sys.addaudithook(no_transport)
from security.deployment_attestation import validate_release_manifest,DeploymentAttestationError
manifest_path,node_path,raw_expected=sys.argv[1:]
expected=json.loads(raw_expected)
manifest=json.loads(Path(manifest_path).read_text())
commit=expected["git_commit"]
context={"expected_commit":commit,"current_commit":commit,"ci_mode":False,
         "accepted_commit_set":[commit],"ancestor_continuity":False,"release_lineage":True}
try:
    result=validate_release_manifest(manifest_path,expected_git_commit=commit,
        expected_policy_bundle_hash=expected["policy_bundle_hash"],expected_tenant_id="synthetic-tenant",
        expected_provenance_context=context,node_policy_path=node_path,
        now=datetime.fromisoformat("2026-11-07T12:00:00+00:00"))
    observed={"outcome":"PASS","signature_valid":result["release_signature_valid"],
              "release_hash":result["release_hash"],"gateway_imported":"gateway.app" in sys.modules}
except DeploymentAttestationError as error:
    observed={"outcome":"DENY","reason":str(error),"gateway_imported":"gateway.app" in sys.modules}
files=("security/deployment_attestation.py","security/node_identity.py","security/tenant_context.py",
       "security/runtime_artifact_authority.py","security/runtime_artifact_provenance.py")
observed["module_hashes"]={}
observed["module_origins_match"]=True
for relative in files:
    module=sys.modules[relative[:-3].replace("/",".")]
    path=Path(module.__file__).resolve()
    observed["module_origins_match"] &= path == Path(expected["source_root"])/relative
    observed["module_hashes"][relative]=hashlib.sha256(path.read_bytes()).hexdigest()
print(json.dumps(observed))
'''


class NativeReleaseCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OBSERVATIONS.clear()
        transaction_fixtures.ReleaseTransactionWriterTests.setUpClass()

    def setUp(self):
        self.fixture=transaction_fixtures.ReleaseTransactionWriterTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def native_verify(self, raw):
        fixture=self.fixture
        root=Path(fixture.temp.name)/"native-fixture"
        root.mkdir(mode=0o700,exist_ok=True)
        policies=root/"governance";policies.mkdir(mode=0o700,exist_ok=True)
        tenant={"allowed_tenant_ids":["synthetic-tenant"],"tenant_evidence_isolation":True,
                "tenant_export_permissions":{"synthetic-tenant":True},
                "tenant_retention_policy":{"synthetic-tenant":{"retention_days":1}}}
        (policies/"tenant_policy.json").write_text(json.dumps(tenant))
        node={"required_attestation_mode":"mock_local","allowed_node_roles":["gateway"],
              "attestation_ttl_seconds":60,"require_hardware_backing":False,"production_rejects_mock":True,
              "enrolled_nodes":{"synthetic":{"role":"gateway","public_identity":{"node_label":"synthetic-compat-node"}}}}
        node_path=policies/"node.json";node_path.write_text(json.dumps(node))
        manifest=root/"release-fixture.json";manifest.write_bytes(raw)
        env={"TMPDIR":str(root),"USBAY_ENV":"test","PYTHONDONTWRITEBYTECODE":"1",
             "USBAY_TENANT_POLICY_ROOT":str(root),"USBAY_TENANT_AUTHORITY_FIXTURE_ROOT":str(root),
             "USBAY_DEPLOYMENT_SIGNING_MATERIAL":fixture.signer.material.decode("ascii")}
        source_root=Path(__file__).resolve().parents[1]
        expected=json.dumps({"git_commit":fixture.state["source_commit"],"source_root":str(source_root),
                             "policy_bundle_hash":fixture.state["policy_bundle_hash"].split(":")[1]})
        result=subprocess.run([sys.executable,"-c",CHILD,str(manifest),str(node_path),expected],
            env=env,cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,"Native child did not complete")
        output=json.loads(result.stdout)
        self.assertFalse(output["gateway_imported"])
        self.assertTrue(output["module_origins_match"])
        self.assertEqual(output["module_hashes"],
                         {p:hashlib.sha256((source_root/p).read_bytes()).hexdigest() for p in CONSUMER_FILES})
        OBSERVATIONS.append({"case":self.id(),"observed":output})
        return output

    def stored_output(self):
        with sqlite3.connect(self.fixture.path) as db:
            return db.execute("SELECT output FROM outputs ORDER BY rowid DESC").fetchone()[0]

    def commit_output(self):
        self.assertEqual(self.fixture.writer.write(self.fixture.records,self.fixture.core).outcome,"COMMITTED")
        return self.stored_output()

    def resign(self, manifest):
        payload=dict(manifest);payload.pop("release_signature",None)
        signature="hmac-sha256:"+hmac.new(self.fixture.signer.material,canonical_bytes(payload),hashlib.sha256).hexdigest()
        return canonical_bytes(dict(payload,release_signature=signature))

    def test_writer_output_passes_existing_release_verifier(self):
        fixture=self.fixture
        output=self.native_verify(self.commit_output())
        self.assertEqual(output["outcome"],"PASS",output)
        self.assertTrue(output["signature_valid"])
        self.assertEqual(output["release_hash"],fixture.store.state()["predecessor_hash"].split(":")[1])

    def test_second_generation_passes_existing_release_verifier(self):
        self.commit_output()
        fixture=self.fixture;state=fixture.store.state();core=fixture.successor_core(state)
        def mutate(kind,payload):
            if kind=="request":payload["nonce"]="synthetic-next-nonce"
        records,trust=fixture.chain(mutate,state=state,core=core)
        source=transaction_fixtures.FixtureSource(records,trust,state)
        self.assertEqual(fixture.writer_for(authority_source=source).write(records,core).outcome,"COMMITTED")
        output=self.native_verify(self.stored_output())
        self.assertEqual(output["outcome"],"PASS",output)
        self.assertEqual(output["release_hash"],fixture.store.state()["predecessor_hash"].split(":")[1])

    def test_native_verifier_rejects_missing_history(self):
        manifest=json.loads(self.commit_output());del manifest["release_history"]
        output=self.native_verify(self.resign(manifest))
        self.assertEqual(output.get("reason"),"rollback_lineage_ambiguous")

    def test_native_verifier_rejects_wrong_predecessor(self):
        manifest=json.loads(self.commit_output());manifest["previous_release_hash"]="f"*64
        output=self.native_verify(self.resign(manifest))
        self.assertEqual(output.get("reason"),"previous_release_hash_mismatch")

    def test_native_verifier_rejects_invalid_hmac(self):
        manifest=json.loads(self.commit_output());manifest["release_signature"]="hmac-sha256:"+"0"*64
        output=self.native_verify(canonical_bytes(manifest))
        self.assertEqual(output.get("reason"),"release_signature_invalid")

    def test_native_verifier_rejects_wrong_bundle(self):
        manifest=json.loads(self.commit_output());manifest["policy_bundle_hash"]="0"*64
        output=self.native_verify(self.resign(manifest))
        self.assertEqual(output.get("reason"),"policy_bundle_hash_mismatch")

    def test_native_verifier_rejects_unaccepted_commit(self):
        manifest=json.loads(self.commit_output());manifest["git_commit"]="f"*40
        output=self.native_verify(self.resign(manifest))
        self.assertEqual(output.get("reason"),"git_commit_mismatch")

    def test_native_verifier_rejects_future_timestamp(self):
        manifest=json.loads(self.commit_output());manifest["deployment_timestamp"]="2026-11-07T12:01:00Z"
        output=self.native_verify(self.resign(manifest))
        self.assertEqual(output.get("reason"),"deployment_timestamp_invalid")

    def test_native_verifier_rejects_unknown_node(self):
        manifest=json.loads(self.commit_output());manifest["activating_node_id"]="unknown-node"
        output=self.native_verify(self.resign(manifest))
        self.assertEqual(output.get("reason"),"activating_node_unknown")


if __name__=="__main__":unittest.main()
