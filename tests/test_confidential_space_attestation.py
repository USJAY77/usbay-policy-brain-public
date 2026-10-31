"""Synthetic issuers/workloads only; real RSA signatures, UDS and native workers."""
import base64
import concurrent.futures
from copy import deepcopy
from dataclasses import replace
import hashlib
import http.server
import json
import os
from pathlib import Path
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from security import confidential_space_attestation as cs
from security.decision_evidence_consumption_store import SQLiteDecisionEvidenceConsumptionStore
from security.hydra_nodes import InProcessHydraNode, SubprocessHydraNode
from security.request_signing import sign_request_payload, request_signature_message
from security.runtime_attestation import AttestationError

pytestmark = [pytest.mark.governance, pytest.mark.regression]


def encoded(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    monkeypatch.chdir(tmp_path)
    (tmp_path/"governance").mkdir()
    for name in ["node_attestation_policy.json","tenant_policy.json","replay_policy.json","policy_registry.json"]:
        (tmp_path/"governance"/name).write_bytes((root/"governance"/name).read_bytes())
    policy = json.loads((tmp_path/"governance/node_attestation_policy.json").read_text())
    policy.update(required_attestation_mode="external_attestation_service", require_hardware_backing=True)
    (tmp_path/"governance/node_attestation_policy.json").write_text(json.dumps(policy))
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    request_key = ed25519.Ed25519PrivateKey.generate()
    public_path = tmp_path/"request.pub"
    public_path.write_bytes(request_key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    request_config = tmp_path/"request-keys.json"
    request_config.write_text(json.dumps({"active_keys":["synthetic-request"],"revoked_keys":[],"key_map":{"synthetic-request":str(public_path)}}))
    monkeypatch.setenv("USBAY_REQUEST_SIGNING_KEY_CONFIG_PATH",str(request_config))
    monkeypatch.setenv("USBAY_ENV","test")
    monkeypatch.setenv("USBAY_NODE_ATTESTATION_ADAPTER",cs.PROFILE)
    for name in ["REDIS_URL","USBAY_REDIS_URL","HYDRA_NODE_URLS","USBAY_HYDRA_BACKEND"]:
        monkeypatch.delenv(name,raising=False)
    db=tmp_path/"attestation-replay.db"
    # Explicit synthetic provisioning using the unchanged existing store.
    SQLiteDecisionEvidenceConsumptionStore(db)._connect().close()
    now=int(time.time())
    enrollment=dict(role="primary",tenants=["t1"],project_id="synthetic-project",project_number="123456789",service_account="synthetic@synthetic-project.iam.gserviceaccount.com",image_digest="sha256:"+"a"*64,image_reference="synthetic.invalid/workload@sha256:"+"a"*64,subjects=["synthetic-instance-1"],args=["/opt/venv/bin/python","-m","staging.launch"],env={},swversions=[["20261000"]],hardware_models=["GCP_AMD_SEV"])
    config=dict(profile=cs.PROFILE,issuer=cs.ISSUER,audience="https://synthetic.invalid/usbay-node",synthetic_fixture=True,launcher_socket="",acquisition_timeout_seconds=.3,snapshot_issued_at=now-10,snapshot_expires_at=now+600,max_token_lifetime_seconds=300,replay_db=str(db),keys={"synthetic-rsa":dict(public_pem=rsa_key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode(),not_before=now-100,not_after=now+600,revoked=False)},nodes={"node-1":enrollment,"node-2":dict(enrollment,role="secondary")})
    # swversions is an allowlist of exact arrays, matching the documented claim type.
    config["nodes"]["node-1"]["swversions"]=["20261000"]
    config["nodes"]["node-2"]["swversions"]=["20261000"]
    def sign(claims,header=None,raw_claims=None,raw_header=None):
        h=encoded(raw_header or cs.canonical(header or {"alg":"RS256","kid":"synthetic-rsa","typ":"JWT"}))
        c=encoded(raw_claims or cs.canonical(claims))
        sig=rsa_key.sign((h+"."+c).encode(),padding.PKCS1v15(),hashes.SHA256())
        return h+"."+c+"."+encoded(sig)
    def claims(nonce):
        n=int(time.time());en=config["nodes"]["node-1"]
        return dict(iss=config["issuer"],aud=config["audience"],iat=n,nbf=n-1,exp=n+120,eat_nonce=[nonce],sub=en["subjects"][0],google_service_accounts=[en["service_account"]],oemid=11129,dbgstat="disabled-since-boot",secboot=True,swname="CONFIDENTIAL_SPACE",swversion=["20261000"],hwmodel="GCP_AMD_SEV",submods=dict(gce=dict(project_id=en["project_id"],project_number=en["project_number"]),container=dict(image_digest=en["image_digest"],image_reference=en["image_reference"],args=en["args"],env={},cmd_override=[],env_override={}),confidential_space=dict(support_attributes=["STABLE","USABLE"])))
    def request(node="node-1"):
        raw=dict(actor_id="synthetic-actor",nonce=os.urandom(16).hex(),timestamp=int(time.time()),tenant_id="t1",policy_version="1.0",action="synthetic-decision-only")
        private=request_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        signed=sign_request_payload(raw,private,"synthetic-request")
        rh=hashlib.sha256(request_signature_message(signed).encode()).hexdigest()
        from security.policy_registry import validate_policy_registry_shape,policy_hash
        registry=validate_policy_registry_shape(cs.decode(Path('governance/policy_registry.json').read_bytes()))
        context=dict(tenant_id="t1",policy_hash=policy_hash(registry),nonce_hash=hashlib.sha256(raw["nonce"].encode()).hexdigest(),attestation_timestamp=time.time(),confidential_space_signed_request=signed)
        return node,rh,"1.0",context
    short=tempfile.TemporaryDirectory(prefix="cs-",dir="/private/tmp")
    sock=str(Path(short.name)/"launcher.sock")
    monkeypatch.setenv("USBAY_TEST_ALLOWED_SOCKET",sock)
    config["launcher_socket"]=sock
    control={"status":200,"delay":0,"malformed":False,"calls":0,"mutate":lambda c:None}
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            control["calls"]+=1
            assert self.path=="/v1/token"
            data=cs.decode(self.rfile.read(int(self.headers["Content-Length"])))
            assert data["token_type"]=="OIDC" and data["audience"]==config["audience"] and len(data["nonces"])==1
            payload=claims(data["nonces"][0]);control["mutate"](payload)
            time.sleep(control["delay"])
            result=b"not-a-token" if control["malformed"] else sign(payload).encode()
            try:
                self.send_response(control["status"]);self.end_headers();self.wfile.write(result)
            except BrokenPipeError:pass
        def log_message(self,*args):pass
    class Server(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):
        daemon_threads=True
    server=None;thread=None
    def start_launcher():
        nonlocal server,thread
        server=Server(sock,Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    trust=tmp_path/"trust.json"
    def write():trust.write_bytes(cs.canonical(config))
    write();monkeypatch.setenv("USBAY_CONFIDENTIAL_SPACE_TRUST_PATH",str(trust))
    yield dict(config=config,sign=sign,claims=claims,request=request,control=control,write=write,tmp=tmp_path,start_launcher=start_launcher)
    if server is not None:
        server.shutdown();server.server_close();thread.join(timeout=2)
    short.cleanup()


def packet(f,node="node-1"):
    args=f["request"](node);config,policy=cs.settings()
    # Socket-free cryptographic unit fixture; real launcher protocol tested separately.
    raw=cs.produce(*args,config,policy,acquire=lambda audience,nonce:f["sign"](f["claims"](nonce)))
    return raw,cs.scope(*args),config,policy


def test_in_process_connected(fixture,caplog):
    fixture["start_launcher"]()
    result=InProcessHydraNode().evaluate(*fixture["request"]()[1:])
    assert result.decision=="allow" and result.hardware_backed and result.attestation_provider_mode=="external_attestation_service"
    assert fixture["control"]["calls"]==1
    assert "VERIFIED" in caplog.text and "synthetic-actor" not in caplog.text and "eyJ" not in caplog.text


def test_real_worker_connected_without_deadline_extension(fixture):
    fixture["start_launcher"]()
    args=fixture["request"]("node-2")
    result=SubprocessHydraNode().evaluate(*args[1:])
    assert result.node_id=="node-2" and result.hardware_backed
    with pytest.raises(cs.AttestationRejected,match="REPLAY"):
        SubprocessHydraNode().evaluate(*args[1:])


@pytest.mark.parametrize("fault,code",[
    ("issuer","ISSUER_AUDIENCE"),("audience","ISSUER_AUDIENCE"),("challenge","CHALLENGE_RESPONSE"),
    ("expired","TIME"),("future","TIME"),("nbf","TIME"),("expiry_equality","TIME"),("bool_time","TIME"),
    ("debug","PLATFORM"),("boot","PLATFORM"),("platform","PLATFORM"),("software","PLATFORM"),
    ("version","PLATFORM"),("support","PLATFORM"),("image","MEASUREMENT"),("image_id_only","MEASUREMENT"),
    ("args","MEASUREMENT"),("env_override","MEASUREMENT"),("cmd_override","MEASUREMENT"),
    ("project","WORKLOAD"),("subject","WORKLOAD"),("service_account","WORKLOAD"),
])
def test_signed_claim_negatives_reach_target(fixture,fault,code):
    raw,expected,cfg,policy=packet(fixture);env=cs.decode(raw);claims=fixture["claims"](cs.commitment(env["response"],expected));now=time.time()
    if fault=="issuer":claims["iss"]="https://synthetic-wrong.invalid"
    elif fault=="audience":claims["aud"]="wrong-audience"
    elif fault=="challenge":claims["eat_nonce"]=["0"*64]
    elif fault=="expired":claims.update(iat=int(now)-100,nbf=int(now)-101,exp=int(now)-1)
    elif fault=="future":claims["iat"]=int(now)+100
    elif fault=="nbf":claims["nbf"]=int(now)+100
    elif fault=="expiry_equality":claims["exp"]=claims["iat"]+1;now=claims["exp"]
    elif fault=="bool_time":claims["iat"]=True
    elif fault=="debug":claims["dbgstat"]="enabled"
    elif fault=="boot":claims["secboot"]=False
    elif fault=="platform":claims["hwmodel"]="GCP_SHIELDED_VM"
    elif fault=="software":claims["swname"]="GCE"
    elif fault=="version":claims["swversion"]=["unapproved"]
    elif fault=="support":claims["submods"]["confidential_space"]["support_attributes"]=["EXPERIMENTAL"]
    elif fault=="image":claims["submods"]["container"]["image_digest"]="sha256:"+"b"*64
    elif fault=="image_id_only":claims["submods"]["container"]["image_id"]=claims["submods"]["container"].pop("image_digest")
    elif fault=="args":claims["submods"]["container"]["args"]=["arbitrary-token-oracle"]
    elif fault=="env_override":claims["submods"]["container"]["env_override"]={"PYTHONPATH":"/untrusted"}
    elif fault=="cmd_override":claims["submods"]["container"]["cmd_override"]=["shell"]
    elif fault=="project":claims["submods"]["gce"]["project_id"]="another-project"
    elif fault=="subject":claims["sub"]="another-instance"
    elif fault=="service_account":claims["google_service_accounts"]=["other-synthetic-account"]
    env["token"]=fixture["sign"](claims)
    with pytest.raises(cs.AttestationRejected,match=code):cs.verify(cs.canonical(env),expected,cfg,policy,now=now)
    # Same valid positive control remains admissible: the negative did not consume it.
    assert cs.verify(raw,expected,cfg,policy).hardware_backed


@pytest.mark.parametrize("fault,code",[("unknown_key","KEY"),("revoked","KEY"),("stale_key","KEY_STALE"),("stale_snapshot","TRUST_STALE"),("none","ALGORITHM"),("hs256","ALGORITHM"),("jku","ALGORITHM"),("jwk","ALGORITHM"),("x5u","ALGORITHM"),("bad_signature","SIGNATURE"),("duplicate_header","DUPLICATE"),("duplicate_claim","DUPLICATE"),("duplicate_nested","DUPLICATE")])
def test_key_and_jwt_boundary(fixture,fault,code):
    raw,expected,cfg,policy=packet(fixture);env=cs.decode(raw);claims=fixture["claims"](cs.commitment(env["response"],expected));head={"alg":"RS256","kid":"synthetic-rsa","typ":"JWT"}
    if fault=="unknown_key":head["kid"]="unknown"
    elif fault=="revoked":cfg=deepcopy(cfg);cfg["keys"]["synthetic-rsa"]["revoked"]=True
    elif fault=="stale_key":cfg=deepcopy(cfg);cfg["keys"]["synthetic-rsa"]["not_after"]=int(time.time())-1
    elif fault=="stale_snapshot":cfg=deepcopy(cfg);cfg["snapshot_expires_at"]=int(time.time())-1
    elif fault in ("none","hs256"):head["alg"]=fault.upper() if fault=="hs256" else "none"
    elif fault in ("jku","jwk","x5u"):head[fault]="https://not-fetched.invalid"
    kwargs={}
    if fault=="duplicate_header":kwargs["raw_header"]=b'{"alg":"RS256","alg":"RS256","kid":"synthetic-rsa","typ":"JWT"}'
    elif fault=="duplicate_claim":kwargs["raw_claims"]=cs.canonical(claims)[:-1]+b',"iss":"duplicate"}'
    elif fault=="duplicate_nested":kwargs["raw_claims"]=cs.canonical(claims).replace(b'"secboot":true',b'"secboot":true,"nested":{"a":1,"a":2}')
    env["token"]=fixture["sign"](claims,head,**kwargs)
    if fault=="bad_signature":
        parts=env["token"].split('.');signature=bytearray(cs.b64(parts[2]));signature[0]^=1
        env["token"]=parts[0]+'.'+parts[1]+'.'+encoded(signature)
    with pytest.raises(cs.AttestationRejected,match=code):cs.verify(cs.canonical(env),expected,cfg,policy)


@pytest.mark.parametrize("field",["node_id","node_role","tenant_id","policy_hash","nonce_hash","request_hash","policy_version","decision"])
def test_response_substitution(fixture,field):
    raw,expected,cfg,policy=packet(fixture);env=cs.decode(raw)
    env["response"][field]="deny" if field=="decision" else "substitution"
    with pytest.raises(cs.AttestationRejected):cs.verify(cs.canonical(env),expected,cfg,policy)
    assert cs.verify(raw,expected,cfg,policy).decision=="allow"


def test_hardware_boolean_cannot_create_proof(fixture):
    raw,expected,cfg,policy=packet(fixture);env=cs.decode(raw);env["response"]["hardware_backed"]=True
    with pytest.raises(cs.AttestationRejected,match="UNVERIFIED_HARDWARE"):cs.verify(cs.canonical(env),expected,cfg,policy)


def test_producer_verifies_request_and_is_not_hash_oracle(fixture):
    args=list(fixture["request"]());cfg,policy=cs.settings()
    args[3]["response_hash"]="f"*64
    with pytest.raises(cs.AttestationRejected,match="ORACLE_INPUT"):cs.produce(*args,cfg,policy)
    assert fixture["control"]["calls"]==0
    args=fixture["request"]();args[3]["confidential_space_signed_request"]["actor_id"]="tampered"
    with pytest.raises(cs.AttestationRejected,match="REQUEST_SIGNATURE"):cs.produce(*args,cfg,policy)
    assert fixture["control"]["calls"]==0


def test_token_laundering_wrong_context(fixture):
    raw,expected,cfg,policy=packet(fixture);other=cs.scope(*fixture["request"]())
    with pytest.raises(cs.AttestationRejected,match="SCOPE"):cs.verify(raw,other,cfg,policy)
    assert cs.verify(raw,expected,cfg,policy).hardware_backed


def test_replay_and_conflicting_fresh_token(fixture):
    args=fixture["request"]();cfg,policy=cs.settings();expected=cs.scope(*args)
    acquire=lambda audience,nonce:fixture["sign"](fixture["claims"](nonce))
    raw=cs.produce(*args,cfg,policy,acquire=acquire);assert cs.verify(raw,expected,cfg,policy)
    with pytest.raises(cs.AttestationRejected,match="REPLAY"):cs.verify(raw,expected,cfg,policy)
    # Newly acquired valid token, same authenticated request, even with new challenge time.
    args[3]["attestation_timestamp"]+=2
    fresh=cs.produce(*args,cfg,policy,acquire=acquire)
    with pytest.raises(cs.AttestationRejected,match="REPLAY"):cs.verify(fresh,cs.scope(*args),cfg,policy)


def test_concurrent_atomic_admission(fixture):
    raw,expected,cfg,policy=packet(fixture)
    def attempt(_):
        try:cs.verify(raw,expected,cfg,policy);return True
        except cs.AttestationRejected:return False
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        assert sum(pool.map(attempt,range(6)))==1


def test_native_restart_replay(fixture):
    raw,expected,cfg,policy=packet(fixture);assert cs.verify(raw,expected,cfg,policy)
    script="import json,sys; from security import confidential_space_attestation as c; d=json.loads(sys.stdin.read()); cfg,p=c.settings();\ntry: c.verify(d['packet'],d['scope'],cfg,p); print('ACCEPTED')\nexcept c.AttestationRejected as e: print(e.code)"
    child=subprocess.run([sys.executable,"-s","-c",script],input=cs.canonical({"packet":raw.decode(),"scope":expected}),capture_output=True,timeout=5)
    assert child.returncode==0 and child.stdout.startswith(b"REPLAY_OR_STORE_REPLAY_BLOCKED")
    assert not child.stderr


@pytest.mark.parametrize("fault",["missing","corrupt","schema","locked"])
def test_store_unavailable_does_not_admit(fixture,fault):
    raw,expected,cfg,policy=packet(fixture);db=Path(cfg["replay_db"]);lock=None
    if fault=="missing":db.unlink()
    elif fault=="corrupt":db.write_bytes(b'not-sqlite')
    elif fault=="schema":
        with sqlite3.connect(db) as conn:conn.execute("DROP TABLE decision_evidence_consumption")
    else:lock=sqlite3.connect(db);lock.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(cs.AttestationRejected,match="REPLAY_OR_STORE"):cs.verify(raw,expected,cfg,policy)
    finally:
        if lock:lock.rollback();lock.close()
    if fault=="missing":assert not db.exists()


@pytest.mark.parametrize("fault",["unavailable","reply","worker_timeout"])
def test_provider_and_worker_failure(fixture,fault,caplog):
    fixture["start_launcher"]()
    if fault=="unavailable":fixture["control"]["status"]=503
    elif fault=="reply":fixture["control"]["malformed"]=True
    else:fixture["control"]["delay"]=.2
    args=fixture["request"]("node-2")
    node=SubprocessHydraNode(timeout_seconds=.05 if fault=="worker_timeout" else 1)
    with pytest.raises(subprocess.SubprocessError):node.evaluate(*args[1:])
    assert ("WORKER_TIMEOUT" if fault=="worker_timeout" else "WORKER_EXIT") in caplog.text
    assert "synthetic-actor" not in caplog.text and "eyJ" not in caplog.text


def test_disabled_default_and_production_mock_still_rejected(fixture,monkeypatch):
    monkeypatch.delenv("USBAY_NODE_ATTESTATION_ADAPTER");monkeypatch.delenv("USBAY_CONFIDENTIAL_SPACE_TRUST_PATH")
    policy=cs.decode(Path('governance/node_attestation_policy.json').read_bytes());policy.update(required_attestation_mode='mock_local',require_hardware_backing=False)
    Path('governance/node_attestation_policy.json').write_bytes(cs.canonical(policy))
    monkeypatch.setenv("USBAY_ENV","production")
    with pytest.raises(AttestationError,match="mock_attestation_rejected_in_production"):
        InProcessHydraNode().evaluate(*fixture["request"]()[1:])
    assert fixture["control"]["calls"]==0


def test_missing_trust_and_production_fixture_rejected(fixture,monkeypatch):
    monkeypatch.delenv("USBAY_CONFIDENTIAL_SPACE_TRUST_PATH")
    with pytest.raises(cs.AttestationRejected,match="TRUST"):InProcessHydraNode().evaluate(*fixture["request"]()[1:])
    fixture["write"]();monkeypatch.setenv("USBAY_CONFIDENTIAL_SPACE_TRUST_PATH",str(fixture["tmp"]/'trust.json'))
    monkeypatch.setenv("USBAY_ENV","production")
    with pytest.raises(cs.AttestationRejected,match="SYNTHETIC_PROFILE"):cs.settings()


def test_native_concurrent_verifiers(fixture):
    raw,expected,cfg,policy=packet(fixture)
    script="import json,sys; from security import confidential_space_attestation as c; d=json.loads(sys.stdin.read()); cfg,p=c.settings();\ntry: c.verify(d['packet'],d['scope'],cfg,p); print('ACCEPTED')\nexcept c.AttestationRejected: print('BLOCKED')"
    data=cs.canonical({"packet":raw.decode(),"scope":expected})
    children=[subprocess.Popen([sys.executable,"-s","-c",script],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for _ in range(3)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        results=list(pool.map(lambda p:p.communicate(data,timeout=5),children))
    assert all(p.returncode==0 for p in children) and all(not err for _,err in results)
    assert sum(out.strip()==b'ACCEPTED' for out,_ in results)==1


def test_explicit_synthetic_issuer_and_rotation(fixture):
    raw,expected,cfg,policy=packet(fixture);env=cs.decode(raw);cfg=deepcopy(cfg)
    cfg['issuer']='https://synthetic-issuer.invalid'
    claims=fixture['claims'](cs.commitment(env['response'],expected));claims['iss']=cfg['issuer']
    # A verifier-controlled key snapshot rotation retains old replay history.
    cfg['keys']['rotated-synthetic']=deepcopy(cfg['keys']['synthetic-rsa'])
    env['token']=fixture['sign'](claims,{'alg':'RS256','kid':'rotated-synthetic','typ':'JWT'})
    assert cs.verify(cs.canonical(env),expected,cfg,policy).hardware_backed
    with pytest.raises(cs.AttestationRejected,match='REPLAY'):
        cs.verify(cs.canonical(env),expected,cfg,policy)


@pytest.mark.parametrize('fault',['role','tenant','policy_mode'])
def test_verifier_owned_enrollment_boundary(fixture,fault):
    raw,expected,cfg,policy=packet(fixture);cfg=deepcopy(cfg);policy=deepcopy(policy)
    if fault=='role':policy['enrolled_nodes']['node-1']['role']='secondary'
    elif fault=='tenant':cfg['nodes']['node-1']['tenants']=['t2']
    else:policy['required_attestation_mode']='mock_local'
    with pytest.raises(cs.AttestationRejected,match='POLICY_NOT_APPROVED|ENROLLMENT'):
        cs.verify(raw,expected,cfg,policy)


@pytest.mark.parametrize('raw,code',[(b'{"a":1,"a":2}','DUPLICATE'),(b'{"a":NaN}','JSON'),(b'\xff','JSON'),(b'{','JSON'),(b'['*20+b'0'+b']'*20,'SIZE'),(b'"'+b'a'*65536+b'"','SIZE')])
def test_bounded_parser(raw,code):
    with pytest.raises(cs.AttestationRejected,match=code):cs.decode(raw)


def test_trust_revoked_during_acquisition(fixture,monkeypatch):
    def acquire(client,audience,nonce):
        token=fixture['sign'](fixture['claims'](nonce))
        fixture['config']['keys']['synthetic-rsa']['revoked']=True;fixture['write']()
        return token
    monkeypatch.setattr(cs.LauncherClient,'acquire',acquire)
    with pytest.raises(cs.AttestationRejected,match='KEY'):
        InProcessHydraNode().evaluate(*fixture['request']()[1:])
    with sqlite3.connect(fixture['config']['replay_db']) as db:
        assert db.execute('SELECT count(*) FROM decision_evidence_consumption').fetchone()[0]==0


def test_bounded_worker_cause_diagnostics(caplog):
    cs.worker_failure('{"error":{"code":"PROVIDER_UNAVAILABLE","stage":"acquisition"}}','node-2','synthetic-hash',2)
    assert 'PROVIDER_UNAVAILABLE' in caplog.text and 'WORKER_EXIT' in caplog.text
    cs.worker_failure('do not log this arbitrary token or customer text','node-2','synthetic-hash',2)
    assert 'customer text' not in caplog.text


@pytest.mark.parametrize('family',['remote','live'])
def test_private_local_request_never_enters_remote_transport(fixture,monkeypatch,family):
    from security import hydra_nodes
    captured={};original=hydra_nodes.request.Request
    def request(*args,**kwargs):
        captured.update(cs.decode(kwargs['data']))
        return original(*args,**kwargs)
    monkeypatch.setattr(hydra_nodes.request,'Request',request)
    args=fixture['request']()
    with pytest.raises(ValueError,match='authorization_missing'):
        if family=='remote':hydra_nodes.RemoteHydraNode().evaluate(*args[1:])
        else:
            from security.hydra_live_client import HydraLiveNodeClient
            HydraLiveNodeClient('node3',url='http://localhost:8001/hydra/evaluate').vote(args[1],args[2],context=args[3])
    assert 'confidential_space_signed_request' not in captured['context']
    assert fixture['control']['calls']==0


def test_producer_rejects_substituted_policy_context(fixture):
    args=fixture['request']();args[3]['policy_hash']='1'*64
    cfg,policy=cs.settings()
    with pytest.raises(cs.AttestationRejected,match='POLICY_BINDING'):
        cs.produce(*args,cfg,policy)
    assert fixture['control']['calls']==0


def test_mixed_live_backend_not_silently_accepted(fixture,monkeypatch):
    monkeypatch.setenv('USBAY_HYDRA_BACKEND','services')
    with pytest.raises(cs.AttestationRejected,match='BACKEND_CONFLICT'):cs.settings()
    assert fixture['control']['calls']==0


@pytest.mark.parametrize("attestation", ["valid", "signed_wrong_image"])
def test_gateway_decide_connected_attestation(fixture, tmp_path, monkeypatch, caplog, attestation):
    """Real /decide and local nodes; synthetic issuer and unrelated Gateway stores.

    No live transport grant: the real node-3 client must remain unavailable.
    The negative token is correctly signed/fresh but names an unapproved image.
    """
    root = Path(__file__).resolve().parents[1]
    # Complete the existing fixture's public, signed policy dependencies without
    # copying private policy keys or changing its existing shared setup.
    for name in ("policy_registry.sig", "policy_public.key", "policy_release_manifest.json",
                 "policy_key_config.json", "policy_authority.json", "compute_policy.json"):
        (tmp_path / "governance" / name).write_bytes((root / "governance" / name).read_bytes())

    import gateway.app as gateway_app
    from security.hydra_nodes import RemoteHydraNode, default_node_clients
    from tests.test_gateway_hydra import build_payload, configure_gateway, sign_payload

    # Existing helpers install a verifiable synthetic runtime authority,
    # request keys, runtime attestation, temporary audit chain and local stores.
    # Cache values and every helper/environment override are restored by pytest.
    monkeypatch.setattr(gateway_app, "_policy_registry_cache", None)
    monkeypatch.setattr(gateway_app, "_policy_registry_cache_key", None)
    monkeypatch.delenv("USBAY_HYDRA_TRANSPORT_MANDATES_PATH", raising=False)
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setenv("USBAY_REQUEST_SIGNING_KEY_CONFIG_PATH",
                       str(gateway_app.REQUEST_SIGNING_KEY_CONFIG_PATH))
    clients = default_node_clients()
    assert [type(node) for node in clients] == [InProcessHydraNode, SubprocessHydraNode, RemoteHydraNode]
    monkeypatch.setattr(gateway_app, "hydra_node_clients", clients)
    registry = gateway_app.load_policy_registry(
        provenance_context=gateway_app.runtime_provenance_context())
    payload = build_payload({"policy_version": registry["version"]},
                            nonce="cs-gateway-" + os.urandom(16).hex())
    sign_payload(payload)
    request_hash = hashlib.sha256(request_signature_message(payload).encode()).hexdigest()
    nonce_hash = hashlib.sha256(payload["nonce"].encode()).hexdigest()
    actor_hash = hashlib.sha256(payload["actor_id"].encode()).hexdigest()
    tenant_hash = hashlib.sha256(payload["tenant_id"].encode()).hexdigest()
    assert gateway_app._signature_validation(payload) == (True, "ok")
    assert nonce_hash not in gateway_app.decision_store.nonces
    with sqlite3.connect(fixture["config"]["replay_db"]) as db:
        assert db.execute("SELECT count(*) FROM decision_evidence_consumption").fetchone()[0] == 0

    if attestation == "signed_wrong_image":
        def wrong_image(claims):
            claims["submods"]["container"]["image_digest"] = "sha256:" + "b" * 64
        # Handler signs AFTER mutation: signature, time, request nonce and
        # response commitment remain valid; only enrollment measurement fails.
        fixture["control"]["mutate"] = wrong_image
    fixture["start_launcher"]()
    # TestClient invokes registered ASGI routing without a listening Gateway.
    response = client.post("/decide", json=payload)
    assert response.status_code == 200
    body = response.json()
    expected_decision = "ALLOW" if attestation == "valid" else "DENY"
    assert body["decision"] == expected_decision
    assert body["reason"] == ("approved" if attestation == "valid" else "no_majority")
    assert body["request_hash"] == request_hash
    assert body["actor_hash"] == actor_hash
    assert body["policy_hash"] == registry["policy_hash"]
    assert body["signature_valid"] is True and body["policy_signature_valid"] is True
    assert body["used"] is False
    record = gateway_app.decision_store.load_decision(body["decision_id"])
    assert record["request_hash"] == request_hash and record["nonce_hash"] == nonce_hash
    assert record["tenant_id"] == payload["tenant_id"] and record["tenant_hash"] == tenant_hash
    assert gateway_app.decision_store.nonces[nonce_hash] > int(time.time())
    bundle = record["consensus_evidence_bundle"]
    nodes = {node["node_id"]: node for node in bundle["nodes"]}
    assert set(nodes) == {"node-1", "node-2", "node-3"}
    assert nodes["node-3"]["decision"] == "deny"
    assert nodes["node-3"]["reason"] == "node_unavailable"
    assert not nodes["node-3"]["attestation_hash"]
    assert fixture["control"]["calls"] == 2
    diagnostics = [json.loads(item.getMessage().split("USBAY_CS_DIAGNOSTIC ", 1)[1])
                   for item in caplog.records if "USBAY_CS_DIAGNOSTIC " in item.getMessage()]
    with sqlite3.connect(fixture["config"]["replay_db"]) as db:
        admissions = db.execute("SELECT replay_key, consumed_decision_evidence_hash "
                                "FROM decision_evidence_consumption").fetchall()
    if attestation == "valid":
        assert bundle["votes_allow"] == 2 and bundle["consensus_result"] == "allow"
        assert len(admissions) == 2 and len({row[0] for row in admissions}) == 2
        for node_id in ("node-1", "node-2"):
            node = nodes[node_id]
            assert node["decision"] == "allow" and node["hardware_backed"] is True
            assert node["tenant_hash"] == tenant_hash and node["nonce_hash"] == nonce_hash
            assert node["policy_hash"] == registry["policy_hash"]
            assert len(node["attestation_hash"]) == 64
            assert node["attestation_provider_mode"] == "external_attestation_service"
        assert {(d["node_id"], d["stage"]) for d in diagnostics if d["code"] == "VERIFIED"} == {
            ("node-1", "admission"), ("node-2", "worker_admission")}
    else:
        assert bundle["votes_allow"] == 0 and bundle["consensus_result"] == "deny"
        assert bundle["reason"] == "quorum_unavailable" and admissions == []
        assert {(d["node_id"], d["stage"]) for d in diagnostics if d["code"] == "MEASUREMENT"} == {
            ("node-1", "identity"), ("node-2", "identity")}
        assert not any(d["code"] == "VERIFIED" for d in diagnostics)
        assert all(nodes[node_id]["decision"] == "deny" and
                   not nodes[node_id]["attestation_hash"] for node_id in ("node-1", "node-2"))

    assert gateway_app.audit_chain.verify() is True
    events = gateway_app.audit_chain.load()
    created = [event["decision"] for event in events if event["action"] == "decision_created"]
    assert len(created) == 1
    audit = created[0]
    for field, expected in (("decision_id", body["decision_id"]), ("request_hash", request_hash),
                            ("nonce_hash", nonce_hash), ("actor_hash", actor_hash),
                            ("tenant_id", payload["tenant_id"]), ("tenant_hash", tenant_hash),
                            ("policy_hash", registry["policy_hash"]), ("decision", expected_decision)):
        assert audit[field] == expected
    consensus_events = [event["decision"] for event in events
                        if event["action"] in ("consensus_allow", "consensus_deny")]
    assert len(consensus_events) == 1
    assert consensus_events[0]["evidence_hash"] == record["consensus_evidence_hash"]
    # Neither raw signed requests nor provider JWTs belong in public diagnostics/audit.
    audit_text = json.dumps(events, sort_keys=True)
    assert payload["signature"] not in audit_text + caplog.text
    assert payload["nonce"] not in audit_text + caplog.text
    assert "eyJ" not in caplog.text
