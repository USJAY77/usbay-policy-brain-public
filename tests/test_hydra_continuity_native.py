"""Preserved recovery faults with real HTTPS and independently live reference processes."""
import concurrent.futures,json,os,pathlib,secrets,sqlite3,subprocess,sys,time
from datetime import datetime,timezone,timedelta
import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from governance.durable_authority_registries import HUMAN_APPROVAL

pytestmark=[pytest.mark.governance,pytest.mark.regression]
HELPERS=pathlib.Path(__file__).parent/"helpers"
from security.hydra_continuity import reserve as reserve_continuity
from security.hydra_live_client import hydra_endpoint_url_hash
from tests.helpers.hydra_transport import configure_transport_authority,NOW
from tests.test_hydra_live_client import authorized_context

def tls_material(tmp,stem="tls"):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"localhost")])
    now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
        .not_valid_after(now+timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),critical=False).sign(key,hashes.SHA256()))
    (tmp/(stem+".key")).write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    (tmp/(stem+".pem")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))

@pytest.fixture
def resources():
    active=[]
    try:yield active
    finally:
        for fixture in active:fixture.close()

@pytest.fixture
def node(tmp_path,monkeypatch,resources):
    tls_material(tmp_path)
    monkeypatch.setenv("USBAY_HYDRA_NODE_1_KEY",secrets.token_hex(32))
    for name in ("HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","http_proxy","https_proxy","all_proxy"):
        monkeypatch.delenv(name,raising=False)
    child=subprocess.Popen([sys.executable,"-s",str(HELPERS/"hydra_native_node.py"),str(tmp_path)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    deadline=time.monotonic()+10
    try:
        while not (tmp_path/"port").exists():
            assert child.poll() is None,"NODE_START_FAILED"
            assert time.monotonic()<deadline,"NODE_START_TIMEOUT"
            time.sleep(.01)
        monkeypatch.setenv("SSL_CERT_FILE",str(tmp_path/"tls.pem"))
        yield "https://localhost:"+(tmp_path/"port").read_text()+"/vote",tmp_path,resources
    finally:
        child.terminate();child.wait(timeout=5)
        error=child.stderr.read()
        assert not error,"NODE_PROCESS_ERROR"

def setup(node,tmp_path,monkeypatch,*,path="/vote",hostname="localhost"):
    url,node_dir,resources=node
    url=url.replace("localhost",hostname).replace("/vote",path)
    signed,registry,record=configure_transport_authority(tmp_path,monkeypatch,native=True)
    resources.append(signed.continuity)
    record["allowed_endpoint_hashes"]=[hydra_endpoint_url_hash(url)]
    registry.update_authority(HUMAN_APPROVAL,record)
    context=authorized_context()
    context["hydra_remote_transport_authorization"]["endpoint_url_hash"]=hydra_endpoint_url_hash(url)
    payload={"url":url,"now":NOW,"context":signed(context)}
    fixture=tmp_path/"client-fixture.json"
    fixture.write_text(json.dumps(payload))
    return fixture,registry,record

def attempt(fixture):
    result=subprocess.run([sys.executable,"-s",str(HELPERS/"hydra_native_client.py"),str(fixture)],capture_output=True,text=True,timeout=10)
    assert result.returncode==0,"CLIENT_PROCESS_FAILED"
    assert not result.stderr,"CLIENT_STDERR"
    return json.loads(result.stdout)
def count(tmp):
    file=tmp/"entries"
    return file.read_text().count("NODE_ENTRY") if file.exists() else 0
def evidence(name,value):
    directory=os.getenv("USBAY_TEST_EVIDENCE_DIRECTORY")
    if not directory:return
    file=pathlib.Path(directory)/(name+".json")
    assert not file.exists()
    file.write_text(json.dumps(value,indent=2))
def revoke(registry,record):
    registry.revoke_authority(HUMAN_APPROVAL,record["authority_reference"],
        tenant_reference=record["tenant_reference"],environment_reference=record["environment_reference"],
        reason_code="SYNTHETIC_REVOCATION")

@pytest.mark.parametrize("fault",["delete_replay","rollback_replay","rollback_registry_pair"])
def test_recovery_must_not_admit_again(node,tmp_path,monkeypatch,fault):
    fixture,registry,record=setup(node,tmp_path,monkeypatch)
    replay=tmp_path/"replay.db"
    # Migration: the signed fixture explicitly provisioned the v2 schema above.
    saved_db=replay.read_bytes()
    saved_registry=registry.registry_path.read_bytes()
    saved_evidence=registry.evidence_path.read_bytes()
    if fault=="rollback_registry_pair":
        revoke(registry,record)
        control=attempt(fixture)
        assert not control["admitted"] and count(tmp_path)==0
        registry.registry_path.write_bytes(saved_registry)
        registry.evidence_path.write_bytes(saved_evidence)
    else:
        control=attempt(fixture)
        assert control["admitted"] and count(tmp_path)==1
        if fault=="delete_replay":replay.unlink()
        else:replay.write_bytes(saved_db)
    before=count(tmp_path)
    observed=attempt(fixture) # Always a fresh native client process.
    after=count(tmp_path)
    evidence(fault,{"control":control,"result":observed,"node_entries_before":before,
                   "node_entries_after":after,"extra_node_entries":after-before,"fresh_client_process":True})
    assert not observed["admitted"] and after==before

def test_valid_then_replay_after_client_restart(node,tmp_path,monkeypatch):
    fixture,registry,record=setup(node,tmp_path,monkeypatch)
    first=attempt(fixture);second=attempt(fixture)
    evidence("valid-replay",{"first":first,"second":second,"node_entries":count(tmp_path)})
    assert first["admitted"] and not second["admitted"] and count(tmp_path)==1

def test_native_continuity_replay_preserves_denial_code(node,tmp_path,monkeypatch):
    fixture,_,_=setup(node,tmp_path,monkeypatch)
    continuity=node[2][-1]
    mandate=json.loads(fixture.read_text())["context"]["hydra_remote_transport_authorization"]
    reserve_continuity(continuity.config,mandate)
    observed=attempt(fixture)
    assert not observed["admitted"]
    assert observed["reason"]=="hydra_remote_transport_authorization_replayed"

def test_registry_only_restore_is_blocked(node,tmp_path,monkeypatch):
    fixture,registry,record=setup(node,tmp_path,monkeypatch)
    saved=registry.registry_path.read_bytes()
    revoke(registry,record)
    registry.registry_path.write_bytes(saved)
    observed=attempt(fixture)
    evidence("registry-only-restore",{"result":observed,"node_entries":count(tmp_path)})
    assert not observed["admitted"] and count(tmp_path)==0

@pytest.mark.parametrize("fault",["untrusted_ca","wrong_hostname","redirect"])
def test_native_transport_controls(node,tmp_path,monkeypatch,fault):
    if fault=="untrusted_ca":
        tls_material(tmp_path,"untrusted")
    fixture,registry,record=setup(node,tmp_path,monkeypatch,
        path="/redirect" if fault=="redirect" else "/vote",
        hostname="127.0.0.1" if fault=="wrong_hostname" else "localhost")
    if fault=="untrusted_ca":monkeypatch.setenv("SSL_CERT_FILE",str(tmp_path/"untrusted.pem"))
    observed=attempt(fixture)
    evidence(fault,{"result":observed,"node_entries":count(tmp_path)})
    assert not observed["admitted"] and count(tmp_path)==0

def test_eight_concurrent_native_clients(node,tmp_path,monkeypatch):
    fixture,registry,record=setup(node,tmp_path,monkeypatch)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(lambda _:attempt(fixture),range(8)))
    evidence("concurrency",{"results":results,"node_entries":count(tmp_path)})
    assert sum(x["admitted"] for x in results)==1 and count(tmp_path)==1


def test_eight_gateway_snapshot_clones_have_one_authoritative_winner(node,tmp_path,monkeypatch):
    fixture,_,_=setup(node,tmp_path,monkeypatch)
    image=(tmp_path/"replay.db").read_bytes()
    paths=[]
    for index in range(8):
        path=tmp_path/("replica-"+str(index)+".db");path.write_bytes(image);paths.append(path)
    def cloned_attempt(path):
        result=subprocess.run([sys.executable,"-s",str(HELPERS/"hydra_native_client.py"),str(fixture)],
            env={**os.environ,"USBAY_HYDRA_TRANSPORT_REPLAY_DB":str(path)},capture_output=True,text=True,timeout=15)
        assert result.returncode==0 and not result.stderr
        return json.loads(result.stdout)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(cloned_attempt,paths))
    assert sum(x["admitted"] for x in results)==1 and count(tmp_path)==1
    evidence("independent-eight-clones",dict(results=results,node_entries=1,independent_local_stores=8))


def new_fixture(node, path, *, identifier="new-auth", nonce="new-nonce", client_kind="live"):
    continuity=node[2][-1]
    payload=json.loads(path.read_text())
    unsigned=authorized_context(node_id="node-3" if client_kind=="remote" else "node1",url=payload["url"])
    unsigned["hydra_remote_transport_authorization"]["authorization_id"]=identifier
    payload["context"]=continuity.sign_context(unsigned,nonce=nonce)
    payload["client_kind"]=client_kind
    target=path.with_name(identifier+".json");target.write_text(json.dumps(payload))
    return target


@pytest.mark.parametrize("domain",["service","witness"])
def test_native_domain_rollback_and_restart_fail_closed(node,tmp_path,monkeypatch,domain):
    fixture,_,_=setup(node,tmp_path,monkeypatch)
    continuity=node[2][-1];store=getattr(continuity,domain).log.path
    snapshot=store.read_bytes()
    assert attempt(fixture)["admitted"] and count(tmp_path)==1
    store.write_bytes(snapshot)
    result=attempt(new_fixture(node,fixture))
    assert not result["admitted"] and count(tmp_path)==1
    continuity.restart(domain)
    result=attempt(new_fixture(node,fixture,identifier="after-restart",nonce="after-restart"))
    assert not result["admitted"] and count(tmp_path)==1
    evidence("native-"+domain+"-rollback",dict(result=result,node_entries=1))


@pytest.mark.parametrize("domain",["service","witness"])
def test_unavailable_reference_process_blocks_node(node,tmp_path,monkeypatch,domain):
    fixture,_,_=setup(node,tmp_path,monkeypatch)
    continuity=node[2][-1];child=continuity.children[0 if domain=="service" else 1]
    child.terminate();child.wait(timeout=5)
    assert not attempt(fixture)["admitted"] and count(tmp_path)==0
    assert not attempt(fixture)["admitted"] and count(tmp_path)==0


@pytest.mark.parametrize("domain",["service","witness"])
def test_fresh_process_rejects_old_signed_receipt_or_witness_response(node,tmp_path,monkeypatch,domain):
    fixture,_,_=setup(node,tmp_path,monkeypatch)
    continuity=node[2][-1];directory=getattr(continuity,domain).log.path.parent
    local=tmp_path/"replay.db";snapshot=local.read_bytes()
    (directory/"capture-response").touch()
    assert attempt(fixture)["admitted"] and count(tmp_path)==1
    (directory/"capture-response").unlink()
    assert (directory/"recorded-response.json").exists()
    local.write_bytes(snapshot);(directory/"replay-response").touch()
    result=attempt(fixture)
    assert not result["admitted"] and count(tmp_path)==1
    evidence("fresh-process-old-"+domain+"-response",dict(result=result,extra_node_entries=0))


def test_native_remote_client_uses_same_boundary(node,tmp_path,monkeypatch):
    fixture,registry,record=setup(node,tmp_path,monkeypatch,path="/evaluate")
    fixture=new_fixture(node,fixture,client_kind="remote")
    assert attempt(fixture)["admitted"] and count(tmp_path)==1
    assert not attempt(fixture)["admitted"] and count(tmp_path)==1


def test_native_timeout_consumption_survives_fresh_client(node,tmp_path,monkeypatch):
    fixture,_,_=setup(node,tmp_path,monkeypatch)
    (tmp_path/"delay").touch()
    payload=json.loads(fixture.read_text());payload["timeout"]=.05
    fixture.write_text(json.dumps(payload))
    assert not attempt(fixture)["admitted"] and count(tmp_path)==1
    assert not attempt(fixture)["admitted"] and count(tmp_path)==1


def wait_for(path,child):
    deadline=time.monotonic()+10
    while not path.exists():
        assert child.poll() is None and time.monotonic()<deadline
        time.sleep(.01)


def test_killed_client_after_admission_cannot_dispatch_on_restart(node,tmp_path,monkeypatch):
    fixture,_,_=setup(node,tmp_path,monkeypatch)
    marker=tmp_path/"client-reserved"
    payload=json.loads(fixture.read_text());payload["pause_before_node"]=str(marker)
    fixture.write_text(json.dumps(payload))
    child=subprocess.Popen([sys.executable,"-s",str(HELPERS/"hydra_native_client.py"),str(fixture)],
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        wait_for(marker,child)
        child.kill();child.wait(timeout=5)
    finally:
        if child.poll() is None:child.terminate();child.wait(timeout=5)
    del payload["pause_before_node"];fixture.write_text(json.dumps(payload))
    assert not attempt(fixture)["admitted"] and count(tmp_path)==0


@pytest.mark.parametrize("stage",["db-commit","witness"])
def test_killed_service_between_commits_preserves_uncertainty(node,tmp_path,monkeypatch,stage):
    fixture,_,_=setup(node,tmp_path,monkeypatch)
    continuity=node[2][-1];directory=continuity.service.log.path.parent
    (directory/("pause-after-"+stage)).touch()
    child=subprocess.Popen([sys.executable,"-s",str(HELPERS/"hydra_native_client.py"),str(fixture)],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        wait_for(directory/"commit-paused",child)
        continuity.restart("service")
        output,error=child.communicate(timeout=10)
        assert child.returncode==0 and not error and not json.loads(output)["admitted"]
    finally:
        if child.poll() is None:child.terminate();child.wait(timeout=5)
    assert not attempt(fixture)["admitted"] and count(tmp_path)==0
    result=attempt(new_fixture(node,fixture))
    assert result["admitted"]==(stage=="witness")
    assert count(tmp_path)==(1 if stage=="witness" else 0)
    evidence("native-killed-service-"+stage,dict(new_independent_grant=result,node_entries=count(tmp_path)))


def test_signed_gateway_native_quorum_and_audit(node,tmp_path,monkeypatch):
    import gateway.app as gateway
    from security.hydra_live_client import HydraLiveNodeClient
    from security.decision_store import verify_decision_signatures
    from tests.test_gateway_hydra import configure_gateway,build_payload,sign_payload
    from tests.test_hydra_live_client import remote_authorization
    client=configure_gateway(tmp_path,monkeypatch)
    payload=build_payload(nonce="native-continuity-quorum");sign_payload(payload)
    request_hash=gateway.request_hash(gateway.request_signature_message(payload))
    policy=gateway.load_policy_registry(provenance_context=gateway.runtime_provenance_context())
    now=time.time()
    signed,registry,record=configure_transport_authority(tmp_path,monkeypatch,tenant="t1",
        policy_hash="sha256:"+policy["policy_hash"].removeprefix("sha256:"),now=now,
        node_ids=("node1","node2","node3"),native=True)
    node[2].append(signed.continuity)
    second=tmp_path/"node2";second.mkdir()
    for name in ("tls.pem","tls.key"):(second/name).write_bytes((tmp_path/name).read_bytes())
    monkeypatch.setenv("USBAY_HYDRA_NODE_2_KEY",secrets.token_hex(32))
    child=subprocess.Popen([sys.executable,"-s",str(HELPERS/"hydra_native_node.py"),str(second)],
        env={**os.environ,"SYNTHETIC_NODE_ID":"node2"},stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    try:
        wait_for(second/"port",child)
        urls={"node1":node[0],"node2":"https://localhost:"+(second/"port").read_text()+"/vote"}
        record["allowed_endpoint_hashes"]=[hydra_endpoint_url_hash(url) for url in urls.values()]
        registry.update_authority(HUMAN_APPROVAL,record)
        grants={}
        for identity,url in urls.items():
            grant=remote_authorization(node_id=identity,url=url,request_hash=request_hash,
                policy_version=payload["policy_version"],issued_at=now-1,expires_at=now+60)
            grant["authorization_id"]="native-quorum-"+identity
            grants[identity]=signed({"hydra_remote_transport_authorization":grant},nonce=identity)["hydra_remote_transport_authorization"]
        path=tmp_path/"native-grants.json";path.write_text(json.dumps({request_hash:grants}))
        monkeypatch.setenv("USBAY_HYDRA_TRANSPORT_MANDATES_PATH",str(path))
        monkeypatch.setenv("USBAY_HYDRA_BACKEND","services")
        monkeypatch.setattr(gateway,"hydra_node_clients",[HydraLiveNodeClient(identity,url) for identity,url in urls.items()])
        response=client.post("/decide",json=payload)
        assert response.status_code==200 and response.json()["decision"]=="ALLOW"
        decision=gateway.decision_store.load_decision(response.json()["decision_id"])
        assert decision["tenant_id"]=="t1" and verify_decision_signatures(decision)
        assert gateway.audit_chain.verify() and count(tmp_path)==count(second)==1
        event=[e for e in gateway.audit_chain.load() if e.get("action")=="consensus_allow"][-1]
        assert event["decision"]["tenant_id"]=="t1" and event["decision"]["votes_allow"]==2
        replay=client.post("/decide",json=payload)
        assert replay.status_code==403 and replay.json()["reason"]=="replay_detected"
        assert count(tmp_path)==count(second)==1
        evidence("native-gateway-quorum",dict(status=response.status_code,decision="ALLOW",votes_allow=2,
            node_entries=[count(tmp_path),count(second)],audit_verified=True,decision_signatures_verified=True))
    finally:
        child.terminate();child.wait(timeout=5)
