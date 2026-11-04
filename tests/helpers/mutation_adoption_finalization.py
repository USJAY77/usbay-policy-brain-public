"""TEST ONLY builder for signed adoption-finalization artifacts."""
from copy import deepcopy

from governance.mutation_adoption_finalization import pending_record_reference
from governance.tenant_enrollment_contracts import canonical,digest
from tests.helpers.tenant_enrollment import common


def build_finalization_artifacts(f):
    pending=f.pending
    p=pending["policy"]["payload"]
    a=pending["adoption"]["payload"]
    b=pending["advance"]["payload"]
    with __import__("sqlite3").connect(f.path) as conn:
        rows=[
            ( __import__("governance.tenant_enrollment_contracts",fromlist=["parse_json"]).parse_json(row[0]), row[1])
            for row in conn.execute(
                "SELECT payload,event_hash FROM enrollment_events ORDER BY sequence")
        ]
    matches=[(event,event_hash) for event,event_hash in rows
             if event.get("kind")=="ADOPTION_PENDING"
             and event.get("adoption_core_hash")==digest(a)
             and event.get("head_advance_grant_hash")==digest(b)]
    assert len(matches)==1
    pending_event,pending_event_hash=matches[0]
    record_ref=pending_record_reference(
        pending_event_hash=pending_event_hash,
        adoption_core_hash=digest(a))
    challenge="synthetic-finalization-challenge"
    request_digest=digest({"synthetic-finalization-request":f.command["payload"]["transaction_id"]})
    h=common("witness","H")
    h.update(
        policy_id=p["policy_id"],policy_version=p["policy_version"],policy_hash=digest(p),
        role="H",head_hash=b["head_hash"],sequence=b["sequence"],generation=b["generation"],
        epoch=b["epoch"],lineage_hash=b["lineage_hash"],previous_head_hash=b["previous_head_hash"],
        adoption_core_hash=digest(a),adoption_record_hash=record_ref,
        head_advance_grant_hash=digest(b),challenge=challenge,request_digest=request_digest,
        revocation_reference=p["revocation_reference"],anchor_hash=digest({"synthetic-finalization-anchor":1}))
    w=deepcopy(h);w.update(issuer_id="W",issuer_key_id="W",role="W")
    h_env=f.f.enrollment.sign(h)
    w_env=f.f.enrollment.sign(w)
    artifacts={
        "policy":deepcopy(pending["policy"]),
        "adoption":deepcopy(pending["adoption"]),
        "advance":deepcopy(pending["advance"]),
        "h":h_env,"w":w_env,"expected":deepcopy(h),
        "challenge":challenge,"request_digest":request_digest,
    }
    return artifacts,pending_event,pending_event_hash
