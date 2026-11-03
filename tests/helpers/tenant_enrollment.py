"""Synthetic-only ephemeral keys and explicit disposable schema preparation.

Never imported by production. Does not use the designated pilot tenant, real
identities, old runtime databases, provider credentials or live trust files.
"""
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from governance.tenant_enrollment_contracts import (
    FLAGS, FORBIDDEN, TRUST_DOMAIN, POLICY_DOMAIN, PURPOSE, ENROLL, ADOPT, ADVANCE,
    canonical, digest, object_id, key_id, SCOPE_FIELDS,
)
from security.enrollment_policy_currentness import EnrollmentTrust, ScopedPublicKey
from security.enrollment_policy_witness import target_head

NOW = datetime(2026, 1, 2, 12, 0, tzinfo=timezone.utc)


@dataclass
class SyntheticEnrollment:
    inputs: dict
    head: dict
    trust: EnrollmentTrust
    private: dict

    def sign(self, payload):
        return {"payload": deepcopy(payload), "signature": self.private[payload["issuer_key_id"]].sign(canonical(payload)).hex()}

    def store(self, path):
        # Explicit TEST ONLY provisioning in tmp_path. Production has no such API.
        from governance.authority_registry import MediaAuthorityRegistry
        MediaAuthorityRegistry(path)
        with sqlite3.connect(path) as conn:
            conn.executescript("""
                CREATE TABLE enrollment_meta(name TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE enrollment_events(sequence INTEGER PRIMARY KEY,payload TEXT NOT NULL,event_hash TEXT UNIQUE NOT NULL);
                CREATE TABLE enrollment_uses(kind TEXT NOT NULL,identity TEXT NOT NULL,PRIMARY KEY(kind,identity));
                CREATE TABLE enrollment_tenants(scope TEXT PRIMARY KEY,record TEXT NOT NULL);
                CREATE TRIGGER enrollment_no_update BEFORE UPDATE ON enrollment_events BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER enrollment_no_delete BEFORE DELETE ON enrollment_events BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER enrollment_no_release BEFORE DELETE ON enrollment_uses BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER enrollment_no_rewrite BEFORE UPDATE ON enrollment_uses BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER enrollment_no_tenant_update BEFORE UPDATE ON enrollment_tenants BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER enrollment_no_tenant_delete BEFORE DELETE ON enrollment_tenants BEGIN SELECT RAISE(ABORT,'immutable'); END;
            """)
            state = {"schema": "usbay.enrollment.storage.v3", "head": self.head, "publication": "FINALIZED", "event_tip": "sha256:" + "0" * 64}
            conn.execute("INSERT INTO enrollment_meta VALUES('state',?)", (canonical(state).decode(),))

    def next_adoption(self):
        p = deepcopy(self.inputs["policy"]["payload"])
        p.update(policy_version="synthetic-policy-2", parent_policy_reference=digest(self.inputs["policy"]["payload"]))
        a = deepcopy(self.inputs["adoption"]["payload"])
        a.update(policy_version=p["policy_version"], policy_hash=digest(p), sequence=2,
                 previous_head_hash=self.head["head_hash"], grant_id="synthetic-adopt-2", nonce="synthetic-adopt-nonce-2", replay_identity="synthetic-adopt-replay-2")
        b = common("advance", "advance")
        b.update(policy_id=p["policy_id"], policy_version=p["policy_version"], policy_hash=digest(p),
            action=ADVANCE, grant_id="synthetic-advance-2", advance_actor="advance", nonce="synthetic-advance-nonce-2",
            replay_identity="synthetic-advance-replay-2", previous_head_hash=self.head["head_hash"],
            sequence=2, generation=1, epoch=1, lineage_hash=a["lineage_hash"], adoption_core_hash=digest(a), max_advances=1)
        b["head_hash"] = target_head(b)
        prior = {k: deepcopy(self.inputs[k]) for k in ("policy", "adoption", "h", "w", "revocations")}
        prior.update(challenge=self.inputs["request"]["payload"]["nonce"], request_digest=digest(self.inputs["request"]["payload"]))
        return {"policy": self.sign(p), "adoption": self.sign(a), "advance": self.sign(b), "prior": prior}


def common(kind, issuer):
    return dict(schema_version="usbay.enrollment." + kind + ".v3", trust_domain=TRUST_DOMAIN,
        policy_domain=POLICY_DOMAIN, tenant_id="synthetic-enrollment-tenant", environment="non-production", purpose=PURPOSE,
        registry_instance_reference=digest({"registry": "synthetic-only"}), authority_flags=dict.fromkeys(FLAGS, False), delegation_allowed=False,
        issuer_id=issuer, issuer_key_id=issuer, algorithm="Ed25519", issued_at="2026-01-02T11:59:59Z",
        valid_from="2026-01-02T11:00:00Z", expires_at="2026-01-02T13:00:00Z")


def object_revocation(model, payload, *, effective_at="2026-01-02T12:00:00Z"):
    """Explicit synthetic all-version scope for one derived semantic identity."""
    kinds = {"policy": "POLICY_OBJECT_REVOCATION", "grant": "GRANT_OBJECT_REVOCATION",
             "adoption": "ADOPTION_REVOCATION", "advance": "HEAD_ADVANCE_OBJECT_REVOCATION"}
    return dict(kind=kinds[model.kind], target_id=object_id(model, payload),
                target_scope={k: payload[k] for k in SCOPE_FIELDS}, coverage="ALL_VERSIONS_OF_OBJECT",
                effective_at=effective_at)


def synthetic_enrollment(revoked_signers=(), *, private_keys=None, sequence=1, previous=None, revocations=()):
    private = private_keys if private_keys is not None else {role: Ed25519PrivateKey.generate() for role in ("policy", "adoption", "advance", "enrollment", "request", "revocation", "H", "W")}
    keys = tuple(ScopedPublicKey(role, role, key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), (role,),
        "synthetic-enrollment-tenant", digest({"registry": "synthetic-only"}), "2026-01-01T00:00:00Z", "2026-01-03T00:00:00Z",
        digest({"synthetic-root-provenance": role})) for role, key in private.items())
    f = SyntheticEnrollment({}, {}, EnrollmentTrust(keys, max_age_seconds=60), private)
    r = common("revocation", "revocation")
    entries = list(deepcopy(revocations))
    for role in revoked_signers:
        payload = common("policy", role)
        entries.append(dict(kind="KEY_REVOCATION", target_id=key_id(payload),
            target_scope={k: payload[k] for k in SCOPE_FIELDS}, coverage="EXACT_KEY_ID",
            effective_at="2026-01-02T12:00:00Z"))
    r.update(revocations=entries, sequence=sequence, generation=1, epoch=1)
    r["revocation_reference"] = digest(r)
    p = common("policy", "policy")
    p.update(policy_id="synthetic-policy", policy_version=str(sequence), allowed_action=ENROLL, registrar_constraints=["request"],
        parent_policy_reference=previous["policy_hash"] if previous else digest({"synthetic-prior-policy": 1}), lineage_hash=digest({"synthetic-lineage": 1}),
        revocation_reference=r["revocation_reference"], currentness_reference=digest({"contract": "synthetic-currentness"}),
        adoption_authority_reference=digest({"contract": "synthetic-adoption-authority"}))
    a = common("adoption", "adoption")
    a.update(policy_id=p["policy_id"], policy_version=p["policy_version"], policy_hash=digest(p), action=ADOPT,
        grant_id="synthetic-adoption", adopter_actor="adoption", nonce="synthetic-adoption-nonce", replay_identity="synthetic-adoption-replay",
        previous_head_hash=previous["head_hash"] if previous else digest({"synthetic-prior-head": 1}), sequence=sequence, generation=1, epoch=1,
        lineage_hash=p["lineage_hash"], max_adoptions=1, approval_references=[p["adoption_authority_reference"]])
    g = common("grant", "enrollment")
    g.update(domain="USBAY_TENANT_ENROLLMENT", action=ENROLL, grant_id="synthetic-enrollment", registrar_actor="request",
        request_id="synthetic-request", enrollment_valid_until="2026-01-02T12:30:00Z", policy_id=p["policy_id"],
        policy_version=p["policy_version"], policy_hash=digest(p), currentness_reference=p["currentness_reference"],
        revocation_reference=r["revocation_reference"], nonce="synthetic-enrollment-nonce", replay_identity="synthetic-enrollment-replay",
        max_registrations=1, forbidden_capabilities=list(FORBIDDEN))
    request = common("request", "request")
    request.update(policy_id=p["policy_id"], policy_version=p["policy_version"], policy_hash=digest(p), action=ENROLL,
        actor="request", request_id=g["request_id"], nonce="synthetic-request-nonce", replay_identity="synthetic-request-replay",
        method="INTERNAL", path="tenant-enrollment", grant_hash=digest(g), correlation_id="synthetic-correlation")
    h = common("witness", "H")
    h.update(policy_id=p["policy_id"], policy_version=p["policy_version"], policy_hash=digest(p), role="H",
        head_hash=digest({"synthetic-head": sequence}), sequence=sequence, generation=1, epoch=1, lineage_hash=p["lineage_hash"],
        previous_head_hash=a["previous_head_hash"], adoption_core_hash=digest(a), adoption_record_hash=digest({"synthetic-adoption-record": 1}),
        head_advance_grant_hash=digest({"synthetic-prior-advance": 1}), challenge=request["nonce"], request_digest=digest(request),
        revocation_reference=r["revocation_reference"], anchor_hash=digest({"synthetic-anchor": 1}))
    w = deepcopy(h)
    w.update(issuer_id="W", issuer_key_id="W", role="W")
    f.inputs = {name: f.sign(payload) for name, payload in dict(policy=p, adoption=a, grant=g, request=request, h=h, w=w, revocations=r).items()}
    f.head = deepcopy(h)
    return f


def native_enrollment_worker(path, inputs, keys, queue):
    from governance.authority_registry import EnrollmentAuthorityView
    trust = EnrollmentTrust(keys, max_age_seconds=60)
    queue.put(EnrollmentAuthorityView(path, trust, clock=lambda: NOW).enroll(inputs))


def native_adoption_worker(path, inputs, keys, queue):
    from governance.authority_registry import EnrollmentAuthorityView
    trust = EnrollmentTrust(keys, max_age_seconds=60)
    queue.put(EnrollmentAuthorityView(path, trust, clock=lambda: NOW).propose_adoption(inputs))


def native_crash_worker(path, inputs, keys, point):
    """Real SQLite, real verifier; terminate at the instrumented DB boundary."""
    import os
    from governance.authority_registry import EnrollmentAuthorityView
    view = EnrollmentAuthorityView(path, EnrollmentTrust(keys, max_age_seconds=60), clock=lambda: NOW)
    connection = view._connect_existing()

    class CrashConnection:
        def execute(self, sql, *args):
            if point == "before_commit" and sql == "COMMIT":
                os._exit(73)
            value = connection.execute(sql, *args)
            if point == "after_reservation" and sql.startswith("INSERT INTO enrollment_uses"):
                os._exit(74)
            if point == "after_commit" and sql == "COMMIT":
                os._exit(75)
            return value

        def close(self):
            connection.close()

    view._connect_existing = lambda: CrashConnection()
    view.enroll(inputs)
    os._exit(76)  # Distinct failure: the intended crash point was not reached.


def native_stale_precheck_worker(path, inputs, old_head, keys, validated, writer_done, queue):
    """A validates outside the transaction; B then replaces TEST fixture state."""
    from governance.authority_registry import EnrollmentAuthorityView
    from governance.tenant_enrollment_verification import evaluate_enrollment
    trust = EnrollmentTrust(keys, max_age_seconds=60)
    precheck = evaluate_enrollment(trust, inputs, expected=old_head, now=NOW)
    if precheck.get("verification_valid") is not True:
        queue.put({"error": "PRECHECK_DID_NOT_SUCCEED"})
        validated.set()
        return
    validated.set()
    if not writer_done.wait(10):
        queue.put({"error": "WRITER_BARRIER_TIMEOUT"})
        return
    queue.put(EnrollmentAuthorityView(path, trust, clock=lambda: NOW).enroll(inputs))
