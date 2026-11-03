"""Ephemeral SYNTHETIC root only. No owner approvals or live provisioning.

Only this test helper signs authority status or reserves issuance. Durable test
consumption uses the existing SQLite history/consumption primitives, never a
production issuance API. Rollback, reopen and corruption are observable.
"""
from copy import deepcopy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from governance.mutation_authority import COMMON
from governance.mutation_issuer_authority import (
    SCOPES, OBJECT_FIELDS, authority_fingerprint, identity_reference,
)
from governance.tenant_enrollment_contracts import canonical, digest, require
from security.enrollment_policy_currentness import EnrollmentTrust, ScopedPublicKey


def seal_authority(f, payload, kind):
    p = deepcopy(payload)
    name = {"root":"root_fingerprint", "issuer":"issuer_grant_fingerprint",
            "review_policy":"review_policy_fingerprint", "status":"status_fingerprint"}[kind]
    p[name] = authority_fingerprint(p, kind)
    return f.sign(p)


class SyntheticRootAuthoritySource:
    def __init__(self, f):
        self.private = f.private['test-root-currentness']
        self.root = deepcopy(f.root_authority['payload'])
        self.issuer = deepcopy(f.issuer_grant['payload'])
        self.head = f.enrollment.head['head_hash']
        self.revocation = f.enrollment.inputs['revocations']['payload']['revocation_reference']
        self.root_status = self.issuer_status = 'ACTIVE'
        self.challenges = []
        self.store = None

    def attach_store(self, view):
        self.store = view

    def read_issuer_authority(self, *, request_binding, challenge):
        self.challenges.append(challenge)
        consumed = False
        sequence = 1
        if self.store is not None:
            conn = self.store._connect_existing(read_only=True)
            try:
                conn.execute('BEGIN')
                self.store._snapshot(conn)
                sequence = conn.execute('SELECT COUNT(*)+1 FROM enrollment_events').fetchone()[0]
                identities = self.consumption_payload(request_binding)
                checks = [conn.execute('SELECT 1 FROM enrollment_uses WHERE kind=? AND identity=?',
                    ('mutation_issuance:'+label, digest({'issuer':identities['issuer_id'], 'value':identities[label]}))).fetchone() is not None
                    for label in ('grant_id','nonce','replay_identity')]
                # ID or nonce already consumed also forbids a new proposal/hash.
                consumed = any(checks)
            finally:
                conn.close()
        p = {k:deepcopy(self.root[k]) for k in COMMON}
        p.update(schema_version='usbay.mutation_issuance.status.v1',
            issuer_id='synthetic-root-source', issuer_key_id='test-root-currentness',
            root_authority_id=self.root['root_authority_id'], root_authority_hash=digest(self.root),
            issuer_grant_id=self.issuer['issuer_grant_id'], issuer_grant_hash=digest(self.issuer),
            subject_issuer_id=self.issuer['issuer_id'], root_status=self.root_status, issuer_status=self.issuer_status,
            issuance_state='CONSUMED' if consumed else 'AVAILABLE', state_sequence=sequence, state_epoch=1,
            expected_current_head=self.head, revocation_reference=self.revocation,
            request_binding=request_binding, challenge=challenge,
            issued_at='2026-01-02T12:00:00Z', valid_from='2026-01-02T12:00:00Z')
        p['status_fingerprint'] = authority_fingerprint(p,'status')
        return dict(payload=p, signature=self.private.sign(canonical(p)).hex())

    def consumption_payload(self, binding):
        return dict(issuer_id=self.issuer['issuer_id'],grant_id=self.issuer['issuer_grant_id'],
                    nonce=self.issuer['issuance_nonce'],replay_identity=binding)

    def reserve_for_test(self, binding, *, rollback=False):
        """Explicit test-only consumer; no production mutation writer integration."""
        require(self.store is not None, 'TEST_STORE_REQUIRED')
        conn = self.store._connect_existing()
        try:
            conn.execute('BEGIN IMMEDIATE')
            state = self.store._snapshot(conn)
            self.store._consume(conn, 'mutation_issuance', self.consumption_payload(binding))
            self.store._append(conn, state, dict(kind='SYNTHETIC_ISSUANCE_CONSUMED', issuance_binding=binding))
            conn.rollback() if rollback else conn.commit()
        finally:
            conn.close()


def attach_synthetic_issuance(f):
    p = f.grant['payload']
    keys = [key for key in f.trust._keys.values() if key.key_id not in ("test-root", "test-root-currentness")]
    for name, principal, roles in (
        ('test-root', 'synthetic-governance-root', ('mutation_root_authority','mutation_issuer_issuance','mutation_review_policy')),
        ('test-root-currentness','synthetic-root-source',('mutation_root_currentness',))):
        private = f.private.get(name) or Ed25519PrivateKey.generate()
        f.private[name] = private
        keys.append(ScopedPublicKey(principal,name,private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw),
            roles,p['tenant_id'],p['registry_instance_reference'],'2026-01-01T00:00:00Z','2026-01-03T00:00:00Z',
            digest({'explicit-synthetic-identity-only':name})))
    f.trust = EnrollmentTrust(tuple(keys),max_age_seconds=60)
    common = {k:deepcopy(p[k]) for k in COMMON}
    common.update(issuer_id='synthetic-governance-root',issuer_key_id='test-root')
    policy = dict(common,schema_version='usbay.mutation_issuance.review_policy.v1',
        review_policy_id='synthetic-review-policy',required_reviewers=['USBAY-AUDIT','USBAY-GLOBAL23'],
        threshold=2,required=2,distinct_reviewers=True,proposal_binding='EXACT_PROPOSAL_VERSION_HASH')
    f.review_policy = seal_authority(f,policy,'review_policy')
    scopes = dict(allowed_actor_scope=[p['actor_id']],allowed_purpose_scope=[p['purpose']],
        allowed_actions=[p['allowed_action']],allowed_resource_types=[p['resource_type']],allowed_resource_scope=[p['resource_id']],
        allowed_object_scope=[{k:p[k] for k in OBJECT_FIELDS}],allowed_policy_scope=[p['policy_id']],
        allowed_grant_scope=[] if p['target_grant_id'] is None else [p['target_grant_id']],
        allowed_adoption_scope=[] if p['adoption_id'] is None else [p['adoption_id']])
    root = dict(common,**scopes,schema_version='usbay.mutation_issuance.root.v1',
        root_authority_id='synthetic-root',root_identity_reference=identity_reference(f.trust._keys['test-root']),
        lineage_reference=digest({'test-only-explicit-root-establishment':1}),governance_role='USBAY_OWNER_ROOT',
        capability='AUTHORIZE_BOUNDED_MUTATION_ISSUER',allowed_issuer_scope=[p['issuer_id']],
        redelegation_allowed=False,review_policy_reference=digest(f.review_policy['payload']))
    f.root_authority = seal_authority(f,root,'root')
    issuer = dict(common,**scopes,schema_version='usbay.mutation_issuance.issuer.v1',
        issuer_id=p['issuer_id'],authority_issuer_id='synthetic-governance-root',subject_key_id=p['issuer_key_id'],
        issuer_grant_id='synthetic-one-time-issuer',issuer_identity_reference=identity_reference(f.trust._keys[p['issuer_key_id']]),
        parent_authority_id=root['root_authority_id'],parent_authority_hash=digest(f.root_authority['payload']),
        capability='ISSUE_BOUNDED_MUTATION_GRANT',redelegation_allowed=False,
        review_policy_reference=digest(f.review_policy['payload']),issuance_nonce='synthetic-one-time-issuance-nonce',max_child_grants=1)
    f.issuer_grant = seal_authority(f,issuer,'issuer')
    f.parent['payload'].update(parent_authority_id=issuer['issuer_grant_id'],parent_authority_hash=digest(f.issuer_grant['payload']))
    f.refresh()
    f.parent_source.install_test_record(f)
    f.root_source = SyntheticRootAuthoritySource(f)
