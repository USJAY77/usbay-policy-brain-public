"""No provisioned trust by default. Configuration is a trusted composition input,
not an HTTP/caller context, key discovery mechanism or an authority issuer.

No operational composition is installed by this package. Synthetic tests pass
ephemeral scoped public-key bindings explicitly. A live composition additionally
needs independently established root provenance and H/W independence evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from governance.tenant_enrollment_contracts import (
    Contract, EnrollmentPolicy, PolicyAdoption, RevocationRecord, CurrentHeadWitness,
    TRUST_DOMAIN, POLICY_DOMAIN, PURPOSE, canonical, digest, instant, require, scope, check_revocation,
)
from security.enrollment_policy_witness import verify_witness_pair


@dataclass(frozen=True)
class ScopedPublicKey:
    """Pinned by an independently governed future composition, never a request.
    Public verification data only; this type alone creates no trust or mandate.
    """
    issuer_id: str
    key_id: str
    public_key: bytes
    roles: tuple[str, ...]
    tenant_id: str
    registry_instance_reference: str
    valid_from: str
    expires_at: str
    provenance_reference: str
    trust_domain: str = TRUST_DOMAIN
    policy_domain: str = POLICY_DOMAIN
    environment: str = "non-production"
    purpose: str = PURPOSE


class EnrollmentTrust:
    """Immutable snapshot for a verifier, empty unless explicitly composed.

    No environment loading, TOFU, register-key or private-key API. Replacing this
    snapshot cannot be an admission operation. Revocation/currentness are checked
    separately at every protected transaction; no cached ALLOW context is used.
    """
    def __init__(self, keys: tuple[ScopedPublicKey, ...] = (), *, max_age_seconds: int = 0):
        require(type(keys) is tuple and all(type(k) is ScopedPublicKey for k in keys), "TRUST_CONFIG_INVALID")
        require(type(max_age_seconds) is int and max_age_seconds >= 0, "TRUST_CONFIG_INVALID")
        require(len({k.key_id for k in keys}) == len(keys), "TRUST_CONFIG_INVALID")
        self._keys = MappingProxyType({k.key_id: k for k in keys})
        self.max_age_seconds = max_age_seconds

    def verify(self, envelope: dict, model: type[Contract], role: str, now: datetime) -> dict:
        require(type(envelope) is dict and set(envelope) == {"payload", "signature"}, "SIGNED_ENVELOPE_INVALID")
        payload = model.from_payload(envelope["payload"]).payload
        key = self._keys.get(payload["issuer_key_id"])
        require(key is not None and self.max_age_seconds > 0, "TRUST_MISSING")
        require(key.issuer_id == payload["issuer_id"] and role in key.roles, "SIGNER_SCOPE_INVALID")
        require((key.trust_domain, key.policy_domain, key.tenant_id, key.environment, key.purpose,
                 key.registry_instance_reference) == scope(payload), "SIGNER_SCOPE_INVALID")
        require(type(key.provenance_reference) is str and key.provenance_reference.startswith("sha256:")
                and len(key.provenance_reference) == 71, "TRUST_PROVENANCE_MISSING")
        require(instant(key.valid_from) <= now < instant(key.expires_at), "TRUST_EXPIRED")
        require(instant(payload["valid_from"]) <= now < instant(payload["expires_at"]), "EXPIRED")
        age = (now - instant(payload["issued_at"])).total_seconds()
        require(0 <= age <= self.max_age_seconds, "STALE_EVIDENCE")
        require(type(envelope["signature"]) is str and len(envelope["signature"]) == 128, "SIGNATURE_INVALID")
        try:
            Ed25519PublicKey.from_public_bytes(key.public_key).verify(
                bytes.fromhex(envelope["signature"]), canonical(payload))
        except Exception:
            # The bounded error never discloses the payload, token or key.
            from governance.tenant_enrollment_contracts import EnrollmentDenied
            raise EnrollmentDenied("SIGNATURE_INVALID") from None
        return payload


def verify_currentness(trust: EnrollmentTrust, *, policy: dict, adoption: dict,
                       h: dict, w: dict, revocations: dict, expected: dict,
                       challenge: str, request_digest: str, now: datetime) -> tuple[dict, dict, dict]:
    require(type(trust) is EnrollmentTrust, "TRUST_CONTEXT_INVALID")
    p = trust.verify(policy, EnrollmentPolicy, "policy", now)
    a = trust.verify(adoption, PolicyAdoption, "adoption", now)
    r = trust.verify(revocations, RevocationRecord, "revocation", now)
    hh = trust.verify(h, CurrentHeadWitness, "H", now)
    ww = trust.verify(w, CurrentHeadWitness, "W", now)
    require(trust._keys[hh["issuer_key_id"]].public_key != trust._keys[ww["issuer_key_id"]].public_key,
            "WITNESS_SEPARATION_INVALID")
    require(scope(p) == scope(a) == scope(r), "POLICY_SCOPE_INVALID")
    require(a["policy_id"] == p["policy_id"] and a["policy_version"] == p["policy_version"]
            and a["policy_hash"] == digest(p), "ADOPTION_POLICY_INVALID")
    # The policy names a governance contract, not a future grant that itself
    # contains this policy's hash (which would be a circular digest).
    require(p["adoption_authority_reference"] in a["approval_references"], "ADOPTION_AUTHORITY_INVALID")
    require(p["lineage_hash"] == a["lineage_hash"] == hh["lineage_hash"], "LINEAGE_INVALID")
    require(all(r[k] == hh[k] for k in ("sequence", "generation", "epoch", "revocation_reference")), "REVOCATION_NOT_CURRENT")
    require(p["revocation_reference"] == r["revocation_reference"] == hh["revocation_reference"], "REVOCATION_NOT_CURRENT")
    require(r["revocation_reference"] == digest({k: v for k, v in r.items() if k != "revocation_reference"}),
            "REVOCATION_NOT_CURRENT")
    for payload, model in ((p, EnrollmentPolicy), (a, PolicyAdoption),
                           (hh, CurrentHeadWitness), (ww, CurrentHeadWitness), (r, RevocationRecord)):
        check_revocation(r, payload, model, now)
    verify_witness_pair(hh, ww, policy=p, adoption_hash=digest(a), expected=expected,
                        challenge=challenge, request_digest=request_digest)
    return p, a, r
