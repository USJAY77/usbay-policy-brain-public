import time

from security.evidence_export_authorization import EVIDENCE_EXPORT_AUDIENCE


SYNTHETIC_EVIDENCE_EXPORT_TOKEN = "synthetic-evidence-export-test-token"
SYNTHETIC_EVIDENCE_EXPORT_HEADERS = {
    "authorization": f"Bearer {SYNTHETIC_EVIDENCE_EXPORT_TOKEN}",
}


def install_synthetic_evidence_export_verifier(monkeypatch, gateway_app, *, tenant_id="t1"):
    def verifier(credential, *, required_audience, required_scope):
        assert credential == SYNTHETIC_EVIDENCE_EXPORT_TOKEN
        assert required_audience == EVIDENCE_EXPORT_AUDIENCE
        assert required_scope == "evidence:read"
        return {
            "subject_id": "synthetic-export-subject",
            "tenant_id": tenant_id,
            "audience": EVIDENCE_EXPORT_AUDIENCE,
            "scopes": ["evidence:read"],
            "expires_at_epoch": int(time.time()) + 600,
            "revoked": False,
            "rotation_state": "ROTATION_CURRENT",
            "credential_id": "synthetic-export-credential",
        }

    monkeypatch.setattr(gateway_app, "evidence_export_identity_verifier", verifier)