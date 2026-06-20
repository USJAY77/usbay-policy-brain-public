"""PB-TRAVEL-003 Voucher Redemption Authority — unit + endpoint tests.

Covers the standalone signing authority (simulator/voucher.py) and the
simulator-scoped issue/verify endpoints. Everything is training-only and
fail-closed: no payment, booking, cash value, crypto, or cashback. The
interactive Partner Verification Console is covered by the Playwright suite
scripts/_shot_voucher_v3.py.
"""

import time

import pytest
from fastapi.testclient import TestClient

from gateway import app as gateway_app
from simulator import voucher as V


# --------------------------------------------------------------------------- #
# Unit tests against the standalone authority module
# --------------------------------------------------------------------------- #
def _issue(**kw):
    return V.issue_voucher(
        kw.pop("voucher_id", "VCHR-BUS-TEST0001"),
        kw.pop("client_id", "trainee01"),
        kw.pop("partner_id", "bus"),
        **kw,
    )


def test_issue_sets_signed_fields_and_non_monetary_markers():
    v = _issue()
    for f in V.REQUIRED_FIELDS:
        assert v.get(f) not in (None, "")
    assert v["voucher_signature"]
    # non-monetary contract
    assert v["cash_value"] == "none"
    assert v["transferable"] is False
    assert v["funding"] == "partner_funded"


def test_verify_active_round_trip():
    v = _issue()
    res = V.verify_voucher(v)
    assert res["valid"] is True
    assert res["status"] == "active"
    assert res["reasons"] == ["VOUCHER_ACTIVE"]


def test_verify_expired_fails_closed():
    now = int(time.time() * 1000)
    v = _issue(issued_at=now - 10 * 86400000, expires_at=now - 86400000)
    res = V.verify_voucher(v, now_ms=now)
    assert res["valid"] is False
    assert res["status"] == "expired"
    assert res["reasons"] == ["VOUCHER_EXPIRED"]


def test_verify_revoked_fails_closed():
    now = int(time.time() * 1000)
    v = _issue(revoked_at=now)
    res = V.verify_voucher(v, now_ms=now)
    assert res["valid"] is False
    assert res["status"] == "revoked"
    assert res["reasons"] == ["VOUCHER_REVOKED"]


def test_tampered_field_breaks_signature():
    v = _issue()
    v["expires_at"] = int(v["expires_at"]) + 999999999  # extend validity, no re-sign
    res = V.verify_voucher(v)
    assert res["valid"] is False
    assert res["status"] == "invalid"
    assert res["reasons"] == ["BAD_SIGNATURE"]


def test_tampered_signature_rejected():
    v = _issue()
    v["voucher_signature"] = "0" * 64
    res = V.verify_voucher(v)
    assert res["valid"] is False
    assert res["reasons"] == ["BAD_SIGNATURE"]


def test_ownership_binding_enforced():
    v = _issue(client_id="trainee01")
    ok = V.verify_voucher(v, expected_client_id="trainee01")
    assert ok["valid"] is True
    bad = V.verify_voucher(v, expected_client_id="someone-else")
    assert bad["valid"] is False
    assert bad["reasons"] == ["OWNERSHIP_MISMATCH"]


def test_missing_fields_fail_closed():
    res = V.verify_voucher({"voucher_id": "X"})
    assert res["valid"] is False
    assert "MISSING_FIELD" in res["reasons"]
    assert "MISSING_SIGNATURE" in res["reasons"]


def test_audit_trail_events():
    now = int(time.time() * 1000)
    active = V.verify_voucher(_issue())
    assert [e["event"] for e in active["audit_trail"]] == ["issued", "viewed", "verified"]
    revoked = V.verify_voucher(_issue(revoked_at=now), now_ms=now)
    assert [e["event"] for e in revoked["audit_trail"]] == [
        "issued", "viewed", "verified", "revoked",
    ]
    expired = V.verify_voucher(
        _issue(issued_at=now - 10 * 86400000, expires_at=now - 86400000), now_ms=now
    )
    assert [e["event"] for e in expired["audit_trail"]] == [
        "issued", "viewed", "verified", "expired",
    ]


def test_secret_is_required_for_valid_signature():
    v = _issue()
    # A different secret must not validate the signature.
    res = V.verify_voucher(v, secret=b"a-different-secret")
    assert res["valid"] is False
    assert res["reasons"] == ["BAD_SIGNATURE"]


# --------------------------------------------------------------------------- #
# Endpoint tests
# --------------------------------------------------------------------------- #
@pytest.fixture()
def client():
    return TestClient(gateway_app.app, raise_server_exceptions=False)


def _q(v):
    return {
        "voucher_id": v["voucher_id"],
        "client_id": v["client_id"],
        "partner_id": v["partner_id"],
        "issued_at": v["issued_at"],
        "expires_at": v["expires_at"],
        "revoked_at": "" if v.get("revoked_at") is None else v["revoked_at"],
        "voucher_signature": v["voucher_signature"],
    }


def test_endpoint_issue_and_verify_active(client):
    iss = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01"})
    assert iss.status_code == 200
    body = iss.json()
    assert body["ok"] is True
    v = body["voucher"]
    res = client.get("/simulator/voucher/verify", params=_q(v)).json()
    assert res["valid"] is True
    assert res["status"] == "active"


def test_endpoint_verify_tamper_fails_closed(client):
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01"}).json()["voucher"]
    q = _q(v)
    q["expires_at"] = int(q["expires_at"]) + 999999999
    res = client.get("/simulator/voucher/verify", params=q).json()
    assert res["valid"] is False
    assert res["reasons"] == ["BAD_SIGNATURE"]


def test_endpoint_verify_revoked_fails_closed(client):
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01", "revoke": 1}).json()["voucher"]
    res = client.get("/simulator/voucher/verify", params=_q(v)).json()
    assert res["valid"] is False
    assert res["status"] == "revoked"


def test_endpoint_verify_ownership_mismatch(client):
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01"}).json()["voucher"]
    q = _q(v)
    q["expected_client_id"] = "someone-else"
    res = client.get("/simulator/voucher/verify", params=q).json()
    assert res["valid"] is False
    assert res["reasons"] == ["OWNERSHIP_MISMATCH"]


def test_endpoint_verify_empty_fails_closed(client):
    res = client.get("/simulator/voucher/verify").json()
    assert res["valid"] is False
    assert res["status"] == "invalid"


def test_endpoint_verify_non_integer_timestamps_fail_closed(client):
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01"}).json()["voucher"]
    q = _q(v)
    q["issued_at"] = "not-a-number"
    q["expires_at"] = "NaN"
    res = client.get("/simulator/voucher/verify", params=q).json()
    assert res["valid"] is False
    assert res["status"] == "invalid"
    assert "MISSING_FIELD" in res["reasons"]


def test_endpoint_responses_are_no_store(client):
    iss = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01"})
    assert "no-store" in iss.headers.get("cache-control", "")
    v = iss.json()["voucher"]
    ver = client.get("/simulator/voucher/verify", params=_q(v))
    assert "no-store" in ver.headers.get("cache-control", "")


def test_endpoint_issue_rejects_bad_ids(client):
    bad_client = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "bad id!"})
    assert bad_client.status_code == 400
    bad_partner = client.get("/simulator/voucher/issue", params={"partner_id": "bad partner!", "client_id": "trainee01"})
    assert bad_partner.status_code == 400


def test_voucher_ui_present(client):
    html = client.get("/simulator").text
    assert "Partner Verification Console" in html
    assert "voucher/verify" in html
    assert "voucher/issue" in html


def test_control_plane_untouched(client):
    res = client.post("/decide", json={})
    assert res.status_code in (400, 401, 403, 422)


# --------------------------------------------------------------------------- #
# PB-TRAVEL-004 — central revocation registry (CRL) unit tests
# --------------------------------------------------------------------------- #
class _DictStore:
    """Minimal in-memory key/value store standing in for a StorageAdapter."""

    def __init__(self, seed=None):
        self._d = dict(seed or {})

    def get(self, key):
        return self._d.get(key)

    def set(self, key, value):
        self._d[key] = value

    def delete(self, key):
        self._d.pop(key, None)


class _BrokenStore:
    """Storage adapter that always raises -> registry must fail closed."""

    def get(self, key):
        raise RuntimeError("storage offline")

    def set(self, key, value):
        raise RuntimeError("storage offline")

    def delete(self, key):
        raise RuntimeError("storage offline")


def test_client_ref_is_non_reversible_and_omits_raw_id():
    ref = V.client_ref("trainee01")
    assert ref.startswith("cref_")
    assert "trainee01" not in ref
    assert V.client_ref("trainee01") == ref  # stable
    assert V.client_ref(None) == "anon"


def test_registry_round_trip_and_idempotent():
    reg = V.RevocationRegistry(_DictStore())
    assert reg.is_revoked("VCHR-BUS-AAA") is False
    out = reg.revoke("VCHR-BUS-AAA", "trainee01", reason="fraud", source="ops")
    assert out["already"] is False
    assert reg.is_revoked("VCHR-BUS-AAA") is True
    rec = reg.get_record("VCHR-BUS-AAA")
    assert rec["reason"] == "fraud" and rec["source"] == "ops"
    # raw client id is never stored
    assert "trainee01" not in str(rec)
    again = reg.revoke("VCHR-BUS-AAA", "trainee01")
    assert again["already"] is True
    assert len(reg.list_records()) == 1


def test_registry_corrupt_data_fails_closed():
    reg = V.RevocationRegistry(_DictStore({V.REVOCATION_REGISTRY_KEY: "{not json"}))
    with pytest.raises(Exception):
        reg.get_record("VCHR-BUS-AAA")
    # A non-object payload must also fail closed.
    reg2 = V.RevocationRegistry(_DictStore({V.REVOCATION_REGISTRY_KEY: "[1,2,3]"}))
    with pytest.raises(Exception):
        reg2.is_revoked("VCHR-BUS-AAA")


def test_registry_malformed_entry_fails_closed():
    # A present-but-tampered per-voucher entry (non-object) must fail closed,
    # never be silently treated as "not revoked".
    for bad in ('{"VCHR-BUS-AAA": "tampered"}', '{"VCHR-BUS-AAA": 123}'):
        reg = V.RevocationRegistry(_DictStore({V.REVOCATION_REGISTRY_KEY: bad}))
        with pytest.raises(Exception):
            reg.get_record("VCHR-BUS-AAA")
        v = _issue(voucher_id="VCHR-BUS-AAA")
        res = V.verify_voucher(v, registry=reg)
        assert res["valid"] is False
        assert res["status"] == "unavailable"
        assert res["reasons"] == ["REVOCATION_REGISTRY_UNAVAILABLE"]
    # An absent key is legitimately "not revoked" (does not raise).
    reg_ok = V.RevocationRegistry(_DictStore({V.REVOCATION_REGISTRY_KEY: '{"OTHER": {"voucher_id":"OTHER"}}'}))
    assert reg_ok.get_record("VCHR-BUS-AAA") is None


def test_verify_with_registry_revoked():
    reg = V.RevocationRegistry(_DictStore())
    v = _issue(voucher_id="VCHR-BUS-REVOKE01")
    reg.revoke(v["voucher_id"], v["client_id"], reason="partner_dispute")
    res = V.verify_voucher(v, registry=reg)
    assert res["valid"] is False
    assert res["status"] == "revoked"
    assert res["reasons"] == ["VOUCHER_REVOKED"]
    assert res["revocation"]["reason"] == "partner_dispute"
    events = [e["event"] for e in res["audit_trail"]]
    assert events == ["issued", "viewed", "verified", "revoked"]
    # audit rows carry the enriched evidence fields, no raw client id
    for row in res["audit_trail"]:
        assert "client_ref" in row and "status" in row and "reason_code" in row
        assert "client_id" not in row
        assert v["client_id"] not in str(row)


def test_verify_with_registry_active_passthrough():
    reg = V.RevocationRegistry(_DictStore())
    v = _issue(voucher_id="VCHR-BUS-ACTIVE01")
    res = V.verify_voucher(v, registry=reg)
    assert res["valid"] is True
    assert res["status"] == "active"
    assert "revocation" not in res


def test_verify_registry_unavailable_fails_closed():
    reg = V.RevocationRegistry(_BrokenStore())
    v = _issue(voucher_id="VCHR-BUS-UNAVAIL01")
    res = V.verify_voucher(v, registry=reg)
    assert res["valid"] is False
    assert res["status"] == "unavailable"
    assert res["reasons"] == ["REVOCATION_REGISTRY_UNAVAILABLE"]
    events = [e["event"] for e in res["audit_trail"]]
    assert events == ["issued", "viewed", "verified", "revoke_failed"]


def test_verify_without_registry_is_backward_compatible():
    v = _issue(voucher_id="VCHR-BUS-NOREG01")
    res = V.verify_voucher(v)  # registry omitted -> signed-field behaviour only
    assert res["valid"] is True
    assert res["status"] == "active"


# --------------------------------------------------------------------------- #
# PB-TRAVEL-004 — revoke endpoint tests
# --------------------------------------------------------------------------- #
def test_endpoint_revoke_requires_ids(client):
    no_voucher = client.get("/simulator/voucher/revoke", params={"client_id": "trainee01"})
    assert no_voucher.status_code == 400
    assert no_voucher.json()["reason_code"] == "INVALID_VOUCHER_ID"
    bad_client = client.get(
        "/simulator/voucher/revoke",
        params={"voucher_id": "VCHR-BUS-XYZ", "client_id": "bad id!"},
    )
    assert bad_client.status_code == 400
    assert bad_client.json()["reason_code"] == "INVALID_CLIENT_ID"
    assert "no-store" in no_voucher.headers.get("cache-control", "")


def test_endpoint_revoke_then_verify_revoked(client):
    v = client.get(
        "/simulator/voucher/issue",
        params={"partner_id": "bus", "client_id": "trainee01"},
    ).json()["voucher"]
    rev = client.get(
        "/simulator/voucher/revoke",
        params={"voucher_id": v["voucher_id"], "client_id": v["client_id"]},
    )
    assert rev.status_code == 200
    body = rev.json()
    assert body["ok"] is True
    assert body["status"] == "revoked"
    assert body["reason_code"] == "VOUCHER_REVOKED"
    # raw client id never leaves the registry record
    assert v["client_id"] not in str(body["revocation"])
    res = client.get("/simulator/voucher/verify", params=_q(v)).json()
    assert res["valid"] is False
    assert res["status"] == "revoked"
    assert res["reasons"] == ["VOUCHER_REVOKED"]
    events = [e["event"] for e in res["audit_trail"]]
    assert "revoked" in events


def test_endpoint_revoke_is_idempotent(client):
    v = client.get(
        "/simulator/voucher/issue",
        params={"partner_id": "bus", "client_id": "trainee01"},
    ).json()["voucher"]
    p = {"voucher_id": v["voucher_id"], "client_id": v["client_id"]}
    first = client.get("/simulator/voucher/revoke", params=p).json()
    second = client.get("/simulator/voucher/revoke", params=p).json()
    assert first["already_revoked"] is False
    assert second["already_revoked"] is True


# --------------------------------------------------------------------------- #
# PB-TRAVEL-005 — governance approval-chain evidence unit tests
# --------------------------------------------------------------------------- #
def test_issue_attaches_approval_evidence_by_default():
    v = _issue()
    ev = v["approval_evidence"]
    # evidence-only markers: no monetary or reward value is ever conferred
    assert ev["evidence_kind"] == "governance_approval"
    assert ev["confers_value"] == "none"
    assert ev["approver"] == "USBAY-GOVERNANCE"
    assert ev["approval_signature"]
    # the attestation binds the voucher subject via a non-reversible client_ref
    assert ev["subject"]["client_ref"] == V.client_ref(v["client_id"])
    assert v["client_id"] not in str(ev)
    assert V.verify_approval_evidence(v, ev) is None


def test_issue_can_omit_approval_evidence():
    v = _issue(with_approval=False)
    assert "approval_evidence" not in v


def test_verify_approval_evidence_subject_binding():
    v = _issue()
    ev = v["approval_evidence"]
    # every bound field must match the voucher subject
    for f in V.APPROVAL_BIND_FIELDS:
        broken = dict(ev)
        broken["subject"] = dict(ev["subject"])
        broken["subject"][f] = "tampered-" + str(broken["subject"].get(f))
        broken["approval_signature"] = V.sign_approval(broken)
        assert V.verify_approval_evidence(v, broken) == "APPROVAL_SUBJECT_MISMATCH"


def test_verify_approval_evidence_missing_and_invalid():
    v = _issue()
    ev = v["approval_evidence"]
    assert V.verify_approval_evidence(v, None) == "APPROVAL_MISSING"
    assert V.verify_approval_evidence(v, {}) == "APPROVAL_MISSING"
    assert V.verify_approval_evidence(v, dict(ev, approved_at=None)) == "TIMESTAMP_MISSING"
    bad_sig = dict(ev, approval_signature="0" * 64)
    assert V.verify_approval_evidence(v, bad_sig) == "APPROVAL_INVALID"
    no_approver = dict(ev, approver="")
    assert V.verify_approval_evidence(v, no_approver) == "APPROVAL_INVALID"


def test_verify_approval_evidence_timestamps():
    v = _issue()
    ev = v["approval_evidence"]
    assert V.verify_approval_evidence(v, dict(ev, approved_at=None)) == "TIMESTAMP_MISSING"
    assert V.verify_approval_evidence(v, dict(ev, approved_at="nope")) == "TIMESTAMP_INVALID"
    assert V.verify_approval_evidence(v, dict(ev, approval_expires_at="nope")) == "TIMESTAMP_INVALID"
    assert V.verify_approval_evidence(v, dict(ev, approval_expires_at=None)) == "APPROVAL_INVALID"


def test_verify_approval_evidence_expired():
    v = _issue()
    ev = V.make_approval_evidence(v, approved_at=1000, approval_expires_at=2000)
    assert V.verify_approval_evidence(v, ev, now_ms=5000) == "APPROVAL_EXPIRED"
    assert V.verify_approval_evidence(v, ev, now_ms=1500) is None


def test_verify_voucher_enforce_approval_valid_and_audit():
    v = _issue()
    res = V.verify_voucher(v, enforce_approval=True)
    assert res["valid"] is True
    assert res["approval"]["status"] == "approved"
    events = [e["event"] for e in res["audit_trail"]]
    assert "approved" in events


def test_verify_voucher_enforce_approval_failed_audit():
    v = _issue(with_approval=False)
    res = V.verify_voucher(v, enforce_approval=True)
    assert res["valid"] is False
    assert res["reasons"] == ["APPROVAL_MISSING"]
    events = [e["event"] for e in res["audit_trail"]]
    assert "approval_failed" in events


def test_verify_voucher_approval_disabled_is_backward_compatible():
    v = _issue(with_approval=False)
    res = V.verify_voucher(v)  # enforce_approval defaults off
    assert res["valid"] is True
    assert "approval" not in res


def test_verify_voucher_tamper_precedes_approval():
    # A tampered signed field must surface BAD_SIGNATURE before the approval gate.
    v = _issue()
    v = dict(v)
    v["expires_at"] = int(v["expires_at"]) + 999999999
    res = V.verify_voucher(v, enforce_approval=True)
    assert res["reasons"] == ["BAD_SIGNATURE"]


def test_verify_voucher_partial_bind_for_revoke():
    # The revoke endpoint only knows voucher_id + client_id.
    v = _issue()
    ev = v["approval_evidence"]
    subset = {"voucher_id": v["voucher_id"], "client_id": v["client_id"]}
    assert V.verify_approval_evidence(
        subset, ev, bind_fields=("voucher_id", "client_ref")) is None


# --------------------------------------------------------------------------- #
# PB-TRAVEL-005 — approval endpoint tests
# --------------------------------------------------------------------------- #
def _qa(v, evidence=None, enforce=1):
    q = _q(v)
    q["enforce_approval"] = enforce
    if evidence is not None:
        import json as _json
        q["approval_evidence"] = evidence if isinstance(evidence, str) else _json.dumps(evidence)
    return q


def test_endpoint_verify_with_approval_valid(client):
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01"}).json()["voucher"]
    res = client.get("/simulator/voucher/verify", params=_qa(v, v["approval_evidence"])).json()
    assert res["valid"] is True
    assert res["approval"]["status"] == "approved"
    assert "approved" in [e["event"] for e in res["audit_trail"]]


def test_endpoint_verify_approval_missing_fails_closed(client):
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01"}).json()["voucher"]
    res = client.get("/simulator/voucher/verify", params=_qa(v, "")).json()
    assert res["valid"] is False
    assert res["reasons"] == ["APPROVAL_MISSING"]


def test_endpoint_verify_approval_malformed_json_fails_closed(client):
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01"}).json()["voucher"]
    res = client.get("/simulator/voucher/verify", params=_qa(v, "{not json")).json()
    assert res["valid"] is False
    assert res["reasons"] == ["APPROVAL_INVALID"]
    assert "approval_failed" in [e["event"] for e in res["audit_trail"]]


def test_endpoint_verify_approval_tampered_signature_fails_closed(client):
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01"}).json()["voucher"]
    ev = dict(v["approval_evidence"], approval_signature="0" * 64)
    res = client.get("/simulator/voucher/verify", params=_qa(v, ev)).json()
    assert res["valid"] is False
    assert res["reasons"] == ["APPROVAL_INVALID"]


def test_endpoint_verify_approval_subject_mismatch_fails_closed(client):
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01"}).json()["voucher"]
    ev = dict(v["approval_evidence"])
    ev["subject"] = dict(ev["subject"], partner_id="train")
    res = client.get("/simulator/voucher/verify", params=_qa(v, ev)).json()
    assert res["valid"] is False
    assert res["reasons"] == ["APPROVAL_SUBJECT_MISMATCH"]


def test_endpoint_verify_without_enforce_is_backward_compatible(client):
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01"}).json()["voucher"]
    res = client.get("/simulator/voucher/verify", params=_q(v)).json()
    assert res["valid"] is True
    assert "approval" not in res


def test_endpoint_issue_can_disable_approval(client):
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01", "approval": 0}).json()["voucher"]
    assert "approval_evidence" not in v


def test_endpoint_revoke_requires_approval_when_enforced(client):
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01"}).json()["voucher"]
    miss = client.get("/simulator/voucher/revoke", params={
        "voucher_id": v["voucher_id"], "client_id": v["client_id"], "enforce_approval": 1})
    assert miss.status_code == 403
    assert miss.json()["reason_code"] == "APPROVAL_MISSING"
    import json as _json
    bad = client.get("/simulator/voucher/revoke", params={
        "voucher_id": v["voucher_id"], "client_id": v["client_id"],
        "enforce_approval": 1, "approval_evidence": "{bad"})
    assert bad.status_code == 403
    assert bad.json()["reason_code"] == "APPROVAL_INVALID"
    ok = client.get("/simulator/voucher/revoke", params={
        "voucher_id": v["voucher_id"], "client_id": v["client_id"],
        "enforce_approval": 1, "approval_evidence": _json.dumps(v["approval_evidence"])})
    assert ok.status_code == 200
    assert ok.json()["status"] == "revoked"


# --------------------------------------------------------------------------- #
# PB-SIM-TRAVEL-006 — preview-only redemption hardening (unit)
# --------------------------------------------------------------------------- #
def test_redeem_preview_active_is_redeemable():
    v = _issue()
    out = V.redeem_preview(v)
    assert out["preview_only"] is True
    assert out["partner_side"] is True
    assert out["redeemable"] is True
    assert out["valid"] is True
    assert out["redeem_state"] == "redeemable_preview"
    assert out["status"] == "active"
    assert out["confers_value"] == "none"
    # safe reference only, never the raw client id
    assert "client_id" not in out
    assert out["client_ref"] == V.client_ref(v["client_id"])
    assert v["client_id"] not in str(out)
    assert "redeem_preview" in [e["event"] for e in out["audit_trail"]]


@pytest.mark.parametrize("mut", ["revoked", "expired", "wrong_owner", "bad_sig", "missing_approval"])
def test_redeem_preview_blocked_states_never_eligible(mut):
    now = int(time.time() * 1000)
    expected = None
    enforce = False
    if mut == "revoked":
        v = _issue(revoked_at=now)
    elif mut == "expired":
        v = _issue(issued_at=now - 10 * 86400000, expires_at=now - 86400000)
    elif mut == "wrong_owner":
        v = _issue()
        expected = "someone-else"
    elif mut == "bad_sig":
        v = dict(_issue())
        v["voucher_signature"] = "0" * 64
    else:  # missing_approval
        v = _issue(with_approval=False)
        enforce = True
    out = V.redeem_preview(v, now_ms=now, expected_client_id=expected, enforce_approval=enforce)
    assert out["redeemable"] is False
    assert out["valid"] is False
    assert out["redeem_state"] == "blocked"
    assert "redeem_blocked" in [e["event"] for e in out["audit_trail"]]
    # a blocked voucher can never report redeemable, regardless of action
    again = V.redeem_preview(v, now_ms=now, expected_client_id=expected, enforce_approval=enforce, action="preview")
    assert again["redeemable"] is False
    assert "preview_blocked" in [e["event"] for e in again["audit_trail"]]
    # raw client id never leaks into the preview or its audit rows
    assert v["client_id"] not in str(out)


def test_redeem_preview_registry_revoked_blocked():
    reg = V.RevocationRegistry(_DictStore())
    v = _issue(voucher_id="VCHR-BUS-RDM01")
    reg.revoke(v["voucher_id"], v["client_id"], reason="partner_dispute")
    out = V.redeem_preview(v, registry=reg)
    assert out["redeemable"] is False
    assert out["status"] == "revoked"
    assert out["reasons"] == ["VOUCHER_REVOKED"]
    assert v["client_id"] not in str(out)


def test_redeem_preview_registry_unavailable_blocked():
    reg = V.RevocationRegistry(_BrokenStore())
    v = _issue(voucher_id="VCHR-BUS-RDM02")
    out = V.redeem_preview(v, registry=reg)
    assert out["redeemable"] is False
    assert out["status"] == "unavailable"
    assert out["reasons"] == ["REVOCATION_REGISTRY_UNAVAILABLE"]


def test_redeem_preview_action_event_vocabulary():
    v = _issue()
    out = V.redeem_preview(v, action="preview")
    assert out["action"] == "preview"
    assert out["redeemable"] is True
    assert "preview" in [e["event"] for e in out["audit_trail"]]
    # default action is redeem
    assert V.redeem_preview(v)["action"] == "redeem"


# --------------------------------------------------------------------------- #
# PB-SIM-TRAVEL-006 — redeem endpoint tests
# --------------------------------------------------------------------------- #
def test_endpoint_redeem_active_redeemable(client):
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01"}).json()["voucher"]
    res = client.get("/simulator/voucher/redeem", params=_qa(v, v["approval_evidence"])).json()
    assert res["preview_only"] is True
    assert res["partner_side"] is True
    assert res["redeemable"] is True
    assert res["redeem_state"] == "redeemable_preview"
    assert res["confers_value"] == "none"
    assert "redeem_preview" in [e["event"] for e in res["audit_trail"]]
    # raw client id is never echoed back by the endpoint
    assert "trainee01" not in str(res)


def test_endpoint_redeem_revoked_blocked(client):
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01", "revoke": 1}).json()["voucher"]
    res = client.get("/simulator/voucher/redeem", params=_qa(v, v["approval_evidence"])).json()
    assert res["redeemable"] is False
    assert res["status"] == "revoked"
    assert "redeem_blocked" in [e["event"] for e in res["audit_trail"]]


def test_endpoint_redeem_blocked_states_cannot_become_eligible(client):
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01"}).json()["voucher"]
    # tampered signed field -> BAD_SIGNATURE
    q1 = _qa(v, v["approval_evidence"])
    q1["expires_at"] = int(q1["expires_at"]) + 999999999
    r1 = client.get("/simulator/voucher/redeem", params=q1).json()
    assert r1["redeemable"] is False
    assert r1["reasons"] == ["BAD_SIGNATURE"]
    # wrong owner -> OWNERSHIP_MISMATCH
    q2 = _qa(v, v["approval_evidence"])
    q2["expected_client_id"] = "someone-else"
    r2 = client.get("/simulator/voucher/redeem", params=q2).json()
    assert r2["redeemable"] is False
    assert r2["reasons"] == ["OWNERSHIP_MISMATCH"]
    # missing approval evidence -> APPROVAL_MISSING
    r3 = client.get("/simulator/voucher/redeem", params=_qa(v, "")).json()
    assert r3["redeemable"] is False
    assert r3["reasons"] == ["APPROVAL_MISSING"]


def test_endpoint_redeem_is_read_only_does_not_revoke(client):
    # Redeeming an active voucher must not mutate state: a follow-up verify
    # must still report the voucher active.
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01"}).json()["voucher"]
    client.get("/simulator/voucher/redeem", params=_qa(v, v["approval_evidence"]))
    res = client.get("/simulator/voucher/verify", params=_qa(v, v["approval_evidence"])).json()
    assert res["valid"] is True
    assert res["status"] == "active"


def test_endpoint_redeem_no_store(client):
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01"}).json()["voucher"]
    r = client.get("/simulator/voucher/redeem", params=_qa(v, v["approval_evidence"]))
    assert "no-store" in r.headers.get("cache-control", "")


def test_endpoint_redeem_preview_action(client):
    v = client.get("/simulator/voucher/issue", params={"partner_id": "bus", "client_id": "trainee01"}).json()["voucher"]
    q = _qa(v, v["approval_evidence"])
    q["action"] = "preview"
    res = client.get("/simulator/voucher/redeem", params=q).json()
    assert res["action"] == "preview"
    assert res["redeemable"] is True
    assert "preview" in [e["event"] for e in res["audit_trail"]]


def test_redeem_preview_missing_approval_blocked_by_default():
    # The redemption surface enforces governance approval by default: a voucher
    # without approval evidence can never be redeemable.
    v = _issue(with_approval=False)
    out = V.redeem_preview(v)  # enforce defaults on for redemption
    assert out["redeemable"] is False
    assert out["reasons"] == ["APPROVAL_MISSING"]
    assert "redeem_blocked" in [e["event"] for e in out["audit_trail"]]


def test_endpoint_redeem_missing_approval_blocked_even_without_enforce_flag(client):
    # Hard-enforcement: a voucher whose approval evidence is absent can never be
    # redeemable, even when the caller omits enforce_approval or sets it to 0.
    v = client.get(
        "/simulator/voucher/issue",
        params={"partner_id": "bus", "client_id": "trainee01", "approval": 0},
    ).json()["voucher"]
    assert "approval_evidence" not in v
    # no enforce flag at all
    r0 = client.get("/simulator/voucher/redeem", params=_q(v)).json()
    assert r0["redeemable"] is False
    assert r0["reasons"] == ["APPROVAL_MISSING"]
    # explicit enforce_approval=0 must not bypass either
    q = _q(v)
    q["enforce_approval"] = 0
    r1 = client.get("/simulator/voucher/redeem", params=q).json()
    assert r1["redeemable"] is False
    assert r1["reasons"] == ["APPROVAL_MISSING"]
