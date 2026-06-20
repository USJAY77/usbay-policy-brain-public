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
