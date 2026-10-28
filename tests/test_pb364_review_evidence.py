from __future__ import annotations

import base64
import copy
import hashlib
import json

import pytest

from scripts.pb364_review_evidence import PREFIX, REPO, binding, collect, review_text, snapshot

pytestmark = pytest.mark.governance
POLICY = b'{"policy":"synthetic test only"}\n'
MANIFEST = json.dumps({"policy_sha256": hashlib.sha256(POLICY).hexdigest(),
                       "fail_closed_on_manifest_mismatch": True}).encode()
TARGET = binding("a" * 40, MANIFEST, POLICY)


def reviews():
    return [{"id": index, "user": {"login": account, "type": "User"},
             "state": "APPROVED", "commit_id": TARGET["candidate_sha"],
             "submitted_at": "2026-01-01T00:00:00Z", "body": review_text(TARGET),
             "html_url": f"https://github.com/{REPO}/pull/410#pullrequestreview-{index}"}
            for index, account in enumerate(("USBAY-AUDIT", "USBAY-GLOBAL23"), 1)]


def test_two_bound_reviews_record_evidence_without_granting_authority():
    result = collect(reviews(), TARGET)
    assert result["status"] == "REVIEWS_RECORDED"
    assert len(result["reviews"]) == 2
    assert result["authority_status"] == "NOT_VERIFIED"
    assert result["policy_adopted"] is False
    assert result["production_signatures"] is False
    assert result["merge_authorized"] is False


@pytest.mark.parametrize("field,value", [
    ("state", "COMMENTED"), ("state", "DISMISSED"), ("state", "CHANGES_REQUESTED"),
    ("commit_id", "b" * 40), ("submitted_at", None), ("html_url", "https://example.com"),
    ("body", "APPROVED"), ("body", PREFIX + "invalid json"),
    ("user", {"login": "USJAY77", "type": "User"}),
    ("user", {"login": "USBAY-AUDIT", "type": "Bot"}),
])
def test_unbound_or_nonreview_decisions_remain_pending(field, value):
    items = reviews()
    items[0][field] = value
    assert collect(items, TARGET)["status"] == "PENDING_REVIEWS"


@pytest.mark.parametrize("field,value", [
    ("manifest_sha256", "0" * 64), ("policy_sha256", "0" * 64),
    ("scope", "all production actions"), ("excludes", []),
])
def test_wrong_or_broader_binding_is_rejected(field, value):
    items = reviews()
    target = copy.deepcopy(TARGET)
    target[field] = value
    items[0]["body"] = review_text(target)
    assert collect(items, TARGET)["pending_reviewers"] == ["USBAY-AUDIT"]


def test_later_objection_overrides_prior_approval_even_on_older_commit():
    items = reviews()
    objection = dict(items[0], id=3, state="CHANGES_REQUESTED", commit_id="b" * 40)
    assert collect([objection] + items, TARGET)["pending_reviewers"] == ["USBAY-AUDIT"]


def test_duplicate_markers_and_duplicate_accounts_do_not_satisfy_two_reviews():
    items = reviews()
    items[0]["body"] += "\n" + PREFIX + json.dumps(TARGET)
    assert collect(items, TARGET)["status"] == "PENDING_REVIEWS"
    assert collect([reviews()[0], reviews()[0]], TARGET)["status"] == "PENDING_REVIEWS"


def test_policy_hash_mismatch_is_rejected():
    with pytest.raises(ValueError, match="POLICY_MANIFEST_MISMATCH"):
        binding("a" * 40, MANIFEST, b"changed")


def test_snapshot_paginates_and_rejects_head_change():
    pages = []
    calls = 0

    def get(path):
        nonlocal calls
        if path == "pulls/410":
            calls += 1
            return {"state": "open", "head": {"sha": "a" * 40 if calls == 1 else "b" * 40,
                    "repo": {"full_name": REPO}}}
        if path.startswith("contents/"):
            content = MANIFEST if "manifest.json" in path else POLICY
            return {"encoding": "base64", "content": base64.b64encode(content).decode()}
        pages.append(path)
        return [reviews()[0]] * 100 if path.endswith("&page=1") else [reviews()[1]]

    with pytest.raises(ValueError, match="PR_CHANGED_DURING_READ"):
        snapshot(get)
    assert len(pages) == 2


def test_empty_reviews_are_pending_not_approvals():
    assert collect([], TARGET)["pending_reviewers"] == ["USBAY-AUDIT", "USBAY-GLOBAL23"]


def test_repository_owner_lookup_uses_canonical_github_endpoint(monkeypatch):
    from contextlib import contextmanager
    from io import StringIO
    from scripts import pb364_review_evidence as client

    observed = []
    @contextmanager
    def response(request, timeout):
        observed.append(request.full_url)
        yield StringIO('{"ok":true}')

    monkeypatch.setattr(client, "urlopen", response)
    assert client.github_get("") == {"ok": True}
    assert client.github_get("pulls/410") == {"ok": True}
    assert observed == [f"https://api.github.com/repos/{REPO}",
                        f"https://api.github.com/repos/{REPO}/pulls/410"]
