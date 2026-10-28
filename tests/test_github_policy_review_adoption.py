from __future__ import annotations

import copy
import base64
import hashlib
import json

import pytest

from governance.github_policy_review_adoption import (
    APPROVAL_PATH, AUTHORITY_PREFIX, SCHEMA, verify_github_adoption,
)
from scripts.pb364_review_evidence import REPO, binding, review_text

pytestmark = pytest.mark.governance
HEAD = "a" * 40
POLICY = b'{"synthetic":true}\n'
MANIFEST = json.dumps({"policy_sha256": hashlib.sha256(POLICY).hexdigest(),
                       "fail_closed_on_manifest_mismatch": True}).encode()


def fixture():
    target = binding(HEAD, MANIFEST, POLICY)
    declaration = {"status": "ACTIVE", "binding": target,
                   "roles": {"USBAY-AUDIT": "security_reviewer", "USBAY-GLOBAL23": "governance_owner"}}
    comment = {"id": 9, "user": {"id": 123, "type": "User"},
               "issue_url": f"https://api.github.com/repos/{REPO}/issues/410",
               "html_url": f"https://github.com/{REPO}/pull/410#issuecomment-9",
               "body": AUTHORITY_PREFIX + json.dumps(declaration)}
    reviews = [{"id": index, "user": {"login": account, "type": "User"},
                "state": "APPROVED", "commit_id": HEAD,
                "submitted_at": "2026-01-01T00:00:00Z", "body": review_text(target),
                "html_url": f"https://github.com/{REPO}/pull/410#pullrequestreview-{index}"}
               for index, account in enumerate(("USBAY-AUDIT", "USBAY-GLOBAL23"), 1)]
    record = {"schema": SCHEMA, "repository": REPO, "pr": 410, "candidate_sha": HEAD,
              "manifest_sha256": target["manifest_sha256"], "policy_sha256": target["policy_sha256"],
              "authority_comment_id": 9, "review_ids": {"USBAY-AUDIT": 1, "USBAY-GLOBAL23": 2}}
    responses = {"": {"full_name": REPO, "owner": {"id": 123, "type": "User"}},
                 "pulls/410": {"state": "open", "head": {"sha": HEAD, "repo": {"full_name": REPO}}},
                 "issues/410/comments?per_page=100&page=1": [comment],
                 "pulls/410/reviews?per_page=100&page=1": reviews}
    for name, content in [("approved_github_actions_policy.manifest.json", MANIFEST),
                          ("approved_github_actions_policy.json", POLICY)]:
        responses[f"contents/governance/{name}?ref={HEAD}"] = {
            "encoding": "base64", "content": base64.b64encode(content).decode()}
    return record, responses, declaration


def verify(record, responses, head=HEAD):
    return verify_github_adoption(record, MANIFEST, POLICY, head, get=lambda path: responses[path])


def test_live_owner_mandate_and_scoped_reviews_allow_only_ci_adoption():
    record, responses, _ = fixture()
    result = verify(record, responses)
    assert result["decision"] == "PASS"
    assert result["policy_adopted"] is True
    assert result["scope"] == "CI_POLICY_ONLY"
    for key in ("placeholder_signatures", "production_signatures", "merge_authorized",
                "deployment_authorized", "activation_authorized"):
        assert result[key] is False


@pytest.mark.parametrize("field,value", [("schema", "unknown"), ("repository", "other/repo"),
    ("pr", 409), ("candidate_sha", "not a hash"), ("manifest_sha256", "0" * 64),
    ("policy_sha256", "0" * 64), ("authority_comment_id", True),
    ("review_ids", {"USBAY-AUDIT": 1, "USBAY-GLOBAL23": 1})])
def test_forged_local_record_cannot_grant_authority(field, value):
    record, responses, _ = fixture()
    record[field] = value
    assert verify(record, responses)["decision"] == "FAIL_CLOSED"


@pytest.mark.parametrize("mutation", ["missing", "other_owner", "bot", "wrong_pr", "bad_json",
    "revoked", "wrong_manifest", "wrong_roles", "same_role", "missing_role", "extra_role"])
def test_owner_mandate_is_required_and_exact(mutation):
    record, responses, declaration = fixture()
    comments = responses["issues/410/comments?per_page=100&page=1"]
    comment = comments[0]
    if mutation == "missing": comments.clear()
    elif mutation == "other_owner": comment["user"]["id"] = 999
    elif mutation == "bot": comment["user"]["type"] = "Bot"
    elif mutation == "wrong_pr": comment["issue_url"] += "1"
    elif mutation == "bad_json": comment["body"] = AUTHORITY_PREFIX + "broken"
    else:
        if mutation == "revoked": declaration["status"] = "REVOKED"
        elif mutation == "wrong_manifest": declaration["binding"]["manifest_sha256"] = "0" * 64
        elif mutation == "wrong_roles": declaration["roles"]["USBAY-AUDIT"] = "admin"
        elif mutation == "same_role": declaration["roles"]["USBAY-AUDIT"] = "governance_owner"
        elif mutation == "missing_role": del declaration["roles"]["USBAY-AUDIT"]
        elif mutation == "extra_role": declaration["roles"]["extra"] = "security_reviewer"
        comment["body"] = AUTHORITY_PREFIX + json.dumps(declaration)
    assert verify(record, responses)["decision"] == "FAIL_CLOSED"


def test_new_owner_revocation_supersedes_old_active_comment():
    record, responses, declaration = fixture()
    comments = responses["issues/410/comments?per_page=100&page=1"]
    revoked = copy.deepcopy(comments[0])
    declaration["status"] = "REVOKED"
    revoked.update(id=10, body=AUTHORITY_PREFIX + json.dumps(declaration))
    comments.append(revoked)
    assert verify(record, responses)["decision"] == "FAIL_CLOSED"


def test_owner_authored_ai_draft_is_not_an_explicit_mandate():
    record, responses, _ = fixture()
    comment = responses["issues/410/comments?per_page=100&page=1"][0]
    comment["body"] = "AI-PREPARED DRAFT, NOT AN OWNER DECISION\n" + comment["body"]
    assert verify(record, responses)["reason"] == "GITHUB_POLICY_OWNER_MANDATE_NOT_EXPLICIT"


@pytest.mark.parametrize("state", ["COMMENTED", "DISMISSED", "CHANGES_REQUESTED"])
def test_review_dismissal_or_objection_blocks_adoption(state):
    record, responses, _ = fixture()
    responses["pulls/410/reviews?per_page=100&page=1"][0]["state"] = state
    assert verify(record, responses)["decision"] == "FAIL_CLOSED"


def test_wrong_review_reference_fails_closed():
    record, responses, _ = fixture()
    record["review_ids"]["USBAY-AUDIT"] = 100
    assert verify(record, responses)["decision"] == "FAIL_CLOSED"


def test_only_registration_file_may_change_after_review():
    record, responses, _ = fixture()
    head = "b" * 40
    responses["pulls/410"]["head"]["sha"] = head
    comparison = {"status": "ahead", "base_commit": {"sha": HEAD},
                  "merge_base_commit": {"sha": HEAD},
                  "files": [{"filename": APPROVAL_PATH, "status": "modified"}]}
    responses[f"compare/{HEAD}...{head}"] = comparison
    assert verify(record, responses, head)["decision"] == "PASS"
    comparison["files"].append({"filename": "gateway/app.py", "status": "modified"})
    assert verify(record, responses, head)["reason"] == "GITHUB_POLICY_REVIEWED_CONTENT_CHANGED"


def test_api_failure_is_not_offline_approval():
    record, _, _ = fixture()
    def unavailable(path):
        raise TimeoutError("synthetic")
    result = verify_github_adoption(record, MANIFEST, POLICY, HEAD, get=unavailable)
    assert result["decision"] == "FAIL_CLOSED"
    assert result["policy_adopted"] is False


def test_changed_head_during_read_fails_closed():
    record, responses, _ = fixture()
    calls = 0
    def get(path):
        nonlocal calls
        result = copy.deepcopy(responses[path])
        if path == "pulls/410":
            calls += 1
            if calls == 2:
                result["head"]["sha"] = "b" * 40
        return result
    assert verify_github_adoption(record, MANIFEST, POLICY, HEAD, get=get)["reason"] == "GITHUB_POLICY_PR_CHANGED_DURING_READ"


def test_register_command_emits_only_live_verified_references(monkeypatch, capsys):
    from scripts import pb364_review_evidence as cli
    record, responses, _ = fixture()
    for path, content in [("manifest.json", MANIFEST), ("json", POLICY)]:
        name = "approved_github_actions_policy." + path
        responses[f"contents/governance/{name}?ref={HEAD}"] = {
            "encoding": "base64", "content": base64.b64encode(content).decode()}
    monkeypatch.setattr(cli, "github_get", lambda path: responses[path])
    monkeypatch.setattr("sys.argv", ["review-evidence", "register"])
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out) == record
    responses["issues/410/comments?per_page=100&page=1"].clear()
    assert cli.main() != 0
    assert json.loads(capsys.readouterr().out)["status"] == "FAIL_CLOSED"


def test_v2_root_dispatch_uses_actual_bytes_and_checked_out_head(tmp_path, monkeypatch):
    from tests.helpers.governance_policy_approvals import verify_policy_approvals
    from governance import github_policy_review_adoption as implementation
    record, responses, _ = fixture()
    governance = tmp_path / "governance"
    governance.mkdir()
    (governance / "approved_github_actions_policy.approvals.json").write_text(json.dumps(record))
    (governance / "approved_github_actions_policy.manifest.json").write_bytes(MANIFEST)
    (governance / "approved_github_actions_policy.json").write_bytes(POLICY)
    monkeypatch.setattr("subprocess.check_output", lambda *args, **kwargs: HEAD + "\n")
    real_verify = implementation.verify_github_adoption
    monkeypatch.setattr(implementation, "verify_github_adoption",
                        lambda *args: real_verify(*args, get=lambda path: responses[path]))
    assert verify_policy_approvals(root=tmp_path)["decision"] == "PASS"
    (governance / "approved_github_actions_policy.json").write_bytes(b"changed")
    assert verify_policy_approvals(root=tmp_path)["decision"] == "FAIL_CLOSED"


def test_merged_policy_adoption_survives_later_descendant_without_new_authority():
    record, responses, _ = fixture()
    delivery, merged, later = "b" * 40, "c" * 40, "d" * 40
    responses["pulls/410"].update(state="closed", merged=True, merge_commit_sha=merged)
    responses["pulls/410"]["head"]["sha"] = delivery
    responses[f"compare/{HEAD}...{delivery}"] = {
        "status": "ahead", "base_commit": {"sha": HEAD}, "merge_base_commit": {"sha": HEAD},
        "files": [{"filename": APPROVAL_PATH, "status": "modified"}]}
    for sha in (merged, delivery):
        responses[f"git/commits/{sha}"] = {"tree": {"sha": "e" * 40}}
    responses[f"contents/{APPROVAL_PATH}?ref={merged}"] = {
        "encoding": "base64", "content": base64.b64encode(json.dumps(record).encode()).decode()}
    responses[f"compare/{merged}...{later}"] = {
        "status": "ahead", "merge_base_commit": {"sha": merged}}
    assert verify(record, responses, merged)["decision"] == "PASS"
    assert verify(record, responses, later)["decision"] == "PASS"
    responses[f"compare/{merged}...{later}"]["status"] = "diverged"
    assert verify(record, responses, later)["decision"] == "FAIL_CLOSED"
    responses[f"git/commits/{merged}"]["tree"]["sha"] = "f" * 40
    assert verify(record, responses, merged)["reason"] == "GITHUB_POLICY_MERGE_TREE_MISMATCH"


def test_local_hash_declaration_cannot_substitute_different_reviewed_source():
    record, responses, _ = fixture()
    responses[f"contents/governance/approved_github_actions_policy.json?ref={HEAD}"]["content"] = base64.b64encode(b"other").decode()
    assert verify(record, responses)["reason"] == "GITHUB_POLICY_REVIEWED_BYTES_MISMATCH"
