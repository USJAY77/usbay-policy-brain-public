"""GitHub-observed CI policy adoption, with explicit owner mandate.

This is not cryptographic signing, production authority or merge permission.
The caller supplies its checked-out head; all authority is re-read by GET.
"""
from __future__ import annotations

import json
import re
import base64
from urllib.error import HTTPError

from scripts.pb364_review_evidence import PR, REPO, REVIEWERS, binding, collect, github_get

SCHEMA = "usbay.github_actions_policy_approvals.v2"
AUTHORITY_PREFIX = "USBAY_POLICY_AUTHORITY: "
APPROVAL_PATH = "governance/approved_github_actions_policy.approvals.json"


def _pages(get, path):
    result = []
    for page in range(1, 101):
        batch = get(f"{path}?per_page=100&page={page}")
        if not isinstance(batch, list):
            raise ValueError("MALFORMED_GITHUB_RESPONSE")
        result.extend(batch)
        if len(batch) < 100:
            return result
    raise ValueError("INCOMPLETE_GITHUB_PAGINATION")


def _marker(body, prefix):
    if not isinstance(body, str):
        raise ValueError("MALFORMED_DECLARATION")
    lines = [line[len(prefix):] for line in body.splitlines() if line.startswith(prefix)]
    if len(lines) != 1:
        raise ValueError("AMBIGUOUS_DECLARATION")
    return json.loads(lines[0])


def _fail(reason):
    return {"decision": "FAIL_CLOSED", "reason": reason, "fail_closed": True,
            "silent_pass": False, "policy_adopted": False,
            "production_signatures": False, "merge_authorized": False}


def _file(get, path, ref):
    data = get(f"contents/{path}?ref={ref}")
    if data.get("encoding") != "base64":
        raise ValueError("UNSUPPORTED_CONTENT_ENCODING")
    return base64.b64decode(data["content"])


def _pr_state(pr):
    return (pr.get("state"), pr.get("merged"), pr.get("head", {}).get("sha"),
            pr.get("merge_commit_sha"), (pr.get("head", {}).get("repo") or {}).get("full_name"))


def verify_github_adoption(record, manifest, policy, head, *, get=github_get):
    """Reject unsigned local assertions; resolve owner, mandate and reviews live."""
    try:
        required = {"schema", "repository", "pr", "manifest_sha256",
                    "policy_sha256", "verification_mode"}
        if not isinstance(record, dict) or set(record) != required:
            return _fail("GITHUB_POLICY_ADOPTION_RECORD_MALFORMED")
        if record["schema"] != SCHEMA or record["repository"] != REPO or record["pr"] != PR:
            return _fail("GITHUB_POLICY_ADOPTION_SCOPE_MISMATCH")
        if record["verification_mode"] != "LIVE_GITHUB_OWNER_AND_REVIEWS":
            return _fail("GITHUB_POLICY_ADOPTION_MODE_UNKNOWN")
        if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
            return _fail("GITHUB_POLICY_ADOPTION_SHA_MALFORMED")
        pr = get(f"pulls/{PR}")
        candidate = pr["head"]["sha"]
        if not isinstance(candidate, str) or not re.fullmatch(r"[0-9a-f]{40}", candidate):
            return _fail("GITHUB_POLICY_ADOPTION_SHA_MALFORMED")
        target = binding(candidate, manifest, policy)
        if any(record[key] != target[key] for key in ("manifest_sha256", "policy_sha256")):
            return _fail("GITHUB_ACTIONS_POLICY_APPROVALS_MANIFEST_HASH_MISMATCH")
        if (_file(get, "governance/approved_github_actions_policy.manifest.json", candidate) != manifest
                or _file(get, "governance/approved_github_actions_policy.json", candidate) != policy):
            return _fail("GITHUB_POLICY_REVIEWED_BYTES_MISMATCH")
        if json.loads(_file(get, APPROVAL_PATH, candidate)) != record:
            return _fail("GITHUB_POLICY_REVIEWED_SPECIFICATION_MISMATCH")
        repo = get("")
        owner = repo["owner"]
        if repo["full_name"] != REPO or owner.get("type") != "User" or type(owner.get("id")) is not int:
            return _fail("GITHUB_POLICY_OWNER_NOT_VERIFIABLE")
        if pr["head"]["repo"]["full_name"] != REPO:
            return _fail("GITHUB_POLICY_PR_HEAD_MISMATCH")
        if pr.get("state") == "open":
            if pr["head"]["sha"] != head:
                return _fail("GITHUB_POLICY_PR_HEAD_MISMATCH")
        elif pr.get("state") == "closed" and pr.get("merged") is True:
            # Durable adoption after a separately authorized merge: its actual
            # tree must equal the exact PR head reviewed by both accounts.
            merged = pr["merge_commit_sha"]
            if get(f"git/commits/{merged}")["tree"]["sha"] != get(f"git/commits/{candidate}")["tree"]["sha"]:
                return _fail("GITHUB_POLICY_MERGE_TREE_MISMATCH")
            if json.loads(_file(get, APPROVAL_PATH, merged)) != record:
                return _fail("GITHUB_POLICY_MERGED_RECORD_MISMATCH")
            if head != merged:
                comparison = get(f"compare/{merged}...{head}")
                if not (comparison.get("status") == "ahead"
                        and comparison.get("merge_base_commit", {}).get("sha") == merged):
                    return _fail("GITHUB_POLICY_ADOPTION_NOT_IN_CHECKOUT_HISTORY")
        else:
            return _fail("GITHUB_POLICY_PR_CLOSED_WITHOUT_ADOPTION")
        comments = _pages(get, f"issues/{PR}/comments")
        mandates = [comment for comment in comments
                    if comment.get("user", {}).get("id") == owner["id"]
                    and comment.get("user", {}).get("type") == "User"
                    and AUTHORITY_PREFIX in (comment.get("body") or "")]
        if not mandates:
            return _fail("GITHUB_POLICY_OWNER_MANDATE_MISSING")
        mandate = max(mandates, key=lambda comment: comment["id"])
        # A quoted AI draft in an owner-authored conversation is not a mandate.
        # The owner must submit the single declaration line as a separate decision.
        if len(mandate.get("body", "").strip().splitlines()) != 1:
            return _fail("GITHUB_POLICY_OWNER_MANDATE_NOT_EXPLICIT")
        declaration = _marker(mandate.get("body"), AUTHORITY_PREFIX)
        if (mandate.get("issue_url") != f"https://api.github.com/repos/{REPO}/issues/{PR}"
                or mandate.get("html_url") != f"https://github.com/{REPO}/pull/{PR}#issuecomment-{mandate['id']}"
                or declaration.get("status") != "ACTIVE"
                or declaration.get("binding") != target):
            return _fail("GITHUB_POLICY_OWNER_MANDATE_INVALID_OR_REVOKED")
        roles = declaration.get("roles")
        if (not isinstance(roles, dict) or set(roles) != set(REVIEWERS)
                or set(roles.values()) != {"governance_owner", "security_reviewer"}):
            return _fail("GITHUB_POLICY_OWNER_ROLES_INVALID")
        reviews = _pages(get, f"pulls/{PR}/reviews")
        # Native Approve approves the exact head containing this specification
        # and policy. Scope/authority come from the explicit owner mandate, not
        # an invented review-body declaration. Nonempty conflicting text fails.
        observed = collect(reviews, target, allow_empty_approval=True)
        if observed["pending_reviewers"]:
            return _fail("GITHUB_POLICY_SCOPED_REVIEWS_PENDING")
        if (_pages(get, f"issues/{PR}/comments") != comments
                or _pages(get, f"pulls/{PR}/reviews") != reviews):
            return _fail("GITHUB_POLICY_DECISIONS_CHANGED_DURING_READ")
        after = get(f"pulls/{PR}")
        if _pr_state(after) != _pr_state(pr):
            return _fail("GITHUB_POLICY_PR_CHANGED_DURING_READ")
        return {
            "decision": "PASS", "reason": "GITHUB_ACTIONS_POLICY_REVIEW_ADOPTION_VALID",
            "fail_closed": False, "policy_adopted": True, "scope": "CI_POLICY_ONLY",
            "manifest_sha256": target["manifest_sha256"], "required_approvers": 2,
            "binding": target,
            "authority_evidence_url": mandate["html_url"],
            "review_evidence": [dict(review, authority_status="OWNER_MANDATE_CONFIRMED")
                                for review in observed["reviews"]],
            "roles": roles, "placeholder_signatures": False, "production_signatures": False,
            "merge_authorized": False, "deployment_authorized": False,
            "activation_authorized": False, "evidence_source": "LIVE_GITHUB_API_OBSERVATION",
        }
    except HTTPError as error:
        return dict(_fail("GITHUB_POLICY_ADOPTION_SOURCE_HTTP_ERROR"), http_status=error.code)
    except Exception:
        return _fail("GITHUB_POLICY_ADOPTION_EVIDENCE_UNAVAILABLE_OR_MALFORMED")
