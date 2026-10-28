"""Prepare scoped reviews and collect GitHub evidence; never grant authority.

GET-only, public repository access. No token, credentials, runtime imports,
repository writes, review submission, signature fabrication or adoption.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from datetime import datetime, timezone
from urllib.request import Request, urlopen

REPO = "USJAY77/usbay-policy-brain-public"
PR = 410
REVIEWERS = ("USBAY-AUDIT", "USBAY-GLOBAL23")
PREFIX = "USBAY_POLICY_REVIEW: "
SCOPE = "PB-364: setup-python v7 and Ubuntu 24.04 CI labels; Python 3.11 unchanged"
EXCLUSIONS = ["merge", "deployment", "activation", "permission_changes", "production_authorization"]


def github_get(path: str):
    request = Request(
        "https://api.github.com/repos/" + REPO + "/" + path,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "USBAY-PB364-review-evidence"},
    )
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def binding(head: str, manifest: bytes, policy: bytes) -> dict:
    data = json.loads(manifest)
    policy_hash = hashlib.sha256(policy).hexdigest()
    if data.get("policy_sha256") != policy_hash:
        raise ValueError("POLICY_MANIFEST_MISMATCH")
    if data.get("fail_closed_on_manifest_mismatch") is not True:
        raise ValueError("MANIFEST_NOT_FAIL_CLOSED")
    return {
        "candidate_sha": head,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "policy_sha256": policy_hash,
        "scope": SCOPE,
        "excludes": EXCLUSIONS,
    }


def review_text(target: dict) -> str:
    return (
        "I have reviewed this candidate and the stated limitations. "
        "My decision, when submitted with GitHub Approve, is APPROVE_FOR_STATED_SCOPE.\n\n"
        "Scope: " + SCOPE + ". This records my scoped review, not a claim of "
        "production signing authority. Authority validation and the separate policy-adoption gate remain required.\n"
        "This decision does not authorize merge, deployment, activation, permission changes or production use.\n\n"
        + PREFIX + json.dumps(target, sort_keys=True, separators=(",", ":"))
    )


def collect(reviews: list[dict], target: dict) -> dict:
    latest = {}
    for review in reviews:
        account = review.get("user", {}).get("login")
        if account not in REVIEWERS or review.get("state") == "PENDING":
            continue
        if not isinstance(review.get("id"), int):
            raise ValueError("MALFORMED_REVIEW_ID")
        if account not in latest or review["id"] > latest[account]["id"]:
            latest[account] = review
    records, pending = [], []
    for account in REVIEWERS:
        review = latest.get(account)
        markers = [line[len(PREFIX):] for line in (review or {}).get("body", "").splitlines() if line.startswith(PREFIX)]
        try:
            declared = json.loads(markers[0]) if len(markers) == 1 else None
        except (ValueError, TypeError):
            declared = None
        expected_url = f"https://github.com/{REPO}/pull/{PR}#pullrequestreview-{(review or {}).get('id')}"
        if not review or not (
            review.get("state") == "APPROVED"
            and review.get("commit_id") == target["candidate_sha"]
            and review.get("user", {}).get("type") == "User"
            and review.get("submitted_at")
            and review.get("html_url") == expected_url
            and declared == target
        ):
            pending.append(account)
            continue
        records.append({
            "account": account, "review_id": review["id"],
            "submitted_at": review["submitted_at"], "evidence_url": review["html_url"],
            "decision": "APPROVE_FOR_STATED_SCOPE", "binding": target,
            "authority_status": "NOT_VERIFIED", "signature": None,
        })
    return {
        "schema": "usbay.github_policy_review_evidence.v1",
        "repository": REPO, "pr": PR, "binding": target,
        "status": "REVIEWS_RECORDED" if not pending else "PENDING_REVIEWS",
        "reviews": records, "pending_reviewers": pending,
        "authority_status": "NOT_VERIFIED", "policy_adopted": False,
        "production_signatures": False, "merge_authorized": False,
    }


def snapshot(get=github_get) -> tuple[dict, dict]:
    pr = get(f"pulls/{PR}")
    if pr.get("state") != "open" or pr.get("head", {}).get("repo", {}).get("full_name") != REPO:
        raise ValueError("UNEXPECTED_PR_SOURCE")
    head = pr["head"]["sha"]

    def read_file(path):
        data = get(f"contents/{path}?ref={head}")
        if data.get("encoding") != "base64":
            raise ValueError("UNSUPPORTED_CONTENT_ENCODING")
        return base64.b64decode(data["content"])

    target = binding(head, read_file("governance/approved_github_actions_policy.manifest.json"),
                     read_file("governance/approved_github_actions_policy.json"))
    reviews = []
    for page in range(1, 101):
        batch = get(f"pulls/{PR}/reviews?per_page=100&page={page}")
        if not isinstance(batch, list):
            raise ValueError("MALFORMED_REVIEW_RESPONSE")
        reviews.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise ValueError("INCOMPLETE_REVIEW_PAGINATION")
    after = get(f"pulls/{PR}")
    if after.get("head", {}).get("sha") != head or after.get("state") != "open":
        raise ValueError("PR_CHANGED_DURING_READ")
    return target, collect(reviews, target)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "collect"))
    args = parser.parse_args()
    try:
        target, evidence = snapshot()
        if args.mode == "prepare":
            print("AI-PREPARED DRAFT — each reviewer must inspect and submit their own decision.\n")
            print(review_text(target))
            return 0
        evidence["observed_at"] = datetime.now(timezone.utc).isoformat()
        print(json.dumps(evidence, sort_keys=True, indent=2))
        return 0 if not evidence["pending_reviewers"] else 2
    except Exception as error:
        # No arbitrary response bodies, credentials or application content.
        print(json.dumps({"status": "FAIL_CLOSED", "error_type": type(error).__name__,
                          "policy_adopted": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
