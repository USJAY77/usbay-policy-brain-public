from __future__ import annotations

from security.deployment_attestation import RuntimeProvenanceAuthority

# Purpose: isolate governance assertions shared by provenance helper tests.
# Governance scope: immutable authority lineage and release continuity invariants.
# Fail-closed expectation: assertion failures stop tests instead of allowing ambiguity.
# Sensitive-data handling: assertions inspect public hashes and booleans only.


def assert_authority_lineage_valid(authority: RuntimeProvenanceAuthority) -> None:
    context = authority.context_dict()
    assert context["release_lineage"] is True
    assert context["ancestor_continuity"] is True
    assert context["expected_commit"]
    assert context["current_commit"]
    assert context["expected_commit"] in context["accepted_commit_set"]
