from __future__ import annotations

from terminal.verification_harness import append_terminal_evidence_chain


def test_terminal_audit_evidence_chain_hashes_records_without_sensitive_output() -> None:
    chain = append_terminal_evidence_chain(
        [
            {"command": "git status", "stdout_hash": "a" * 64, "stderr_hash": "b" * 64},
            {"command": "git diff --check", "stdout_hash": "c" * 64, "stderr_hash": "d" * 64},
        ]
    )
    assert chain["decision"] == "VERIFIED"
    assert chain["record_count"] == 2
    assert chain["hash_chain"][0]["previous_hash"] == "GENESIS"
    assert chain["hash_chain"][1]["previous_hash"] == chain["hash_chain"][0]["current_hash"]
    assert chain["sensitive_output_stored"] is False
