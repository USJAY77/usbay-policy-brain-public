from dataclasses import replace

from runtime.computer_use.audit_binding import AuditChain


def test_audit_chain_valid() -> None:
    chain = AuditChain()
    chain.append("decision-1", "ALLOW", "pb169")
    chain.append("decision-2", "BLOCK", "pb169")

    assert chain.verify() is True


def test_audit_chain_detects_tamper() -> None:
    chain = AuditChain()
    entry = chain.append("decision-1", "ALLOW", "pb169")
    chain.entries[0] = replace(entry, decision="BLOCK")

    assert chain.verify() is False

