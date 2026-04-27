import json

from audit.hash_chain import AuditHashChain, GENESIS_HASH, compute_hash, verify_chain


def test_audit_hash_chain_links_sequential_events(tmp_path):
    path = tmp_path / "audit_chain.json"
    chain = AuditHashChain(path)

    first = chain.append_event(action="read", decision="ALLOW")
    second = chain.append_event(action="read", decision="BLOCK")

    assert path.exists()
    records = json.loads(path.read_text(encoding="utf-8"))
    assert len(records) == 2
    assert first["hash_prev"] == GENESIS_HASH
    assert second["hash_prev"] == first["hash_current"]
    assert first["hash_current"] != second["hash_current"]

    first_without_hash = dict(first)
    first_without_hash.pop("hash_current")
    second_without_hash = dict(second)
    second_without_hash.pop("hash_current")

    assert compute_hash(first_without_hash, GENESIS_HASH) == first["hash_current"]
    assert compute_hash(second_without_hash, first["hash_current"]) == second["hash_current"]
    assert verify_chain(path)


def test_audit_hash_chain_detects_tampering(tmp_path):
    path = tmp_path / "audit_chain.json"
    chain = AuditHashChain(path)
    chain.append_event(action="read", decision="ALLOW")
    chain.append_event(action="read", decision="BLOCK")

    records = json.loads(path.read_text(encoding="utf-8"))
    records[0]["decision"] = "BLOCK"
    path.write_text(json.dumps(records, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    assert not verify_chain(path)
