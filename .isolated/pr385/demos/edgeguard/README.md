# USBAY EdgeGuard Demo

USBAY EdgeGuard controls where AI workloads run before execution is allowed.

This demo uses the privacy-strict compute profile:

- Local NPU is allowed for high-sensitivity workloads.
- Cloud execution is denied by default.
- Every decision is bound to policy, request, compute evidence, and audit hash-chain evidence.
- Every allowed decision is externally verifiable with `verify_decision.py`.
- Hydra-level audit verification requires distributed verifier quorum.

Run:

```bash
bash demos/edgeguard/run_demo.sh
```

Expected proof:

- high sensitivity + cloud returns `DENY`
- high sensitivity + local NPU returns `ALLOW`
- the exported audit record contains compute evidence
- `scripts/verify_decision.py` returns `VALID`
- `scripts/hydra_verify_audit.py` returns `VALID`

No raw sensitive payloads, private keys, or secrets are printed.

## Safe Reset

Reset generated demo outputs with:

```bash
bash demos/edgeguard/reset_demo.sh
```

The reset script is path-locked to `demos/edgeguard/out`, lists generated files before deletion, writes `demos/edgeguard/out/reset_audit.log`, and preserves the output directory. Audit evidence should not be deleted blindly because it is the proof trail for governance decisions; reset operations need their own visible audit record.

`reset_audit.log` is append-only JSONL. Each entry contains `timestamp`, `actor_id`, `actor_pubkey_id`, `actor_signature`, `file_list_deleted`, `previous_log_hash`, and `current_log_hash`, where `current_log_hash = sha256(previous_log_hash + entry)`. Each entry is signed with Ed25519 by an allowlisted reset actor. Verify the reset log with:

```bash
bash demos/edgeguard/reset_demo.sh --verify-log
```

If the reset log is modified or a previous hash is missing, reset fails closed.

Hydra-level reset log verification:

```bash
python3 scripts/hydra_verify_audit.py --reset-log demos/edgeguard/out/reset_audit.log
```

The reset script also enforces a retention policy through `EDGEGUARD_RESET_MAX_LOG_SIZE_MB` and archives oversized logs with a hash anchor before appending new reset evidence.
