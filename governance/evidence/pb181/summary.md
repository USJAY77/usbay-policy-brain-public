# PB-181 Adapter Approval Binding

Decision: VERIFIED

Status: READY_FOR_REVIEW

PB-181 defines the shared approval binding required by execution adapters. Every adapter request must include decision id, approval id, policy version, execution token, and authority id.

Missing fields fail closed. Valid bindings produce a deterministic binding hash.

Validation:

- python3 compile: PASS
- focused adapter tests: PASS, 22 passed

