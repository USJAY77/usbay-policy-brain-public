# AGENTS.md

## Review guidelines
- Do not disable validation or tests.
- Preserve fail-closed behavior.
- Never remove audit logging.
- Prefer minimal diffs.
- Do not modify secrets handling.
- Do not introduce logging of sensitive data.
- Keep Python import roots consistent with PYTHONPATH=$(pwd)/python.
- For CI failures, fix workflow/runtime alignment before changing application logic.

## Shared USBAY engineering guidance

Before USBAY engineering, read `docs/engineering/USBAY_ENGINEERING_DISCIPLINE.md`.
Expected version: USBAY-ENG-1.1.0
Expected SHA256: 29b8c081032ebedc6326927fbb1cfeee94f6d6f9e290a224ec9bfa0b43ffd274

Preserve higher-priority instructions, authorized scope, existing review rules and product contracts. Missing source or a hash mismatch is a context gap; report it and do not infer protected authority. These are engineering practices, not runtime policy, grants or evidence of production readiness.

Business-risk practice for material changes: connect the human/customer outcome and concrete failure scenario to a control mechanism, required evidence, residual risk and accountable decision role. Define scoped outcome metrics, resilience/recovery limits and cost/uncertainty; distinguish estimates from observations. Risk appetite and residual-risk acceptance remain with authorized humans/governance. A risk score or business case grants no authority. Apply proportionately without resetting the roadmap or adding blanket approval gates.
