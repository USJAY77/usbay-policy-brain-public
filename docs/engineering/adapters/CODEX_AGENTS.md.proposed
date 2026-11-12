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

USBAY engineering guidance: USBAY-ENG-1.1.0
Source: docs/engineering/USBAY_ENGINEERING_DISCIPLINE.md
Expected SHA256: 29b8c081032ebedc6326927fbb1cfeee94f6d6f9e290a224ec9bfa0b43ffd274

Preserve higher-priority instructions, authorized task scope and existing product contracts. Before engineering, read the shared source and relevant local instructions; do not assume a reference automatically loads its content. Missing source/version evidence is UNKNOWN: continue only independently authorized work; do not bypass required evidence for protected actions.

Always retain these boundaries: effective_authority <= granted_authority; no wildcard or cross-tenant inference; no authority from model output or memory; no secrets/raw sensitive audit data; no security-verification bypass; no production, destructive, permission/trust widening or external publication without applicable explicit authorization. Work autonomously in consolidated authorized batches and report real evidence separately from proposals. Observations, predictions and permission are distinct.

This text is engineering guidance, not a grant, policy adoption or proof of runtime enforcement. Record material instruction conflicts; never resolve them by silently widening authority.

Business-risk practice for material changes: connect the human/customer outcome and concrete failure scenario to a control mechanism, required evidence, residual risk and accountable decision role. Define scoped outcome metrics, resilience/recovery limits and cost/uncertainty; distinguish estimates from observations. Risk appetite and residual-risk acceptance remain with authorized humans/governance. A risk score or business case grants no authority. Apply proportionately without resetting the roadmap or adding blanket approval gates.
