# PB-158 Governed Execution Decision Engine

## Purpose

PB-158 adds a local execution decision engine for governed computer-use actions. The engine decides `ALLOW`, `BLOCK`, `HUMAN_REVIEW`, or `FAIL_CLOSED` before any execution path can proceed.

## Implemented Scope

- `runtime/computer_use/action_contract.py`
- `runtime/computer_use/risk_classifier.py`
- `runtime/computer_use/decision_engine.py`
- `tests/test_computer_use_decision_engine.py`
- `tests/test_computer_use_risk_classifier.py`

## Decision Rules

- `LOW` risk -> `ALLOW`
- `MEDIUM` risk -> `HUMAN_REVIEW`
- `HIGH` risk -> `HUMAN_REVIEW`
- `UNKNOWN` risk -> `FAIL_CLOSED`
- missing policy -> `FAIL_CLOSED`
- unsupported action -> `BLOCK`
- provider fail-closed -> `FAIL_CLOSED`
- provider blocked action -> `BLOCK`
- denied/revoked/expired approval state -> `BLOCK`

## Runtime Safety

The engine does not execute browser actions, desktop actions, provider calls, deployments, or external network calls. It produces decision evidence only.

## Decision

VERIFIED

## Status

READY_FOR_REVIEW
