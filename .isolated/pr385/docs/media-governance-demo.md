# USBAY Media Governance Demo

This demo shows USBAY governing AI-generated media operations without storing raw media. It is documentation, artifact, and test scaffolding only; it does not add production release authority, real model credentials, copyrighted media, or runtime enforcement changes.

## What The Demo Proves

USBAY can sit above media workflows for music, film, voice, image, and trailer assets and require:

- human approval before release
- RFC3161-style timestamp evidence
- hash-only provenance evidence
- explicit release status
- offline-reviewable manifest evidence
- fail-closed behavior when evidence is missing or mismatched

## Manifest

`artifacts/media-governance-demo-manifest.json` contains a non-production media release manifest. It stores only metadata and placeholders:

- `media_asset_id`
- `asset_type`
- `ai_generated`
- `model_used_placeholder`
- approval-chain reference
- timestamp-policy reference
- provenance hash placeholder
- release status

No raw audio, video, image frames, voice samples, lyrics, scripts, model credentials, tokens, or private payloads are included.

## Release Governance

Release is blocked unless all required evidence is present:

- approval evidence exists when `human_approval_required=true`
- timestamp evidence validates against the timestamp policy
- provenance hash matches the expected hash-only manifest value
- release status is `VERIFIED_RELEASE`

`BLOCKED` and `REVIEW_REQUIRED` remain non-release states. AI cannot auto-authorize publication.

## Fail-Closed Conditions

The demo returns explicit `FAIL_CLOSED` evidence for:

- missing approval
- missing timestamp
- provenance mismatch
- review-required status
- unsupported or unsafe manifest values
- raw media markers in logs

## Music And Film Positioning

For music and film workflows, USBAY governs the release decision rather than the creative payload. A media team can demonstrate that an AI-assisted track, scene, voiceover, trailer, or visual asset had approval, timestamp, and provenance evidence before publication.
