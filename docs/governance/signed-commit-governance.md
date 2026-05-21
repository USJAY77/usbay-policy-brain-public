# USBAY Signed Commit Governance

This document defines the initial USBAY governance baseline for signed commit enforcement and local developer setup. It is documentation only. It does not enable ruleset enforcement, change workflows, or alter runtime behavior.

## Current Gap

USBAY observed a local commit signing failure:

```text
gpg failed to sign the data
fatal: failed to write commit object
```

This reveals a governance gap:

- local signed commit creation can fail due to signer configuration drift
- commits can still be created without cryptographic verification unless enforcement is enabled
- reviewer and ruleset governance exists, but commit authenticity is not yet hardened
- unsigned commits are not sufficient as trusted governance evidence

## Signing Options

### GPG Signing

GPG signing is widely supported and can provide strong commit authenticity when developer keys are managed correctly.

Governance considerations:

- requires local GPG agent configuration
- can fail due to pinentry, agent, key expiry, or trust database issues
- operationally heavier for developers
- useful for mature environments with established GPG key management

### SSH Signing

SSH commit signing uses SSH keys for Git commit verification. GitHub supports SSH commit verification, and the local setup is usually simpler than GPG.

Governance considerations:

- uses familiar SSH key workflows
- simpler local developer setup
- GitHub can show commits as `Verified`
- easier first baseline for USBAY developer adoption
- still requires key ownership, rotation, and audit discipline

### S/MIME Signing

S/MIME signing uses certificate-backed identity.

Governance considerations:

- suitable for enterprise certificate authority environments
- can align with corporate identity and device trust programs
- requires certificate lifecycle management
- usually heavier than SSH signing for initial local developer workflows

## Recommended USBAY Baseline

USBAY should adopt SSH commit signing as the first signed-commit baseline because:

- GitHub supports SSH commit verification
- setup is simpler than GPG for most local developers
- it reduces local agent and pinentry failure modes
- it gives USBAY a practical path to commit authenticity before stricter enterprise signing controls

GPG and S/MIME remain valid future options for stronger enterprise key lifecycle requirements.

## Fail-Closed Governance Rules

USBAY commit identity governance follows these rules:

- unsigned commits must not be treated as trusted governance evidence
- signed commits are required for governance-sensitive paths
- merge approval does not replace commit authenticity
- bot commits must be separately identified and audited
- failed signing setup must block claims of signed provenance
- unknown commit verification state must be treated as untrusted
- commit authenticity evidence must be preserved in the PR audit trail

Governance-sensitive paths include policy, runtime enforcement, audit chain, trust registry, signing, evidence generation, production-readiness, branch hygiene, and workflow governance files.

## Local Validation Commands

Developers can inspect local signing configuration with:

```bash
git config --get commit.gpgsign
git config --get gpg.format
git config --get user.signingkey
git log --show-signature -1
```

Developers can inspect GitHub commit verification metadata with:

```bash
gh api repos/USJAY77/usbay-policy-brain-public/commits/HEAD --jq '.commit.verification'
```

The GitHub verification result must be treated as audit evidence, not as a substitute for reviewer approval or CI validation.

## GitHub SSH Signing Setup Checklist

1. Add an SSH signing key to the developer GitHub account.
2. Configure Git to use SSH signing:

   ```bash
   git config --global gpg.format ssh
   ```

3. Configure the signing key:

   ```bash
   git config --global user.signingkey ~/.ssh/id_ed25519.pub
   ```

4. Enable commit signing by default:

   ```bash
   git config --global commit.gpgsign true
   ```

5. Create a test signed commit on a non-production branch.
6. Push the branch to GitHub.
7. Verify GitHub shows the commit as `Verified`.
8. Record the verification result in PR audit evidence.

## Bot Commit Governance

Bot commits must be governed separately from human commits.

Required audit evidence for bot commits:

- bot identity
- triggering workflow or automation
- commit hash
- branch name
- GitHub verification status
- workflow run link
- human approval requirement, when applicable

Bot commit signing must not be treated as human reviewer approval.

## Future Enforcement Path

USBAY should not enable strict signed-commit ruleset enforcement until:

- developer signing setup is documented and tested
- bot signing identity is explicitly governed
- exception handling is defined
- CI can report commit verification status deterministically
- governance-sensitive path rules are mapped
- human reviewers understand unsigned-commit fail-closed behavior

When enforcement is enabled, unsigned commits touching governance-sensitive paths should block merge.

## Non-Goals

This document does not:

- change runtime code
- change GitHub workflows
- enable strict signed-commit ruleset enforcement
- replace human review
- replace CI validation
- grant bot commits human approval authority
