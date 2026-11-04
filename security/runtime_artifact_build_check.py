"""Read-only intake of an already issued source artifact, without Git/signing.

This is a build preparation check, not deployment or execution authorization.
The caller supplies exact source pins; public producer trust uses the existing
independent configuration contract. No artifact, trust, or receipt is written.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import sys

from security.runtime_artifact_authority import MANIFEST_NAME, load_runtime_artifact_authority
from security.runtime_artifact_provenance import RuntimeArtifactError, producer_trust_from_environment

_SOURCE_PIN = re.compile(r"[0-9a-f]{40}\Z")


@dataclass(frozen=True)
class CheckedPrebuiltSource:
    """Non-authorizing data; consumers must not treat this as an ALLOW token."""

    source_commit: str
    source_tree_reference: str
    manifest_digest: str
    managed_set_hash: str
    status: str = field(default="PREBUILT_SOURCE_VERIFIED", init=False)
    execution_authorized: bool = field(default=False, init=False)
    deployment_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    claim_freshness_verified: bool = field(default=False, init=False)
    image_identity_verified: bool = field(default=False, init=False)


def check_prebuilt_runtime_artifact(
    root: Path, *, expected_source_commit: str, expected_source_tree: str,
) -> CheckedPrebuiltSource:
    """Verify existing bytes under configured trust and mandatory exact pins.

    Pins constrain selection; they are not authority or anti-rollback policy.
    The canonical package manifest is required. Runtime still independently
    verifies its artifact, release, tenant, replay, policy and other gates.
    Filesystem verification is point-in-time, not an immutable image proof.
    """
    for pin in (expected_source_commit, expected_source_tree):
        if type(pin) is not str or not _SOURCE_PIN.fullmatch(pin):
            raise RuntimeArtifactError("runtime_prebuilt_source_pin_invalid")
    if os.getenv("USBAY_RUNTIME_SOURCE_MANIFEST", MANIFEST_NAME) != MANIFEST_NAME:
        raise RuntimeArtifactError("runtime_prebuilt_manifest_selection_invalid")
    trust = producer_trust_from_environment()
    authority = load_runtime_artifact_authority(root, trust=trust, manifest_name=MANIFEST_NAME)
    verified = authority.verified
    if (verified.source_commit != expected_source_commit
            or verified.source_tree_reference != expected_source_tree):
        raise RuntimeArtifactError("runtime_prebuilt_source_pin_mismatch")
    authority.assert_fresh()
    if (producer_trust_from_environment() != trust
            or os.getenv("USBAY_RUNTIME_SOURCE_MANIFEST", MANIFEST_NAME) != MANIFEST_NAME):
        raise RuntimeArtifactError("runtime_prebuilt_configuration_changed")
    return CheckedPrebuiltSource(
        verified.source_commit, verified.source_tree_reference,
        verified.manifest_digest, verified.managed_set_hash,
    )


class _Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise RuntimeArtifactError("runtime_prebuilt_arguments_invalid")


def main(argv: list[str] | None = None) -> int:
    parser = _Arguments(description="Check a prebuilt signed USBAY source package")
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-source-tree", required=True)
    try:
        args = parser.parse_args(argv)
        check_prebuilt_runtime_artifact(
            Path(args.artifact_root), expected_source_commit=args.expected_source_commit,
            expected_source_tree=args.expected_source_tree,
        )
    except (RuntimeError, OSError, ValueError, TypeError):
        # Do not emit paths, inputs, environment values or exception contents.
        print("runtime_prebuilt_source_denied", file=sys.stderr)
        return 1
    print("runtime_prebuilt_source_verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
