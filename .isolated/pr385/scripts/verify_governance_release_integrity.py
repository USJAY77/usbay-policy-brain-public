#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from governance.release_integrity import (  # noqa: E402
    DEFAULT_BASELINE_TAG,
    GovernanceReleaseIntegrityError,
    build_release_integrity_manifest,
    canonical_json,
    validate_release_integrity_file,
    validate_release_integrity_manifest,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate USBAY governance release integrity metadata")
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--baseline-tag", default=DEFAULT_BASELINE_TAG)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--release-id", default="usbay-governance-release-integrity")
    args = parser.parse_args(argv)
    try:
        if args.build:
            manifest = build_release_integrity_manifest(
                args.root,
                release_id=args.release_id,
                governance_baseline_tag=args.baseline_tag,
            )
            summary = validate_release_integrity_manifest(
                manifest,
                args.root,
                expected_baseline_tag=args.baseline_tag,
            )
            print(canonical_json({"GOVERNANCE_RELEASE_INTEGRITY_VALID": True, **summary.to_dict()}))
            return 0
        if args.manifest is None:
            raise GovernanceReleaseIntegrityError("release_integrity_manifest_path_required")
        summary = validate_release_integrity_file(
            args.manifest,
            args.root,
            expected_baseline_tag=args.baseline_tag,
        )
        print(canonical_json({"GOVERNANCE_RELEASE_INTEGRITY_VALID": True, **summary.to_dict()}))
        return 0
    except GovernanceReleaseIntegrityError as exc:
        print(canonical_json({"GOVERNANCE_RELEASE_INTEGRITY_VALID": False, "failure": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
