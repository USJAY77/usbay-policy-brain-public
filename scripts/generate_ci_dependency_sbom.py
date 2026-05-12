#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.verify_production_readiness import (
    CI_SBOM_ARTIFACT_PATH,
    GOVERNANCE_CRYPTO_PACKAGES,
    PRODUCTION_READINESS_WORKFLOW,
    REQUIRED_CI_PACKAGES,
    REQUIRED_CI_REQUIREMENTS,
    parse_ci_dependency_lock,
)

SBOM_SCHEMA = "usbay.production_readiness_ci_dependency_sbom.v1"
WORKFLOW_VERSION = "production-readiness-v1"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pip_version() -> str:
    completed = subprocess.run(
        [sys.executable, "-m", "pip", "--version"],
        text=True,
        capture_output=True,
        check=True,
    )
    return completed.stdout.strip()


def build_sbom(root: Path, generated_at: str | None = None) -> dict[str, Any]:
    root = root.resolve()
    dependencies, failures = parse_ci_dependency_lock(root)
    if failures:
        raise SystemExit("SBOM_DEPENDENCY_LOCK_INVALID:" + ",".join(sorted(failures)))
    if not dependencies:
        raise SystemExit("SBOM_DEPENDENCY_INVENTORY_EMPTY")
    incomplete = [
        str(dep.get("name", "unknown"))
        for dep in dependencies
        if not dep.get("name") or not dep.get("version") or not dep.get("sha256_hashes") or not dep.get("source_registry")
    ]
    if incomplete:
        raise SystemExit("SBOM_DEPENDENCY_INVENTORY_INCOMPLETE:" + ",".join(sorted(incomplete)))
    requirements_path = root / REQUIRED_CI_REQUIREMENTS
    workflow_path = root / PRODUCTION_READINESS_WORKFLOW
    if not workflow_path.is_file():
        raise SystemExit(f"SBOM_WORKFLOW_MISSING:{PRODUCTION_READINESS_WORKFLOW}")
    return {
        "sbom_schema": SBOM_SCHEMA,
        "audit_metadata": {
            "python_version": platform.python_version(),
            "python_executable": Path(sys.executable).name,
            "pip_version": _pip_version(),
            "workflow_version": WORKFLOW_VERSION,
            "workflow_path": PRODUCTION_READINESS_WORKFLOW,
            "workflow_sha256": _sha256_file(workflow_path),
            "generated_at": generated_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        },
        "dependency_lock": {
            "path": REQUIRED_CI_REQUIREMENTS,
            "sha256": _sha256_file(requirements_path),
            "install_command": "python -m pip install --require-hashes -r requirements-ci.txt",
        },
        "dependencies": dependencies,
    }


def validate_sbom(sbom: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if sbom.get("sbom_schema") != SBOM_SCHEMA:
        failures.append("SBOM_SCHEMA_INVALID")
    metadata = sbom.get("audit_metadata")
    if not isinstance(metadata, dict):
        failures.append("SBOM_AUDIT_METADATA_MISSING")
    else:
        for key in ("python_version", "pip_version", "workflow_version", "workflow_sha256", "generated_at"):
            if not metadata.get(key):
                failures.append(f"SBOM_AUDIT_METADATA_FIELD_MISSING:{key}")
    dependencies = sbom.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        failures.append("SBOM_DEPENDENCY_INVENTORY_EMPTY")
        return failures
    seen: set[str] = set()
    for index, dependency in enumerate(dependencies):
        if not isinstance(dependency, dict):
            failures.append(f"SBOM_DEPENDENCY_INVALID:{index}")
            continue
        name = dependency.get("name")
        version = dependency.get("version")
        hashes = dependency.get("sha256_hashes")
        registry = dependency.get("source_registry")
        if not name or not version:
            failures.append(f"SBOM_DEPENDENCY_ID_INCOMPLETE:{index}")
        elif str(name).lower() in seen:
            failures.append(f"SBOM_DEPENDENCY_DUPLICATE:{name}")
        else:
            seen.add(str(name).lower())
        if not isinstance(hashes, list) or not hashes:
            failures.append(f"SBOM_DEPENDENCY_HASH_MISSING:{name or index}")
        else:
            for digest in hashes:
                if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                    failures.append(f"SBOM_DEPENDENCY_HASH_INVALID:{name or index}")
        if registry != "https://pypi.org/simple":
            failures.append(f"SBOM_DEPENDENCY_REGISTRY_INVALID:{name or index}")
    if "pytest" not in seen:
        failures.append("SBOM_DEPENDENCY_PYTEST_MISSING")
    for package in sorted(REQUIRED_CI_PACKAGES):
        if package not in seen:
            failures.append(f"SBOM_DEPENDENCY_REQUIRED_PACKAGE_MISSING:{package}")
    for package in sorted(GOVERNANCE_CRYPTO_PACKAGES):
        if package not in seen:
            failures.append(f"SBOM_DEPENDENCY_GOVERNANCE_CRYPTO_MISSING:{package}")
    return sorted(set(failures))


def write_sbom(root: Path, output: Path) -> None:
    sbom = build_sbom(root)
    failures = validate_sbom(sbom)
    if failures:
        raise SystemExit("SBOM_VALIDATION_FAILED:" + ",".join(failures))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"CI_DEPENDENCY_SBOM_GENERATED={output}")
    print(f"CI_DEPENDENCY_SBOM_DEPENDENCIES={len(sbom['dependencies'])}")
    versions = {str(dep["name"]).lower(): dep["version"] for dep in sbom["dependencies"]}
    print(f"CI_CRYPTOGRAPHY_DEPENDENCY_VERSION={versions.get('cryptography', 'missing')}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate hash-verified CI dependency SBOM")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, default=Path(CI_SBOM_ARTIFACT_PATH))
    args = parser.parse_args(argv)
    output = args.output if args.output.is_absolute() else args.root / args.output
    write_sbom(args.root, output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
