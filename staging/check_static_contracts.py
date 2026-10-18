"""Check staging artifacts without importing or executing application modules."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import tomllib


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text())
    proposed = tomllib.loads((root / "staging/replit.proposed.toml").read_text())
    lock_path = root / "staging/requirements-python311.lock"
    lock = lock_path.read_text()
    entries = re.split(r"\n(?=[A-Za-z0-9][A-Za-z0-9_.-]*==)", lock)
    packages: dict[str, str] = {}
    for entry in entries:
        match = re.match(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s\\]+)", entry)
        if match:
            assert "--hash=sha256:" in entry, "A locked package has no artifact hash"
            assert match[1] not in packages, "Duplicate locked package"
            packages[match[1]] = match[2]
    assert len(packages) == 40, "Unexpected lock inventory"
    for package in ("setuptools", "wheel", "build", "pip", "pytest", "uvicorn", "fastapi"):
        assert package in packages, f"Missing dependency: {package}"
    assert project["build-system"]["requires"] == [
        f"setuptools=={packages['setuptools']}"
    ], "Build backend and lock differ"
    assert project["project"]["requires-python"] == ">=3.11,<3.12"
    assert proposed["modules"] == ["python-3.11"]
    assert "deployment" not in proposed
    assert proposed["run"] == ["python3", "-m", "staging.launch"]
    launcher = ast.parse((root / "staging/launch.py").read_text())
    assert any(isinstance(node, ast.FunctionDef) and node.name == "launch_arguments" for node in launcher.body)
    gateway = ast.parse((root / "gateway/app.py").read_text())
    lifespan = next(
        node for node in gateway.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "lifespan"
    )
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "validate_policy_registry_startup"
        for node in ast.walk(lifespan)
    ), "Startup validation is not statically present"
    report = {
        "kind": "STATIC_ONLY_NOT_APPLICATION_TESTS",
        "locked_packages": len(packages),
        "lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        "build_tools": {name: packages[name] for name in ("setuptools", "wheel", "build", "pip")},
        "proposed_config_parses": True,
        "startup_validation_call_present": True,
        "application_imports_executed": 0,
        "startup_executed": False,
        "runtime_compatibility": "UNKNOWN",
        "target_platform": "CPython 3.11, Linux validation candidate",
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
