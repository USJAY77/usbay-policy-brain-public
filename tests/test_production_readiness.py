from __future__ import annotations

from pathlib import Path

from scripts import verify_production_readiness as readiness


def _write_required_docs(root: Path) -> None:
    docs = root / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    for doc in readiness.REQUIRED_DOCS:
        path = root / doc
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ok\n", encoding="utf-8")


def _write_helper(root: Path, size: int = 128) -> None:
    helper = root / "tests" / "provenance_helpers.py"
    helper.parent.mkdir(parents=True, exist_ok=True)
    helper.write_text("x" * size, encoding="utf-8")


def test_guard_accepts_clean_minimal_tree(tmp_path: Path) -> None:
    _write_helper(tmp_path)
    _write_required_docs(tmp_path)

    assert readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"]) == []


def test_guard_detects_oversized_helper_file(tmp_path: Path) -> None:
    _write_helper(tmp_path, readiness.MAX_HELPER_BYTES)
    _write_required_docs(tmp_path)

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert any(failure.startswith("PROVENANCE_HELPER_OVERSIZED") for failure in failures)


def test_guard_detects_tracked_generated_manifest_artifacts(tmp_path: Path) -> None:
    _write_helper(tmp_path)
    _write_required_docs(tmp_path)
    manifest = tmp_path / ("governance_" + "release.json")
    manifest.write_text("{}", encoding="utf-8")
    generated = tmp_path / "generated_manifest_path.json"
    generated.write_text("{}", encoding="utf-8")

    failures = readiness.collect_failures(
        tmp_path,
        tracked_files=[
            "tests/provenance_helpers.py",
            "governance_release.json",
            "generated_manifest_path.json",
        ],
    )

    assert "TRACKED_ROOT_GOVERNANCE_RELEASE:governance_release.json" in failures
    assert "TRACKED_GENERATED_MANIFEST_ARTIFACT:generated_manifest_path.json" in failures


def test_guard_detects_missing_readiness_docs(tmp_path: Path) -> None:
    _write_helper(tmp_path)

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert any(failure.startswith("READINESS_DOC_MISSING:") for failure in failures)


def test_guard_detects_production_manifest_bypass_attempt(monkeypatch) -> None:
    monkeypatch.setattr(readiness, "check_production_manifest_required", lambda: ["PRODUCTION_MANIFEST_BYPASS_ALLOWED"])

    assert "PRODUCTION_MANIFEST_BYPASS_ALLOWED" in readiness.check_production_manifest_required()


def test_guard_rejects_secret_like_markers_in_generated_artifacts(tmp_path: Path) -> None:
    _write_helper(tmp_path)
    _write_required_docs(tmp_path)
    generated = tmp_path / "generated_manifest_path.json"
    marker = "BEGIN " + "PRIVATE KEY"
    generated.write_text(marker, encoding="utf-8")

    failures = readiness.collect_failures(
        tmp_path,
        tracked_files=["tests/provenance_helpers.py", "generated_manifest_path.json"],
    )

    assert f"SECRET_MARKER_IN_GENERATED_ARTIFACT:generated_manifest_path.json:{marker}" in failures


def test_guard_detects_tracked_file_over_50mb(monkeypatch, tmp_path: Path) -> None:
    _write_helper(tmp_path)
    _write_required_docs(tmp_path)
    huge = tmp_path / "huge.bin"
    huge.write_text("x", encoding="utf-8")
    monkeypatch.setattr(readiness, "tracked_file_size", lambda root, tracked: readiness.MAX_TRACKED_BYTES + 1 if tracked == "huge.bin" else 1)

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py", "huge.bin"])

    assert any(failure.startswith("TRACKED_FILE_OVERSIZED:huge.bin:") for failure in failures)
