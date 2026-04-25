from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "sign_execute_request.py"


def load_sign_execute_request_module():
    spec = importlib.util.spec_from_file_location("sign_execute_request", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_curl_uses_data_binary_at_absolute_payload_path(tmp_path: Path) -> None:
    module = load_sign_execute_request_module()
    output_path = tmp_path / "signed_execute_request.json"

    command = module.build_curl_command(
        "http://127.0.0.1:8000/execute",
        output_path,
    )

    assert "--data-binary @" in command
    assert f"--data-binary @{output_path.resolve()}" in command


def test_script_warning_mentions_required_data_binary_at_marker() -> None:
    script = SCRIPT_PATH.read_text(encoding="utf-8")

    assert "Do not remove the @ before the file path." in script
