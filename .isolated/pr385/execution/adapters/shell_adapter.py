from __future__ import annotations

from execution.adapters.base import DisabledExecutionAdapter


class ShellExecutionAdapter(DisabledExecutionAdapter):
    adapter_name = "shell"
