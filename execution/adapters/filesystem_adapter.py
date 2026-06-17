from __future__ import annotations

from execution.adapters.base import DisabledExecutionAdapter


class FilesystemExecutionAdapter(DisabledExecutionAdapter):
    adapter_name = "filesystem"
