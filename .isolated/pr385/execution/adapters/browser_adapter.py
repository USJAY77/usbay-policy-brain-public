from __future__ import annotations

from execution.adapters.base import DisabledExecutionAdapter


class BrowserExecutionAdapter(DisabledExecutionAdapter):
    adapter_name = "browser"
