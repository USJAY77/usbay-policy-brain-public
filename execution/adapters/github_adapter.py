from __future__ import annotations

from execution.adapters.base import DisabledExecutionAdapter


class GitHubExecutionAdapter(DisabledExecutionAdapter):
    adapter_name = "github"
