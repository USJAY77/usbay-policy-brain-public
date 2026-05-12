from __future__ import annotations

from tests.helpers.provenance_authority import install_runtime_authority

# Purpose: runtime-facing compatibility surface for provenance authority installation.
# Governance scope: gateway/runtime tests that require canonical authority injection.
# Fail-closed expectation: installation is delegated to provenance_authority only.
# Sensitive-data handling: this module handles no evidence or secrets directly.

__all__ = ["install_runtime_authority"]
