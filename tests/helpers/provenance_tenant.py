from __future__ import annotations

# Purpose: centralize test tenant defaults for governance provenance helpers.
# Governance scope: tenant-scoped release manifests and evidence exports.
# Fail-closed expectation: callers must validate tenant IDs through runtime policy.
# Sensitive-data handling: this module contains no secrets or raw identity material.

DEFAULT_TEST_TENANT_ID = "t1"
