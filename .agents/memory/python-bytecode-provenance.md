---
name: Python bytecode provenance
description: How fail-closed private-material scans distinguish generated Python caches from forged content.
---

Generated Python bytecode can contain complete scanner signatures even when governed source constructs those signatures from runtime fragments. Treat a cache as a generated derivative only when its code object equals deterministic compilation of the governed canonical source. Pytest assertion-rewrite caches additionally require an exact installed-version filename and equality with deterministic pytest rewriting.

**Why:** Raw byte scanning self-invalidates after normal imports or pytest runs, while blanket cache-directory exclusions create an untracked-content bypass.

**How to apply:** Keep tracked, malformed, stale, version-mismatched, forged, unresolved, external, or source-mismatched caches in the ordinary fail-closed scan path.