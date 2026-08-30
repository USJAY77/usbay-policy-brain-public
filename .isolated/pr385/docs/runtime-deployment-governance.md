# USBAY Runtime Deployment Governance

This deployment profile starts only the USBAY governance gateway ASGI app through the `.replit` `[deployment]` command:

```bash
sh -c ': "${PORT:?PORT is required for USBAY gateway deployment}" && exec python3 -m uvicorn gateway.app:app --host 0.0.0.0 --port "$PORT"'
```

The runtime entrypoint is `gateway.app:app`. The deployment must bind to `0.0.0.0` and the platform-provided `PORT` environment variable only.

Fail-closed deployment rules:

- Missing `PORT` blocks startup.
- `[deployment].run` is the only explicit run command.
- The deployment target is `autoscale`.
- Default port fallbacks are forbidden.
- Hardcoded deployment ports are forbidden.
- Localhost or secondary bind orchestration is forbidden.
- Duplicate `uvicorn` startup paths are forbidden.
- Dashboard orchestration is not part of production deployment startup.

This document describes runtime deployment wiring only. It does not change governance policy evaluation, lifecycle semantics, signing authority, audit lineage, or demo scaffolding.
