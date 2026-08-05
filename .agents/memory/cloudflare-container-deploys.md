---
name: Cloudflare container deploy quirks
description: Hard-won rules for deploying the gateway container via wrangler (stamp fail-closed crash, env delivery, logs, timeouts)
---
- The image must ship a VALID `governance/runtime_commit.txt`: deployment attestation fail-closed exits (`git_commit_unavailable`) on `UNKNOWN`/missing, crash-looping the container ("Container crashed while checking for ports"). Release flow: commit → `scripts/stamp_runtime_commit.py` → deploy; the Dockerfile must NOT overwrite the shipped stamp when the build-arg is absent (wrangler cannot pass build-args).
- Wrangler container builds use the working directory (dirty files included). A stale-looking live `git_commit` usually means the previous rollout/instance is still serving — wait for the rollout (~2-3 min) before concluding drift.
- Container stdout is NOT in `wrangler tail`; enable `[observability] enabled=true` and query `POST /accounts/{id}/workers/observability/telemetry/query` (dataset `containers`) to see the real traceback.
- DO `envVars` delivery proved unreliable at cold start → keep `ENV PORT=5000` in the Dockerfile so the fail-closed CMD guard doesn't kill the container.
- Library default port-wait is 20s (`@cloudflare/containers` 0.0.28); worker.mjs overrides `startAndWaitForPorts` with longer `portReadyTimeoutMS` because governance startup imports take >12s.
- `instance_type` is `standard-1` (4GiB/0.5vCPU); plain "standard" is deprecated.
- Prod `expected_git_commit` stays unenforced: Replit env vars don't reach the Cloudflare container; enforcing needs env plumbed via worker envVars + wrangler vars.
**Why:** an entire batch was spent rediscovering these; the crash symptoms all look identical from outside.
**How to apply:** any change to Dockerfile/wrangler.toml/worker.mjs or any prod outage with "Failed to start container".
