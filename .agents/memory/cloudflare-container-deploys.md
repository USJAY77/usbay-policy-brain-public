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
- Prod deployed-commit enforcement is live: `scripts/release_deploy.sh` is the ONLY sanctioned deploy path (clean-tree preflight over shipped paths, stamp==HEAD check, leased push, `wrangler deploy --var EXPECTED_GIT_COMMIT:<sha>` → worker constructor forwards it into the container as `USBAY_EXPECTED_GIT_COMMIT`, then polls live /api/status until git_commit==HEAD && match). Never bare `wrangler deploy` for releases.
- Cloudflare's remote builder intermittently produced images with a STALE runtime-commit stamp despite correct on-disk content — the script's post-deploy live verification is the guard; if it fails, just rerun the deploy.
- Dev workspace: `USBAY_EXPECTED_GIT_COMMIT` pins HEAD and startup fail-closes on mismatch. Replit auto-commits move HEAD, so a "preview stuck on starting" with `deployment_commit_mismatch` in workflow logs just means the pin is stale — re-pin to `git rev-parse HEAD` and restart; no code fix needed.
**Why:** an entire batch was spent rediscovering these; the crash symptoms all look identical from outside.
**How to apply:** any change to Dockerfile/wrangler.toml/worker.mjs or any prod outage with "Failed to start container".
