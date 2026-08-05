FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY audit ./audit
COPY executors ./executors
COPY gateway ./gateway
COPY governance ./governance
COPY policy ./policy
COPY routing ./routing
COPY runtime ./runtime
COPY scripts ./scripts
COPY surfaces ./surfaces
COPY security ./security
COPY simulator ./simulator
COPY utils ./utils
COPY governance_runtime_monitor.py ./governance_runtime_monitor.py

# Default the serving port in the image. The Worker/DO also passes PORT via
# envVars, but platform delivery of DO envVars has proven unreliable at cold
# start; without a default the fail-closed CMD guard kills the container.
ENV PORT=5000

# Stamp the runtime commit at build time so the dashboard chip shows the
# real serving commit even when .git is not present in the image.
# Pass --build-arg GIT_COMMIT=$(git rev-parse HEAD) when building.
ARG GIT_COMMIT=
RUN if [ -n "${GIT_COMMIT}" ]; then \
      python3 scripts/stamp_runtime_commit.py --commit "${GIT_COMMIT}"; \
    else \
      echo "WARNING: GIT_COMMIT build-arg not provided; invalidating stamp so chip shows UNKNOWN" >&2; \
      printf 'UNKNOWN\n' > governance/runtime_commit.txt; \
    fi

CMD ["sh", "-c", ": \"${PORT:?PORT is required for USBAY gateway deployment}\" && exec python3 -m uvicorn gateway.app:app --host 0.0.0.0 --port \"$PORT\""]
