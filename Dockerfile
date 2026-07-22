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
COPY utils ./utils
COPY governance_runtime_monitor.py ./governance_runtime_monitor.py

CMD ["sh", "-c", ": \"${PORT:?PORT is required for USBAY gateway deployment}\" && exec python3 -m uvicorn gateway.app:app --host 0.0.0.0 --port \"$PORT\""]
