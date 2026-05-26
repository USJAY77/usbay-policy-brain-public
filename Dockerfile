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
COPY runtime ./runtime
COPY security ./security
COPY utils ./utils

CMD ["sh", "-c", ": \"${PORT:?PORT is required for USBAY gateway deployment}\" && exec python3 -m uvicorn gateway.app:app --host 0.0.0.0 --port \"$PORT\""]
