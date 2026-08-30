#!/usr/bin/env bash
set -euo pipefail

export USBAY_HYDRA_NODE_ID="node2"
exec python3 -m uvicorn security.hydra_node_service:app --host 127.0.0.1 --port 8002
