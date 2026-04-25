#!/usr/bin/env python3

import json
import hashlib
import hmac
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from utils.canonical import canonical_json

TENANT_ID = "t1"
POLICY_PATH = ROOT / "policy" / TENANT_ID / "policy.json"
SIG_PATH = ROOT / "policy" / TENANT_ID / "policy.sig"
KEY_PATH = ROOT / "secrets" / "policy.key"

policy_data = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
canonical = canonical_json(policy_data)

key = KEY_PATH.read_bytes().strip()

digest = hashlib.sha256(canonical).digest()
signature = hmac.new(key, digest, hashlib.sha256).hexdigest()

SIG_PATH.write_text(signature + "\n", encoding="utf-8")

print(f"SIGNED: {signature[:8]}...{signature[-8:]}")
