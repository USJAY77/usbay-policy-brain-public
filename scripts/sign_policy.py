import hashlib, hmac, json
from pathlib import Path

policy_path = Path("policy/policy.json")
key_path = Path("secrets/policy.key")
sig_path = Path("policy/policy.sig")

policy = json.loads(policy_path.read_text(encoding="utf-8"))
policy_bytes = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
key = key_path.read_bytes().strip()

digest = hashlib.sha256(policy_bytes).digest()
signature = hmac.new(key, digest, hashlib.sha256).hexdigest()

sig_path.write_text(signature)
print("SIGNED:", signature)
