import requests
import json
import hashlib

BASE = "https://usbay-policy-brain-public.replit.app"

payload = {
    "action": "test",
    "actor": "test_actor"
}

# simpele test signature (zelfde hash mechanisme als server verwacht)
body = json.dumps(payload, separators=(",", ":"))
signature = hashlib.sha256(body.encode()).hexdigest()

headers = {
    "Content-Type": "application/json",
    "X-Actor": "test_actor",
    "X-Signature": signature
}

print("=== DECIDE ===")
r = requests.post(f"{BASE}/decide", headers=headers, json=payload)
print(r.status_code, r.text)

if r.status_code == 200:
    data = r.json()
    decision_id = data.get("decision_id")

    print("\n=== EXECUTE ===")
    r2 = requests.post(f"{BASE}/execute",
                       headers={"Content-Type": "application/json"},
                       json={"decision_id": decision_id})
    print(r2.status_code, r2.text)

    print("\n=== AUDIT ===")
    r3 = requests.get(f"{BASE}/audit/{decision_id}")
    print(r3.status_code, r3.text)
else:
    print("\n❌ SIGNATURE FAILED → server verwacht andere signing logica")
