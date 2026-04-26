from fastapi import FastAPI
from fastapi.responses import JSONResponse
import hashlib
import hmac

from utils.canonical import canonical_json
from utils.keystore import KeyStore

app = FastAPI()
keystore = KeyStore()


def verify_signature(payload: dict) -> bool:
    try:
        signature = payload.get("signature")
        if not signature:
            return False

        unsigned = payload.copy()
        unsigned.pop("signature", None)

        canonical = canonical_json(unsigned)

        secret_data = keystore.load_device_key(
            payload["tenant_id"],
            payload["device"]
        )

        secret = secret_data.get("private_key")
        if not secret:
            return False

        key = secret if isinstance(secret, bytes) else secret.encode()

        expected = hmac.new(
            key,
            canonical.encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(signature, expected)

    except Exception:
        return False


@app.post("/execute")
def execute(payload: dict):
    if not verify_signature(payload):
        return JSONResponse(
            status_code=403,
            content={"detail": "FAIL_CLOSED"}
        )

    return {
        "status": "EXECUTED",
        "message": "USBAY verified execution"
