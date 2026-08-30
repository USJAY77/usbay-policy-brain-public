from __future__ import annotations

import hashlib
import os
import sys

from audit.anchor import LiveRFC3161Client


TEST_MESSAGE = b"USBAY_TIMESTAMP_TEST"


def error_code(exc: Exception) -> str:
    detail = str(exc)
    if ":" in detail:
        return detail.split(":", 1)[0]
    return "tsa_request_failed"


def underlying_exception_type(exc: Exception) -> str:
    detail = str(exc)
    parts = detail.split(":", 2)
    if len(parts) >= 2 and parts[1]:
        return parts[1]
    return type(exc).__name__


def main() -> int:
    tsa_url = os.getenv("USBAY_TSA_URL")
    if not tsa_url:
        print("error=missing_USBAY_TSA_URL", file=sys.stderr)
        return 1

    event_hash = hashlib.sha256(TEST_MESSAGE).hexdigest()

    try:
        proof = LiveRFC3161Client(tsa_url=tsa_url).timestamp(event_hash)
    except Exception as exc:
        print(
            f"error={error_code(exc)} exception_type={underlying_exception_type(exc)} detail={exc}",
            file=sys.stderr,
        )
        return 1

    token_present = bool(proof.get("token"))
    if not token_present:
        print("error=missing_timestamp_token", file=sys.stderr)
        return 1

    if proof.get("mode") != "live" or proof.get("hash") != event_hash:
        print("error=invalid_timestamp_proof", file=sys.stderr)
        return 1

    print(f"tsa_url={tsa_url}")
    print(f"event_hash={event_hash}")
    print(f"token_present={str(token_present).lower()}")
    print(f"mode={proof.get('mode')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
