from __future__ import annotations

import hashlib
import json
from typing import Any


SHA256_PREFIX = "sha256:"
ZERO_SHA256_REFERENCE = SHA256_PREFIX + ("0" * 64)


def canonical_json(payload: Any, *, default_to_str: bool = False) -> str:
    kwargs: dict[str, Any] = {
        "sort_keys": True,
        "separators": (",", ":"),
        "ensure_ascii": True,
    }
    if default_to_str:
        kwargs["default"] = str
    return json.dumps(payload, **kwargs)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(payload: Any, *, default_to_str: bool = False) -> str:
    return sha256_text(canonical_json(payload, default_to_str=default_to_str))


def sha256_reference(payload: Any, *, default_to_str: bool = False) -> str:
    return SHA256_PREFIX + sha256_json(payload, default_to_str=default_to_str)


def is_sha256_hex(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def is_sha256_reference(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith(SHA256_PREFIX):
        return False
    return is_sha256_hex(value.removeprefix(SHA256_PREFIX))
