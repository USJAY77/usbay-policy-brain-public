import os

try:
    import redis
except ImportError:  # pragma: no cover - exercised only when redis-py is absent.
    redis = None

REDIS_URL = os.getenv("USBAY_REDIS_URL", "redis://localhost:6379/0")
DEFAULT_NONCE_TTL_SECONDS = 300

_client = None


def _nonce_key(nonce):
    return f"nonce:{nonce}"


def _ttl_seconds():
    raw_ttl = os.getenv("USBAY_NONCE_TTL_SECONDS", str(DEFAULT_NONCE_TTL_SECONDS))
    try:
        ttl = int(raw_ttl)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Invalid USBAY_NONCE_TTL_SECONDS") from exc

    if ttl <= 0:
        raise RuntimeError("USBAY_NONCE_TTL_SECONDS must be positive")

    return ttl


def _get_client():
    global _client

    if redis is None:
        return None

    if _client is None:
        _client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

    return _client


def nonce_exists(nonce):
    try:
        return _get_client().exists(_nonce_key(nonce)) == 1
    except Exception as exc:
        raise RuntimeError("Redis nonce lookup failed") from exc


def store_nonce(nonce, timestamp):
    client = _get_client()

    if client is None:
        return False

    try:
        stored = client.set(
            _nonce_key(nonce),
            timestamp,
            nx=True,
            ex=_ttl_seconds(),
        )
        if stored is None:
            return False
        return bool(stored)
    except Exception:
        return False
