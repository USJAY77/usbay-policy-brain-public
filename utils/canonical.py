import json

def canonical_json(data: dict) -> str:
    """
    Deterministic JSON serialization:
    - sorted keys
    - no extra whitespace
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":")
    )
