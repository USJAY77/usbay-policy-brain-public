#!/usr/bin/env python3
import json
from pathlib import Path

FILES = [
    "repo_rulesets.json",
    "org_rulesets.json",
    "pr41_timeline.json",
    "pr42_timeline.json",
    "pr41_reviews.json",
    "pr42_reviews.json",
]

def validate(path: Path):
    if not path.exists():
        return "missing", "file not found"

    size = path.stat().st_size
    if size == 0:
        return "invalid", "file size 0 bytes"

    try:
        with open(path, encoding="utf-8") as f:
            json.load(f)
    except Exception as e:
        return "invalid", str(e)

    return "valid", f"{size} bytes"

def main():
    print("JSON export validation (size + parse)")
    for f in FILES:
        status, detail = validate(Path(f))
        print(f"{f}: {status} ({detail})")

if __name__ == "__main__":
    main()
