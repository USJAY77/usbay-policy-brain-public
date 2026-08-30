from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ScreenMetadata:
    capture_id: str
    captured_at: str
    source: str
    width: int | None
    height: int | None
    raw_screenshot_stored: bool
    metadata_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ScreenCapture:
    def __init__(self, *, source: str = "local_metadata_only", persist_raw: bool = False) -> None:
        self.source = source
        self.persist_raw = persist_raw

    def capture_metadata(self, *, width: int | None = None, height: int | None = None) -> ScreenMetadata:
        raw = {
            "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source": self.source,
            "width": width,
            "height": height,
            "raw_screenshot_stored": False,
        }
        capture_hash = hashlib.sha256(json.dumps(raw, sort_keys=True).encode("utf-8")).hexdigest()
        return ScreenMetadata(
            capture_id=f"screen-{capture_hash[:16]}",
            metadata_hash=capture_hash,
            **raw,
        )

    def persist_raw_screenshot(self, *_args: object, **_kwargs: object) -> Path:
        if not self.persist_raw:
            raise RuntimeError("RAW_SCREENSHOT_PERSISTENCE_DISABLED")
        raise RuntimeError("RAW_SCREENSHOT_PERSISTENCE_NOT_IMPLEMENTED")
