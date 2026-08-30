from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


def adapter_view_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AdapterRegistryUIView:
    desktop_adapter_state: str
    browser_adapter_state: str
    api_adapter_state: str
    disabled_adapters: tuple[str, ...]
    blocked_adapters: tuple[str, ...]
    readiness_state: str
    audit_hash: str


def build_adapter_registry_view(dashboard: dict[str, object] | None) -> AdapterRegistryUIView:
    if dashboard is None:
        return _view("FAIL_CLOSED", "FAIL_CLOSED", "FAIL_CLOSED", (), ("desktop", "browser", "api"), "FAIL_CLOSED")
    registered = set(dashboard.get("registered_adapters", []))
    disabled = tuple(dashboard.get("disabled_adapters", []))
    blocked = tuple(dashboard.get("blocked_adapters", []))
    readiness = str(dashboard.get("readiness_state", "FAIL_CLOSED"))
    state_by_adapter = {}
    for adapter in ("desktop", "browser", "api"):
        if adapter in registered:
            state_by_adapter[adapter] = "REGISTERED"
        elif adapter in disabled:
            state_by_adapter[adapter] = "DISABLED"
        elif adapter in blocked:
            state_by_adapter[adapter] = "BLOCKED"
        else:
            state_by_adapter[adapter] = "FAIL_CLOSED"
            blocked = tuple(sorted(set(blocked + (adapter,))))
            readiness = "FAIL_CLOSED"
    if dashboard.get("all_records_audited") is not True:
        readiness = "FAIL_CLOSED"
    return _view(
        state_by_adapter["desktop"],
        state_by_adapter["browser"],
        state_by_adapter["api"],
        disabled,
        blocked,
        readiness,
    )


def _view(desktop: str, browser: str, api: str, disabled: tuple[str, ...], blocked: tuple[str, ...], readiness: str) -> AdapterRegistryUIView:
    return AdapterRegistryUIView(
        desktop_adapter_state=desktop,
        browser_adapter_state=browser,
        api_adapter_state=api,
        disabled_adapters=disabled,
        blocked_adapters=blocked,
        readiness_state=readiness,
        audit_hash=adapter_view_hash(desktop, browser, api, disabled, blocked, readiness),
    )

