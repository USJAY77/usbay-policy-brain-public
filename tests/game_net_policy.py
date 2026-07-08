"""Shared network policy for the /game DOM stability tests.

Distinguishes three classes of network activity observed by the jsdom
harness (tests/game_dom_harness.mjs):

1. FORBIDDEN commercial/booking/payment/provider network calls — never
   allowed under any condition.
2. ALLOWED read-only diagnostic probes made by the Governance Runtime
   Evidence panel (#usbgre) — permitted ONLY under the strict, fail-closed
   conditions below.
3. FORBIDDEN mutating or exfiltrating transports (POST/PUT/PATCH/DELETE,
   WebSocket, EventSource, sendBeacon) — never allowed.

The panel probes are permitted only when ALL of the following hold
(fail-closed — any missing condition forbids ALL network activity):

- the evidence panel is present AND carries all three scope tags:
  READ-ONLY, DIAGNOSTIC ONLY, NO EXECUTION AUTHORITY CHANGED;
- every observed call is a plain GET fetch to one of the two allow-listed
  read-only endpoints (no POST/mutation of any kind observed);
- no booking/payment/credential/provider marker was found in the page
  (harness ``forbidden.found`` is empty).

The /execute contract itself (GET 404 / ungoverned POST 403) is enforced
separately by the gateway route tests; the probe allow-listed here is the
side-effect-free GET used by the panel's dual-proof Execute Guard.
"""

# Read-only GET probes issued by the evidence panel's diagnostic script.
ALLOWED_DIAGNOSTIC_PROBES = frozenset({
    "fetch:GET:/api/runtime/stability-visibility",
    "fetch:GET:/execute",
})

# Transport prefixes that are never allowed regardless of panel state.
_ALWAYS_FORBIDDEN_PREFIXES = ("ws:", "es:", "beacon:")
_MUTATING_MARKERS = (":POST:", ":PUT:", ":PATCH:", ":DELETE:")


def forbidden_net(dom_result: dict) -> list:
    """Return the list of network calls that violate the policy.

    Empty list == compliant. Fail-closed: if the diagnostic scope cannot be
    proven, every observed call is returned as a violation.
    """
    net = list((dom_result.get("unsafe") or {}).get("net") or [])
    if not net:
        return []

    panel = dom_result.get("evidencePanel") or {}
    tags_ok = (
        panel.get("present") is True
        and panel.get("readOnly") is True
        and panel.get("diagnostic") is True
        and panel.get("noAuthority") is True
    )
    markers_clean = (dom_result.get("forbidden") or {}).get("found") == []
    any_mutation = any(
        entry.startswith(_ALWAYS_FORBIDDEN_PREFIXES)
        or any(m in entry for m in _MUTATING_MARKERS)
        for entry in net
    )

    if not (tags_ok and markers_clean) or any_mutation:
        return net  # fail-closed: nothing is allowed
    return [entry for entry in net if entry not in ALLOWED_DIAGNOSTIC_PROBES]
