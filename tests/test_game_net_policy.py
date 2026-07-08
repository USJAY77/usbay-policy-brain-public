"""Regression tests for the fail-closed network policy (game_net_policy)."""

from game_net_policy import ALLOWED_DIAGNOSTIC_PROBES, forbidden_net

_PROBES = sorted(ALLOWED_DIAGNOSTIC_PROBES)
_FULL_PANEL = {
    "present": True,
    "readOnly": True,
    "diagnostic": True,
    "noAuthority": True,
}


def _dom(net, panel=None, found=None):
    return {
        "unsafe": {"net": list(net)},
        "evidencePanel": dict(_FULL_PANEL if panel is None else panel),
        "forbidden": {"found": [] if found is None else list(found)},
    }


def test_allowed_probes_pass_with_full_panel_proof():
    assert forbidden_net(_dom(_PROBES)) == []


def test_empty_net_is_always_compliant():
    assert forbidden_net(_dom([], panel={})) == []


def test_missing_any_panel_tag_fails_closed():
    for tag in ("present", "readOnly", "diagnostic", "noAuthority"):
        panel = dict(_FULL_PANEL)
        panel[tag] = False
        assert forbidden_net(_dom(_PROBES, panel=panel)) == _PROBES, tag


def test_missing_panel_entirely_fails_closed():
    dom = _dom(_PROBES)
    del dom["evidencePanel"]
    assert forbidden_net(dom) == _PROBES


def test_forbidden_marker_fails_closed():
    assert forbidden_net(_dom(_PROBES, found=["credit card"])) == _PROBES


def test_mutating_post_rejected_even_with_full_panel_proof():
    net = _PROBES + ["fetch:POST:/execute"]
    assert forbidden_net(_dom(net)) == net


def test_exfil_transports_always_rejected():
    for entry in ("ws://x", "es:/stream", "beacon:/track",
                  "xhr:PUT:/api/x", "fetch:DELETE:/api/x", "fetch:PATCH:/api/x"):
        prefixed = entry if ":" in entry.split(":", 1)[0] else entry
        net = [prefixed if not entry.startswith("ws") else "ws:" + entry]
        assert forbidden_net(_dom(net)) == net, entry


def test_non_allowlisted_get_is_a_violation():
    net = ["fetch:GET:/api/booking/create"]
    assert forbidden_net(_dom(net)) == net
