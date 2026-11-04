"""Concrete bounded non-production REVOKE_GRANT_OBJECT writer."""
from __future__ import annotations
from contextlib import contextmanager
from copy import deepcopy
import sqlite3

from governance.mutation_commit import CommitFenceRejected
from governance.mutation_currentness_source import projection_scope_hash
from governance.mutation_grant_revocation_terminal import (
    verify_grant_revocation_terminal_transition,
)
from governance.tenant_enrollment_contracts import (
    EnrollmentDenied, decision, digest, parse_json, require,
)

class GrantRevocationTransitionSource:
    @contextmanager
    def hold(self, *, command, effect_grant):
        raise EnrollmentDenied("GRANT_REVOCATION_TRANSITION_UNAVAILABLE")
        yield  # pragma: no cover

class GrantRevocationTransitionGuard:
    def successor(self, *, previous_currentness):
        raise EnrollmentDenied("GRANT_REVOCATION_TRANSITION_UNAVAILABLE")
    def recheck(self, *, evidence):
        raise EnrollmentDenied("GRANT_REVOCATION_TRANSITION_UNAVAILABLE")

def _target_consumption_state(conn,target):
    found=[]
    for label in ("grant_id","nonce","replay_identity"):
        identity=digest({"issuer":target["issuer_id"],"value":target[label]})
        found.append(conn.execute(
            "SELECT 1 FROM enrollment_uses WHERE kind=? AND identity=?",
            ("enrollment:"+label,identity)).fetchone() is not None)
    if all(found): return "CONSUMED"
    if not any(found): return "UNCONSUMED"
    raise EnrollmentDenied("GRANT_CONSUMPTION_STATE_INVALID")

class GovernedGrantRevocationWriter:
    def __init__(self,view,*,currentness_fence,transition_source):
        self.view=view
        self.currentness_fence=currentness_fence
        self.transition_source=transition_source

    @staticmethod
    def _effect_consumption(effect_grant,command_hash):
        p=effect_grant["payload"]
        return {"issuer_id":p["issuer_id"],"grant_id":p["grant_id"],"nonce":p["grant_nonce"],
                "replay_identity":digest({"effect_grant_id":p["grant_id"],"command_hash":command_hash})}

    @staticmethod
    def _terminal_projection(command,successor,consumption_state):
        revocations=successor["revocations"]["payload"]
        return {
            "schema_version":"usbay.grant_revocation_terminal_projection.v1",
            "status":"GRANT_REVOKED_NON_PRODUCTION",
            "scope_hash":projection_scope_hash(command),
            "object_id":command["object_id"],
            "object_version_hash":command["object_version_hash"],
            "target_grant_id":command["expected_state"]["grant_id"],
            "consumption_state":consumption_state,
            "revocation_reference":revocations["revocation_reference"],
            "revocation_hash":digest(revocations),
            "revocation_effect_scope":command["revocation_effect_scope"],
            "effect_grant_hash":command["revocation_effect_grant_hash"],
            "command_hash":digest(command),
            "transaction_id":command["transaction_id"],
        }

    def execute(self,command,*,proposal,reviews,grant,revocation_effect):
        attempted_transition=False
        core_event_hash=None
        terminal_event_hash=None
        try:
            require(isinstance(self.transition_source,GrantRevocationTransitionSource),
                    "GRANT_REVOCATION_TRANSITION_UNAVAILABLE")
            with self.view.mutation_attempt(currentness_fence=self.currentness_fence) as attempt:
                verified=attempt.verify(command,proposal=proposal,reviews=reviews,grant=grant,
                                        revocation_effect=revocation_effect)
                if verified["decision"]!="ALLOW": return verified
                c,keys,fence,evidence,conn,fence_guard=attempt._writer_context()
                require(c["action"]=="REVOKE_GRANT_OBJECT","ACTION_NOT_AUTHORIZED")
                require("grant_revocation_terminal" in {
                    row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")},
                    "GRANT_REVOCATION_STORAGE_UNAVAILABLE")
                material=fence_guard.authority_material()
                target=material["target_object"]["payload"]
                consumption_state=_target_consumption_state(conn,target)
                require(consumption_state==c["expected_state"]["expected_consumption_state"],
                        "EXPECTED_STATE_MISMATCH")
                require(target["grant_id"]==c["expected_state"]["grant_id"],
                        "RESOURCE_NOT_AUTHORIZED")

                effect_grant=revocation_effect["grant"]
                with self.transition_source.hold(command=deepcopy(c),
                        effect_grant=deepcopy(effect_grant)) as transition_guard:
                    require(isinstance(transition_guard,GrantRevocationTransitionGuard),
                            "GRANT_REVOCATION_TRANSITION_UNAVAILABLE")
                    transition=transition_guard.successor(
                        previous_currentness=deepcopy(material["currentness"]))
                    require(type(transition) is dict
                            and set(transition)=={"revoked_currentness","continuity_hash"},
                            "GRANT_REVOCATION_TRANSITION_INVALID")
                    successor=transition["revoked_currentness"]
                    require(type(transition["continuity_hash"]) is str
                            and transition["continuity_hash"].startswith("sha256:"),
                            "GRANT_REVOCATION_TRANSITION_INVALID")

                    post_state=self._terminal_projection(
                        c,successor,consumption_state)
                    prepared_transition=fence_guard.prepare_transition(
                        conn,command=deepcopy(c),
                        successor_currentness=deepcopy(successor),
                        post_state=deepcopy(post_state),terminal=False)
                    proposed_position=deepcopy(
                        prepared_transition["proposed_position"])

                    for kind,identity,_ in keys:
                        conn.execute("INSERT INTO enrollment_uses(kind,identity) VALUES(?,?)",
                                     ("mutation:"+kind,identity))
                    issuer=material["issuer_grant"]["payload"]
                    self.view._consume(conn,"mutation_issuance",{
                        "issuer_id":issuer["issuer_id"],"grant_id":issuer["issuer_grant_id"],
                        "nonce":issuer["issuance_nonce"],"replay_identity":evidence["command_hash"]})
                    self.view._consume(conn,"grant_revocation_effect",
                        self._effect_consumption(effect_grant,evidence["command_hash"]))

                    state=parse_json(conn.execute(
                        "SELECT value FROM enrollment_meta WHERE name='state'").fetchone()[0])
                    core_event_hash=self.view._append(conn,state,{
                        "kind":"GRANT_REVOCATION_MUTATION_CORE_NON_PRODUCTION",
                        "tenant_reference":evidence["tenant_reference"],
                        "command_hash":evidence["command_hash"],
                        "transaction_id":c["transaction_id"],
                        "object_id":c["object_id"],
                        "object_version_hash":c["object_version_hash"],
                        "target_grant_id":target["grant_id"],
                        "consumption_state":consumption_state,
                        "effect_grant_hash":c["revocation_effect_grant_hash"],
                        "revocation_effect_scope":c["revocation_effect_scope"],
                        "continuity_hash":transition["continuity_hash"],
                        "proposed_position_hash":digest(proposed_position),
                    })

                    terminal=verify_grant_revocation_terminal_transition(
                        self.view.trust,target_grant=material["target_object"],
                        previous_currentness=material["currentness"],
                        revoked_currentness=successor,now=self.view.clock(),
                        command_hash=evidence["command_hash"],
                        transaction_id=c["transaction_id"],
                        effect_grant_hash=c["revocation_effect_grant_hash"],
                        mutation_event_hash=core_event_hash,
                        durable_position_hash=digest(proposed_position),
                        consumption_state=consumption_state)
                    require(terminal["decision"]=="ALLOW",
                            terminal.get("reason","GRANT_REVOCATION_TERMINAL_PROOF_INVALID"))
                    proof=terminal["terminal_proof"];proof_hash=terminal["terminal_proof_hash"]
                    revocations=successor["revocations"]["payload"]

                    conn.execute(
                        "INSERT INTO grant_revocation_terminal("
                        "scope_hash,object_id,object_version_hash,target_grant_id,consumption_state,"
                        "revocation_reference,revocation_hash,terminal_projection_hash,terminal_proof_hash,"
                        "source_epoch,source_version,command_hash,transaction_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (proposed_position["scope_hash"],c["object_id"],c["object_version_hash"],target["grant_id"],
                         consumption_state,revocations["revocation_reference"],digest(revocations),
                         proposed_position["projection_hash"],proof_hash,proposed_position["source_epoch"],
                         proposed_position["source_version"],evidence["command_hash"],c["transaction_id"]))

                    state=parse_json(conn.execute(
                        "SELECT value FROM enrollment_meta WHERE name='state'").fetchone()[0])
                    terminal_event_hash=self.view._append(conn,state,{
                        "kind":"GRANT_REVOCATION_TERMINAL_NON_PRODUCTION",
                        "scope_hash":proposed_position["scope_hash"],
                        "object_id":c["object_id"],"object_version_hash":c["object_version_hash"],
                        "target_grant_id":target["grant_id"],"consumption_state":consumption_state,
                        "revocation_reference":revocations["revocation_reference"],
                        "revocation_hash":digest(revocations),
                        "terminal_projection_hash":proposed_position["projection_hash"],
                        "terminal_proof_hash":proof_hash,
                        "source_epoch":proposed_position["source_epoch"],
                        "source_version":proposed_position["source_version"],
                        "command_hash":evidence["command_hash"],"transaction_id":c["transaction_id"],
                        "core_event_hash":core_event_hash,"effect_grant_hash":c["revocation_effect_grant_hash"],
                        "terminal_status":proof["status"],"continuity_hash":transition["continuity_hash"]})

                    rechecked=transition_guard.recheck(evidence=deepcopy(transition))
                    require(rechecked==transition,"GRANT_REVOCATION_TRANSITION_STALE")
                    require(_target_consumption_state(conn,target)==consumption_state,
                            "GRANT_CONSUMPTION_STATE_INVALID")
                    attempted_transition=True
                    receipt=fence_guard.commit_transition_if_current(
                        conn,fence=deepcopy(fence),now=self.view.clock(),
                        prepared_transition=deepcopy(prepared_transition),
                        update_id=c["transaction_id"],
                        transition_evidence_hash=proof_hash)
                    require(not conn.in_transaction,"COMMIT_STATE_UNKNOWN")

                return decision("GRANT_OBJECT_REVOKED_NON_PRODUCTION",allowed=True,
                    mutation_executed=True,object_id=c["object_id"],target_grant_id=target["grant_id"],
                    consumption_state=consumption_state,revocation_effect_scope=c["revocation_effect_scope"],
                    terminal_proof_hash=proof_hash,terminal_event_hash=terminal_event_hash,
                    high_water_event_hash=receipt["event_hash"],source_epoch=proposed_position["source_epoch"],
                    source_version=proposed_position["source_version"])
        except Exception as error:
            if type(error) is CommitFenceRejected:return decision(str(error))
            if attempted_transition:
                return decision("COMMIT_STATE_UNKNOWN",commit_outcome="UNKNOWN",
                    reconciliation_required=True,core_event_hash=core_event_hash,
                    terminal_event_hash=terminal_event_hash)
            return decision(str(error) if type(error) is EnrollmentDenied
                            else "GRANT_REVOCATION_WRITER_INVALID")
