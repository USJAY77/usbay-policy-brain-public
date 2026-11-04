"""Concrete bounded non-production REVOKE_ADOPTION writer.

Only an already-FINALIZED adoption may be revoked. The writer never finalizes a
pending adoption, creates a replacement adoption, provisions trust, or grants
production authority. The current adopted-policy source becomes terminal until a
separately governed replacement adoption exists.
"""
from __future__ import annotations
from contextlib import contextmanager
from copy import deepcopy

from governance.mutation_commit import CommitFenceRejected
from governance.mutation_currentness_source import projection_scope_hash
from governance.mutation_adoption_revocation_terminal import (
    verify_adoption_revocation_terminal_transition,
)
from governance.tenant_enrollment_contracts import (
    EnrollmentDenied, decision, digest, parse_json, require,
)

class AdoptionRevocationTransitionSource:
    @contextmanager
    def hold(self, *, command, effect_grant):
        raise EnrollmentDenied("ADOPTION_REVOCATION_TRANSITION_UNAVAILABLE")
        yield  # pragma: no cover

class AdoptionRevocationTransitionGuard:
    def successor(self, *, previous_currentness):
        raise EnrollmentDenied("ADOPTION_REVOCATION_TRANSITION_UNAVAILABLE")
    def recheck(self, *, evidence):
        raise EnrollmentDenied("ADOPTION_REVOCATION_TRANSITION_UNAVAILABLE")

class GovernedAdoptionRevocationWriter:
    def __init__(self,view,*,currentness_fence,transition_source):
        self.view=view
        self.currentness_fence=currentness_fence
        self.transition_source=transition_source

    @staticmethod
    def _effect_consumption(effect_grant,command_hash):
        p=effect_grant["payload"]
        return {
            "issuer_id":p["issuer_id"],
            "grant_id":p["grant_id"],
            "nonce":p["grant_nonce"],
            "replay_identity":digest({
                "effect_grant_id":p["grant_id"],
                "command_hash":command_hash,
            }),
        }

    @staticmethod
    def _terminal_projection(command,successor,finalization_state,consumption_snapshot_hash):
        revocations=successor["revocations"]["payload"]
        return {
            "schema_version":"usbay.adoption_revocation_terminal_projection.v1",
            "status":"ADOPTION_REVOKED_NON_PRODUCTION",
            "scope_hash":projection_scope_hash(command),
            "object_id":command["object_id"],
            "object_version_hash":command["object_version_hash"],
            "adoption_id":command["expected_state"]["adoption_id"],
            "policy_id":successor["policy"]["payload"]["policy_id"],
            "finalization_state":finalization_state,
            "consumption_snapshot_hash":consumption_snapshot_hash,
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
            require(isinstance(self.transition_source,AdoptionRevocationTransitionSource),
                    "ADOPTION_REVOCATION_TRANSITION_UNAVAILABLE")
            with self.view.mutation_attempt(currentness_fence=self.currentness_fence) as attempt:
                verified=attempt.verify(
                    command,proposal=proposal,reviews=reviews,grant=grant,
                    revocation_effect=revocation_effect)
                if verified["decision"]!="ALLOW":
                    return verified
                c,keys,fence,evidence,conn,fence_guard=attempt._writer_context()
                require(c["action"]=="REVOKE_ADOPTION","ACTION_NOT_AUTHORIZED")
                state=self.view._snapshot(conn,require_finalized=False)
                require(state["publication"]=="FINALIZED","ADOPTION_FINALIZATION_STATE_INVALID")
                require(c["expected_state"]["expected_finalization_state"]=="FINALIZED",
                        "ADOPTION_FINALIZATION_STATE_INVALID")
                require("adoption_revocation_terminal" in {
                    row[0] for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'")},
                    "ADOPTION_REVOCATION_STORAGE_UNAVAILABLE")

                material=fence_guard.authority_material()
                target=material["target_object"]["payload"]
                require(c["expected_state"]["adoption_id"]==c["object_id"],
                        "RESOURCE_NOT_AUTHORIZED")
                require(target["policy_id"]==c["expected_state"].get(
                    "policy_id",target["policy_id"]),
                    "RESOURCE_NOT_AUTHORIZED")
                consumption_snapshot=[
                    list(row) for row in conn.execute(
                        "SELECT kind,identity FROM enrollment_uses ORDER BY kind,identity")
                ]
                consumption_snapshot_hash=digest({
                    "consumption":consumption_snapshot})

                effect_grant=revocation_effect["grant"]
                with self.transition_source.hold(
                        command=deepcopy(c),effect_grant=deepcopy(effect_grant)) as transition_guard:
                    require(isinstance(transition_guard,AdoptionRevocationTransitionGuard),
                            "ADOPTION_REVOCATION_TRANSITION_UNAVAILABLE")
                    transition=transition_guard.successor(
                        previous_currentness=deepcopy(material["currentness"]))
                    require(type(transition) is dict
                            and set(transition)=={"revoked_currentness","continuity_hash"},
                            "ADOPTION_REVOCATION_TRANSITION_INVALID")
                    successor=transition["revoked_currentness"]
                    require(type(transition["continuity_hash"]) is str
                            and transition["continuity_hash"].startswith("sha256:"),
                            "ADOPTION_REVOCATION_TRANSITION_INVALID")

                    post_state=self._terminal_projection(
                        c,successor,"FINALIZED",consumption_snapshot_hash)
                    prepared_transition=fence_guard.prepare_transition(
                        conn,command=deepcopy(c),
                        successor_currentness=deepcopy(successor),
                        post_state=deepcopy(post_state),terminal=True)
                    proposed_position=deepcopy(
                        prepared_transition["proposed_position"])

                    for kind,identity,_ in keys:
                        conn.execute(
                            "INSERT INTO enrollment_uses(kind,identity) VALUES(?,?)",
                            ("mutation:"+kind,identity))
                    issuer=material["issuer_grant"]["payload"]
                    self.view._consume(conn,"mutation_issuance",{
                        "issuer_id":issuer["issuer_id"],
                        "grant_id":issuer["issuer_grant_id"],
                        "nonce":issuer["issuance_nonce"],
                        "replay_identity":evidence["command_hash"],
                    })
                    self.view._consume(
                        conn,"adoption_revocation_effect",
                        self._effect_consumption(
                            effect_grant,evidence["command_hash"]))

                    state=parse_json(conn.execute(
                        "SELECT value FROM enrollment_meta WHERE name='state'").fetchone()[0])
                    core_event_hash=self.view._append(conn,state,{
                        "kind":"ADOPTION_REVOCATION_MUTATION_CORE_NON_PRODUCTION",
                        "tenant_reference":evidence["tenant_reference"],
                        "command_hash":evidence["command_hash"],
                        "transaction_id":c["transaction_id"],
                        "object_id":c["object_id"],
                        "object_version_hash":c["object_version_hash"],
                        "adoption_id":c["expected_state"]["adoption_id"],
                        "finalization_state":"FINALIZED",
                        "consumption_snapshot_hash":consumption_snapshot_hash,
                        "effect_grant_hash":c["revocation_effect_grant_hash"],
                        "revocation_effect_scope":c["revocation_effect_scope"],
                        "continuity_hash":transition["continuity_hash"],
                        "proposed_position_hash":digest(proposed_position),
                    })

                    terminal=verify_adoption_revocation_terminal_transition(
                        self.view.trust,
                        target_adoption=material["target_object"],
                        previous_currentness=material["currentness"],
                        revoked_currentness=successor,
                        now=self.view.clock(),
                        command_hash=evidence["command_hash"],
                        transaction_id=c["transaction_id"],
                        effect_grant_hash=c["revocation_effect_grant_hash"],
                        mutation_event_hash=core_event_hash,
                        durable_position_hash=digest(proposed_position),
                        finalization_state="FINALIZED")
                    require(terminal["decision"]=="ALLOW",
                            terminal.get(
                                "reason","ADOPTION_REVOCATION_TERMINAL_PROOF_INVALID"))
                    proof=terminal["terminal_proof"]
                    proof_hash=terminal["terminal_proof_hash"]
                    revocations=successor["revocations"]["payload"]

                    conn.execute(
                        "INSERT INTO adoption_revocation_terminal("
                        "scope_hash,object_id,object_version_hash,adoption_id,policy_id,"
                        "finalization_state,revocation_reference,revocation_hash,"
                        "terminal_projection_hash,terminal_proof_hash,source_epoch,"
                        "source_version,command_hash,transaction_id) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (proposed_position["scope_hash"],c["object_id"],
                         c["object_version_hash"],c["expected_state"]["adoption_id"],
                         proof["policy_id"],"FINALIZED",
                         revocations["revocation_reference"],digest(revocations),
                         proposed_position["projection_hash"],proof_hash,
                         proposed_position["source_epoch"],proposed_position["source_version"],
                         evidence["command_hash"],c["transaction_id"]))

                    state=parse_json(conn.execute(
                        "SELECT value FROM enrollment_meta WHERE name='state'").fetchone()[0])
                    terminal_event_hash=self.view._append(conn,state,{
                        "kind":"ADOPTION_REVOCATION_TERMINAL_NON_PRODUCTION",
                        "scope_hash":proposed_position["scope_hash"],
                        "object_id":c["object_id"],
                        "object_version_hash":c["object_version_hash"],
                        "adoption_id":c["expected_state"]["adoption_id"],
                        "policy_id":proof["policy_id"],
                        "finalization_state":"FINALIZED",
                        "revocation_reference":revocations["revocation_reference"],
                        "revocation_hash":digest(revocations),
                        "terminal_projection_hash":proposed_position["projection_hash"],
                        "terminal_proof_hash":proof_hash,
                        "source_epoch":proposed_position["source_epoch"],
                        "source_version":proposed_position["source_version"],
                        "command_hash":evidence["command_hash"],
                        "transaction_id":c["transaction_id"],
                        "core_event_hash":core_event_hash,
                        "effect_grant_hash":c["revocation_effect_grant_hash"],
                        "terminal_status":proof["status"],
                        "consumption_snapshot_hash":consumption_snapshot_hash,
                        "continuity_hash":transition["continuity_hash"],
                    })

                    rechecked=transition_guard.recheck(
                        evidence=deepcopy(transition))
                    require(rechecked==transition,
                            "ADOPTION_REVOCATION_TRANSITION_STALE")
                    current_consumption_hash=digest({
                        "consumption":[
                            list(row) for row in conn.execute(
                                "SELECT kind,identity FROM enrollment_uses "
                                "WHERE kind NOT LIKE 'mutation:%' "
                                "AND kind NOT LIKE 'mutation_issuance:%' "
                                "AND kind NOT LIKE 'adoption_revocation_effect:%' "
                                "ORDER BY kind,identity")
                        ]})
                    original_nonmutation_hash=digest({
                        "consumption":[row for row in consumption_snapshot
                            if not row[0].startswith(("mutation:","mutation_issuance:",
                                                    "adoption_revocation_effect:"))]})
                    require(current_consumption_hash==original_nonmutation_hash,
                            "ADOPTION_CONSUMPTION_STATE_CHANGED")
                    attempted_transition=True
                    receipt=fence_guard.commit_transition_if_current(
                        conn,fence=deepcopy(fence),now=self.view.clock(),
                        prepared_transition=deepcopy(prepared_transition),
                        update_id=c["transaction_id"],
                        transition_evidence_hash=proof_hash)
                    require(not conn.in_transaction,"COMMIT_STATE_UNKNOWN")

                return decision(
                    "ADOPTION_REVOKED_NON_PRODUCTION",allowed=True,
                    mutation_executed=True,object_id=c["object_id"],
                    adoption_id=c["expected_state"]["adoption_id"],
                    finalization_state="FINALIZED",
                    revocation_effect_scope=c["revocation_effect_scope"],
                    terminal_proof_hash=proof_hash,
                    terminal_event_hash=terminal_event_hash,
                    high_water_event_hash=receipt["event_hash"],
                    source_epoch=proposed_position["source_epoch"],
                    source_version=proposed_position["source_version"])
        except Exception as error:
            if type(error) is CommitFenceRejected:
                return decision(str(error))
            if attempted_transition:
                return decision(
                    "COMMIT_STATE_UNKNOWN",commit_outcome="UNKNOWN",
                    reconciliation_required=True,
                    core_event_hash=core_event_hash,
                    terminal_event_hash=terminal_event_hash)
            return decision(
                str(error) if type(error) is EnrollmentDenied
                else "ADOPTION_REVOCATION_WRITER_INVALID")
