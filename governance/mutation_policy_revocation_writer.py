"""Concrete bounded non-production REVOKE_POLICY_OBJECT writer.

No signer, witness producer, trust bootstrap, schema migration, production
activation or provider execution exists here. The writer only accepts:
- a verified MutationAttempt with additive all-version effect authority;
- a separately injected successor transition source containing already-signed
  policy/adoption/revocation/H/W evidence;
- an existing terminal materialization table.

The held currentness guard owns the final high-water transition and SQLite
COMMIT. Any uncertain outcome is reconciled read-only; never retried blindly.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import sqlite3

from governance.mutation_commit import CommitFenceRejected
from governance.mutation_currentness_source import projection_scope_hash
from governance.mutation_policy_revocation_terminal import (
    verify_policy_revocation_terminal_transition,
)
from governance.tenant_enrollment_contracts import (
    EnrollmentDenied, canonical, decision, digest, parse_json, require,
)


class PolicyRevocationTransitionSource:
    """Privileged successor-evidence source. Default always denies."""

    @contextmanager
    def hold(self, *, command, effect_grant):
        raise EnrollmentDenied("POLICY_REVOCATION_TRANSITION_UNAVAILABLE")
        yield  # pragma: no cover


class PolicyRevocationTransitionGuard:
    def successor(self, *, previous_currentness):
        raise EnrollmentDenied("POLICY_REVOCATION_TRANSITION_UNAVAILABLE")

    def recheck(self, *, evidence):
        raise EnrollmentDenied("POLICY_REVOCATION_TRANSITION_UNAVAILABLE")


class GovernedPolicyRevocationWriter:
    def __init__(self, view, *, currentness_fence, transition_source):
        self.view = view
        self.currentness_fence = currentness_fence
        self.transition_source = transition_source

    @staticmethod
    def _effect_consumption(effect_grant, command_hash):
        payload = effect_grant["payload"]
        return {
            "issuer_id": payload["issuer_id"],
            "grant_id": payload["grant_id"],
            "nonce": payload["grant_nonce"],
            "replay_identity": digest({
                "effect_grant_id": payload["grant_id"],
                "command_hash": command_hash,
            }),
        }

    @staticmethod
    def _terminal_projection(command, successor):
        revocations = successor["revocations"]["payload"]
        payload = {
            "schema_version":
                "usbay.policy_revocation_terminal_projection.v1",
            "status": "REVOKED_NON_PRODUCTION",
            "scope_hash": projection_scope_hash(command),
            "object_id": command["object_id"],
            "object_version_hash": command["object_version_hash"],
            "policy_id": command["expected_state"]["policy_id"],
            "revocation_reference": revocations["revocation_reference"],
            "revocation_hash": digest(revocations),
            "revocation_effect_scope": command["revocation_effect_scope"],
            "effect_grant_hash": command["revocation_effect_grant_hash"],
            "command_hash": digest(command),
            "transaction_id": command["transaction_id"],
        }
        canonical(payload)
        return payload

    def execute(
            self, command, *, proposal, reviews, grant, revocation_effect):
        attempted_transition = False
        core_event_hash = None
        terminal_event_hash = None
        try:
            require(isinstance(self.transition_source,
                               PolicyRevocationTransitionSource),
                    "POLICY_REVOCATION_TRANSITION_UNAVAILABLE")
            with self.view.mutation_attempt(
                    currentness_fence=self.currentness_fence) as attempt:
                verified = attempt.verify(
                    command,
                    proposal=proposal,
                    reviews=reviews,
                    grant=grant,
                    revocation_effect=revocation_effect,
                )
                if verified["decision"] != "ALLOW":
                    return verified

                c, keys, fence, evidence, conn, fence_guard = (
                    attempt._writer_context())
                require(c["action"] == "REVOKE_POLICY_OBJECT",
                        "ACTION_NOT_AUTHORIZED")
                require(
                    "policy_revocation_terminal" in {
                        row[0] for row in conn.execute(
                            "SELECT name FROM sqlite_master "
                            "WHERE type='table'")
                    },
                    "POLICY_REVOCATION_STORAGE_UNAVAILABLE")

                effect_grant = revocation_effect["grant"]
                with self.transition_source.hold(
                        command=deepcopy(c),
                        effect_grant=deepcopy(effect_grant)) as transition_guard:
                    require(isinstance(
                        transition_guard, PolicyRevocationTransitionGuard),
                        "POLICY_REVOCATION_TRANSITION_UNAVAILABLE")
                    material = fence_guard.authority_material()
                    transition = transition_guard.successor(
                        previous_currentness=deepcopy(
                            material["currentness"]))
                    require(type(transition) is dict
                            and set(transition)
                            == {"revoked_currentness", "continuity_hash"},
                            "POLICY_REVOCATION_TRANSITION_INVALID")
                    require(type(transition["continuity_hash"]) is str
                            and transition["continuity_hash"].startswith(
                                "sha256:"),
                            "POLICY_REVOCATION_TRANSITION_INVALID")
                    successor = transition["revoked_currentness"]

                    projection = self._terminal_projection(c, successor)
                    proposed_position = {
                        "scope_hash": projection_scope_hash(c),
                        "source_epoch": fence["source_epoch"],
                        "source_version": fence["source_version"] + 1,
                        "projection_hash": digest(projection),
                    }

                    for kind, identity, _ in keys:
                        conn.execute(
                            "INSERT INTO enrollment_uses(kind,identity) "
                            "VALUES(?,?)",
                            ("mutation:" + kind, identity),
                        )
                    issuer = material["issuer_grant"]["payload"]
                    self.view._consume(
                        conn,
                        "mutation_issuance",
                        {
                            "issuer_id": issuer["issuer_id"],
                            "grant_id": issuer["issuer_grant_id"],
                            "nonce": issuer["issuance_nonce"],
                            "replay_identity": evidence["command_hash"],
                        },
                    )
                    self.view._consume(
                        conn,
                        "policy_revocation_effect",
                        self._effect_consumption(
                            effect_grant, evidence["command_hash"]),
                    )

                    state = parse_json(conn.execute(
                        "SELECT value FROM enrollment_meta "
                        "WHERE name='state'").fetchone()[0])
                    core_event_hash = self.view._append(
                        conn,
                        state,
                        {
                            "kind":
                                "POLICY_REVOCATION_MUTATION_CORE_NON_PRODUCTION",
                            "tenant_reference":
                                evidence["tenant_reference"],
                            "command_hash": evidence["command_hash"],
                            "transaction_id": c["transaction_id"],
                            "object_id": c["object_id"],
                            "object_version_hash":
                                c["object_version_hash"],
                            "effect_grant_hash":
                                c["revocation_effect_grant_hash"],
                            "revocation_effect_scope":
                                c["revocation_effect_scope"],
                            "continuity_hash":
                                transition["continuity_hash"],
                            "proposed_position_hash":
                                digest(proposed_position),
                        },
                    )

                    terminal = verify_policy_revocation_terminal_transition(
                        self.view.trust,
                        target_policy=material["target_object"],
                        previous_currentness=material["currentness"],
                        revoked_currentness=successor,
                        now=self.view.clock(),
                        command_hash=evidence["command_hash"],
                        transaction_id=c["transaction_id"],
                        effect_grant_hash=
                            c["revocation_effect_grant_hash"],
                        mutation_event_hash=core_event_hash,
                        durable_position_hash=
                            digest(proposed_position),
                    )
                    require(
                        terminal["decision"] == "ALLOW",
                        terminal.get(
                            "reason",
                            "REVOCATION_TERMINAL_PROOF_INVALID"))
                    proof = terminal["terminal_proof"]
                    proof_hash = terminal["terminal_proof_hash"]
                    revocations = successor["revocations"]["payload"]

                    conn.execute(
                        "INSERT INTO policy_revocation_terminal("
                        "scope_hash,object_id,object_version_hash,"
                        "revocation_reference,revocation_hash,"
                        "terminal_projection_hash,terminal_proof_hash,"
                        "source_epoch,source_version,command_hash,"
                        "transaction_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            proposed_position["scope_hash"],
                            c["object_id"],
                            c["object_version_hash"],
                            revocations["revocation_reference"],
                            digest(revocations),
                            proposed_position["projection_hash"],
                            proof_hash,
                            proposed_position["source_epoch"],
                            proposed_position["source_version"],
                            evidence["command_hash"],
                            c["transaction_id"],
                        ),
                    )

                    state = parse_json(conn.execute(
                        "SELECT value FROM enrollment_meta "
                        "WHERE name='state'").fetchone()[0])
                    terminal_event_hash = self.view._append(
                        conn,
                        state,
                        {
                            "kind":
                                "POLICY_REVOCATION_TERMINAL_NON_PRODUCTION",
                            "scope_hash":
                                proposed_position["scope_hash"],
                            "object_id": c["object_id"],
                            "object_version_hash":
                                c["object_version_hash"],
                            "revocation_reference":
                                revocations["revocation_reference"],
                            "revocation_hash":
                                digest(revocations),
                            "terminal_projection_hash":
                                proposed_position["projection_hash"],
                            "terminal_proof_hash": proof_hash,
                            "source_epoch":
                                proposed_position["source_epoch"],
                            "source_version":
                                proposed_position["source_version"],
                            "command_hash": evidence["command_hash"],
                            "transaction_id": c["transaction_id"],
                            "core_event_hash": core_event_hash,
                            "effect_grant_hash":
                                c["revocation_effect_grant_hash"],
                            "terminal_status": proof["status"],
                            "continuity_hash":
                                transition["continuity_hash"],
                        },
                    )

                    rechecked = transition_guard.recheck(
                        evidence=deepcopy(transition))
                    require(rechecked == transition,
                            "POLICY_REVOCATION_TRANSITION_STALE")
                    attempted_transition = True
                    receipt = fence_guard.commit_transition_if_current(
                        conn,
                        fence=deepcopy(fence),
                        now=self.view.clock(),
                        proposed_position=deepcopy(
                            proposed_position),
                        update_id=c["transaction_id"],
                    )
                    require(not conn.in_transaction,
                            "COMMIT_STATE_UNKNOWN")

                return decision(
                    "POLICY_OBJECT_REVOKED_NON_PRODUCTION",
                    allowed=True,
                    mutation_executed=True,
                    object_id=c["object_id"],
                    revocation_effect_scope=
                        c["revocation_effect_scope"],
                    terminal_proof_hash=proof_hash,
                    terminal_event_hash=terminal_event_hash,
                    high_water_event_hash=receipt["event_hash"],
                    source_epoch=proposed_position["source_epoch"],
                    source_version=proposed_position["source_version"],
                )
        except Exception as error:
            if type(error) is CommitFenceRejected:
                return decision(str(error))
            if attempted_transition:
                return decision(
                    "COMMIT_STATE_UNKNOWN",
                    commit_outcome="UNKNOWN",
                    reconciliation_required=True,
                    core_event_hash=core_event_hash,
                    terminal_event_hash=terminal_event_hash,
                )
            return decision(
                str(error) if type(error) is EnrollmentDenied
                else "POLICY_REVOCATION_WRITER_INVALID")
