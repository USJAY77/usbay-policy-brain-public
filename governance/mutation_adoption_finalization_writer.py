"""Concrete bounded non-production FINALIZE_POLICY_ADOPTION writer.

The writer creates no witnesses, keys, head-advance grants, trust anchors,
external receipts, or publication authority. It can only finalize an existing
durable ADOPTION_PENDING state using injected already-signed successor artifacts.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import sqlite3

from governance.mutation_adoption_finalization import (
    pending_record_reference,
    verify_finalization_composition,
)
from governance.mutation_commit import CommitFenceRejected
from governance.mutation_currentness_source import projection_scope_hash
from governance.tenant_enrollment_contracts import (
    EnrollmentDenied, decision, digest, parse_json, require,
)


class AdoptionFinalizationArtifactSource:
    """Privileged artifact source; default unavailable and non-producing."""

    @contextmanager
    def hold(self, *, command):
        raise EnrollmentDenied("FINALIZATION_EVIDENCE_UNAVAILABLE")
        yield  # pragma: no cover


class AdoptionFinalizationArtifactGuard:
    def artifacts(self, *, previous_currentness, pending_event):
        raise EnrollmentDenied("FINALIZATION_EVIDENCE_UNAVAILABLE")

    def recheck(self, *, evidence):
        raise EnrollmentDenied("FINALIZATION_EVIDENCE_UNAVAILABLE")


def _consumed(conn, kind, payload):
    for label in ("grant_id", "nonce", "replay_identity"):
        identity = digest({
            "issuer": payload["issuer_id"],
            "value": payload[label],
        })
        if conn.execute(
                "SELECT 1 FROM enrollment_uses WHERE kind=? AND identity=?",
                (kind + ":" + label, identity)).fetchone() is None:
            return False
    return True


class GovernedAdoptionFinalizationWriter:
    def __init__(self, view, *, currentness_fence, artifact_source):
        self.view = view
        self.currentness_fence = currentness_fence
        self.artifact_source = artifact_source

    @staticmethod
    def _witness_reference(composition):
        return digest({
            "h_witness_hash": composition["h_witness_hash"],
            "w_witness_hash": composition["w_witness_hash"],
        })

    @staticmethod
    def _projection(command, composition):
        return {
            "schema_version":
                "usbay.adoption_finalization_terminal_projection.v1",
            "status": "FINALIZED_NON_PRODUCTION",
            "scope_hash": projection_scope_hash(command),
            "adoption_id": composition["adoption_id"],
            "adoption_version_hash": composition["adoption_version_hash"],
            "policy_id": composition["policy_id"],
            "policy_hash": composition["policy_hash"],
            "previous_head": composition["previous_head_hash"],
            "target_head": composition["target_head"],
            "pending_event_hash": composition["pending_event_hash"],
            "composition_hash": digest(composition),
            "command_hash": digest(command),
            "transaction_id": command["transaction_id"],
        }

    def execute(self, command, *, proposal, reviews, grant):
        attempted_transition = False
        final_event_hash = None
        try:
            require(isinstance(
                self.artifact_source, AdoptionFinalizationArtifactSource),
                "FINALIZATION_EVIDENCE_UNAVAILABLE")
            with self.view.mutation_attempt(
                    currentness_fence=self.currentness_fence) as attempt:
                verified = attempt.verify(
                    command,
                    proposal=proposal,
                    reviews=reviews,
                    grant=grant,
                )
                if verified["decision"] != "ALLOW":
                    return verified

                c, keys, fence, evidence, conn, fence_guard = (
                    attempt._writer_context())
                require(c["action"] == "FINALIZE_POLICY_ADOPTION",
                        "ACTION_NOT_AUTHORIZED")
                state = self.view._snapshot(
                    conn, require_finalized=False)
                require(state["publication"] == "PENDING",
                        "EXPECTED_STATE_MISMATCH")
                require("adoption_finalization" in {
                    row[0] for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'")
                    },
                    "FINALIZATION_STORAGE_UNAVAILABLE")

                pending_rows = [
                    (parse_json(row[0]), row[1])
                    for row in conn.execute(
                        "SELECT payload,event_hash FROM enrollment_events "
                        "ORDER BY sequence")
                    if parse_json(row[0]).get("kind") == "ADOPTION_PENDING"
                ]
                matches = [
                    (event, event_hash)
                    for event, event_hash in pending_rows
                    if event.get("adoption_core_hash")
                        == c["object_version_hash"]
                    and event.get("policy_hash")
                        == c["expected_state"]["policy_hash"]
                    and event.get("target_head")
                        == c["expected_state"]["proposed_new_head"]
                ]
                require(len(matches) == 1,
                        "FINALIZATION_PENDING_EVIDENCE_INVALID")
                pending_event, pending_event_hash = matches[0]

                material = fence_guard.authority_material()
                target_adoption = material["target_object"]["payload"]
                require(target_adoption["policy_id"]
                        == c["expected_state"]["policy_id"],
                        "RESOURCE_NOT_AUTHORIZED")
                require(_consumed(conn, "adoption", target_adoption),
                        "FINALIZATION_REPLAY_STATE_INVALID")

                with self.artifact_source.hold(
                        command=deepcopy(c)) as artifact_guard:
                    require(isinstance(
                        artifact_guard,
                        AdoptionFinalizationArtifactGuard),
                        "FINALIZATION_EVIDENCE_UNAVAILABLE")
                    finalization = artifact_guard.artifacts(
                        previous_currentness=deepcopy(
                            material["currentness"]),
                        pending_event=deepcopy(pending_event),
                    )
                    require(type(finalization) is dict
                            and set(finalization)
                            == {"artifacts", "continuity_hash"},
                            "FINALIZATION_EVIDENCE_INVALID")
                    artifacts = finalization["artifacts"]
                    require(type(finalization["continuity_hash"]) is str
                            and finalization[
                                "continuity_hash"].startswith("sha256:"),
                            "FINALIZATION_EVIDENCE_INVALID")

                    advance_payload = artifacts["advance"]["payload"]
                    require(_consumed(conn, "advance", advance_payload),
                            "FINALIZATION_REPLAY_STATE_INVALID")

                    composition_result = verify_finalization_composition(
                        self.view.trust,
                        previous_currentness=material["currentness"],
                        previous_head=state["head"],
                        pending_event=pending_event,
                        pending_event_hash=pending_event_hash,
                        artifacts=artifacts,
                        now=self.view.clock(),
                    )
                    require(composition_result["decision"] == "ALLOW",
                            composition_result.get(
                                "reason",
                                "FINALIZATION_EVIDENCE_INVALID"))
                    composition = composition_result["composition"]
                    composition_hash = composition_result[
                        "composition_hash"]

                    require(
                        composition["adoption_id"]
                            == c["expected_state"]["adoption_id"]
                        and composition["adoption_version_hash"]
                            == c["expected_state"][
                                "adoption_version_hash"]
                        and composition["policy_id"]
                            == c["expected_state"]["policy_id"]
                        and composition["policy_hash"]
                            == c["expected_state"]["policy_hash"]
                        and composition["target_head"]
                            == c["expected_state"]["proposed_new_head"],
                        "EXPECTED_STATE_MISMATCH")
                    require(
                        c["expected_state"]["witness_reference"]
                            == self._witness_reference(composition),
                        "FINALIZATION_EVIDENCE_INVALID")
                    require(
                        c["expected_state"]["finality_reference"]
                            == composition_hash,
                        "FINALIZATION_EVIDENCE_INVALID")

                    post_state = self._projection(c, composition)
                    successor_currentness = {
                        "policy": deepcopy(artifacts["policy"]),
                        "adoption": deepcopy(artifacts["adoption"]),
                        "h": deepcopy(artifacts["h"]),
                        "w": deepcopy(artifacts["w"]),
                        "revocations": deepcopy(
                            material["currentness"]["revocations"]),
                        "expected": deepcopy(artifacts["expected"]),
                        "challenge": artifacts["challenge"],
                        "request_digest": artifacts["request_digest"],
                    }
                    prepared_transition = fence_guard.prepare_transition(
                        conn,
                        command=deepcopy(c),
                        successor_currentness=successor_currentness,
                        post_state=deepcopy(post_state),
                        terminal=False,
                    )
                    proposed_position = deepcopy(
                        prepared_transition["proposed_position"])

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

                    conn.execute(
                        "INSERT INTO adoption_finalization("
                        "scope_hash,adoption_id,adoption_version_hash,"
                        "policy_id,policy_hash,previous_head,target_head,"
                        "pending_event_hash,composition_hash,source_epoch,"
                        "source_version,command_hash,transaction_id) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            proposed_position["scope_hash"],
                            composition["adoption_id"],
                            composition["adoption_version_hash"],
                            composition["policy_id"],
                            composition["policy_hash"],
                            composition["previous_head_hash"],
                            composition["target_head"],
                            composition["pending_event_hash"],
                            composition_hash,
                            proposed_position["source_epoch"],
                            proposed_position["source_version"],
                            evidence["command_hash"],
                            c["transaction_id"],
                        ),
                    )

                    state["publication"] = "FINALIZED"
                    state["head"] = deepcopy(artifacts["expected"])
                    final_event_hash = self.view._append(
                        conn,
                        state,
                        {
                            "kind": "ADOPTION_FINALIZED_NON_PRODUCTION",
                            "scope_hash":
                                proposed_position["scope_hash"],
                            "adoption_id": composition["adoption_id"],
                            "adoption_version_hash":
                                composition["adoption_version_hash"],
                            "policy_id": composition["policy_id"],
                            "policy_hash": composition["policy_hash"],
                            "previous_head":
                                composition["previous_head_hash"],
                            "target_head": composition["target_head"],
                            "pending_event_hash":
                                composition["pending_event_hash"],
                            "composition_hash": composition_hash,
                            "source_epoch":
                                proposed_position["source_epoch"],
                            "source_version":
                                proposed_position["source_version"],
                            "command_hash": evidence["command_hash"],
                            "transaction_id": c["transaction_id"],
                            "continuity_hash":
                                finalization["continuity_hash"],
                        },
                    )

                    rechecked = artifact_guard.recheck(
                        evidence=deepcopy(finalization))
                    require(rechecked == finalization,
                            "FINALIZATION_EVIDENCE_STALE")
                    require(_consumed(
                        conn, "adoption", target_adoption)
                        and _consumed(
                            conn, "advance", advance_payload),
                        "FINALIZATION_REPLAY_STATE_INVALID")

                    attempted_transition = True
                    receipt = fence_guard.commit_transition_if_current(
                        conn,
                        fence=deepcopy(fence),
                        now=self.view.clock(),
                        prepared_transition=deepcopy(
                            prepared_transition),
                        update_id=c["transaction_id"],
                        transition_evidence_hash=composition_hash,
                    )
                    require(not conn.in_transaction,
                            "COMMIT_STATE_UNKNOWN")

                return decision(
                    "POLICY_ADOPTION_FINALIZED_NON_PRODUCTION",
                    allowed=True,
                    mutation_executed=True,
                    adoption_id=composition["adoption_id"],
                    target_head=composition["target_head"],
                    composition_hash=composition_hash,
                    finalization_event_hash=final_event_hash,
                    high_water_event_hash=receipt["event_hash"],
                    source_epoch=proposed_position["source_epoch"],
                    source_version=proposed_position[
                        "source_version"],
                )
        except Exception as error:
            if type(error) is CommitFenceRejected:
                return decision(str(error))
            if attempted_transition:
                return decision(
                    "COMMIT_STATE_UNKNOWN",
                    commit_outcome="UNKNOWN",
                    reconciliation_required=True,
                    finalization_event_hash=final_event_hash,
                )
            return decision(
                str(error) if type(error) is EnrollmentDenied
                else "FINALIZATION_WRITER_INVALID")
