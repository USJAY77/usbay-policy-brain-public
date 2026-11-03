"""Non-production mutation currentness projection and held SQLite fence.

No trust, keys, roots, authority, schema, recovery, or production updater is
provisioned here. This adapter can only expose already-governed signed artifacts
through the existing EnrollmentAuthorityView SQLite transaction boundary.

A usable source requires:
- an existing projection table prepared by separately governed schema work;
- pinned signers already present in EnrollmentTrust for exact status roles;
- an independent high-water anchor whose hold spans SQLite COMMIT.

Without those dependencies protected mutation remains fail-closed.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from datetime import timedelta
import sqlite3

from governance.mutation_authority import (
    AUTHORITY_DOMAIN, COMMON, ParentAuthorityStatusV1, fingerprint, _signed,
)
from governance.mutation_commit import (
    CommitFenceRejected, MutationAuthorityCurrentnessFence, MutationCommitFenceV1,
    MutationFenceGuard, commit_fingerprint,
)
from governance.mutation_issuer_authority import (
    IssuerAuthorityStatusV1, authority_fingerprint,
)
from governance.tenant_enrollment_contracts import (
    SCOPE_FIELDS, EnrollmentDenied, canonical, digest, instant, parse_json, require,
)

PROJECTION_SCHEMA = "usbay.mutation_currentness.projection.v1"
PROJECTION_TABLE = "mutation_currentness_projection"
PROJECTION_FIELDS = {
    "schema_version", "scope", "authority_domain", "parent_artifact",
    "root_authority", "issuer_grant", "review_policy", "currentness",
    "target_object", "target_state", "parent_status_signer",
    "root_status_signer", "commit_fence_signer", "expected_current_head",
    "revocation_reference", "authority_status",
}
AUTHORITY_STATUS_FIELDS = {
    "parent_status", "root_status", "issuer_status", "issuance_state",
}
SIGNER_FIELDS = {"issuer_id", "issuer_key_id"}
STATUS_ROLES = {
    "parent": "mutation_parent_currentness",
    "root": "mutation_root_currentness",
    "commit": "mutation_commit_fence",
}


def _time_text(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def projection_scope(command):
    return {k: command[k] for k in (*SCOPE_FIELDS, "authority_domain")}


def projection_scope_hash(command):
    return digest(projection_scope(command))


def projection_payload_hash(payload):
    return digest(payload)


class MutationProjectionSigner:
    """Privileged signer interface. No key material or default signer lives here."""

    issuer_id: str
    key_id: str

    def sign(self, payload: dict, *, role: str) -> dict:
        raise EnrollmentDenied("AUTHORITY_CURRENTNESS_UNPROVEN")


class MutationCurrentnessHighWater:
    """Rollback-resistant anchor interface; default is unavailable."""

    @contextmanager
    def hold(self, *, scope_hash: str):
        raise EnrollmentDenied("AUTHORITY_CURRENTNESS_UNPROVEN")
        yield  # pragma: no cover


class MutationCurrentnessProjectionUpdater:
    """Governed updater interface only; no live writer is supplied."""

    def update(self, *args, **kwargs):
        raise EnrollmentDenied("AUTHORITY_CURRENTNESS_UPDATER_UNAVAILABLE")


class MutationCurrentnessUpdaterAuthority:
    """Privileged updater-authority interface; default always denies."""

    def authorize_update(self, **kwargs):
        raise EnrollmentDenied("AUTHORITY_CURRENTNESS_UPDATER_UNAVAILABLE")


class MutationCurrentnessUpdateRejected(EnrollmentDenied):
    """High-water/update provider rejected before SQLite COMMIT."""


class MutationCurrentnessUpdateUncertain(Exception):
    """High-water/update provider cannot prove whether SQLite COMMIT completed."""


def _validate_signer_reference(value):
    require(type(value) is dict and set(value) == SIGNER_FIELDS,
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    require(all(type(value[k]) is str and value[k] and "*" not in value[k]
                for k in SIGNER_FIELDS), "AUTHORITY_CURRENTNESS_UNPROVEN")
    return deepcopy(value)


def _validate_projection(payload, command):
    require(type(payload) is dict and set(payload) == PROJECTION_FIELDS,
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    canonical(payload)
    require(payload["schema_version"] == PROJECTION_SCHEMA
            and payload["authority_domain"] == AUTHORITY_DOMAIN,
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    require(payload["scope"] == projection_scope(command), "TENANT_MISMATCH")
    require(payload["expected_current_head"] == command["expected_current_head"],
            "EXPECTED_HEAD_MISMATCH")
    require(payload["target_state"] == command["expected_state"],
            "EXPECTED_STATE_MISMATCH")
    for name in ("parent_artifact", "root_authority", "issuer_grant",
                 "review_policy", "target_object"):
        require(type(payload[name]) is dict
                and set(payload[name]) == {"payload", "signature"},
                "AUTHORITY_CURRENTNESS_UNPROVEN")
    require(type(payload["currentness"]) is dict
            and set(payload["currentness"]) ==
                {"policy", "adoption", "h", "w", "revocations", "expected",
                 "challenge", "request_digest"},
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    for name in ("policy", "adoption", "h", "w", "revocations"):
        require(type(payload["currentness"][name]) is dict
                and set(payload["currentness"][name]) == {"payload", "signature"},
                "AUTHORITY_CURRENTNESS_UNPROVEN")
    require(payload["currentness"]["expected"]["head_hash"]
            == command["expected_current_head"], "EXPECTED_HEAD_MISMATCH")
    require(payload["revocation_reference"]
            == payload["currentness"]["revocations"]["payload"].get("revocation_reference"),
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    require(type(payload["authority_status"]) is dict
            and set(payload["authority_status"]) == AUTHORITY_STATUS_FIELDS,
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    status = payload["authority_status"]
    require(status["parent_status"] in ("ACTIVE", "REVOKED")
            and status["root_status"] in ("ACTIVE", "REVOKED")
            and status["issuer_status"] in ("ACTIVE", "REVOKED")
            and status["issuance_state"] in ("AVAILABLE", "CONSUMED"),
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    for name in ("parent_status_signer", "root_status_signer",
                 "commit_fence_signer"):
        _validate_signer_reference(payload[name])
    return deepcopy(payload)


def _signer_key(trust, signer_ref, role):
    key = trust._keys.get(signer_ref["issuer_key_id"])
    require(key is not None and key.issuer_id == signer_ref["issuer_id"]
            and role in key.roles, "AUTHORITY_CURRENTNESS_UNPROVEN")
    return key


def _bounded_status_deadline(trust, now, signer_key, *payloads):
    deadlines = [
        instant(signer_key.expires_at),
        now + timedelta(seconds=trust.max_age_seconds),
    ]
    for payload in payloads:
        end = payload.get("valid_until", payload.get("expires_at"))
        require(end is not None, "AUTHORITY_CURRENTNESS_UNPROVEN")
        deadlines.append(instant(end))
    result = min(deadlines)
    require(now < result, "AUTHORITY_CURRENTNESS_UNPROVEN")
    return result


class _ProjectionStatusSource:
    def __init__(self, projection, *, trust, signer, signer_ref, kind,
                 epoch, version, clock):
        self._projection = projection
        self._trust = trust
        self._signer = signer
        self._signer_ref = signer_ref
        self._kind = kind
        self._epoch = epoch
        self._version = version
        self._clock = clock

    def _signed_status(self, payload, model, role):
        envelope = self._signer.sign(deepcopy(payload), role=role)
        parsed, _ = _signed(self._trust, envelope, model, role, self._clock())
        require(parsed == payload, "AUTHORITY_CURRENTNESS_UNPROVEN")
        return envelope

    def read_parent_authority(self, *, request_binding, challenge):
        require(self._kind == "parent", "AUTHORITY_CURRENTNESS_UNPROVEN")
        p = self._projection
        parent = p["parent_artifact"]["payload"]
        signer_key = _signer_key(
            self._trust, self._signer_ref, STATUS_ROLES["parent"])
        now = self._clock()
        valid_until = _bounded_status_deadline(
            self._trust, now, signer_key, parent)
        common = {
            k: deepcopy(parent[k]) for k in COMMON
            if k not in ("schema_version", "issuer_id", "issuer_key_id",
                         "valid_from", "valid_until", "issued_at")
        }
        payload = dict(
            common,
            schema_version="usbay.mutation_authority.parent_status.v1",
            issuer_id=self._signer_ref["issuer_id"],
            issuer_key_id=self._signer_ref["issuer_key_id"],
            valid_from=_time_text(now),
            valid_until=_time_text(valid_until),
            issued_at=_time_text(now),
            parent_authority_id=parent["authority_id"],
            parent_authority_hash=digest(parent),
            subject_issuer_id=parent["subject_issuer_id"],
            issuance_scope=AUTHORITY_DOMAIN,
            parent_status=p["authority_status"]["parent_status"],
            state_sequence=self._version,
            state_epoch=self._epoch,
            expected_current_head=p["expected_current_head"],
            revocation_reference=p["revocation_reference"],
            challenge=challenge,
            request_binding=request_binding,
            status_fingerprint="",
        )
        payload["status_fingerprint"] = fingerprint(payload, "parent_status")
        ParentAuthorityStatusV1.from_payload(payload)
        return self._signed_status(
            payload, ParentAuthorityStatusV1, STATUS_ROLES["parent"])

    def read_issuer_authority(self, *, request_binding, challenge):
        require(self._kind == "root", "AUTHORITY_CURRENTNESS_UNPROVEN")
        p = self._projection
        root = p["root_authority"]["payload"]
        issuer = p["issuer_grant"]["payload"]
        signer_key = _signer_key(
            self._trust, self._signer_ref, STATUS_ROLES["root"])
        now = self._clock()
        valid_until = _bounded_status_deadline(
            self._trust, now, signer_key, root, issuer)
        common = {
            k: deepcopy(issuer[k]) for k in COMMON
            if k not in ("schema_version", "issuer_id", "issuer_key_id",
                         "valid_from", "valid_until", "issued_at")
        }
        payload = dict(
            common,
            schema_version="usbay.mutation_issuance.status.v1",
            issuer_id=self._signer_ref["issuer_id"],
            issuer_key_id=self._signer_ref["issuer_key_id"],
            valid_from=_time_text(now),
            valid_until=_time_text(valid_until),
            issued_at=_time_text(now),
            root_authority_id=root["root_authority_id"],
            root_authority_hash=digest(root),
            issuer_grant_id=issuer["issuer_grant_id"],
            issuer_grant_hash=digest(issuer),
            subject_issuer_id=issuer["issuer_id"],
            root_status=p["authority_status"]["root_status"],
            issuer_status=p["authority_status"]["issuer_status"],
            issuance_state=p["authority_status"]["issuance_state"],
            state_sequence=self._version,
            state_epoch=self._epoch,
            expected_current_head=p["expected_current_head"],
            revocation_reference=p["revocation_reference"],
            challenge=challenge,
            request_binding=request_binding,
            status_fingerprint="",
        )
        payload["status_fingerprint"] = authority_fingerprint(payload, "status")
        IssuerAuthorityStatusV1.from_payload(payload)
        return self._signed_status(
            payload, IssuerAuthorityStatusV1, STATUS_ROLES["root"])


class SQLiteMutationCurrentnessProjectionUpdater(MutationCurrentnessProjectionUpdater):
    """Bounded non-production projection updater.

    The updater creates no authority and has no default authorizer or high-water
    implementation. A successful update requires an independently composed
    updater authority plus a high-water object whose update hold spans COMMIT.
    """

    def __init__(self, view, *, updater_authority, high_water):
        self._view = view
        self._updater_authority = updater_authority
        self._high_water = high_water

    def update(self, command, projection, *, expected_epoch, expected_version,
               expected_projection_hash, update_id):
        conn = None
        commit_attempted = False
        try:
            require(isinstance(self._updater_authority,
                               MutationCurrentnessUpdaterAuthority),
                    "AUTHORITY_CURRENTNESS_UPDATER_UNAVAILABLE")
            require(isinstance(self._high_water, MutationCurrentnessHighWater),
                    "AUTHORITY_CURRENTNESS_UNPROVEN")
            require(type(update_id) is str and 0 < len(update_id) <= 128
                    and "*" not in update_id, "CURRENTNESS_UPDATE_INVALID")
            conn = self._view._connect_existing()
            conn.execute("BEGIN IMMEDIATE")
            state = self._view._snapshot(conn, require_finalized=False)
            scope_hash = projection_scope_hash(command)
            epoch, version, current, current_hash = (
                SQLiteMutationCurrentnessFence._load(conn, scope_hash))
            require((epoch, version, current_hash) ==
                    (expected_epoch, expected_version,
                     expected_projection_hash), "CURRENTNESS_UPDATE_STALE")
            proposed = _validate_projection(deepcopy(projection), command)
            proposed_hash = projection_payload_hash(proposed)
            require(proposed_hash != current_hash, "CURRENTNESS_UPDATE_INVALID")
            auth = self._updater_authority.authorize_update(
                command=deepcopy(command),
                previous_projection_hash=current_hash,
                proposed_projection_hash=proposed_hash,
                source_epoch=epoch,
                source_version=version,
                update_id=update_id,
                now=self._view.clock(),
            )
            require(type(auth) is dict
                    and set(auth) == {"decision", "evidence_hash",
                                      "source_status_hash", "consumption"}
                    and auth["decision"] == "ALLOW"
                    and all(type(auth[k]) is str
                            and auth[k].startswith("sha256:")
                            for k in ("evidence_hash", "source_status_hash"))
                    and type(auth["consumption"]) is dict
                    and set(auth["consumption"])
                        == {"issuer_id", "grant_id", "nonce", "replay_identity"}
                    and all(type(auth["consumption"][k]) is str
                            and bool(auth["consumption"][k])
                            for k in ("issuer_id", "grant_id", "nonce", "replay_identity")),
                    "AUTHORITY_CURRENTNESS_UPDATER_UNAVAILABLE")
            self._view._consume(
                conn, "mutation_high_water_authority",
                deepcopy(auth["consumption"]))
            expected = {
                "scope_hash": scope_hash,
                "source_epoch": epoch,
                "source_version": version,
                "projection_hash": current_hash,
            }
            proposed_position = {
                "scope_hash": scope_hash,
                "source_epoch": epoch,
                "source_version": version + 1,
                "projection_hash": proposed_hash,
            }
            hold_update = getattr(self._high_water, "hold_update", None)
            require(callable(hold_update),
                    "AUTHORITY_CURRENTNESS_UPDATER_UNAVAILABLE")
            with hold_update(
                    scope_hash=scope_hash, expected=deepcopy(expected),
                    proposed=deepcopy(proposed_position),
                    update_id=update_id) as anchor:
                require(anchor.current() == expected,
                        "AUTHORITY_CURRENTNESS_UNPROVEN")
                cursor = conn.execute(
                    "UPDATE mutation_currentness_projection "
                    "SET source_version=?,projection=?,projection_hash=? "
                    "WHERE scope_hash=? AND source_epoch=? AND source_version=? "
                    "AND projection_hash=?",
                    (version + 1, canonical(proposed).decode(), proposed_hash,
                     scope_hash, epoch, version, current_hash),
                )
                require(cursor.rowcount == 1, "CURRENTNESS_UPDATE_STALE")
                event = {
                    "kind": "MUTATION_CURRENTNESS_PROJECTED_NON_PRODUCTION",
                    "scope_reference": scope_hash,
                    "source_epoch": epoch,
                    "previous_source_version": version,
                    "source_version": version + 1,
                    "previous_projection_hash": current_hash,
                    "projection_hash": proposed_hash,
                    "update_id_reference": digest({"update_id": update_id}),
                    "updater_evidence_hash": auth["evidence_hash"],
                    "source_status_hash": auth["source_status_hash"],
                }
                event_hash = self._view._append(conn, state, event)
                commit_update = getattr(anchor, "commit_update", None)
                require(callable(commit_update),
                        "AUTHORITY_CURRENTNESS_UPDATER_UNAVAILABLE")
                commit_attempted = True
                commit_update(
                    conn, expected=deepcopy(expected),
                    proposed=deepcopy(proposed_position),
                    update_id=update_id,
                )
                require(not conn.in_transaction, "CURRENTNESS_UPDATE_STATE_UNKNOWN")
            from governance.tenant_enrollment_contracts import decision
            return decision(
                "CURRENTNESS_PROJECTION_UPDATED_NON_PRODUCTION",
                allowed=True,
                update_outcome="COMMITTED_NON_EXECUTING",
                mutation_executed=False,
                event_hash=event_hash,
                source_epoch=epoch,
                source_version=version + 1,
                projection_hash=proposed_hash,
            )
        except MutationCurrentnessUpdateRejected as error:
            if conn is not None and conn.in_transaction:
                conn.rollback()
            from governance.tenant_enrollment_contracts import decision
            return decision(str(error))
        except MutationCurrentnessUpdateUncertain:
            from governance.tenant_enrollment_contracts import decision
            return decision(
                "CURRENTNESS_UPDATE_STATE_UNKNOWN",
                update_outcome="UNKNOWN",
                reconciliation_required=True,
                retry_allowed=False,
            )
        except Exception as error:
            from governance.tenant_enrollment_contracts import decision
            if commit_attempted:
                return decision(
                    "CURRENTNESS_UPDATE_STATE_UNKNOWN",
                    update_outcome="UNKNOWN",
                    reconciliation_required=True,
                    retry_allowed=False,
                )
            if conn is not None and conn.in_transaction:
                conn.rollback()
            reason = (str(error) if type(error) is EnrollmentDenied
                      else "CURRENTNESS_UPDATE_INVALID")
            return decision(reason)
        finally:
            if conn is not None:
                conn.close()


class SQLiteMutationCurrentnessFence(MutationAuthorityCurrentnessFence):
    """Held non-production source in the existing authority SQLite database."""

    def __init__(self, view, *, signers: dict,
                 high_water: MutationCurrentnessHighWater):
        self._view = view
        self._signers = dict(signers or {})
        self._high_water = high_water

    def _signer(self, name, projection):
        role = STATUS_ROLES[name]
        signer = self._signers.get(role)
        require(isinstance(signer, MutationProjectionSigner),
                "AUTHORITY_CURRENTNESS_UNPROVEN")
        field = {
            "parent": "parent_status_signer",
            "root": "root_status_signer",
            "commit": "commit_fence_signer",
        }[name]
        ref = projection[field]
        require(signer.issuer_id == ref["issuer_id"]
                and signer.key_id == ref["issuer_key_id"],
                "AUTHORITY_CURRENTNESS_UNPROVEN")
        _signer_key(self._view.trust, ref, role)
        return signer, ref

    @staticmethod
    def _load(connection, scope_hash):
        try:
            row = connection.execute(
                "SELECT source_epoch,source_version,projection,projection_hash "
                "FROM mutation_currentness_projection WHERE scope_hash=?",
                (scope_hash,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise EnrollmentDenied("COMMIT_FENCE_UNAVAILABLE") from exc
        require(row is not None, "AUTHORITY_CURRENTNESS_UNPROVEN")
        epoch, version, encoded, stored_hash = row
        require(type(epoch) is int and type(version) is int
                and epoch >= 1 and version >= 1,
                "AUTHORITY_CURRENTNESS_UNPROVEN")
        payload = parse_json(encoded)
        require(stored_hash == projection_payload_hash(payload),
                "AUTHORITY_CURRENTNESS_UNPROVEN")
        if version > 1:
            events = [
                parse_json(item[0]) for item in connection.execute(
                    "SELECT payload FROM enrollment_events ORDER BY sequence")
            ]
            matches = [
                event for event in events
                if event.get("kind") == "MUTATION_CURRENTNESS_PROJECTED_NON_PRODUCTION"
                and event.get("scope_reference") == scope_hash
            ]
            require(bool(matches), "AUTHORITY_CURRENTNESS_UNPROVEN")
            latest = matches[-1]
            require(latest.get("source_epoch") == epoch
                    and latest.get("source_version") == version
                    and latest.get("projection_hash") == stored_hash,
                    "AUTHORITY_CURRENTNESS_UNPROVEN")
        return epoch, version, payload, stored_hash

    @contextmanager
    def hold(self, connection, *, command, challenge):
        require(connection.in_transaction, "TRANSACTION_CONFLICT")
        scope_hash = projection_scope_hash(command)
        require(isinstance(self._high_water, MutationCurrentnessHighWater),
                "AUTHORITY_CURRENTNESS_UNPROVEN")
        with self._high_water.hold(scope_hash=scope_hash) as anchor:
            epoch, version, projection, projection_hash = self._load(
                connection, scope_hash)
            projection = _validate_projection(projection, command)
            current = anchor.current()
            require(current == {
                "scope_hash": scope_hash,
                "source_epoch": epoch,
                "source_version": version,
                "projection_hash": projection_hash,
            }, "AUTHORITY_CURRENTNESS_UNPROVEN")
            yield _SQLiteMutationCurrentnessGuard(
                self, connection, command, challenge, projection,
                projection_hash, epoch, version, anchor)


class _SQLiteMutationCurrentnessGuard(MutationFenceGuard):
    def __init__(self, source, connection, command, challenge, projection,
                 projection_hash, epoch, version, anchor):
        self._source = source
        self._connection = connection
        self._command = deepcopy(command)
        self._challenge = challenge
        self._projection = projection
        self._projection_hash = projection_hash
        self._epoch = epoch
        self._version = version
        self._anchor = anchor
        self._parent_signer, self._parent_ref = source._signer(
            "parent", projection)
        self._root_signer, self._root_ref = source._signer(
            "root", projection)
        self._commit_signer, self._commit_ref = source._signer(
            "commit", projection)

    def authority_material(self):
        p = self._projection
        clock = self._source._view.clock
        return dict(
            parent_artifact=deepcopy(p["parent_artifact"]),
            parent_source=_ProjectionStatusSource(
                p, trust=self._source._view.trust,
                signer=self._parent_signer, signer_ref=self._parent_ref,
                kind="parent", epoch=self._epoch,
                version=self._version, clock=clock),
            root_authority=deepcopy(p["root_authority"]),
            issuer_grant=deepcopy(p["issuer_grant"]),
            review_policy=deepcopy(p["review_policy"]),
            root_source=_ProjectionStatusSource(
                p, trust=self._source._view.trust,
                signer=self._root_signer, signer_ref=self._root_ref,
                kind="root", epoch=self._epoch,
                version=self._version, clock=clock),
            currentness=deepcopy(p["currentness"]),
            target_object=deepcopy(p["target_object"]),
        )

    def read_state(self, connection, command):
        require(connection is self._connection and connection.in_transaction,
                "TRANSACTION_CONFLICT")
        require(projection_scope_hash(command)
                == projection_scope_hash(self._command), "TENANT_MISMATCH")
        return deepcopy(self._projection["target_state"])

    def evidence(self, *, command, bindings, now):
        require(command == self._command, "COMMIT_FENCE_MISMATCH")
        payload = {k: deepcopy(command[k]) for k in COMMON}
        payload.update(
            schema_version="usbay.mutation_commit.fence.v1",
            issuer_id=self._commit_ref["issuer_id"],
            issuer_key_id=self._commit_ref["issuer_key_id"],
            **deepcopy(bindings),
            source_version=self._version,
            source_epoch=self._epoch,
            issued_at=_time_text(now),
            valid_from=_time_text(now),
            fence_created_at=_time_text(now),
            valid_until=bindings["verification_valid_until"],
            fence_valid_until=bindings["verification_valid_until"],
            fence_fingerprint="",
        )
        payload["fence_fingerprint"] = commit_fingerprint(payload, "fence")
        MutationCommitFenceV1.from_payload(payload)
        envelope = self._commit_signer.sign(
            deepcopy(payload), role=STATUS_ROLES["commit"])
        parsed, _ = _signed(
            self._source._view.trust, envelope, MutationCommitFenceV1,
            STATUS_ROLES["commit"], now)
        require(parsed == payload, "COMMIT_FENCE_MISMATCH")
        return envelope

    def commit_if_current(self, connection, *, fence, now):
        require(connection is self._connection and connection.in_transaction,
                "TRANSACTION_CONFLICT")
        try:
            epoch, version, projection, projection_hash = self._source._load(
                connection, projection_scope_hash(self._command))
            if (epoch, version, projection_hash) != (
                    self._epoch, self._version, self._projection_hash):
                raise CommitFenceRejected("COMMIT_FENCE_STALE")
            if projection_payload_hash(
                    _validate_projection(projection, self._command)
            ) != self._projection_hash:
                raise CommitFenceRejected("COMMIT_FENCE_STALE")
            if not (instant(fence["valid_from"])
                    <= now < instant(fence["fence_valid_until"])):
                raise CommitFenceRejected("COMMIT_FENCE_STALE")
            expected = {
                "scope_hash": projection_scope_hash(self._command),
                "source_epoch": self._epoch,
                "source_version": self._version,
                "projection_hash": self._projection_hash,
            }
            if self._anchor.current() != expected:
                raise CommitFenceRejected("COMMIT_FENCE_STALE")
            self._anchor.commit_if_unchanged(connection, expected=expected)
        except CommitFenceRejected:
            raise
        except Exception as exc:
            raise CommitFenceRejected("COMMIT_FENCE_STALE") from exc
