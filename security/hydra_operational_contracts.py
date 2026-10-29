"""Experimental, pure evidence verification. No operational admission authority.

Only UTF-8 JSON packets are accepted, so duplicate fields cannot disappear in
an upstream dictionary conversion. Trusted context is supplied by the verifier.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import math
import re
from types import MappingProxyType
from typing import Mapping

from security.hydra_continuity_contracts import canonical, public_key

ENVELOPE = "usbay.hydra.operational.experimental.envelope.v1"
ANCHOR = "usbay.hydra.operational.experimental.anchor.v1"
PREFIX = "usbay.hydra.operational.experimental.preservation_prefix.v1"
PLAN = "usbay.hydra.operational.experimental.recovery_review.v1"
ANCHOR_PURPOSE = "anchor_observation"
PREFIX_PURPOSE = "preservation_prefix"
PLAN_PURPOSE = "recovery_review"
MAX_BYTES = 131072
MAX_DEPTH = 12
MAX_NODES = 8192
MAX_RECORDS = 256
MAX_NUMBER = 2**53 - 1
UNRESOLVED = ("protected_currentness", "complete_history_including_local_pending_tail", "receiver_fencing")
SCOPE_FIELDS = frozenset({"tenant_reference", "environment_reference", "policy_reference", "policy_hash",
    "continuity_identity", "witness_identity", "store_identity", "generation", "authority_epoch"})


class EvidenceInvalid(ValueError):
    """Bounded error: never includes packet, keys, content or decoder details."""
    def __init__(self):
        super().__init__("HYDRA_OPERATIONAL_EVIDENCE_INVALID")


def _require(condition):
    if not condition:
        raise EvidenceInvalid()


def _exact(value, fields):
    _require(type(value) is dict and set(value) == set(fields))


def _integer(value, minimum=0):
    _require(type(value) is int and minimum <= value <= MAX_NUMBER)


def _number(value):
    _require(type(value) in (int, float) and abs(value) <= MAX_NUMBER and math.isfinite(value))


def _hash(value):
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None)


def _identifier(value):
    _require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value) is not None)


def _digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _freeze(value):
    if type(value) is dict:
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if type(value) is list:
        return tuple(_freeze(v) for v in value)
    return value


def _decode(raw):
    _require(type(raw) in (bytes, str))
    if type(raw) is str:
        # Check characters before encoding to bound work even for large strings.
        _require(len(raw) <= MAX_BYTES)
        raw = raw.encode("utf-8")
    _require(0 < len(raw) <= MAX_BYTES)
    text = raw.decode("utf-8")
    # Bound nesting before the recursive JSON decoder, respecting string escapes.
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            _require(depth <= MAX_DEPTH)
        elif char in "]}":
            depth -= 1
            _require(depth >= 0)
    _require(depth == 0 and not quoted)

    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result)
            result[key] = value
        return result

    def constant(_):
        raise EvidenceInvalid()

    value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    nodes = 0

    def visit(item):
        nonlocal nodes
        nodes += 1
        _require(nodes <= MAX_NODES)
        if type(item) is dict:
            for key, val in item.items():
                _require(len(key) <= 256)
                visit(val)
        elif type(item) is list:
            _require(len(item) <= MAX_RECORDS)
            for val in item:
                visit(val)
        elif type(item) in (int, float):
            _number(item)
        elif type(item) is str:
            _require(len(item) <= 4096)
        else:
            _require(item is None or type(item) is bool)
    visit(value)
    return value, raw


@dataclass(frozen=True)
class EvidenceScope:
    tenant_reference: str
    environment_reference: str
    policy_reference: str
    policy_hash: str
    continuity_identity: str
    witness_identity: str
    store_identity: str
    generation: int
    authority_epoch: int

    def fields(self):
        return {name: getattr(self, name) for name in SCOPE_FIELDS}


@dataclass(frozen=True)
class VerificationKey:
    signer_id: str
    key_id: str
    purpose: str
    public_key_pem: str


@dataclass(frozen=True)
class VerifierContext:
    scope: EvidenceScope
    purpose: str
    challenge: str
    now: int | float
    keys: tuple[VerificationKey, ...]


@dataclass(frozen=True)
class VerifiedEvidence:
    reference: str
    content: Mapping
    packet: bytes
    status: str = "AUTHENTICITY_ONLY"
    unresolved: tuple[str, ...] = UNRESOLVED


@dataclass(frozen=True)
class RecoveryReview:
    reference: str
    content: Mapping
    state: str = "STOPPED_RECONCILIATION_ONLY"
    unresolved: tuple[str, ...] = UNRESOLVED


def _context(context):
    _require(type(context) is VerifierContext and type(context.scope) is EvidenceScope)
    _require(context.purpose in (ANCHOR_PURPOSE, PREFIX_PURPOSE, PLAN_PURPOSE))
    _hash(context.challenge)
    _number(context.now)
    _require(context.now >= 0)
    expected = context.scope.fields()
    for key in SCOPE_FIELDS - {"generation", "authority_epoch"}:
        val = expected[key]
        _require(type(val) is str and val.startswith("sha256:"))
        _hash(val[7:])
    _integer(expected["generation"], 1)
    _integer(expected["authority_epoch"], 1)
    _require(type(context.keys) is tuple and 0 < len(context.keys) <= 32)
    seen = set()
    for key in context.keys:
        _require(type(key) is VerificationKey)
        _identifier(key.signer_id); _identifier(key.key_id)
        _require(key.purpose in (ANCHOR_PURPOSE, PREFIX_PURPOSE))
        _require(type(key.public_key_pem) is str and len(key.public_key_pem) <= 1024)
        identity = (key.signer_id, key.key_id, key.purpose)
        _require(identity not in seen)
        seen.add(identity)
    return expected


def _scope(value, expected):
    _exact(value, SCOPE_FIELDS)
    _require(all(type(value[k]) is type(expected[k]) and value[k] == expected[k] for k in SCOPE_FIELDS))


def _validity(value, now):
    start, end = value["issued_at"], value["expires_at"]
    _number(start); _number(end)
    _require(0 <= start <= now < end and start < end)


def _anchor(value):
    _exact(value, {"schema", "observation_id", "sequence", "head", "witness_head"})
    _require(value["schema"] == ANCHOR)
    _hash(value["observation_id"]); _integer(value["sequence"])
    _hash(value["head"]); _hash(value["witness_head"])


def _prefix(value):
    _exact(value, {"schema", "records", "commitment"})
    _require(value["schema"] == PREFIX and type(value["records"]) is list)
    records, commitment = value["records"], value["commitment"]
    _require(0 < len(records) <= MAX_RECORDS)
    _exact(commitment, {"record_count", "first_sequence", "previous", "last_head", "records_hash"})
    _integer(commitment["record_count"], 1); _integer(commitment["first_sequence"])
    for key in ("previous", "last_head", "records_hash"):
        _hash(commitment[key])
    previous = commitment["previous"]
    for index, record in enumerate(records):
        _exact(record, {"schema", "sequence", "previous", "event_hash", "head"})
        _require(record["schema"] == PREFIX + ".record")
        _integer(record["sequence"])
        for key in ("previous", "event_hash", "head"):
            _hash(record[key])
        _require(record["sequence"] == commitment["first_sequence"] + index and record["previous"] == previous)
        _require(record["head"] == _digest({k: v for k, v in record.items() if k != "head"}))
        previous = record["head"]
    _require(commitment["record_count"] == len(records) and commitment["last_head"] == previous
             and commitment["records_hash"] == _digest(records))


def verify_evidence(packet, expected_context: VerifierContext) -> VerifiedEvidence:
    """Authenticate a bounded packet under caller-supplied scope/time/key trust.

    A valid signed observation is NOT proof of protected currentness, independent
    custody, enrollment, complete local history or authority to act.
    """
    try:
        expected = _context(expected_context)
        _require(expected_context.purpose in (ANCHOR_PURPOSE, PREFIX_PURPOSE))
        value, raw = _decode(packet)
        _exact(value, {"signed", "signature"})
        signed = value["signed"]
        _exact(signed, {"schema", "purpose", "signer_id", "key_id", "scope", "issued_at", "expires_at", "challenge", "payload"})
        _require(signed["schema"] == ENVELOPE and signed["purpose"] == expected_context.purpose)
        _scope(signed["scope"], expected)
        _hash(signed["challenge"])
        _require(signed["challenge"] == expected_context.challenge)
        _identifier(signed["signer_id"]); _identifier(signed["key_id"])
        _validity(signed, expected_context.now)
        signature = value["signature"]
        _require(type(signature) is str and re.fullmatch(r"[0-9a-f]{128}", signature) is not None)
        matches = [k for k in expected_context.keys if (k.signer_id, k.key_id, k.purpose) ==
                   (signed["signer_id"], signed["key_id"], signed["purpose"])]
        _require(len(matches) == 1)
        public_key(matches[0].public_key_pem).verify(bytes.fromhex(signature), canonical(signed))
        (_anchor if signed["purpose"] == ANCHOR_PURPOSE else _prefix)(signed["payload"])
        return VerifiedEvidence(_digest(value), _freeze(signed), raw)
    except Exception:
        raise EvidenceInvalid() from None


def validate_recovery_plan(plan, verified_records, expected_context: VerifierContext) -> RecoveryReview:
    """Validate review data only; reverify supplied evidence rather than trusting a label.

    No transition, epoch advancement, revocation, fencing or recovery is done.
    The proposed epoch is compared to the explicitly trusted context, whose
    operational currency this pure API cannot establish.
    """
    try:
        expected = _context(expected_context)
        _require(expected_context.purpose == PLAN_PURPOSE)
        value, _ = _decode(plan)
        _exact(value, {"schema", "purpose", "scope", "challenge", "issued_at", "expires_at", "state",
                       "proposed_epoch", "anchor_reference", "prefix_reference", "expected_sequence", "expected_head"})
        _require(value["schema"] == PLAN and value["purpose"] == PLAN_PURPOSE and
                 value["state"] == "STOPPED_RECONCILIATION_ONLY")
        _scope(value["scope"], expected)
        _hash(value["challenge"])
        _require(value["challenge"] == expected_context.challenge)
        _validity(value, expected_context.now)
        _integer(value["proposed_epoch"], expected_context.scope.authority_epoch + 1)
        _integer(value["expected_sequence"])
        for field in ("anchor_reference", "prefix_reference", "expected_head"):
            _hash(value[field])
        _require(type(verified_records) in (tuple, list) and len(verified_records) == 2)
        records = {}
        for record in verified_records:
            _require(type(record) is VerifiedEvidence)
            # Neither a caller-forged dataclass nor mutable replacement content
            # is proof. Re-authenticate original bytes under this context.
            authenticated = None
            for purpose in (ANCHOR_PURPOSE, PREFIX_PURPOSE):
                try:
                    authenticated = verify_evidence(record.packet, replace(expected_context, purpose=purpose))
                    break
                except EvidenceInvalid:
                    pass
            _require(authenticated is not None and authenticated.reference == record.reference)
            purpose = authenticated.content["purpose"]
            _require(purpose not in records)
            records[purpose] = authenticated
        _require(set(records) == {ANCHOR_PURPOSE, PREFIX_PURPOSE})
        anchor, prefix = records[ANCHOR_PURPOSE], records[PREFIX_PURPOSE]
        _require(value["anchor_reference"] == anchor.reference and value["prefix_reference"] == prefix.reference)
        observed, preserved = anchor.content["payload"], prefix.content["payload"]
        _require(value["expected_sequence"] == observed["sequence"] == preserved["records"][-1]["sequence"]
                 and value["expected_head"] == observed["head"] == preserved["commitment"]["last_head"])
        return RecoveryReview(_digest(value), _freeze(value))
    except Exception:
        raise EvidenceInvalid() from None
