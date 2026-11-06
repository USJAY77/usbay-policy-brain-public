"""Proposed V2 signed inputs + native timestamp observations, never authority.

The legacy exporter is unchanged. This candidate does not validate the audit
ledger/release/WORM semantics, adopt signer/TSA trust or authorize an export.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from audit.export_input_contract import PACKAGE_FILES, read_regular, strict_json, _identity
from audit.rfc3161_crypto import inspect_timestamp_temporal


FORMAT = 'USBAY_TENANT_AUDIT_PACKAGE_V2'
INDEX_FORMAT = 'USBAY_TENANT_AUDIT_EVIDENCE_INDEX_V2'
SIGNATURE_FORMAT = 'USBAY_TENANT_AUDIT_SIGNATURE_V2'
REQUEST_FILE = 'rfc3161_request.tsq'
CRL_FILE = 'tsa_revocation.crl.pem'
V2_FILES = PACKAGE_FILES | {REQUEST_FILE, CRL_FILE}
UNSIGNED_REPORT_FILE = 'verification_report.md'
PAYLOAD_FILES = V2_FILES - {'verification_manifest.json','package_signature.json',
                          'evidence_index.json',UNSIGNED_REPORT_FILE}
CORE_FILES = frozenset({'audit.jsonl','ledger.sha256','signatures.json',
                        'consensus_evidence.json','governance_release.json','tenant_context.json'})
BINDING_FIELDS = frozenset({'tenant_id','tenant_reference','actor_reference',
    'resource_reference','source_commit','source_tree','purpose','action',
    'tsa_policy_hash','tsa_policy_version','tsa_policy_oid'})
_HEX = re.compile(r'[0-9a-f]{64}')


class ExportTimestampV2Error(RuntimeError):
    pass


@dataclass(frozen=True)
class ExportTimestampV2Observation:
    manifest_sha256: str
    index_sha256: str
    signer_public_key_sha256: str
    bindings_sha256: str
    timestamp_response_sha256: str
    timestamp_request_sha256: str
    crls_sha256: str
    observed_file_hashes: tuple[tuple[str,str], ...]
    scope: str = 'V2_SIGNED_INPUT_AND_NATIVE_TIMESTAMP_ONLY'
    remaining_requirements: tuple[str, ...] = (
        'ADOPTED_PACKAGE_SIGNER_AND_TSA_TRUST_CONTEXT',
        'GOVERNED_IDENTITY_TENANT_ACTOR_RESOURCE_PURPOSE_BINDINGS',
        'AUDIT_LEDGER_RELEASE_WORM_SEMANTIC_VERIFICATION',
        'VERIFIED_SOURCE_AND_NATIVE_BUILD_ARTIFACT',
        'GOVERNED_CLOCK_PROFILE_CURRENTNESS_AND_RECOVERY',
        'REQUEST_ORIGIN_AND_APPLICABLE_REPLAY_VERIFICATION',
        'EXPORT_EXECUTION_AUTHORITY',
    )


def canonical(value) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ExportTimestampV2Error(code)


def _bindings(value) -> dict:
    _require(type(value) is dict and set(value)==BINDING_FIELDS,'V2_BINDINGS_INVALID')
    result=dict(value)
    for field in BINDING_FIELDS:
        _require(type(result[field]) is str,'V2_BINDINGS_INVALID')
    _require(bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',result['tenant_id'])),'V2_TENANT_INVALID')
    for field in ('tenant_reference','actor_reference','resource_reference','tsa_policy_hash'):
        _require(bool(re.fullmatch(r'sha256:[0-9a-f]{64}',result[field])),'V2_REFERENCE_INVALID')
    for field in ('source_commit','source_tree'):
        _require(bool(re.fullmatch(r'[0-9a-f]{40}',result[field])),'V2_SOURCE_INVALID')
    _require(result['purpose']=='audit_export_integrity' and result['action']=='audit.timestamp.verify','V2_ACTION_PURPOSE_INVALID')
    _require(bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',result['tsa_policy_version'])),'V2_POLICY_VERSION_INVALID')
    _require(len(result['tsa_policy_oid'])<=160 and bool(re.fullmatch(r'(?:0|1|2)(?:\.(?:0|[1-9][0-9]*)){2,31}',result['tsa_policy_oid'])),'V2_POLICY_OID_INVALID')
    arcs=result['tsa_policy_oid'].split('.')
    _require(int(arcs[0])==2 or int(arcs[1])<=39,'V2_POLICY_OID_INVALID')
    return result


def timestamp_imprint(core_hashes: dict, bindings: dict) -> str:
    """Pre-timestamp preimage. No response/request/CRL or final-manifest cycle."""
    checked=_bindings(bindings)
    _require(type(core_hashes) is dict and set(core_hashes)==CORE_FILES,'V2_CORE_HASHES_INVALID')
    _require(all(type(v) is str and _HEX.fullmatch(v) for v in core_hashes.values()),'V2_CORE_HASHES_INVALID')
    return digest(canonical({'domain':'USBAY_EXPORT_TIMESTAMP_IMPRINT_V2',
        'bindings':checked,'core_hashes':dict(sorted(core_hashes.items()))}))


def _snapshot(root: Path) -> dict[str,bytes]:
    _require(root.is_dir() and root.resolve(strict=True)==root,'V2_PACKAGE_PATH_INVALID')
    _require(set(os.listdir(root))==V2_FILES,'V2_PACKAGE_INVENTORY_INVALID')
    # The reused reader rejects rebinding, symlinks, hardlinks, FIFO and oversize
    # reads. Re-read every input after native verification before returning.
    result={};total=0
    for name in sorted(V2_FILES):
        raw=read_regular(root,name,2*1024*1024)
        total+=len(raw)
        _require(total<=32*1024*1024,'V2_PACKAGE_TOO_LARGE')
        result[name]=raw
    return result


def inspect_native_export_v2(package: Path | str, *, expected_bindings: dict,
                             expected_manifest_sha256: str, signer_public_key: bytes,
                             tsa_roots_pem: bytes, evaluation_time: datetime,
                             max_age_seconds: int, clock_skew_seconds: int,
                             maximum_accuracy_seconds: int,
                             max_crl_age_seconds: int) -> ExportTimestampV2Observation:
    """Verify signed file coverage and native time/CRLs under explicit inputs.

    Expected bindings, keys, roots, clock and profiles are NOT adopted by this
    function. A future governed caller must independently verify their authority.
    No legacy fallback, signer lookup from package or caller PASS callback.
    """
    try:
        expected=_bindings(expected_bindings)
        _require(type(expected_manifest_sha256) is str and bool(_HEX.fullmatch(expected_manifest_sha256)), 'V2_EXPECTED_MANIFEST_REQUIRED')
        _require(type(signer_public_key) is bytes and len(signer_public_key)==32,'V2_SIGNER_KEY_INVALID')
        root=Path(package).absolute()
        root_identity=_identity(root.stat(follow_symlinks=False))
        files=_snapshot(root)
        observed={name:digest(raw) for name,raw in files.items()}
        objects={name:strict_json(raw) for name,raw in files.items() if name.endswith('.json')}
        for line in files['audit.jsonl'].splitlines():
            if line.strip():strict_json(line)
        manifest=objects['verification_manifest.json']
        _require(type(manifest) is dict and set(manifest)=={'format','bindings','evidence_hashes','timestamp_imprint'},'V2_MANIFEST_INVALID')
        _require(manifest['format']==FORMAT,'V2_MANIFEST_VERSION_REQUIRED')
        _require(_bindings(manifest['bindings'])==expected,'V2_BINDING_MISMATCH')
        payload_hashes={name:observed[name] for name in sorted(PAYLOAD_FILES)}
        _require(manifest['evidence_hashes']==payload_hashes,'V2_SIGNED_FILE_COVERAGE_MISMATCH')
        imprint=timestamp_imprint({name:observed[name] for name in CORE_FILES},expected)
        _require(manifest['timestamp_imprint']==imprint,'V2_TIMESTAMP_PREIMAGE_MISMATCH')
        _require(files['verification_manifest.json']==canonical(manifest),'V2_MANIFEST_ENCODING_INVALID')
        _require(observed['verification_manifest.json']==expected_manifest_sha256,'V2_EXPECTED_MANIFEST_MISMATCH')
        expected_index={'format':INDEX_FORMAT,'manifest_sha256':expected_manifest_sha256,
                        'evidence_hashes':payload_hashes}
        _require(objects['evidence_index.json']==expected_index and files['evidence_index.json']==canonical(expected_index),'V2_INDEX_MISMATCH')
        fingerprint=digest(signer_public_key)
        signature_basis={'format':SIGNATURE_FORMAT,'public_key_sha256':fingerprint,
                         'manifest_sha256':expected_manifest_sha256,
                         'index_sha256':observed['evidence_index.json']}
        signature=objects['package_signature.json']
        _require(type(signature) is dict and set(signature)==set(signature_basis)|{'signature'},'V2_SIGNATURE_INVALID')
        _require(all(signature[k]==v for k,v in signature_basis.items()),'V2_SIGNATURE_BINDING_MISMATCH')
        _require(type(signature['signature']) is str and bool(re.fullmatch(r'[0-9a-f]{128}',signature['signature'])),'V2_SIGNATURE_INVALID')
        try:
            Ed25519PublicKey.from_public_bytes(signer_public_key).verify(bytes.fromhex(signature['signature']),canonical(signature_basis))
        except Exception:
            raise ExportTimestampV2Error('V2_SIGNATURE_INVALID') from None
        for name in ('tenant_context.json','governance_release.json'):
            _require(type(objects[name]) is dict and objects[name].get('tenant_id')==expected['tenant_id'],'V2_TENANT_CONTENT_MISMATCH')
        _require(objects['governance_release.json'].get('git_commit')==expected['source_commit'],'V2_SOURCE_CONTENT_MISMATCH')
        _require(files['tsa_policy_oid.txt']==(expected['tsa_policy_oid']+'\n').encode('ascii'),'V2_POLICY_FILE_MISMATCH')
        _require(type(files[CRL_FILE]) is bytes and bool(files[CRL_FILE]),'V2_REVOCATION_REQUIRED')
        native=inspect_timestamp_temporal(response_der=files['rfc3161_timestamp.tsr'],
            request_der=files[REQUEST_FILE],expected_imprint=imprint,
            expected_policy_oid=expected['tsa_policy_oid'],roots_pem=tsa_roots_pem,
            intermediates_pem=files['tsa_certificate_chain.pem'],crls_pem=files[CRL_FILE],
            evaluation_time=evaluation_time,max_crl_age_seconds=max_crl_age_seconds,
            max_age_seconds=max_age_seconds,clock_skew_seconds=clock_skew_seconds,
            maximum_accuracy_seconds=maximum_accuracy_seconds)
        _require('SIGNED_FULL_CHAIN_CRL_REVOCATION' in native.crypto.checks,'V2_REVOCATION_INCOMPLETE')
        _require(files==_snapshot(root),'V2_INPUT_CHANGED')
        _require(_identity(root.stat(follow_symlinks=False))==root_identity,'V2_INPUT_CHANGED')
        return ExportTimestampV2Observation(expected_manifest_sha256,observed['evidence_index.json'],
            fingerprint,digest(canonical(expected)),observed['rfc3161_timestamp.tsr'],
            observed[REQUEST_FILE],observed[CRL_FILE],tuple(sorted(observed.items())))
    except ExportTimestampV2Error:
        raise
    except Exception:
        raise ExportTimestampV2Error('V2_VERIFICATION_FAILED') from None
