"""Native RFC3161 cryptographic observations; never execution authority.

This boundary does not establish production policy adoption, request origin,
replay consumption or execution permission. Temporal and CRL checks require
explicit inputs and return observations within their stated verification scope.
No runtime/export consumer may replace those checks with this observation.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import serialization


MAX_DER_BYTES = 2 * 1024 * 1024
MAX_CERTIFICATE_BYTES = 128 * 1024
ENGINE = Path('/usr/bin/openssl')
INFO_ENGINE = Path(__file__).with_name('rfc3161_info')
_PEM = re.compile(rb'-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----')
_CRL_PEM = re.compile(rb'-----BEGIN X509 CRL-----\r?\n[A-Za-z0-9+/=\r\n]+-----END X509 CRL-----')
_OID = re.compile(r'(?:0|1|2)(?:\.(?:0|[1-9][0-9]*)){2,31}')
_HEX = re.compile(r'[0-9a-f]{64}')
_LAUNCHER = (
    'import os,resource,sys;'
    'os.umask(0o077);'
    'resource.setrlimit(resource.RLIMIT_CORE,(0,0));'
    'resource.setrlimit(resource.RLIMIT_CPU,(2,2));'
    'resource.setrlimit(resource.RLIMIT_AS,(536870912,536870912));'
    'resource.setrlimit(resource.RLIMIT_FSIZE,(4194304,4194304));'
    'resource.setrlimit(resource.RLIMIT_NOFILE,(32,32));'
    'os.execve(sys.argv[1],sys.argv[1:],dict(os.environ))'
)


class TimestampCryptoError(RuntimeError):
    """Only bounded internal reason codes cross this interface."""


@dataclass(frozen=True)
class TimestampCryptoObservation:
    response_sha256: str
    request_sha256: str
    roots_sha256: str
    intermediates_sha256: str
    expected_imprint: str
    expected_policy_oid: str
    evaluated_at: str
    checks: tuple[str, ...] = (
        'CMS_SIGNATURE', 'EXPLICIT_CERTIFICATE_PATH', 'TIMESTAMP_SIGNING_PURPOSE',
        'SHA256_MESSAGE_IMPRINT', 'REQUESTED_TIMESTAMP_POLICY', 'SUPPLIED_REQUEST_BINDING',
        'CERTIFICATE_VALIDITY_AT_EVALUATION_TIME', 'CANONICAL_RESPONSE_AND_REQUEST_ENCODING',
    )
    remaining_requirements: tuple[str, ...] = (
        'GOVERNED_TRUST_ADOPTION', 'TRUST_CONTEXT_IDENTITY_TENANT_PURPOSE_BINDINGS',
        'GOVERNED_CLOCK_AND_TIMESTAMP_FRESHNESS', 'SIGNED_REVOCATION_EVIDENCE',
        'GOVERNED_REQUEST_ORIGIN_AND_REPLAY_BINDINGS', 'CURRENTNESS_AND_RECOVERY',
    )
    crls_sha256: str | None = None
    max_crl_age_seconds: int | None = None


@dataclass(frozen=True)
class TimestampTemporalObservation:
    crypto: TimestampCryptoObservation
    signed_generated_at: str
    signed_accuracy_microseconds: int
    max_age_seconds: int
    clock_skew_seconds: int
    maximum_accuracy_seconds: int
    # Clock/profile trust remains an independent governance requirement.
    remaining_requirements: tuple[str, ...]


@dataclass(frozen=True)
class CertificateRevocationObservation:
    certificate_sha256: str
    roots_sha256: str
    intermediates_sha256: str
    crls_sha256: str
    evaluated_at: str
    max_crl_age_seconds: int
    scope: str = 'EXPLICIT_CERTIFICATE_PATH_AND_SIGNED_FULL_CHAIN_CRL_CHECKS'
    remaining_requirements: tuple[str, ...] = ('GOVERNED_TRUST_AND_CLOCK_ADOPTION', 'RESOURCE_IDENTITY_PURPOSE_BINDING')


def _bytes(value: bytes, limit: int) -> None:
    if type(value) is not bytes or not value or len(value) > limit:
        raise TimestampCryptoError('TSA_INPUT_INVALID')


def _certificates(value: bytes, *, roots: bool) -> bytes:
    _bytes(value, MAX_CERTIFICATE_BYTES)
    blocks = _PEM.findall(value)
    if not blocks or len(blocks) > 8 or _PEM.sub(b'', value).strip():
        raise TimestampCryptoError('TSA_CERTIFICATE_INPUT_INVALID')
    try:
        certs = [x509.load_pem_x509_certificate(block) for block in blocks]
        encoded = [c.public_bytes(serialization.Encoding.DER) for c in certs]
        if len(set(encoded)) != len(encoded):
            raise ValueError('duplicate')
        if roots:
            for cert in certs:
                if cert.subject != cert.issuer or not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                    raise ValueError('root')
                cert.verify_directly_issued_by(cert)
        return b''.join(c.public_bytes(serialization.Encoding.PEM) for c in certs)
    except Exception:
        raise TimestampCryptoError('TSA_CERTIFICATE_INPUT_INVALID') from None


def _run_command(directory: Path, command: list[str], *, code: str) -> None:
    # Do not copy the parent environment: no credentials, plugins, CA defaults,
    # preload libraries or caller OpenSSL configuration enter this process.
    env = {'LC_ALL': 'C', 'LANG': 'C', 'OPENSSL_CONF': str(directory/'openssl.cnf'),
           'HOME': str(directory)}
    try:
        completed = subprocess.run(
            [sys.executable, '-I', '-S', '-c', _LAUNCHER, *command],
            cwd=directory, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5, check=False, close_fds=True,
        )
        if completed.returncode != 0:
            raise TimestampCryptoError(code)
    except subprocess.TimeoutExpired:
        raise TimestampCryptoError('TSA_ENGINE_TIMEOUT') from None
    except OSError:
        raise TimestampCryptoError('TSA_ENGINE_UNAVAILABLE') from None


def _run(directory: Path, args: list[str], *, code: str) -> None:
    _run_command(directory, [str(ENGINE), *args], code=code)


def _evaluation_time(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise TimestampCryptoError('TSA_EVALUATION_TIME_INVALID')
    at = value.astimezone(timezone.utc)
    if not 0 <= at.timestamp() < 4102444800 or at.microsecond:
        raise TimestampCryptoError('TSA_EVALUATION_TIME_INVALID')
    return at


def _crls(value: bytes, at: datetime, maximum_age: int) -> bytes:
    _bytes(value, MAX_CERTIFICATE_BYTES)
    if type(maximum_age) is not int or not 1 <= maximum_age <= 604800:
        raise TimestampCryptoError('TSA_CRL_PROFILE_INVALID')
    blocks = _CRL_PEM.findall(value)
    if not blocks or len(blocks) > 8 or _CRL_PEM.sub(b'', value).strip():
        raise TimestampCryptoError('TSA_CRL_INPUT_INVALID')
    encoded = []
    try:
        for block in blocks:
            crl = x509.load_pem_x509_crl(block)
            if crl.signature_hash_algorithm is None or crl.signature_hash_algorithm.name not in {'sha256','sha384','sha512'}:
                raise TimestampCryptoError('TSA_CRL_ALGORITHM_UNSUPPORTED')
            for extension in crl.extensions:
                # This bounded profile does not implement delta/indirect or
                # partitioned CRLs, or unknown critical extension semantics.
                if extension.critical or isinstance(extension.value,(x509.DeltaCRLIndicator,x509.IssuingDistributionPoint)):
                    raise TimestampCryptoError('TSA_CRL_PROFILE_UNSUPPORTED')
            for entry in crl:
                for extension in entry.extensions:
                    if extension.critical or isinstance(extension.value,x509.CertificateIssuer):
                        raise TimestampCryptoError('TSA_CRL_PROFILE_UNSUPPORTED')
            if (crl.next_update_utc is None or crl.next_update_utc <= crl.last_update_utc
                    or not crl.last_update_utc <= at < crl.next_update_utc
                    or (at-crl.last_update_utc).total_seconds() > maximum_age):
                raise TimestampCryptoError('TSA_CRL_TIME_INVALID')
            encoded.append(crl.public_bytes(serialization.Encoding.PEM))
        if len(set(encoded)) != len(encoded):
            raise TimestampCryptoError('TSA_CRL_INPUT_INVALID')
        return b''.join(encoded)
    except TimestampCryptoError:
        raise
    except Exception:
        raise TimestampCryptoError('TSA_CRL_INPUT_INVALID') from None


def inspect_timestamp_crypto(*, response_der: bytes, request_der: bytes,
                             expected_imprint: str, expected_policy_oid: str,
                             roots_pem: bytes, intermediates_pem: bytes,
                             evaluation_time: datetime, crls_pem: bytes | None = None,
                             max_crl_age_seconds: int | None = None) -> TimestampCryptoObservation:
    """Verify crypto against explicit inputs; return observations, never ALLOW.

    The caller must independently establish the authority of trust, clock,
    expected imprint/policy and supplied request. This function cannot do so.
    Public certificate inputs are observations, not adopted trust anchors.
    Revocation is checked only with explicit CRLs and an explicit age profile;
    absent CRLs remain a stated gap, never an inferred good status.
    """
    _bytes(response_der, MAX_DER_BYTES)
    _bytes(request_der, MAX_DER_BYTES)
    if type(expected_imprint) is not str or not _HEX.fullmatch(expected_imprint):
        raise TimestampCryptoError('TSA_IMPRINT_INVALID')
    if type(expected_policy_oid) is not str or len(expected_policy_oid) > 160 or not _OID.fullmatch(expected_policy_oid):
        raise TimestampCryptoError('TSA_POLICY_INVALID')
    arcs = expected_policy_oid.split('.')
    if int(arcs[0]) < 2 and int(arcs[1]) > 39:
        raise TimestampCryptoError('TSA_POLICY_INVALID')
    at = _evaluation_time(evaluation_time)
    roots = _certificates(roots_pem, roots=True)
    intermediates = _certificates(intermediates_pem, roots=False)
    if (crls_pem is None) != (max_crl_age_seconds is None):
        raise TimestampCryptoError('TSA_CRL_PROFILE_INVALID')
    crls = _crls(crls_pem, at, max_crl_age_seconds) if crls_pem is not None else b''
    if not ENGINE.is_absolute() or not ENGINE.is_file():
        raise TimestampCryptoError('TSA_ENGINE_UNAVAILABLE')
    try:
        with tempfile.TemporaryDirectory(prefix='usbay-tsa-crypto-') as temporary:
            directory = Path(temporary)
            (directory/'empty-ca').mkdir(mode=0o700)
            inputs = {'response.der': response_der, 'request.der': request_der,
                      'roots.pem': roots+crls, 'intermediates.pem': intermediates,
                      'openssl.cnf': b''}
            for name, content in inputs.items():
                with (directory/name).open('xb') as file:
                    file.write(content)
                (directory/name).chmod(0o600)
            # Round-trip parsing uses native schemas, never human-readable text.
            _run(directory, ['ts','-reply','-in','response.der','-out','response.canonical.der'], code='TSA_RESPONSE_DER_INVALID')
            _run(directory, ['ts','-query','-in','request.der','-out','request.canonical.der'], code='TSA_REQUEST_DER_INVALID')
            if ((directory/'response.canonical.der').read_bytes() != response_der or
                    (directory/'request.canonical.der').read_bytes() != request_der):
                raise TimestampCryptoError('TSA_ENCODING_AMBIGUOUS')
            # A separate expected request binds SHA256 and TSTInfo.policy even
            # when the supplied original request did not request a policy.
            _run(directory, ['ts','-query','-digest',expected_imprint,'-sha256',
                             '-tspolicy',expected_policy_oid,'-no_nonce','-out','expected.der'], code='TSA_EXPECTED_REQUEST_FAILED')
            common = ['ts','-verify','-in','response.der','-CAfile','roots.pem',
                      '-CApath',str(directory/'empty-ca'),
                      '-CAstore',(directory/'roots.pem').as_uri(),
                      '-untrusted','intermediates.pem','-purpose','timestampsign',
                      '-x509_strict','-auth_level','2','-verify_depth','6',
                      '-attime',str(int(at.timestamp()))]
            if crls:
                common.append('-crl_check_all')
            _run(directory, [*common,'-queryfile','expected.der'], code='TSA_SIGNATURE_CHAIN_IMPRINT_POLICY_FAILED')
            _run(directory, [*common,'-queryfile','request.der'], code='TSA_SUPPLIED_REQUEST_MISMATCH')
    except TimestampCryptoError:
        raise
    except OSError:
        raise TimestampCryptoError('TSA_PRIVATE_WORKSPACE_FAILED') from None
    digest = lambda value: hashlib.sha256(value).hexdigest()
    observation = TimestampCryptoObservation(
        digest(response_der), digest(request_der), digest(roots_pem),
        digest(intermediates_pem), expected_imprint, expected_policy_oid, at.isoformat(),
    )
    if crls:
        observation = replace(observation,
            checks=observation.checks+('SIGNED_FULL_CHAIN_CRL_REVOCATION','CRL_TIME_AND_AGE'),
            remaining_requirements=tuple(v for v in observation.remaining_requirements if v!='SIGNED_REVOCATION_EVIDENCE'),
            crls_sha256=digest(crls_pem), max_crl_age_seconds=max_crl_age_seconds)
    return observation


def inspect_timestamp_temporal(*, max_age_seconds: int, clock_skew_seconds: int,
                               maximum_accuracy_seconds: int, **crypto_inputs) -> TimestampTemporalObservation:
    """Verify actual signature first, then read its signed time via native TS API.

    Explicit time/age parameters are NOT proof of a governed clock or profile.
    This native profile requires explicit accuracy and at most microsecond time
    precision. Unsupported precision fails closed rather than being truncated.
    """
    for value, lower, upper in ((max_age_seconds,1,86400),(clock_skew_seconds,0,60),(maximum_accuracy_seconds,0,60)):
        if type(value) is not int or not lower <= value <= upper:
            raise TimestampCryptoError('TSA_FRESHNESS_PROFILE_INVALID')
    observed = inspect_timestamp_crypto(**crypto_inputs)
    if not INFO_ENGINE.is_absolute() or not INFO_ENGINE.is_file():
        raise TimestampCryptoError('TSA_INFO_ENGINE_UNAVAILABLE')
    try:
        with tempfile.TemporaryDirectory(prefix='usbay-tsa-info-') as temporary:
            directory=Path(temporary)
            (directory/'response.der').write_bytes(crypto_inputs['response_der'])
            (directory/'openssl.cnf').write_bytes(b'')
            _run_command(directory,[str(INFO_ENGINE),'response.der','fields.json'],code='TSA_SIGNED_TIME_PROFILE_UNSUPPORTED')
            encoded=(directory/'fields.json').read_bytes()
            if len(encoded)>512:
                raise TimestampCryptoError('TSA_INFO_RESULT_INVALID')
            fields=json.loads(encoded)
            if type(fields) is not dict or set(fields)!={'schema','generalized_time','accuracy_us'} or type(fields['schema']) is not int or fields['schema']!=1:
                raise TimestampCryptoError('TSA_INFO_RESULT_INVALID')
            wire=fields['generalized_time'];accuracy=fields['accuracy_us']
            if (type(wire) is not str or not re.fullmatch(r'[0-9]{14}(?:\.[0-9]{1,6})?Z',wire) or
                    type(accuracy) is not int or not 0 <= accuracy <= 86400000000):
                raise TimestampCryptoError('TSA_INFO_RESULT_INVALID')
            generated=datetime.strptime(wire,'%Y%m%d%H%M%S.%fZ' if '.' in wire else '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
    except TimestampCryptoError:
        raise
    except Exception:
        raise TimestampCryptoError('TSA_INFO_RESULT_INVALID') from None
    if accuracy>maximum_accuracy_seconds*1000000:
        raise TimestampCryptoError('TSA_ACCURACY_EXCEEDED')
    at=_evaluation_time(crypto_inputs['evaluation_time'])
    uncertainty=timedelta(microseconds=accuracy)
    # Require the entire signed uncertainty interval to fit the freshness window.
    if generated-uncertainty < at-timedelta(seconds=max_age_seconds):
        raise TimestampCryptoError('TSA_TIMESTAMP_STALE')
    if generated+uncertainty > at+timedelta(seconds=clock_skew_seconds):
        raise TimestampCryptoError('TSA_TIMESTAMP_IN_FUTURE')
    remaining=tuple('GOVERNED_CLOCK_AND_FRESHNESS_PROFILE_ADOPTION' if v=='GOVERNED_CLOCK_AND_TIMESTAMP_FRESHNESS' else v for v in observed.remaining_requirements)
    return TimestampTemporalObservation(observed,generated.isoformat(),accuracy,max_age_seconds,
                                        clock_skew_seconds,maximum_accuracy_seconds,remaining)


def inspect_certificate_revocation(*, certificate_pem: bytes, intermediates_pem: bytes,
                                   roots_pem: bytes, crls_pem: bytes,
                                   evaluation_time: datetime,
                                   max_crl_age_seconds: int) -> CertificateRevocationObservation:
    """Verify a supplied certificate path and signed full-chain CRLs only.

    This generic primitive does not assert timestamp signer purpose or identify
    the signer of a separate response. Timestamp verification uses ts -verify
    with CRLs against the actual signer instead of trusting a supplied leaf.
    """
    at=_evaluation_time(evaluation_time)
    leaf=_certificates(certificate_pem,roots=False)
    if len(x509.load_pem_x509_certificates(leaf))!=1:
        raise TimestampCryptoError('TSA_CERTIFICATE_INPUT_INVALID')
    roots=_certificates(roots_pem,roots=True)
    intermediates=_certificates(intermediates_pem,roots=False)
    crls=_crls(crls_pem,at,max_crl_age_seconds)
    if not ENGINE.is_absolute() or not ENGINE.is_file():
        raise TimestampCryptoError('TSA_ENGINE_UNAVAILABLE')
    try:
        with tempfile.TemporaryDirectory(prefix='usbay-crl-check-') as temporary:
            directory=Path(temporary);(directory/'empty-ca').mkdir(mode=0o700)
            for name,value in {'leaf.pem':leaf,'roots.pem':roots+crls,
                               'intermediates.pem':intermediates,'openssl.cnf':b''}.items():
                (directory/name).write_bytes(value)
            _run(directory,['verify','-CAfile','roots.pem','-CApath',str(directory/'empty-ca'),
                            '-CAstore',(directory/'roots.pem').as_uri(),'-untrusted','intermediates.pem',
                            '-purpose','any','-auth_level','2','-x509_strict','-verify_depth','6',
                            '-attime',str(int(at.timestamp())),'-crl_check_all','leaf.pem'],
                 code='TSA_CERTIFICATE_REVOCATION_FAILED')
    except TimestampCryptoError:
        raise
    except OSError:
        raise TimestampCryptoError('TSA_PRIVATE_WORKSPACE_FAILED') from None
    digest=lambda value:hashlib.sha256(value).hexdigest()
    return CertificateRevocationObservation(digest(certificate_pem),digest(roots_pem),
        digest(intermediates_pem),digest(crls_pem),at.isoformat(),max_crl_age_seconds)
