"""No external providers; guard real I/O boundaries during pure API calls."""
import builtins
import socket
import sqlite3
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from security import hydra_operational_contracts as c
from security import hydra_operational_provider as p
from tests.test_hydra_operational_contracts import material, encode, review

pytestmark = [pytest.mark.governance, pytest.mark.regression]


def forbid(*args, **kwargs):
    raise AssertionError('OPERATIONAL_IO_FORBIDDEN')


@pytest.fixture
def io_guard(monkeypatch):
    monkeypatch.setattr(builtins, 'open', forbid)
    monkeypatch.setattr(Path, 'open', forbid)
    monkeypatch.setattr(Path, 'mkdir', forbid)
    monkeypatch.setattr(socket, 'socket', forbid)
    monkeypatch.setattr(sqlite3, 'connect', forbid)
    monkeypatch.setattr(subprocess, 'Popen', forbid)


@pytest.mark.parametrize('operation', ['observe_current', 'reserve', 'read_preservation_evidence'])
def test_unavailable_provider_stops_before_io_or_input_inspection(io_guard, operation, caplog):
    class SensitiveInput:
        def __getattribute__(self, name):
            raise AssertionError('INPUT_INSPECTION_FORBIDDEN')
    provider = p.UnavailableOperationalProvider()
    before = dict(vars(provider))
    with pytest.raises(p.OperationalProviderUnavailable) as error:
        getattr(provider, operation)(SensitiveInput())
    assert str(error.value) == 'HYDRA_OPERATIONAL_PROVIDER_UNAVAILABLE'
    assert vars(provider) == before and caplog.text == ''


def test_valid_pure_apis_work_with_io_forbidden(material, io_guard):
    assert c.verify_evidence(encode(material['anchor']), material['context']).status == 'AUTHENTICITY_ONLY'
    result = review(material)
    assert result.state == 'STOPPED_RECONCILIATION_ONLY' and result.unresolved == c.UNRESOLVED


def test_malformed_pure_api_still_does_not_touch_io(material, io_guard):
    with pytest.raises(c.EvidenceInvalid): c.verify_evidence(b'{}', material['context'])
    with pytest.raises(c.EvidenceInvalid): c.validate_recovery_plan(b'{}', [],
        replace(material['context'], purpose=c.PLAN_PURPOSE))


def test_no_runtime_imports_activation_or_fallback():
    # Static dependency boundary complements guarded invocation. Existing runtime
    # code must not discover this provider or consume its review results.
    root = Path(__file__).resolve().parents[1]
    for directory in ('security', 'gateway', 'governance'):
        for source in (root/directory).glob('*.py'):
            if source.name.startswith('hydra_operational_'): continue
            text = source.read_text()
            assert 'hydra_operational_' not in text
    provider = (root/'security/hydra_operational_provider.py').read_text()
    assert 'os.getenv' not in provider and 'load_trust' not in provider
    assert 'entry_points' not in provider and 'reference_only' not in provider
