from copy import deepcopy

import pytest

from governance.tenant_enrollment_contracts import (
    EnrollmentDenied, EnrollmentGrant, EnrollmentPolicy, PolicyAdoption,
    CurrentHeadWitness, RevocationRecord, EnrollmentRequest, HeadAdvance,
    canonical, parse_json,
)
from tests.helpers.tenant_enrollment import synthetic_enrollment, NOW

MODELS = {"grant": EnrollmentGrant, "policy": EnrollmentPolicy, "adoption": PolicyAdoption,
          "h": CurrentHeadWitness, "w": CurrentHeadWitness, "revocations": RevocationRecord,
          "request": EnrollmentRequest}


@pytest.mark.parametrize("name", MODELS)
def test_closed_typed_schemas_roundtrip_and_reject_unsigned_extensions(name):
    f = synthetic_enrollment()
    p = f.inputs[name]["payload"]
    assert MODELS[name].from_payload(p).payload == p
    changed = deepcopy(p)
    changed["trusted"] = True
    with pytest.raises(EnrollmentDenied):
        MODELS[name].from_payload(changed)


@pytest.mark.parametrize("name", MODELS)
def test_every_protected_field_is_covered_by_signature(name):
    f = synthetic_enrollment()
    envelope = f.inputs[name]
    role = {"grant": "enrollment", "h": "H", "w": "W", "revocations": "revocation"}.get(name, name)
    f.trust.verify(envelope, MODELS[name], role, NOW)
    # Each field is mutated independently; preserve the original signature.
    for key in envelope["payload"]:
        changed = deepcopy(envelope)
        value = changed["payload"][key]
        changed["payload"][key] = (not value if type(value) is bool else value + 1 if type(value) is int
                                  else value + "-changed" if type(value) is str else None)
        with pytest.raises(EnrollmentDenied):
            f.trust.verify(changed, MODELS[name], role, NOW)


@pytest.mark.parametrize("raw", ['{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', 'not-json'])
def test_strict_json_rejects_ambiguous_or_nonfinite(raw):
    with pytest.raises(EnrollmentDenied):
        parse_json(raw)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 1.5, {1: "bad"}, (1, 2)])
def test_canonical_rejects_coercion(value):
    with pytest.raises(EnrollmentDenied):
        canonical(value)


@pytest.mark.parametrize("legacy", ["usbay.tenant_enrollment.grant.proposed.v1", "usbay.enrollment.grant.v2"])
def test_explicit_v3_does_not_reinterpret_legacy_grant(legacy):
    p = synthetic_enrollment().inputs["grant"]["payload"]
    p["schema_version"] = legacy
    with pytest.raises(EnrollmentDenied):
        EnrollmentGrant.from_payload(p)


def test_advance_schema_and_every_field_signature_binding():
    f = synthetic_enrollment()
    envelope = f.next_adoption()["advance"]
    f.trust.verify(envelope, HeadAdvance, "advance", NOW)
    for key in envelope["payload"]:
        changed = deepcopy(envelope)
        changed["payload"][key] = None
        with pytest.raises(EnrollmentDenied):
            f.trust.verify(changed, HeadAdvance, "advance", NOW)


from governance.tenant_enrollment_contracts import COMMON, FIELDS

MUTATION_OBJECTS = dict(MODELS, advance=HeadAdvance)
MUTATION_CASES = [(name, field) for name, model in MUTATION_OBJECTS.items()
                  for field in sorted(COMMON | FIELDS[model.kind])]


@pytest.mark.parametrize("name,field", MUTATION_CASES, ids=[name + "." + field for name, field in MUTATION_CASES])
def test_complete_protected_field_matrix_with_classified_rejection(name, field, record_property):
    f = synthetic_enrollment()
    envelope = f.next_adoption()["advance"] if name == "advance" else f.inputs[name]
    model = MUTATION_OBJECTS[name]
    role = {"grant": "enrollment", "h": "H", "w": "W", "revocations": "revocation"}.get(name, name)
    f.trust.verify(envelope, model, role, NOW)
    changed = deepcopy(envelope)
    value = changed["payload"][field]
    if type(value) is dict:
        changed["payload"][field] = dict(value, execution_authorized=True)
    elif type(value) is list:
        changed["payload"][field] = value + ["unapproved-extension"]
    elif type(value) is bool:
        changed["payload"][field] = not value
    elif type(value) is int:
        changed["payload"][field] = value + 1
    elif value.startswith("sha256:"):
        changed["payload"][field] = "sha256:" + ("a" if value[-1] != "a" else "b") * 64
    elif value.endswith("Z") and "T" in value:
        changed["payload"][field] = "2026-01-02T11:59:58Z"
    else:
        changed["payload"][field] = value + "-changed"
    assert {key for key in changed["payload"] if changed["payload"][key] != envelope["payload"][key]} == {field}
    try:
        model.from_payload(changed["payload"])
    except EnrollmentDenied:
        category = "SCHEMA_REJECTION"
    else:
        category = "SIGNATURE_OR_SCOPE_REJECTION"
    with pytest.raises(EnrollmentDenied) as rejected:
        f.trust.verify(changed, model, role, NOW)
    if category != "SCHEMA_REJECTION":
        category = "SIGNATURE_INTEGRITY_REJECTION" if str(rejected.value) == "SIGNATURE_INVALID" else "SCOPE_OR_VALIDITY_REJECTION"
    record_property("protected_object", name)
    record_property("protected_field", field)
    record_property("rejection_category", category)
    record_property("rejection_reason", str(rejected.value))


@pytest.mark.parametrize("name", MUTATION_OBJECTS)
@pytest.mark.parametrize("location", ["payload", "envelope"])
def test_unsigned_extensions_are_rejected_for_each_signed_object(name, location):
    f = synthetic_enrollment()
    envelope = deepcopy(f.next_adoption()["advance"] if name == "advance" else f.inputs[name])
    (envelope["payload"] if location == "payload" else envelope)["trusted"] = True
    role = {"grant": "enrollment", "h": "H", "w": "W", "revocations": "revocation"}.get(name, name)
    with pytest.raises(EnrollmentDenied):
        f.trust.verify(envelope, MUTATION_OBJECTS[name], role, NOW)


@pytest.mark.parametrize("name", ["policy", "grant", "adoption", "advance"])
def test_derived_object_identity_is_stable_but_full_version_hash_remains_signed(name):
    from governance.tenant_enrollment_contracts import object_id, object_version_hash
    f = synthetic_enrollment()
    envelope = f.next_adoption()["advance"] if name == "advance" else f.inputs[name]
    model = MUTATION_OBJECTS[name]
    p = deepcopy(envelope["payload"])
    original = object_id(model, p)
    assert original == object_id(model, model.from_payload(p).payload)
    assert original != object_version_hash(model, p)
    field = "revocation_reference" if name in ("policy", "grant") else "policy_hash"
    p[field] = "sha256:" + "f" * 64
    assert object_id(model, p) == original
    assert object_version_hash(model, p) != object_version_hash(model, envelope["payload"])
    role = "enrollment" if name == "grant" else name
    with pytest.raises(EnrollmentDenied, match="^SIGNATURE_INVALID$"):
        f.trust.verify(dict(payload=p, signature=envelope["signature"]), model, role, NOW)
    # An explicit new test signature binds ALL new bytes; hashing an ID is never
    # a replacement for that signature, trust, currentness or admission.
    f.trust.verify(f.sign(p), model, role, NOW)


@pytest.mark.parametrize("name", ["policy", "grant", "adoption", "advance"])
@pytest.mark.parametrize("field", ["tenant_id", "issuer_id", "registry_instance_reference"])
def test_object_identity_binds_signed_issuer_tenant_and_registry(name, field):
    from governance.tenant_enrollment_contracts import object_id, digest
    f = synthetic_enrollment()
    p = deepcopy((f.next_adoption()["advance"] if name == "advance" else f.inputs[name])["payload"])
    model = MUTATION_OBJECTS[name]
    before = object_id(model, p)
    p[field] = digest({"other-registry": 1}) if field.endswith("reference") else "other-identity"
    assert object_id(model, p) != before


@pytest.mark.parametrize("field,value", [("environment", "production"), ("purpose", "SEND_EMAIL"),
                                         ("policy_domain", "other-domain"), ("action", "OTHER")])
def test_invalid_object_identity_scope_is_rejected_not_wildcarded(field, value):
    from governance.tenant_enrollment_contracts import object_id
    p = synthetic_enrollment().inputs["grant"]["payload"]
    p[field] = value
    with pytest.raises(EnrollmentDenied):
        object_id(EnrollmentGrant, p)


def test_object_id_is_never_accepted_as_a_caller_supplied_protected_field():
    f = synthetic_enrollment()
    p = deepcopy(f.inputs["policy"]["payload"])
    p["object_id"] = "sha256:" + "f" * 64
    with pytest.raises(EnrollmentDenied, match="^SCHEMA_INVALID$"):
        EnrollmentPolicy.from_payload(p)


@pytest.mark.parametrize("field", ["kind", "target_id", "target_scope", "coverage", "effective_at",
                                  "scope.trust_domain", "scope.policy_domain", "scope.tenant_id",
                                  "scope.environment", "scope.purpose", "scope.registry_instance_reference"])
def test_nested_revocation_entry_mutation_is_protected(field, record_property):
    from tests.helpers.tenant_enrollment import object_revocation
    base = synthetic_enrollment()
    entry = object_revocation(EnrollmentPolicy, base.inputs["policy"]["payload"])
    f = synthetic_enrollment(private_keys=base.private, revocations=[entry])
    envelope = f.inputs["revocations"]
    f.trust.verify(envelope, RevocationRecord, "revocation", NOW)
    changed = deepcopy(envelope)
    target = changed["payload"]["revocations"][0]
    if field.startswith("scope."):
        target["target_scope"][field.split(".", 1)[1]] = "other"
    elif field == "target_scope":
        target[field] = {}
    elif field == "target_id":
        target[field] = "sha256:" + "f" * 64
    elif field == "effective_at":
        target[field] = "2026-01-02T12:00:01Z"
    else:
        target[field] = "other"
    with pytest.raises(EnrollmentDenied):
        f.trust.verify(changed, RevocationRecord, "revocation", NOW)
    record_property("protected_object", "revocation-entry")
    record_property("protected_field", field)
