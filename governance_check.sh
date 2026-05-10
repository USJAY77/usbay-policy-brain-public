#!/bin/bash
set -u

FAILURES=0
CURRENT_POLICY_HASH="$(python3 - <<'PY'
import runtime.policy_validator as policy_validator
print(policy_validator.compute_policy_hash())
PY
)"
APPROVAL_MODE="${USBAY_GOVERNANCE_APPROVAL_MODE:-production}"

echo "USBAY GOVERNANCE HEALTH CHECK"
echo "================================"

mkdir -p audit/logs

if [ "$APPROVAL_MODE" = "development" ] || [ "$APPROVAL_MODE" = "ci" ] || [ "$APPROVAL_MODE" = "dev" ] || [ "$APPROVAL_MODE" = "test" ]; then
    echo "Development approval mode active: using NON_PRODUCTION CI_ONLY approval artifacts"
    cp approvals/dev-ci/policy-approval-1.json approvals/policy-approval-1.json
    cp approvals/dev-ci/policy-approval-1.sig approvals/policy-approval-1.sig
    cp approvals/dev-ci/approver1_public_key.pem approvals/approver1_public_key.pem
    cp approvals/dev-ci/policy-approval-2.json approvals/policy-approval-2.json
    cp approvals/dev-ci/policy-approval-2.sig approvals/policy-approval-2.sig
    cp approvals/dev-ci/approver2_public_key.pem approvals/approver2_public_key.pem
fi

run_check() {
    local name="$1"
    shift

    echo ""
    echo "$name"

    if "$@"; then
        echo "✓ $name"
    else
        echo "✗ $name"
        echo "DEBUG: failed check: $name"
        FAILURES=$((FAILURES + 1))
    fi
}

debug_artifact_state() {
    echo "DEBUG: approvals directory"
    ls -la approvals/
    echo "DEBUG: policy directory"
    ls -la policy/
    echo "DEBUG: runtime directory"
    ls -la runtime/
    echo "DEBUG: approval artifact hashes"
    sha256sum approvals/policy-approval-1.json
    sha256sum approvals/policy-approval-2.json
}

debug_signature_verification() {
    echo "DEBUG: policy validator output start"
    if [ "$APPROVAL_MODE" = "development" ] || [ "$APPROVAL_MODE" = "ci" ] || [ "$APPROVAL_MODE" = "dev" ] || [ "$APPROVAL_MODE" = "test" ]; then
        python3 - <<'PY'
import runtime.policy_validator as policy_validator
policy_validator.validate_required_files()
policy_validator.validate_policy_json()
policy_validator.validate_sha256()
policy_validator.validate_signature()
metadata = policy_validator.load_policy_metadata()
policy_validator.validate_approval_artifacts(
    policy_hash=metadata["policy_hash"],
    policy_version=metadata["policy_version"],
)
print("GOVERNANCE_DEVELOPMENT_VALIDATION_OK")
PY
    else
        python3 runtime/policy_validator.py
    fi
    local rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "DEBUG: policy validator exit=0"
    else
        echo "DEBUG: policy validator exit=$rc"
        echo "VALIDATOR FAILED"
        FAILURES=$((FAILURES + 1))
        echo "DEBUG: policy validator output end"
        return 1
    fi
    echo "DEBUG: policy validator output end"
}

runtime_starts() {
    debug_artifact_state
    debug_signature_verification || return 1
    if [ "$APPROVAL_MODE" = "development" ] || [ "$APPROVAL_MODE" = "ci" ] || [ "$APPROVAL_MODE" = "dev" ] || [ "$APPROVAL_MODE" = "test" ]; then
        return 0
    fi
    if ! USBAY_EXPECTED_POLICY_HASH="$CURRENT_POLICY_HASH" python3 runtime/enforcement_gateway.py; then
        echo "ENFORCEMENT FAILED"
        FAILURES=$((FAILURES + 1))
        return 1
    fi
}

private_key_detection() {
    touch private_key.pem
    USBAY_EXPECTED_POLICY_HASH="$CURRENT_POLICY_HASH" python3 runtime/enforcement_gateway.py >/dev/null 2>&1
    local rc=$?
    rm -f private_key.pem
    [ "$rc" -ne 0 ]
}

audit_writeability_detection() {
    chmod a-w audit/logs
    USBAY_EXPECTED_POLICY_HASH="$CURRENT_POLICY_HASH" python3 runtime/enforcement_gateway.py >/dev/null 2>&1
    local rc=$?
    chmod a+w audit/logs
    [ "$rc" -ne 0 ]
}

policy_tamper_detection() {
    echo "DEBUG: policy.json hash:"
    sha256sum policy/policy.json || true

    echo "DEBUG: approval-1.json hash:"
    sha256sum approvals/policy-approval-1.json || true

    echo "DEBUG: approval-2.json hash:"
    sha256sum approvals/policy-approval-2.json || true

    echo "DEBUG: verifying signatures..."

    python3 - <<'PY' || {
import runtime.policy_validator as policy_validator
metadata = policy_validator.load_policy_metadata()
policy_validator.validate_approval_artifacts(
    policy_hash=metadata["policy_hash"],
    policy_version=metadata["policy_version"],
)
print("APPROVAL_SIGNATURES_VALID")
PY
        echo "APPROVAL SIGNATURE VALIDATION FAILED"
        FAILURES=$((FAILURES + 1))
      }

    cp policy/policy.json policy/policy_backup.json
    printf '\nBREAK_TEST\n' >> policy/policy.json

    USBAY_EXPECTED_POLICY_HASH="$CURRENT_POLICY_HASH" python3 runtime/enforcement_gateway.py >/dev/null 2>&1
    local rc=$?

    mv policy/policy_backup.json policy/policy.json
    sha256sum policy/policy.json | awk '{print $1}' > policy/policy.sha256

    [ "$rc" -ne 0 ]
}

run_check "1. Runtime startup test" runtime_starts
run_check "2. Private key detection test" private_key_detection
run_check "3. Audit writeability test" audit_writeability_detection
run_check "4. Policy integrity test" policy_tamper_detection

echo ""
echo "Governance check complete"

if [ "$FAILURES" -gt 0 ]; then
    echo "Governance check FAILED ($FAILURES failures)"
    exit 1
fi

echo "Governance check PASSED"
