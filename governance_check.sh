#!/bin/bash
set -u

FAILURES=0
CURRENT_POLICY_HASH="$(python3 - <<'PY'
from runtime import policy_validator
print(policy_validator.compute_policy_hash())
PY
)"

echo "USBAY GOVERNANCE HEALTH CHECK"
echo "================================"

mkdir -p audit/logs

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
    python3 runtime/policy_validator.py
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

    openssl dgst -sha256 -verify approvals/approver1_public_key.pem \
      -signature approvals/policy-approval-1.sig \
      approvals/policy-approval-1.json || {
        echo "SIG1 FAILED"
        FAILURES=$((FAILURES + 1))
      }

    openssl dgst -sha256 -verify approvals/approver2_public_key.pem \
      -signature approvals/policy-approval-2.sig \
      approvals/policy-approval-2.json || {
        echo "SIG2 FAILED"
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
