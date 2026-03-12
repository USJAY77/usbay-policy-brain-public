#!/bin/bash
set -u

FAILURES=0

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
        FAILURES=$((FAILURES + 1))
    fi
}

runtime_starts() {
    python3 runtime/enforcement_gateway.py >/dev/null 2>&1
}

private_key_detection() {
    touch private_key.pem
    python3 runtime/enforcement_gateway.py >/dev/null 2>&1
    local rc=$?
    rm -f private_key.pem
    [ "$rc" -ne 0 ]
}

audit_writeability_detection() {
    chmod a-w audit/logs
    python3 runtime/enforcement_gateway.py >/dev/null 2>&1
    local rc=$?
    chmod a+w audit/logs
    [ "$rc" -ne 0 ]
}

policy_tamper_detection() {
    cp policy/policy.json policy/policy_backup.json
    printf '\nBREAK_TEST\n' >> policy/policy.json

    python3 runtime/enforcement_gateway.py >/dev/null 2>&1
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

if [ "$FAILURES" -ne 0 ]; then
    echo "Governance check FAILED ($FAILURES failing check(s))"
    exit 1
fi

echo "Governance check PASSED"
exit 0
