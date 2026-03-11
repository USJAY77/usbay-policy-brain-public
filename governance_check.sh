#!/bin/bash

echo "USBAY GOVERNANCE HEALTH CHECK"
echo "================================"

# 1. Runtime startup test
echo ""
echo "1. Runtime startup test"
python3 runtime/enforcement_gateway.py >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Runtime start OK"
else
    echo "✗ Runtime start FAILED"
fi

# 2. Private key detection test
echo ""
echo "2. Private key detection test"

touch private_key.pem

python3 runtime/enforcement_gateway.py >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "✓ Private key detection OK"
else
    echo "✗ Private key detection FAILED"
fi

rm -f private_key.pem

# 3. Audit log protection test
echo ""
echo "3. Audit writeability test"

chmod a-w audit/logs

python3 runtime/enforcement_gateway.py >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "✓ Audit writeability block OK"
else
    echo "✗ Audit writeability block FAILED"
fi

chmod a+w audit/logs

# 4. Policy tamper detection test
echo ""
echo "4. Policy integrity test"

cp policy/policy.json policy/policy_backup.json

echo "BREAK_TEST" >> policy/policy.json

python3 runtime/enforcement_gateway.py >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "✓ Policy tamper detection OK"
else
    echo "✗ Policy tamper detection FAILED"
fi

mv policy/policy_backup.json policy/policy.json

# regenerate policy hash
shasum -a 256 policy/policy.json | awk '{print $1}' > policy/policy.sha256

echo ""
echo "Governance check complete"
