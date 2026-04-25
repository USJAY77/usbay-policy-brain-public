#!/bin/bash

echo "==== USBAY RUNTIME TEST ===="

BASE_URL="http://127.0.0.1:8000/execute"

echo ""
echo "---- ALLOW TEST ----"

ALLOW_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST $BASE_URL \
  -H "Content-Type: application/json" \
  -d '{"action":"read","user_id":"u1","device":"laptop-1"}')

echo "HTTP $ALLOW_CODE"

if [ "$ALLOW_CODE" == "200" ]; then
  echo "ALLOW OK"
elif [ "$ALLOW_CODE" == "500" ]; then
  echo "ALLOW FAIL-CLOSED (expected if policy/signature issue)"
else
  echo "ALLOW UNEXPECTED"
fi


echo ""
echo "---- BLOCK TEST ----"

BLOCK_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST $BASE_URL \
  -H "Content-Type: application/json" \
  -d '{"action":"delete","user_id":"u1","device":"laptop-1"}')

echo "HTTP $BLOCK_CODE"

if [ "$BLOCK_CODE" == "403" ]; then
  echo "BLOCK OK"
elif [ "$BLOCK_CODE" == "500" ]; then
  echo "BLOCK FAIL-CLOSED"
else
  echo "BLOCK UNEXPECTED"
fi


echo ""
echo "---- AUDIT LOG ----"

if [ -f audit/audit_log.jsonl ]; then
  tail -n 5 audit/audit_log.jsonl
else
  echo "No audit log found"
fi

echo ""
echo "==== TEST COMPLETE ===="
