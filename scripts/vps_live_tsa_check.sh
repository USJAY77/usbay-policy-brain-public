#!/usr/bin/env bash
set -u

status=0
tmp_dir="$(mktemp -d)"

cleanup() {
  if [ -n "${tmp_dir:-}" ] && [ -d "$tmp_dir" ]; then
    find "$tmp_dir" -mindepth 1 -maxdepth 1 -delete
    rmdir "$tmp_dir"
  fi
}
trap cleanup EXIT

pass() {
  echo "PASS $1"
}

fail() {
  echo "FAIL $1"
  status=1
}

if [ -z "${USBAY_TSA_URL:-}" ]; then
  fail "USBAY_TSA_URL=missing"
  exit 1
fi

hostname_value="$(hostname 2>/dev/null || true)"
if [ -n "$hostname_value" ]; then
  pass "hostname=$hostname_value"
else
  fail "hostname=unavailable"
fi

public_ip="$(curl -s --max-time 10 https://ifconfig.me 2>/dev/null || true)"
if [ -n "$public_ip" ]; then
  pass "public_ip=$public_ip"
else
  fail "public_ip=unavailable"
fi

if command -v openssl >/dev/null 2>&1; then
  pass "openssl_present"
else
  fail "openssl_missing"
  exit 1
fi

if command -v python3 >/dev/null 2>&1; then
  pass "python3_present"
else
  fail "python3_missing"
  exit 1
fi

# RFC3161 TSA endpoints require POST/binary timestamp requests.
# Do not use curl HEAD/GET health checks here.

if USBAY_TSA_URL="$USBAY_TSA_URL" bash scripts/test_live_tsa_openssl.sh >"$tmp_dir/openssl.out" 2>"$tmp_dir/openssl.err"; then
  pass "openssl_rfc3161_response"
else
  fail "openssl_rfc3161_no_response"
fi

if USBAY_TSA_URL="$USBAY_TSA_URL" PYTHONPATH="$(pwd)" python3 scripts/test_live_tsa.py >"$tmp_dir/python.out" 2>"$tmp_dir/python.err"; then
  pass "python_rfc3161_response"
else
  fail "python_rfc3161_no_response"
fi

exit "$status"
