#!/usr/bin/env bash
set -u

tmp_dir="$(mktemp -d)"
message_file="$tmp_dir/message.bin"
request_file="$tmp_dir/request.tsq"
response_file="$tmp_dir/response.tsr"
request_created=false
response_present=false
mode=live

cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

printf '%s' 'USBAY_TIMESTAMP_TEST' > "$message_file"

if [ -n "${USBAY_TSA_URL:-}" ]; then
  if openssl ts -query -data "$message_file" -sha256 -cert -out "$request_file" 2>/dev/null; then
    request_created=true
  fi

  if [ "$request_created" = true ]; then
    if curl \
      --silent \
      --show-error \
      --fail \
      --output "$response_file" \
      --header "Content-Type: application/timestamp-query" \
      --data-binary "@$request_file" \
      "$USBAY_TSA_URL" 2>/dev/null; then
      if [ -s "$response_file" ]; then
        response_present=true
      fi
    fi
  fi
fi

echo "tsa_url=${USBAY_TSA_URL:-}"
echo "request_created=$request_created"
echo "response_present=$response_present"
echo "mode=$mode"

if [ -z "${USBAY_TSA_URL:-}" ] || [ "$request_created" != true ] || [ "$response_present" != true ]; then
  exit 1
fi

