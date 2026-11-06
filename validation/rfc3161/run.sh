#!/bin/sh
# Standalone candidate validation only; no application startup or network.
set -eu
task_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$task_root"
cc -std=c11 -Wall -Wextra -Werror -O2 -D_FORTIFY_SOURCE=2 -fPIE -pie \
  -Wl,-z,relro,-z,now audit/rfc3161_info.c -lcrypto -o audit/rfc3161_info
cc -std=c11 -Wall -Wextra -Werror -O2 -D_FORTIFY_SOURCE=2 -fPIE -pie \
  -Wl,-z,relro,-z,now validation/rfc3161/tests/make_memory_tsa_vectors.c -lcrypto -o validation/rfc3161/tests/make_memory_tsa_vectors
PYTHONPATH="$task_root/validation/rfc3161/tests:$task_root/python" python3 -m unittest \
  test_rfc3161_crypto_native test_rfc3161_temporal_revocation test_export_timestamp_v2 \
  test_rfc3161_projection test_public_x509_fixtures test_export_input_contract \
  test_export_intake_v2 -q
