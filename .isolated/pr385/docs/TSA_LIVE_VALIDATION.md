# TSA Live Validation

USBAY supports live RFC3161 timestamp authority checks for audit anchoring. Local Mac runs may fail because of local DNS, firewall, TLS, or sandbox network restrictions. Treat local failures as inconclusive unless the failure is a deterministic dependency or code error.

Final live proof must be run from a VPS or another clean server network path.

## VPS Check

```bash
ssh <user>@<server-ip>
git clone <repo>
cd usbay-policy-brain
pip3 install -r requirements.txt || pip3 install rfc3161ng pyasn1 requests
USBAY_TSA_URL="https://timestamp.sectigo.com" bash scripts/vps_live_tsa_check.sh
```

The VPS check prints only `PASS` or `FAIL` lines. It does not print TSA token contents, private keys, or sensitive payloads.

Required pass conditions:
- `USBAY_TSA_URL` is set.
- `openssl` is installed.
- `python3` is installed.
- The TSA endpoint responds to a header request.
- The OpenSSL RFC3161 request receives a response.
- The Python `rfc3161ng` live client receives a timestamp token.

If any required check fails, the script exits nonzero.
