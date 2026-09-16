# USBAY removable-volume permission denial record

## Scope

This record adds one owner clarification to the consumed-run evidence. It does not modify the existing failure review and does not authorize any setting change, permission grant, retry, installation, key creation, USB write, cleanup, deletion, application restart, deployment, or production action.

## Authoritative references

- Consumed-run post-failure review: `attached_assets/usbay-consumed-run-post-failure-review.md`
- Consumed-run post-failure review SHA-256: `f79d9d1699354ce21556f2c6166f465bc3f6c25ddbe5d9c2e63aa0f92ba065ac`
- Authorized script: `attached_assets/usbay-age-preservation.zsh`
- Authorized script SHA-256: `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`

## Owner clarification

The owner reports:

> I selected “Don’t Allow” on the macOS removable-volume access prompt.

## Bounded conclusion

- Owner-reported permission choice: DENIED.
- Evidence source: direct owner report.
- Exact macOS privacy-setting state after the prompt: UNKNOWN because it was not inspected.
- Permission denial as the cause of the `diskutil` result: UNKNOWN.
- Exact failing `diskutil` subcommand: UNKNOWN.
- Internal status `124` cause: UNKNOWN.
- Process-group or descendant cleanup success: UNKNOWN.

This record supersedes only the prior `UNKNOWN` permission-outcome statement. It does not change the supported `PARTIAL` inference that failure occurred during initial USB discovery, and it does not convert correlation between the prompt and failure into proof of causation.

## Governance disposition

- One-run authorization: CONSUMED.
- Consumed run result: FAILED with overall script exit `1`.
- Removable-volume permission choice: owner-reported DENIED.
- Gate B: UNKNOWN and not validated.
- Retry: NOT AUTHORIZED.
- Permission change: NOT AUTHORIZED.
- Cleanup or deletion: NOT AUTHORIZED.

## Governance verdict

The owner-reported denial is recorded. It does not prove that denial caused the `diskutil` failure or that cleanup succeeded. No further operational action is authorized.