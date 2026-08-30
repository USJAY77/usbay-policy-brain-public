"""USBAY governance boundary modules.

Governance scope: typed interfaces and validation helpers for evidence,
chronology, timestamp, and trust-policy control planes.
Fail-closed expectation: callers must treat any returned failure as a deny.
Sensitive-data handling: modules must not log secrets, private keys, raw
approval material, or raw nonce values.
"""

