#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


REPO_ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str]) -> int:
    output_dir = Path(argv[1]) if len(argv) > 1 else REPO_ROOT / "governance"
    output_dir.mkdir(parents=True, exist_ok=True)
    private_path = output_dir / "policy_private.key"
    public_path = output_dir / "policy_public.key"

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    print(f"private_key={private_path}")
    print(f"public_key={public_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
