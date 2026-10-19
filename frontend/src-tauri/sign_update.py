#!/usr/bin/env python3
"""
Sign a Tauri updater latest.json file with a minisign-compatible Ed25519 key.

Usage:
    python sign_update.py --private-key BASE64_PRIVATE_KEY --input latest.json.template --output latest.json

The script:
1. Reads the template JSON (with empty or placeholder signature)
2. Removes the "signature" field
3. Canonicalizes the remaining JSON (sorted keys, no whitespace)
4. Signs it with the Ed25519 private key
5. Writes the base64-encoded signature back into the JSON
6. Outputs the signed latest.json ready to upload as a GitHub release asset
"""

import argparse
import base64
import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption


def canonical_json(obj: dict) -> bytes:
    """Return canonical JSON bytes: sorted keys, compact separators."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sign a Tauri updater latest.json")
    parser.add_argument(
        "--private-key",
        required=True,
        help="Base64-encoded Ed25519 private key (minisign secret key)",
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to the latest.json template",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path for the signed latest.json output",
    )
    args = parser.parse_args()

    # Decode the private key
    try:
        priv_bytes = base64.b64decode(args.private_key)
    except Exception as exc:
        print(f"Error: invalid base64 private key: {exc}", file=sys.stderr)
        sys.exit(1)

    if len(priv_bytes) != 32:
        print(
            f"Error: private key must be 32 bytes, got {len(priv_bytes)}",
            file=sys.stderr,
        )
        sys.exit(1)

    private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)

    # Read the template
    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Remove the signature field before signing
    data.pop("signature", None)

    # Canonicalize and sign
    payload = canonical_json(data)
    signature = private_key.sign(payload)
    sig_b64 = base64.b64encode(signature).decode("ascii")

    # Re-insert the signature
    data["signature"] = sig_b64

    # Write the signed file (pretty-printed for readability)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    print(f"Signed {args.input} -> {args.output}")
    print(f"Signature: {sig_b64}")


if __name__ == "__main__":
    main()