"""
Cryptographic Hashing Utilities
SHA-256 implementation for document integrity and canonical serialization.
"""

import hashlib
import json
from typing import Any, Dict


def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hex digest for given bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(filepath: str) -> str:
    """Compute SHA-256 hex digest for a file on disk."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    """
    Serialize dictionary deterministically to UTF-8 encoded bytes.
    Ensures identical byte sequence across platforms for cryptographic signing.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def hash_canonical_payload(payload: Dict[str, Any]) -> str:
    """Compute SHA-256 hex digest of canonically serialized payload."""
    return sha256_bytes(canonical_json_bytes(payload))
