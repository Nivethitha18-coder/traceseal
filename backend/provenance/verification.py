"""
Cryptographic Provenance Verification Service
Verifies digital signatures and document integrity matches for provenance events.
"""

from typing import Dict, Any, Tuple, Union
from backend.crypto.pqc import pqc_provider
from backend.crypto.hashing import sha256_bytes
from backend.provenance.events import serialize_canonical


def verify_event_signature(
    event: Union[Dict[str, Any], str],
    signature_hex: str,
    public_key_hex: str,
) -> Tuple[bool, str]:
    """
    Verify digital signature for canonical provenance event.
    Accepts either pre-serialized canonical string or event dictionary.
    Returns: (is_valid, signed_payload_hash)
    """
    if isinstance(event, str):
        canonical_str = event
    else:
        canonical_str = serialize_canonical(event)
    payload_bytes = canonical_str.encode("utf-8")
    payload_hash = sha256_bytes(payload_bytes)

    valid = pqc_provider.verify(public_key_hex, payload_bytes, signature_hex)
    return valid, payload_hash
