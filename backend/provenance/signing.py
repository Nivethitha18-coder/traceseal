"""
Cryptographic Provenance Signing Service
Digitally signs canonical decryption events using NIST-standardized ML-DSA.
"""

from typing import Dict, Any, Tuple
from backend.crypto.pqc import pqc_provider
from backend.provenance.events import serialize_canonical


def sign_provenance_event(
    event: Dict[str, Any],
    private_key_hex: str = None,
    public_key_hex: str = None,
) -> Tuple[str, str, str, str]:
    """
    Deterministically serialize canonical event and digitally sign with ML-DSA-44.
    Returns: (canonical_payload_str, signature_hex, algorithm, public_key_ref)
    """
    canonical_payload = serialize_canonical(event)
    payload_bytes = canonical_payload.encode("utf-8")

    if private_key_hex:
        signature = pqc_provider.sign(private_key_hex, payload_bytes)
        pubkey = public_key_hex or "recipient_key"
    else:
        signature = pqc_provider.sign_with_authority(payload_bytes)
        pubkey = pqc_provider.get_authority_public_key()

    algorithm = pqc_provider.sig_algorithm_name
    return canonical_payload, signature, algorithm, pubkey
