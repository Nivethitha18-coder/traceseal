"""
Forensic Watermark Identifier Generator
Generates unique, cryptographically random, non-attributable watermark identifiers.
Does NOT encode recipient names directly into the watermark.
"""

import hmac
import hashlib
import secrets
import string
from typing import Optional


def generate_watermark_id(
    prefix: str = "FP-",
    length: int = 8,
    document_id: Optional[str] = None,
    recipient_user_id: Optional[str] = None,
    decryption_event_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> str:
    """
    Generate a cryptographically derived forensic fingerprint identifier.
    Uses HMAC-SHA256 with cryptographically random event material, session info, and nonce.
    Format: FP-XXXX-YYYY (e.g. FP-8A72-X91B)
    """
    alphabet = string.ascii_uppercase + string.digits
    nonce = secrets.token_hex(16)
    salt = secrets.token_bytes(32)

    event_material = (
        f"{document_id or 'DOC'}:{recipient_user_id or 'USR'}:"
        f"{decryption_event_id or 'EVT'}:{session_id or 'SES'}:{nonce}"
    )
    digest = hmac.new(salt, event_material.encode("utf-8"), hashlib.sha256).digest()

    part1 = "".join(alphabet[b % len(alphabet)] for b in digest[:4])
    part2 = "".join(alphabet[b % len(alphabet)] for b in digest[4:8])
    return f"{prefix}{part1}-{part2}"
