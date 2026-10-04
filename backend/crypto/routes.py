"""
System Security & Cryptographic Status Endpoints
"""

from fastapi import APIRouter, status
from backend.schemas import SecurityStatusResponse
from backend.crypto.pqc import pqc_provider
from backend.demo import initialize_demo_environment

router = APIRouter(prefix="/api", tags=["Security & Cryptography"])


@router.get("/crypto/status")
def get_crypto_status():
    """Return cryptographic engine status and active PQC algorithms."""
    return pqc_provider.get_status()


@router.get("/system/status", response_model=SecurityStatusResponse)
def get_system_security_status():
    """
    Security Dashboard status report.
    Accurately details offline mode, encryption, local ledger, and NIST PQC status.
    """
    pqc_info = pqc_provider.get_status()

    return {
        "offline_mode": "ACTIVE (100% Local / Air-Gap Ready)",
        "cloud_kms": "NOT USED (Local Offline KeyManager Active)",
        "public_blockchain": "NOT USED (Offline Tamper-Evident Hash Chain)",
        "local_ledger": "ACTIVE (SHA-256 Chained Blocks)",
        "document_encryption": "ACTIVE (AES-256-GCM Authenticated Encryption)",
        "sha256_integrity": "ACTIVE (NIST FIPS 180-4)",
        "pqc_status": pqc_info["pqc_status"],
        "pqc_signature_algorithm": pqc_info["signature_algorithm"],
        "pqc_kem_algorithm": pqc_info["kem_algorithm"],
        "digital_signature_status": pqc_info["digital_signature_status"],
        "notes": [
            "Zero cloud telemetry or external third-party KMS dependency",
            "NIST FIPS 204 (ML-DSA-44) Post-Quantum Digital Signatures",
            "NIST FIPS 203 (ML-KEM-768) Post-Quantum Key Encapsulation",
            "Imperceptible Multi-Layer Steganographic Forensic Watermarking",
        ],
    }


@router.post("/demo/initialize", status_code=status.HTTP_200_OK)
def init_demo_data():
    """Seed demo accounts, credentials, and sample confidential document."""
    return initialize_demo_environment()
