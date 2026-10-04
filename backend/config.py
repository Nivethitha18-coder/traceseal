"""
TraceSeal Configuration Module
Offline-first document provenance & forensic attribution system.
"""

from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent

# DATA_DIR: where all persistent runtime data lives.
# Set TRACESEAL_DATA_DIR=/data in production (Railway volume mount).
# Falls back to BASE_DIR for local development (no change needed).
_data_dir_env = os.getenv("TRACESEAL_DATA_DIR", "")
DATA_DIR = Path(_data_dir_env) if _data_dir_env else BASE_DIR

STORAGE_DIR = DATA_DIR / "storage"
ENCRYPTED_DIR = STORAGE_DIR / "encrypted"
DECRYPTED_DIR = STORAGE_DIR / "decrypted"
LEAKED_DIR = STORAGE_DIR / "leaked"
EVIDENCE_DIR = STORAGE_DIR / "evidence"
LEDGER_DIR = DATA_DIR / "ledger_data"

LEDGER_FILE = LEDGER_DIR / "ledger.jsonl"
NODE_ALPHA_LEDGER_FILE = LEDGER_DIR / "node_alpha_ledger.jsonl"
NODE_BRAVO_REPLICA_FILE = LEDGER_DIR / "node_bravo_replica.jsonl"
NODE_CHARLIE_REPLICA_FILE = LEDGER_DIR / "node_charlie_replica.jsonl"
DB_PATH = DATA_DIR / "traceseal.db"
KEY_STORE_PATH = STORAGE_DIR / "key_vault.json"
AUTHORITY_KEY_PATH = STORAGE_DIR / "authority_keys.json"
VALIDATOR_KEY_PATH = STORAGE_DIR / "validator_keys.json"

JWT_SECRET = os.getenv("TRACESEAL_SECRET", "traceseal-offline-airgap-master-secret-key-2026-sih26237")
MASTER_ENCRYPTION_KEY = os.getenv("TRACESEAL_MASTER_KEY", os.getenv("ENCRYPTION_KEY", JWT_SECRET))
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

PQC_ENABLED = os.getenv("PQC_ENABLED", "true").lower() in ("true", "1", "yes")

STATIC_DIR = BASE_DIR / "frontend"


def ensure_directories():
    """Ensure all required local directories exist before application operations."""
    for directory in [
        STORAGE_DIR,
        ENCRYPTED_DIR,
        DECRYPTED_DIR,
        LEAKED_DIR,
        EVIDENCE_DIR,
        LEDGER_DIR,
    ]:
        directory.mkdir(parents=True, exist_ok=True)
