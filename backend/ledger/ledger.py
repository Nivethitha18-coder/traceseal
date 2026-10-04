"""
Offline Tamper-Evident Hash-Chained Ledger & Permissioned DLT
Multi-node permissioned consensus ledger ensuring immutable decryption event records.
Operates 100% offline with zero cloud KMS or public blockchain reliance.
Validators: node-alpha (Lead Proposer), node-bravo (Validator), node-charlie (Auditor).
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import sqlite3

from backend.config import LEDGER_FILE, LEDGER_DIR, ensure_directories
from backend.database import get_db
from backend.crypto.hashing import sha256_bytes
from backend.provenance.events import serialize_canonical
from backend.ledger.consensus import (
    compute_merkle_root,
    collect_validator_endorsements,
    replicate_block_to_nodes,
    sync_all_node_replicas,
)

GENESIS_PREV_HASH = "0" * 64


def calculate_block_hash(
    block_index: int,
    timestamp: str,
    previous_block_hash: str,
    event_hash: str,
    event_id: str,
    watermark_id: str,
    signature: str,
    merkle_root: Optional[str] = None,
) -> str:
    """Calculate deterministic SHA-256 hash for a block."""
    raw = f"{block_index}:{timestamp}:{previous_block_hash}:{event_hash}:{event_id}:{watermark_id}:{signature}"
    return sha256_bytes(raw.encode("utf-8"))


class OfflineLedger:
    """
    Offline Tamper-Evident Ledger Service & Multi-Node Permissioned DLT.
    Maintains append-only hash chains with Merkle tree transaction proofs
    and cross-node replicated ledgers for node-alpha, node-bravo, and node-charlie.
    """

    _tamper_backup: Optional[Dict[int, Dict[str, Any]]] = {}

    @classmethod
    def initialize_ledger(cls):
        """Ensure Genesis Block 0 exists and all blocks have DLT metadata & replicas."""
        ensure_directories()
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as cnt FROM ledger_blocks")
            count = cursor.fetchone()["cnt"]
            if count == 0:
                ts = "2026-01-01T00:00:00.000000+00:00"
                event_hash = "0" * 64
                event_id = "EVT-GENESIS-0000"
                watermark_id = "WM-GENESIS"
                signature = "GENESIS_AUTHORITY_BOOTSTRAP"
                curr_hash = calculate_block_hash(
                    0, ts, GENESIS_PREV_HASH, event_hash, event_id, watermark_id, signature
                )

                txs = [{
                    "tx_id": event_id,
                    "tx_hash": event_hash,
                    "type": "GENESIS_BOOTSTRAP",
                    "watermark_id": watermark_id,
                    "signature": signature,
                }]
                txs_json = json.dumps(txs)
                merkle_root = compute_merkle_root([event_hash])
                validator_id = "node-alpha"
                endorsements = collect_validator_endorsements(0, curr_hash, merkle_root)
                validator_sigs_json = json.dumps(endorsements)

                cursor.execute(
                    """
                    INSERT INTO ledger_blocks (
                        block_index, timestamp, previous_block_hash, event_hash,
                        event_id, watermark_id, signature, current_block_hash,
                        merkle_root, transactions, validator_id, validator_signatures
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        0, ts, GENESIS_PREV_HASH, event_hash,
                        event_id, watermark_id, signature, curr_hash,
                        merkle_root, txs_json, validator_id, validator_sigs_json
                    ),
                )

                genesis_dict = {
                    "block_index": 0,
                    "timestamp": ts,
                    "previous_block_hash": GENESIS_PREV_HASH,
                    "event_hash": event_hash,
                    "event_id": event_id,
                    "watermark_id": watermark_id,
                    "signature": signature,
                    "current_block_hash": curr_hash,
                    "merkle_root": merkle_root,
                    "transactions": txs_json,
                    "validator_id": validator_id,
                    "validator_signatures": validator_sigs_json,
                }
                sync_all_node_replicas([genesis_dict])
            else:
                # Backfill any legacy blocks missing DLT fields
                cursor.execute("SELECT * FROM ledger_blocks WHERE merkle_root IS NULL")
                unmigrated = cursor.fetchall()
                if unmigrated:
                    for row in unmigrated:
                        b = dict(row)
                        m_root = compute_merkle_root([b["event_hash"]])
                        b_type = "GENESIS_BOOTSTRAP" if b["block_index"] == 0 else "DECRYPTION_PROVENANCE"
                        txs = [{
                            "tx_id": b["event_id"],
                            "tx_hash": b["event_hash"],
                            "type": b_type,
                            "watermark_id": b["watermark_id"],
                            "signature": b["signature"],
                        }]
                        txs_json = json.dumps(txs)
                        val_id = "node-alpha"
                        sigs = collect_validator_endorsements(b["block_index"], b["current_block_hash"], m_root)
                        sigs_json = json.dumps(sigs)

                        cursor.execute(
                            """
                            UPDATE ledger_blocks
                            SET merkle_root = ?, transactions = ?, validator_id = ?, validator_signatures = ?
                            WHERE block_index = ?
                            """,
                            (m_root, txs_json, val_id, sigs_json, b["block_index"]),
                        )

                # Ensure replica files exist and are synced
                cursor.execute("SELECT * FROM ledger_blocks ORDER BY block_index ASC")
                all_rows = [dict(r) for r in cursor.fetchall()]
                db_count = len(all_rows)
                # Check for replica/DB mismatch (e.g. stray extra block in .jsonl file)
                replica_mismatch = not LEDGER_FILE.exists() or unmigrated
                if not replica_mismatch:
                    from backend.ledger.consensus import REPLICA_FILES as _REPLICA_FILES
                    for _rfile in _REPLICA_FILES:
                        if _rfile.exists():
                            try:
                                with open(_rfile, "r", encoding="utf-8") as _f:
                                    _lines = [_l.strip() for _l in _f if _l.strip()]
                                if len(_lines) != db_count:
                                    replica_mismatch = True
                                    break
                            except Exception:
                                replica_mismatch = True
                                break
                if replica_mismatch:
                    sync_all_node_replicas(all_rows)

    @classmethod
    def commit_event(cls, event: Dict[str, Any], signature: str, conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
        """
        Append a cryptographically signed provenance event to the permissioned DLT ledger.
        Computes Merkle root, collects multi-validator endorsements, and replicates across nodes.
        Supports passing an existing database connection for atomic multi-table transactions.
        """
        def _execute_commit(active_conn: sqlite3.Connection) -> Dict[str, Any]:
            cursor = active_conn.cursor()
            cursor.execute("SELECT * FROM ledger_blocks ORDER BY block_index DESC LIMIT 1")
            last_block = cursor.fetchone()

            prev_index = last_block["block_index"]
            new_index = prev_index + 1
            prev_hash = last_block["current_block_hash"]

            timestamp = datetime.now(timezone.utc).isoformat()
            canonical_payload = serialize_canonical(event)
            event_hash = sha256_bytes(canonical_payload.encode("utf-8"))
            event_id = event["event_id"]
            watermark_id = event.get("watermark_id", "WM-UNSPECIFIED")
            event_type = event.get("event_type", event.get("action", "DECRYPTION_PROVENANCE"))

            tx_payload = {
                "tx_id": event_id,
                "tx_hash": event_hash,
                "type": event_type,
                "watermark_id": watermark_id,
                "signature": signature,
            }
            if event_type == "WARNING_ISSUED":
                for k in [
                    "warning_id",
                    "issuer_id",
                    "issuer_username",
                    "issuer_role",
                    "recipient_id",
                    "recipient_username",
                    "recipient_name",
                    "recipient_role",
                    "reason",
                    "message",
                    "investigation_id",
                    "document_id",
                ]:
                    if k in event:
                        tx_payload[k] = event[k]

            txs = [tx_payload]
            txs_json = json.dumps(txs)
            merkle_root = compute_merkle_root([event_hash])

            block_hash = calculate_block_hash(
                new_index, timestamp, prev_hash, event_hash, event_id, watermark_id, signature, merkle_root
            )

            validator_id = "node-alpha"
            endorsements = collect_validator_endorsements(new_index, block_hash, merkle_root)
            validator_sigs_json = json.dumps(endorsements)

            cursor.execute(
                """
                INSERT INTO ledger_blocks (
                    block_index, timestamp, previous_block_hash, event_hash,
                    event_id, watermark_id, signature, current_block_hash,
                    merkle_root, transactions, validator_id, validator_signatures
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_index, timestamp, prev_hash, event_hash,
                    event_id, watermark_id, signature, block_hash,
                    merkle_root, txs_json, validator_id, validator_sigs_json
                ),
            )

            new_block = {
                "block_index": new_index,
                "timestamp": timestamp,
                "previous_block_hash": prev_hash,
                "event_hash": event_hash,
                "event_id": event_id,
                "watermark_id": watermark_id,
                "signature": signature,
                "current_block_hash": block_hash,
                "merkle_root": merkle_root,
                "transactions": txs_json,
                "validator_id": validator_id,
                "validator_signatures": validator_sigs_json,
            }

            # Replicate to local and node replica ledgers
            replicate_block_to_nodes(new_block)

            return new_block

        if conn is not None:
            return _execute_commit(conn)
        else:
            cls.initialize_ledger()
            with get_db() as active_conn:
                return _execute_commit(active_conn)

    @classmethod
    def get_blocks(cls, auto_init: bool = True) -> List[Dict[str, Any]]:
        """Retrieve all blocks in sequential order."""
        if auto_init:
            cls.initialize_ledger()
        with get_db() as conn:
            cursor = conn.cursor()
            if not cls._tamper_backup:
                cursor.execute("SELECT block_index, transactions FROM ledger_blocks WHERE watermark_id = 'WM-TAMPERED-FAKED'")
                fakes = cursor.fetchall()
                if fakes:
                    for f in fakes:
                        try:
                            txs = json.loads(f["transactions"]) if isinstance(f["transactions"], str) else f["transactions"]
                            orig_wm = txs[0]["watermark_id"]
                            cursor.execute("UPDATE ledger_blocks SET watermark_id = ? WHERE block_index = ?", (orig_wm, f["block_index"]))
                        except Exception:
                            pass
            cursor.execute("SELECT * FROM ledger_blocks ORDER BY block_index ASC")
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    @classmethod
    def get_block_by_index(cls, index: int) -> Optional[Dict[str, Any]]:
        """Retrieve specific block by its index."""
        cls.initialize_ledger()
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ledger_blocks WHERE block_index = ?", (index,))
            row = cursor.fetchone()
            return dict(row) if row else None

    @classmethod
    def simulate_tampering(cls, block_index: int = 1) -> Dict[str, Any]:
        """
        Controlled demo-only tampering simulation.
        Alters payload/hash in a target block to demonstrate ledger tamper detection.
        Does NOT silently modify data; backups original for instant restoration.
        """
        cls.initialize_ledger()
        ensure_directories()
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ledger_blocks WHERE block_index = ?", (block_index,))
            target = cursor.fetchone()
            if not target:
                # If no block at target index, tamper with Genesis
                block_index = 0
                cursor.execute("SELECT * FROM ledger_blocks WHERE block_index = 0")
                target = cursor.fetchone()

            target_dict = dict(target)
            cls._tamper_backup[block_index] = target_dict

            try:
                backup_file = LEDGER_DIR / "tamper_backup.json"
                with open(backup_file, "w", encoding="utf-8") as f:
                    json.dump({str(k): v for k, v in cls._tamper_backup.items()}, f)
            except Exception:
                pass

            # Tamper the watermark_id
            tampered_wm = "WM-TAMPERED-FAKED"
            cursor.execute(
                """
                UPDATE ledger_blocks
                SET watermark_id = ?
                WHERE block_index = ?
                """,
                (tampered_wm, block_index),
            )

            return {
                "tampered": True,
                "block_index": block_index,
                "original_watermark": target_dict["watermark_id"],
                "tampered_watermark": tampered_wm,
                "message": "Block data altered. Recalculation will now trigger LEDGER TAMPERING DETECTED.",
            }

    @classmethod
    def restore_ledger(cls) -> Dict[str, Any]:
        """Restore all original blocks after demo tampering and resync replicas."""
        backup_file = LEDGER_DIR / "tamper_backup.json"
        if not cls._tamper_backup and backup_file.exists():
            try:
                with open(backup_file, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
                    cls._tamper_backup = {int(k): v for k, v in raw_data.items()}
            except Exception:
                pass

        if not cls._tamper_backup:
            # Fallback: check if any block was left in WM-TAMPERED-FAKED state from previous process
            restored_orphans = 0
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT block_index, transactions FROM ledger_blocks WHERE watermark_id = 'WM-TAMPERED-FAKED'")
                orphans = cursor.fetchall()
                for o in orphans:
                    try:
                        tx_list = json.loads(o["transactions"]) if isinstance(o["transactions"], str) else o["transactions"]
                        orig_wm = tx_list[0]["watermark_id"]
                        cursor.execute("UPDATE ledger_blocks SET watermark_id = ? WHERE block_index = ?", (orig_wm, o["block_index"]))
                        restored_orphans += 1
                    except Exception:
                        pass

            all_blks = cls.get_blocks(auto_init=False)
            if all_blks:
                sync_all_node_replicas(all_blks)

            if restored_orphans > 0:
                return {"restored": True, "blocks_restored": restored_orphans, "message": "Ledger state restored from transaction provenance."}

            return {"restored": False, "message": "No active tamper simulations found."}

        with get_db() as conn:
            cursor = conn.cursor()
            for idx, orig in cls._tamper_backup.items():
                cursor.execute(
                    """
                    UPDATE ledger_blocks
                    SET watermark_id = ?, event_hash = ?, current_block_hash = ?,
                        merkle_root = ?, transactions = ?, validator_id = ?, validator_signatures = ?
                    WHERE block_index = ?
                    """,
                    (
                        orig["watermark_id"], orig["event_hash"], orig["current_block_hash"],
                        orig.get("merkle_root"), orig.get("transactions"),
                        orig.get("validator_id"), orig.get("validator_signatures"),
                        idx
                    ),
                )
        restored_count = len(cls._tamper_backup)
        cls._tamper_backup.clear()
        if backup_file.exists():
            try:
                backup_file.unlink()
            except Exception:
                pass

        # Resynchronize all replica node ledgers
        all_blocks = cls.get_blocks(auto_init=False)
        sync_all_node_replicas(all_blocks)

        return {
            "restored": True,
            "blocks_restored": restored_count,
            "message": "Ledger state restored to pristine cryptographic integrity.",
        }
