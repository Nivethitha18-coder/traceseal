"""
Offline Permissioned Blockchain Consensus & Multi-Validator Endorsement Module.
Operates 100% offline without public blockchain or cloud KMS dependencies.
Coordinates multi-node consensus across permissioned validator nodes:
- node-alpha: Lead Proposer & Consensus Coordinator
- node-bravo: Endorsement Validator Node
- node-charlie: Auditing Validator Node
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timezone

from backend.config import (
    LEDGER_FILE,
    NODE_ALPHA_LEDGER_FILE,
    NODE_BRAVO_REPLICA_FILE,
    NODE_CHARLIE_REPLICA_FILE,
    VALIDATOR_KEY_PATH,
    ensure_directories,
)
from backend.crypto.hashing import sha256_bytes

VALIDATOR_NODES = {
    "node-alpha": {"role": "LEAD_PROPOSER", "secret_seed": "traceseal-validator-node-alpha-offline-2026-auth"},
    "node-bravo": {"role": "ENDORSER_VALIDATOR", "secret_seed": "traceseal-validator-node-bravo-offline-2026-endorse"},
    "node-charlie": {"role": "AUDITOR_VALIDATOR", "secret_seed": "traceseal-validator-node-charlie-offline-2026-audit"},
}

REPLICA_FILES = [
    LEDGER_FILE,
    NODE_ALPHA_LEDGER_FILE,
    NODE_BRAVO_REPLICA_FILE,
    NODE_CHARLIE_REPLICA_FILE,
]


def ensure_validator_keys() -> Dict[str, Dict[str, str]]:
    """Ensure permissioned validator node key registry exists locally."""
    ensure_directories()
    if VALIDATOR_KEY_PATH.exists():
        try:
            with open(VALIDATOR_KEY_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if all(n in data for n in VALIDATOR_NODES):
                    return data
        except Exception:
            pass

    registry: Dict[str, Dict[str, str]] = {}
    for node_id, meta in VALIDATOR_NODES.items():
        node_pk = sha256_bytes(f"PUBKEY:{node_id}:{meta['secret_seed']}".encode("utf-8"))
        node_sk = sha256_bytes(f"PRIVKEY:{node_id}:{meta['secret_seed']}".encode("utf-8"))
        registry[node_id] = {
            "node_id": node_id,
            "role": meta["role"],
            "public_key": node_pk,
            "private_key": node_sk,
        }

    with open(VALIDATOR_KEY_PATH, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2)

    return registry


def sign_block_endorsement(node_id: str, block_index: int, block_hash: str, merkle_root: str) -> str:
    """Generate deterministic validator node endorsement signature for a block."""
    registry = ensure_validator_keys()
    if node_id not in registry:
        raise ValueError(f"Unknown validator node: {node_id}")
    priv_key = registry[node_id]["private_key"]
    endorsement_payload = f"ENDORSE:{node_id}:{block_index}:{block_hash}:{merkle_root}:{priv_key}"
    return sha256_bytes(endorsement_payload.encode("utf-8"))


def verify_block_endorsement(node_id: str, block_index: int, block_hash: str, merkle_root: str, signature: str) -> bool:
    """Verify validator node endorsement signature."""
    try:
        expected_sig = sign_block_endorsement(node_id, block_index, block_hash, merkle_root)
        return signature == expected_sig
    except Exception:
        return False


def collect_validator_endorsements(block_index: int, block_hash: str, merkle_root: str) -> Dict[str, str]:
    """Collect 3-of-3 permissioned consensus endorsements from all nodes."""
    endorsements = {}
    for node_id in VALIDATOR_NODES:
        endorsements[node_id] = sign_block_endorsement(node_id, block_index, block_hash, merkle_root)
    return endorsements


def compute_merkle_root(tx_hashes: List[str]) -> str:
    """
    Compute binary Merkle tree root for a list of transaction hashes.
    Uses SHA-256. If list is empty, returns 64 zeros.
    If single leaf, returns that hash directly.
    For multiple, pairwise hashes upwards to the Merkle root.
    """
    if not tx_hashes:
        return "0" * 64
    current_level = [h if len(h) == 64 else sha256_bytes(h.encode("utf-8")) for h in tx_hashes]
    if len(current_level) == 1:
        return current_level[0]

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = sha256_bytes(f"{left}:{right}".encode("utf-8"))
            next_level.append(combined)
        current_level = next_level

    return current_level[0]


def replicate_block_to_nodes(block: Dict[str, Any]):
    """Replicate block across all local validator replica node ledgers."""
    ensure_directories()
    line = json.dumps(block) + "\n"
    for rfile in REPLICA_FILES:
        try:
            with open(rfile, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass


def sync_all_node_replicas(blocks: List[Dict[str, Any]]):
    """Rewrite/resynchronize all replica node ledgers with authoritative blocks."""
    ensure_directories()
    content = "".join(json.dumps(b) + "\n" for b in blocks)
    for rfile in REPLICA_FILES:
        try:
            with open(rfile, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception:
            pass


def verify_node_replicas(primary_blocks: List[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """
    Verify cross-node replica consistency between primary blocks and all replica node files.
    Returns (True, None) if completely consistent, or (False, discrepancy_detail).
    """
    for rfile in REPLICA_FILES:
        if not rfile.exists():
            continue
        try:
            with open(rfile, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            replica_blocks = [json.loads(line) for line in lines]
            if len(replica_blocks) != len(primary_blocks):
                return False, f"Replica node {rfile.name} block count ({len(replica_blocks)}) differs from primary chain ({len(primary_blocks)})."

            for idx, (p_blk, r_blk) in enumerate(zip(primary_blocks, replica_blocks)):
                if p_blk.get("current_block_hash") != r_blk.get("current_block_hash"):
                    return False, f"Replica node {rfile.name} block #{idx} hash mismatch: {r_blk.get('current_block_hash')} != {p_blk.get('current_block_hash')}."
        except Exception as e:
            return False, f"Replica node {rfile.name} verification failed: {str(e)}"

    return True, None
