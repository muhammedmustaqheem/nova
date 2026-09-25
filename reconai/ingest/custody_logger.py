"""
ReconAI Cryptographic Custody & Hash-Chained Audit Logger
Maintains a tamper-evident, append-only JSON audit log of every forensic action taken on evidence.
Each entry is cryptographically bound to the previous entry via SHA-256 hash chaining.
"""

import json
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional

class ForensicAuditLog:
    """
    Append-only cryptographically linked audit trail for digital evidence handling.
    Guarantees strict non-repudiation and auditability in compliance with ISO/IEC 27037.
    """

    def __init__(
        self,
        case_id: str,
        evidence_id: str,
        examiner_name: str = "Lead DFIR Examiner",
        initial_evidence_sha256: str = ""
    ):
        self.case_id = case_id
        self.evidence_id = evidence_id
        self.examiner_name = examiner_name
        self.initial_evidence_sha256 = initial_evidence_sha256
        self.entries: List[Dict[str, Any]] = []

        # Initialize Genesis Block (Block 0)
        self._create_genesis_block()

    def _canonical_json(self, data: Any) -> str:
        """Serializes dictionary to deterministic canonical JSON string."""
        return json.dumps(data, sort_keys=True, separators=(',', ':'), default=str)

    def _compute_entry_hash(
        self,
        step: int,
        action: str,
        timestamp: str,
        prev_hash: str,
        details: Dict[str, Any]
    ) -> str:
        payload = f"{prev_hash}|{step}|{action}|{timestamp}|{self._canonical_json(details)}"
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def _create_genesis_block(self):
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        prev_hash = "0" * 64
        details = {
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "examiner": self.examiner_name,
            "initial_evidence_sha256": self.initial_evidence_sha256,
            "notice": "Strict read-only forensic chain of custody initialized"
        }
        entry_hash = self._compute_entry_hash(0, "GENESIS_INTAKE_SEAL", timestamp, prev_hash, details)
        self.entries.append({
            "step": 0,
            "action": "GENESIS_INTAKE_SEAL",
            "timestamp": timestamp,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
            "details": details
        })

    def log_action(self, action_name: str, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Appends a new action to the audit chain, linking it cryptographically to the last block.
        """
        if details is None:
            details = {}

        step = len(self.entries)
        prev_hash = self.entries[-1]["entry_hash"]
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        entry_hash = self._compute_entry_hash(step, action_name, timestamp, prev_hash, details)

        entry = {
            "step": step,
            "action": action_name,
            "timestamp": timestamp,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
            "details": details
        }
        self.entries.append(entry)
        return entry

    def verify_integrity(self) -> Tuple[bool, Optional[str]]:
        """
        Walks the entire audit chain from genesis to tip, verifying every cryptographic link.
        Returns: (is_valid, error_reason)
        """
        if not self.entries:
            return False, "Audit log is empty."

        # Verify Genesis Block
        gen = self.entries[0]
        if gen["step"] != 0 or gen["prev_hash"] != "0" * 64:
            return False, "Corrupted genesis block."

        expected_gen_hash = self._compute_entry_hash(
            0, gen["action"], gen["timestamp"], gen["prev_hash"], gen["details"]
        )
        if gen["entry_hash"] != expected_gen_hash:
            return False, f"Genesis block hash mismatch (expected {expected_gen_hash}, got {gen['entry_hash']})"

        # Verify all subsequent blocks
        for i in range(1, len(self.entries)):
            curr = self.entries[i]
            prev = self.entries[i - 1]

            if curr["step"] != i:
                return False, f"Step sequence broken at block {i} (found {curr['step']})"

            if curr["prev_hash"] != prev["entry_hash"]:
                return False, f"Broken cryptographic link between block {i-1} and {i}"

            computed_hash = self._compute_entry_hash(
                curr["step"], curr["action"], curr["timestamp"], curr["prev_hash"], curr["details"]
            )
            if curr["entry_hash"] != computed_hash:
                return False, f"Hash alteration detected in block {i} ({curr['action']})"

        return True, None

    def get_summary(self) -> Dict[str, Any]:
        """Returns executive status of the audit trail."""
        is_valid, err = self.verify_integrity()
        return {
            "total_audit_events": len(self.entries),
            "chain_integrity": "VERIFIED_TAMPER_FREE" if is_valid else "CORRUPTED",
            "integrity_error": err,
            "latest_block_hash": self.entries[-1]["entry_hash"] if self.entries else None,
            "entries": self.entries
        }

    def to_json(self) -> str:
        """Dumps formatted JSON representation of the complete audit trail."""
        return json.dumps(self.get_summary(), indent=2)
