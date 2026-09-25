"""
ReconAI Ingest - Forensic Evidence Hasher & Chain of Custody
Ensures strictly read-only integrity verification via SHA-256, SHA-1, MD5, and CRC-32.
"""

import os
import hashlib
import zlib
from typing import Dict, Any

CHUNK_SIZE = 64 * 1024  # 64 KB block streaming

def compute_evidence_hash(image_path: str) -> Dict[str, Any]:
    """
    Computes cryptographic hashes (SHA-256, SHA-1, MD5, CRC-32) of the disk image
    without loading the full file into RAM, ensuring strictly read-only access.
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Evidence file not found: {image_path}")

    sha256_hash = hashlib.sha256()
    sha1_hash = hashlib.sha1()
    md5_hash = hashlib.md5()
    crc_val = 0
    total_bytes = 0
    block_count = 0

    # A folder of loose evidence files is sealed as one unit: files are hashed
    # in sorted-name order so the combined digest is reproducible.
    if os.path.isdir(image_path):
        source_files = [
            os.path.join(image_path, f) for f in sorted(os.listdir(image_path))
            if not f.startswith('.') and os.path.isfile(os.path.join(image_path, f))
        ]
        display_name = f"Evidence folder ({len(source_files)} files)"
    else:
        source_files = [image_path]
        display_name = os.path.basename(image_path)

    # Strictly read-only binary mode ('rb')
    for source in source_files:
        with open(source, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256_hash.update(chunk)
                sha1_hash.update(chunk)
                md5_hash.update(chunk)
                crc_val = zlib.crc32(chunk, crc_val)
                total_bytes += len(chunk)
                block_count += 1

    from datetime import datetime
    timestamp_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    return {
        "image_path": os.path.abspath(image_path),
        "filename": display_name,
        "size_bytes": total_bytes,
        "size_mb": round(total_bytes / (1024 * 1024), 2),
        "formatted_size": f"{total_bytes:,} bytes",
        "timestamp_utc": timestamp_utc,
        "primary_seal": sha256_hash.hexdigest(),
        "legacy_hashes": {
            "sha1": sha1_hash.hexdigest(),
            "md5": md5_hash.hexdigest()
        },
        "corruption_check": f"{crc_val & 0xFFFFFFFF:08X}",
        "sha256": sha256_hash.hexdigest(),
        "sha1": sha1_hash.hexdigest(),
        "md5": md5_hash.hexdigest(),
        "crc32": f"{crc_val & 0xFFFFFFFF:08X}",
        "block_count": block_count
    }

def verify_evidence_integrity(image_path: str, reference_sha256: str) -> bool:
    """Verifies that the disk image has not been altered since initial ingestion."""
    current = compute_evidence_hash(image_path)
    return current["sha256"].lower() == reference_sha256.lower()
