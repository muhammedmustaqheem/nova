"""
ReconAI Ransomware & Anti-Forensics Detection Engine
Detects malicious evidence tampering indicators:
1. High-entropy regions (>= 7.85 bits/byte) unassociated with known compressed headers (suspected ransomware ciphers).
2. Known ransomware file extensions and extortion ransom note text patterns.
3. Disk sanitization & wiping patterns (long contiguous runs of 0x00, 0xFF, or wipe patterns).
4. Signature-to-extension masquerading (anti-forensics hiding executables behind doc/image extensions).
Outputs 'Evidence Tampering Indicators' with plain-language investigative explanations.
"""

import os
import re
import math
from typing import List, Dict, Any

RANSOMWARE_EXTENSIONS = {
    ".locked", ".crypto", ".enc", ".crypt", ".crypted", ".ransom",
    ".locky", ".wannacry", ".ryuk", ".revil", ".blackcat", ".darkside"
}

RANSOM_NOTE_PATTERNS = [
    re.compile(r"YOUR FILES (?:HAVE BEEN|ARE) ENCRYPTED", re.IGNORECASE),
    re.compile(r"HOW TO (?:DECRYPT|RESTORE) (?:YOUR )?FILES", re.IGNORECASE),
    re.compile(r"DECRYPT(?:ION)?_INSTRUCTION", re.IGNORECASE),
    re.compile(r"All your data has been locked", re.IGNORECASE),
    re.compile(r"to decrypt your files, send (?:bitcoin|btc|monero)", re.IGNORECASE),
    re.compile(r"download tor browser and visit", re.IGNORECASE)
]

KNOWN_COMPRESSED_HEADERS = [
    b"\x1f\x8b",          # GZIP
    b"PK\x03\x04",        # ZIP
    b"7z\xbc\xaf\x27\x1c",# 7-Zip
    b"BZh",               # BZIP2
    b"\x89PNG\r\n\x1a\n", # PNG
    b"\xFF\xD8\xFF",      # JPEG
    b"Rar!\x1a\x07"       # RAR
]

def calculate_entropy(data: bytes) -> float:
    """Computes Shannon entropy (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts: Dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def detect_tampering_indicators(
    image_path: str,
    recovered_items: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Executes deep bitstream and artifact scanning to identify anti-forensic tampering.
    """
    indicators: List[Dict[str, Any]] = []

    # --- 1. ARTIFACT-LEVEL CHECKS ---
    for item in recovered_items:
        fn = item.get("filename", "")
        ext = (item.get("extension") or os.path.splitext(fn)[1]).lower()
        data = item.get("data", b"")
        preview = item.get("content_preview", "")

        # A. Ransomware Extension Check
        if ext in RANSOMWARE_EXTENSIONS:
            indicators.append({
                "indicator_type": "RANSOMWARE_ENCRYPTED_FILE",
                "severity": "CRITICAL",
                "target_artifact": fn,
                "offset": item.get("offset"),
                "plain_language_explanation": (
                    f"Artifact '{fn}' carries known ransomware extension '{ext}'. "
                    f"The file payload has been symmetrically encrypted by an extortionist payload."
                )
            })

        # B. Ransom Note Detection
        if any(p.search(preview) for p in RANSOM_NOTE_PATTERNS) or "DECRYPT" in fn.upper() or "HOW_TO" in fn.upper():
            indicators.append({
                "indicator_type": "EXTORTION_RANSOM_NOTE",
                "severity": "CRITICAL",
                "target_artifact": fn,
                "offset": item.get("offset"),
                "plain_language_explanation": (
                    f"Ransom demand note detected in '{fn}'. Contains explicit extortion demands, "
                    f"cryptocurrency payment instructions, or Tor negotiation portal URLs."
                )
            })

        # C. Signature-to-Extension Mismatch (Anti-Forensics Masquerading)
        if ext in [".pdf", ".jpg", ".png", ".txt", ".docx"]:
            if data.startswith(b"MZ"):
                indicators.append({
                    "indicator_type": "EXTENSION_SPOOFING_MASQUERADE",
                    "severity": "HIGH",
                    "target_artifact": fn,
                    "offset": item.get("offset"),
                    "plain_language_explanation": (
                        f"Anti-Forensic Masquerading: File is named '{fn}' (claiming to be {ext.upper()}), "
                        f"but the raw byte payload contains a Windows PE Executable (MZ header). "
                        f"This technique is used by threat actors to disguise malware as innocent documents."
                    )
                })
            elif ext == ".pdf" and data.startswith(b"PK\x03\x04"):
                indicators.append({
                    "indicator_type": "EXTENSION_SPOOFING_MASQUERADE",
                    "severity": "MEDIUM",
                    "target_artifact": fn,
                    "offset": item.get("offset"),
                    "plain_language_explanation": (
                        f"Extension Mismatch: Artifact '{fn}' claims to be a PDF, but byte inspection "
                        f"reveals a ZIP compressed archive structure."
                    )
                })

    # --- 2. BITSTREAM-LEVEL SECTOR CHECKS ---
    if os.path.exists(image_path):
        with open(image_path, 'rb') as f:
            raw_bytes = f.read()

        total_len = len(raw_bytes)
        cluster_size = 4096

        # A. High-Entropy Unallocated Region Scan (Encrypted Chunks)
        step = 16384  # 16KB sampling strides
        pos = 0
        high_entropy_blocks = []

        while pos + cluster_size <= total_len:
            chunk = raw_bytes[pos:pos + cluster_size]
            ent = calculate_entropy(chunk)

            # High entropy (> 7.88 bits/byte) without known compression header
            if ent >= 7.88:
                has_comp_hdr = any(chunk.startswith(hdr) for hdr in KNOWN_COMPRESSED_HEADERS)
                if not has_comp_hdr:
                    high_entropy_blocks.append((pos, ent))
                    pos += cluster_size * 4
                    continue
            pos += step

        if high_entropy_blocks:
            sample_offset, sample_ent = high_entropy_blocks[0]
            indicators.append({
                "indicator_type": "HIGH_ENTROPY_CIPHER_REGION",
                "severity": "HIGH",
                "target_artifact": f"Disk Sector Offset {sample_offset}",
                "offset": sample_offset,
                "plain_language_explanation": (
                    f"High-Entropy Cipher Block Detected: Disk region at offset {sample_offset} exhibits "
                    f"near-maximum entropy ({sample_ent:.2f} bits/byte) with zero standard compression headers. "
                    f"Indicates a cryptographic cipher stream or ransomware-encrypted drive sector."
                )
            })

        # B. Disk Sanitization & Wiping Pattern Scan
        wipe_patterns = [
            (b"\x00" * 4096, "Zero-Fill Disk Sanitization (NIST SP 800-88 Clear)"),
            (b"\xFF" * 4096, "Flash Memory Solid-State Bulk Erase Pattern (0xFF Fill)"),
            (b"\x55" * 4096, "DoD 5220.22-M Multi-Pass Overwrite Sequence (0x55 Alternate Fill)")
        ]

        for pattern, desc in wipe_patterns:
            wipe_idx = raw_bytes.find(pattern)
            if wipe_idx != -1:
                # Count length of contiguous wipe
                run_len = len(pattern)
                while wipe_idx + run_len + 4096 <= total_len and raw_bytes[wipe_idx + run_len:wipe_idx + run_len + 4096] == pattern:
                    run_len += 4096

                if run_len >= 8192:
                    indicators.append({
                        "indicator_type": "DISK_WIPING_SANITIZATION",
                        "severity": "HIGH",
                        "target_artifact": f"Storage Sectors at Offset {wipe_idx}",
                        "offset": wipe_idx,
                        "plain_language_explanation": (
                            f"Anti-Forensic Wiping Detected: Contiguous {run_len:,} byte sanitized block "
                            f"at offset {wipe_idx}. Pattern matches '{desc}'. "
                            f"Suggests intentional data destruction to impede forensic investigation."
                        )
                    })
                    break  # One indicator per wipe type is sufficient

    return {
        "tampering_detected": len(indicators) > 0,
        "total_indicators": len(indicators),
        "indicators": indicators,
        "tampering_summary": (
            f"Detected {len(indicators)} Evidence Tampering Indicator(s). Threat indicators include "
            f"{', '.join(set(i['indicator_type'] for i in indicators)) if indicators else 'none'}."
        )
    }
