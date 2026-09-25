#!/usr/bin/env python3
"""
ReconAI - Synthetic Evidence Disk Image Generator
Generates a realistic 64MB raw forensic disk image (FAT32 structure + unallocated space)
containing intact files, filesystem-deleted files, fragmented files, and corrupted archives.
Accompanied by a ground_truth.json manifest for automated scoring & verification.
"""

import os
import json
import struct
import zlib
import zipfile
import io
import hashlib
from datetime import datetime

IMAGE_SIZE = 64 * 1024 * 1024  # 64 MB
SECTOR_SIZE = 512
CLUSTER_SIZE = 4096  # 8 sectors per cluster
RESERVED_SECTORS = 32
SECTORS_PER_FAT = 512
FAT_COUNT = 2

def create_minimal_valid_png(width=100, height=100, color=(0, 242, 254)) -> bytes:
    """Generate a minimal valid PNG file in pure Python (no PIL required)."""
    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', crc)

    header = b'\x89PNG\r\n\x1a\n'
    ihdr = chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
    # Raw scanlines: 0 filter byte followed by RGB
    raw_data = bytearray()
    for _ in range(height):
        raw_data.append(0)  # Filter type 0 (None)
        raw_data.extend(bytes(color) * width)
    idat = chunk(b'IDAT', zlib.compress(bytes(raw_data)))
    iend = chunk(b'IEND', b'')
    return header + ihdr + idat + iend

def create_minimal_valid_jpeg() -> bytes:
    """Generate a minimal valid 1x1 JPEG image in pure Python."""
    return bytes([
        0xFF, 0xD8,  # SOI
        0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01,
        0x00, 0x48, 0x00, 0x48, 0x00, 0x00,  # APP0 (JFIF)
        0xFF, 0xDB, 0x00, 0x43, 0x00,  # DQT
        *([8] * 64),
        0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00,  # SOF0
        0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,  # DHT
        0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x7F,  # SOS + data
        0xFF, 0xD9   # EOI
    ])

def create_rich_jpeg(text_label="RECONAI EVIDENCE") -> bytes:
    """Generate a slightly larger valid JPEG image with EXIF metadata for forensics."""
    base = create_minimal_valid_jpeg()
    # Insert custom comment marker (COM)
    com_data = f"Forensic Artifact: {text_label} | Case: #2026-X7".encode('utf-8')
    com_chunk = b'\xFF\xFE' + struct.pack('>H', len(com_data) + 2) + com_data
    # Insert right after SOI
    return base[:2] + com_chunk + base[2:]

def create_valid_pdf(title="CONFIDENTIAL FINANCIAL AUDIT", body="ReconAI Evidence Document") -> bytes:
    """Generate a valid, parseable PDF document."""
    pdf_content = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length {len(body) + 120} >>
stream
BT
/F1 18 Tf
50 720 Td
({title}) Tj
/F1 12 Tf
0 -30 Td
({body}) Tj
0 -20 Td
(TRANSACTION: Offshore wire transfer \$4,250,000 USD to Wallet 0x742d35Cc6634C0532925a3b844Bc454e4438f44e) Tj
0 -20 Td
(SUSPECT: Unknown Operator - High Priority Fraud Investigation) Tj
ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000224 00000 n 
0000000450 00000 n 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
535
%%EOF
"""
    return pdf_content.encode('utf-8')

def build_fat_boot_sector() -> bytearray:
    """Build a standard FAT32 Boot Parameter Block (BPB)."""
    boot = bytearray(SECTOR_SIZE)
    # Jump instruction
    boot[0:3] = b'\xEB\x58\x90'
    # OEM Name
    boot[3:11] = b'RECON_AI'
    # Bytes per sector: 512
    struct.pack_into('<H', boot, 11, SECTOR_SIZE)
    # Sectors per cluster: 8 (4096 bytes)
    boot[13] = 8
    # Reserved sectors: 32
    struct.pack_into('<H', boot, 14, RESERVED_SECTORS)
    # Number of FATs: 2
    boot[16] = FAT_COUNT
    # Root entries: 0 (FAT32)
    struct.pack_into('<H', boot, 17, 0)
    # Media descriptor: 0xF8 (Fixed disk)
    boot[21] = 0xF8
    # Sectors per FAT (FAT32): 512
    struct.pack_into('<I', boot, 36, SECTORS_PER_FAT)
    # Root cluster: 2
    struct.pack_into('<I', boot, 44, 2)
    # Volume label
    boot[71:82] = b'EVIDENCE_01'
    # File system type
    boot[82:90] = b'FAT32   '
    # Boot signature: 0x55AA
    boot[510] = 0x55
    boot[511] = 0xAA
    return boot

def format_fat_dir_entry(name_8_3: str, is_deleted: bool, start_cluster: int, file_size: int, is_dir=False) -> bytes:
    """Format a 32-byte FAT directory entry. If is_deleted, first byte is 0xE5."""
    parts = name_8_3.upper().split('.')
    name = parts[0].ljust(8)[:8]
    ext = parts[1].ljust(3)[:3] if len(parts) > 1 else '   '
    entry = bytearray(32)
    entry[0:8] = name.encode('ascii')
    entry[8:11] = ext.encode('ascii')
    if is_deleted:
        entry[0] = 0xE5  # Standard FAT deletion marker
    entry[11] = 0x10 if is_dir else 0x20  # Archive or Directory attribute
    # Time/Date: arbitrary valid timestamp
    struct.pack_into('<H', entry, 14, 0x6E21)  # Time: 13:49:02
    struct.pack_into('<H', entry, 16, 0x5D39)  # Date: 2026-09-25
    # High 16-bits of cluster
    struct.pack_into('<H', entry, 20, (start_cluster >> 16) & 0xFFFF)
    # Low 16-bits of cluster
    struct.pack_into('<H', entry, 26, start_cluster & 0xFFFF)
    # File size
    struct.pack_into('<I', entry, 28, file_size)
    return bytes(entry)

def generate_evidence_disk(output_raw: str, output_gt: str):
    print(f"[*] Allocating {IMAGE_SIZE // (1024*1024)}MB virtual raw disk image...")
    disk = bytearray(IMAGE_SIZE)

    # 1. Write Boot Sector
    boot = build_fat_boot_sector()
    disk[0:SECTOR_SIZE] = boot

    # Root Directory Sector Calculation
    fat_size_bytes = SECTORS_PER_FAT * SECTOR_SIZE
    data_region_offset = (RESERVED_SECTORS + FAT_COUNT * SECTORS_PER_FAT) * SECTOR_SIZE
    # Cluster 2 is at data_region_offset
    def cluster_to_offset(c):
        return data_region_offset + (c - 2) * CLUSTER_SIZE

    ground_truth = {
        "case_id": "RECONAI-HACKATHON-2026",
        "created_at": datetime.utcnow().isoformat() + "Z",
        "disk_size_bytes": IMAGE_SIZE,
        "files": []
    }

    dir_entries = bytearray()
    curr_cluster = 3  # Root dir is at cluster 2

    # --- Evidence Item 1: Filesystem-Deleted Sensitive Financial PDF ---
    pdf_bytes = create_valid_pdf("OFFSHORE FINANCIAL TRANSFER", "Audit finding: unauthorized transfer of $4,250,000 to 0x742d35Cc6634C0532925a3b844Bc454e4438f44e.")
    pdf_cluster = curr_cluster
    pdf_offset = cluster_to_offset(pdf_cluster)
    disk[pdf_offset:pdf_offset + len(pdf_bytes)] = pdf_bytes
    dir_entries.extend(format_fat_dir_entry("FINANCE.PDF", is_deleted=True, start_cluster=pdf_cluster, file_size=len(pdf_bytes)))
    ground_truth["files"].append({
        "filename": "FINANCE.PDF",
        "recovery_method": "filesystem_undelete",
        "category": "Financial & Invoices",
        "expected_integrity": "INTACT",
        "expected_quality_score": 100,
        "is_fragmented": False,
        "is_deleted": True,
        "size_bytes": len(pdf_bytes),
        "sha256": hashlib.sha256(pdf_bytes).hexdigest(),
        "offset": pdf_offset,
        "description": "Deleted audit document detailing offshore crypto wire transfer."
    })
    curr_cluster += (len(pdf_bytes) + CLUSTER_SIZE - 1) // CLUSTER_SIZE

    # --- Evidence Item 2: Filesystem-Deleted Credentials (.env) ---
    env_content = (
        "# LEAKED SECRETS AND DATABASE ACCESS\n"
        "DATABASE_URL=postgresql://postgres:SuperSecretAdminPass2026!@10.0.4.15:5432/core_banking\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "JWT_SECRET=reconai_ultra_secure_hash_secret_key_8849\n"
        "STRIPE_API_KEY=sk_test_mock_StripeKeyForFraudInvestigation\n"
    ).encode('utf-8')
    env_cluster = curr_cluster
    env_offset = cluster_to_offset(env_cluster)
    disk[env_offset:env_offset + len(env_content)] = env_content
    dir_entries.extend(format_fat_dir_entry("CREDS.ENV", is_deleted=True, start_cluster=env_cluster, file_size=len(env_content)))
    ground_truth["files"].append({
        "filename": "CREDS.ENV",
        "recovery_method": "filesystem_undelete",
        "category": "Credentials & Secrets",
        "expected_integrity": "INTACT",
        "expected_quality_score": 100,
        "is_fragmented": False,
        "is_deleted": True,
        "size_bytes": len(env_content),
        "sha256": hashlib.sha256(env_content).hexdigest(),
        "offset": env_offset,
        "description": "Environment variable file containing live AWS and database credentials."
    })
    curr_cluster += (len(env_content) + CLUSTER_SIZE - 1) // CLUSTER_SIZE

    # --- Evidence Item 3: Intact Evidence JPEG Photo (Recorded in directory) ---
    jpg_bytes = create_rich_jpeg("CRIME SCENE WEAPON RECOVERY")
    jpg_cluster = curr_cluster
    jpg_offset = cluster_to_offset(jpg_cluster)
    disk[jpg_offset:jpg_offset + len(jpg_bytes)] = jpg_bytes
    dir_entries.extend(format_fat_dir_entry("WEAPON.JPG", is_deleted=False, start_cluster=jpg_cluster, file_size=len(jpg_bytes)))
    ground_truth["files"].append({
        "filename": "WEAPON.JPG",
        "recovery_method": "filesystem_intact",
        "category": "Media & Communications",
        "expected_integrity": "INTACT",
        "expected_quality_score": 100,
        "is_fragmented": False,
        "is_deleted": False,
        "size_bytes": len(jpg_bytes),
        "sha256": hashlib.sha256(jpg_bytes).hexdigest(),
        "offset": jpg_offset,
        "description": "Active camera image of physical evidence."
    })
    curr_cluster += (len(jpg_bytes) + CLUSTER_SIZE - 1) // CLUSTER_SIZE

    # --- Evidence Item 4: Fragmented JPEG Photo (Split across non-contiguous clusters) ---
    # We will split a valid JPEG into 2 fragments across clusters separated by 8 empty clusters!
    frag_source = create_rich_jpeg("SUSPECT PASSPORT SCAN")
    split_point = len(frag_source) // 2
    frag1 = frag_source[:split_point]
    frag2 = frag_source[split_point:]

    frag1_cluster = curr_cluster
    frag1_offset = cluster_to_offset(frag1_cluster)
    disk[frag1_offset:frag1_offset + len(frag1)] = frag1

    curr_cluster += 3  # Gap of clusters simulating disk fragmentation!
    frag2_cluster = curr_cluster
    frag2_offset = cluster_to_offset(frag2_cluster)
    disk[frag2_offset:frag2_offset + len(frag2)] = frag2

    ground_truth["files"].append({
        "filename": "PASSPORT_REASSEMBLED.JPG",
        "recovery_method": "fragment_reassembly",
        "category": "Confidential Documents",
        "expected_integrity": "INTACT",
        "expected_quality_score": 95,
        "is_fragmented": True,
        "fragments": [
            {"offset": frag1_offset, "size": len(frag1), "type": "header"},
            {"offset": frag2_offset, "size": len(frag2), "type": "trailer"}
        ],
        "size_bytes": len(frag_source),
        "sha256": hashlib.sha256(frag_source).hexdigest(),
        "description": "Fragmented suspect passport photo split into 2 non-contiguous sectors."
    })
    curr_cluster += 3

    # --- Evidence Item 5: Unallocated Signature-Carved PNG Seal (No directory entry) ---
    png_bytes = create_minimal_valid_png(64, 64, color=(255, 69, 0))
    png_cluster = curr_cluster
    png_offset = cluster_to_offset(png_cluster)
    disk[png_offset:png_offset + len(png_bytes)] = png_bytes
    # No directory entry added! This mimics a file whose metadata was completely wiped.
    ground_truth["files"].append({
        "filename": f"carved_png_{png_offset}.png",
        "recovery_method": "signature_carving",
        "category": "Media & Communications",
        "expected_integrity": "INTACT",
        "expected_quality_score": 100,
        "is_fragmented": False,
        "is_deleted": True,
        "size_bytes": len(png_bytes),
        "sha256": hashlib.sha256(png_bytes).hexdigest(),
        "offset": png_offset,
        "description": "Carved offshore bank logo found directly in raw unallocated sectors."
    })
    curr_cluster += (len(png_bytes) + CLUSTER_SIZE - 1) // CLUSTER_SIZE

    # --- Evidence Item 6: Corrupted ZIP Archive ---
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('leaked_contracts.doc', 'Proprietary internal contract between Alpha Corp and Shell Co.')
        zf.writestr('wire_details.txt', 'Routing: 021000021 Account: 994829104')
    raw_zip = bytearray(zip_buf.getvalue())
    # Intentionally corrupt the central directory / payload bytes to test Feature 3 (Integrity scoring)
    corrupted_zip = bytearray(raw_zip)
    corrupt_idx = len(corrupted_zip) // 2
    corrupted_zip[corrupt_idx:corrupt_idx + 12] = b'\x00\xDE\xAD\xBE\xEF\xFF\x00\x00\xAA\xBB\xCC\xDD'
    zip_cluster = curr_cluster
    zip_offset = cluster_to_offset(zip_cluster)
    disk[zip_offset:zip_offset + len(corrupted_zip)] = corrupted_zip
    dir_entries.extend(format_fat_dir_entry("BACKUP.ZIP", is_deleted=True, start_cluster=zip_cluster, file_size=len(corrupted_zip)))
    ground_truth["files"].append({
        "filename": "BACKUP.ZIP",
        "recovery_method": "filesystem_undelete",
        "category": "Confidential Documents",
        "expected_integrity": "CORRUPTED",
        "expected_quality_score": 35,
        "is_fragmented": False,
        "is_deleted": True,
        "size_bytes": len(corrupted_zip),
        "sha256": hashlib.sha256(corrupted_zip).hexdigest(),
        "offset": zip_offset,
        "description": "Corrupted ZIP archive with damaged payload byte structure."
    })
    curr_cluster += (len(corrupted_zip) + CLUSTER_SIZE - 1) // CLUSTER_SIZE

    # --- Evidence Item 7: High-Severity Incident Response Auth Log (Text) ---
    auth_log = (
        "Sep 25 03:12:01 secure-gw sshd[18492]: Failed password for invalid user root from 198.51.100.23 port 54122 ssh2\n"
        "Sep 25 03:12:04 secure-gw sshd[18494]: Failed password for invalid user admin from 198.51.100.23 port 54124 ssh2\n"
        "Sep 25 03:12:10 secure-gw sshd[18498]: Accepted password for deployer from 203.0.113.88 port 49210 ssh2\n"
        "Sep 25 03:12:15 secure-gw sudo: deployer : TTY=pts/1 ; PWD=/home/deployer ; USER=root ; COMMAND=/bin/bash\n"
        "Sep 25 03:13:00 secure-gw kernel: [CRITICAL] Data exfiltration detected over port 443 to external C2 node 198.51.100.23\n"
    ).encode('utf-8')
    log_cluster = curr_cluster
    log_offset = cluster_to_offset(log_cluster)
    disk[log_offset:log_offset + len(auth_log)] = auth_log
    dir_entries.extend(format_fat_dir_entry("AUTHLOG.TXT", is_deleted=True, start_cluster=log_cluster, file_size=len(auth_log)))
    ground_truth["files"].append({
        "filename": "AUTHLOG.TXT",
        "recovery_method": "filesystem_undelete",
        "category": "Logs",
        "expected_integrity": "INTACT",
        "expected_recoverability_bucket": "FULLY RECOVERABLE",
        "expected_quality_score": 100,
        "is_fragmented": False,
        "is_deleted": True,
        "size_bytes": len(auth_log),
        "sha256": hashlib.sha256(auth_log).hexdigest(),
        "offset": log_offset,
        "description": "Server authentication log confirming brute force and root privilege escalation."
    })
    curr_cluster += (len(auth_log) + CLUSTER_SIZE - 1) // CLUSTER_SIZE

    # --- Evidence Item 8: Truncated Contract (Header without Footer) ---
    trunc_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\nstream\nCONFIDENTIAL PARTNER CONTRACT - INCOMPLETE EXPORT\n"
    trunc_cluster = curr_cluster
    trunc_offset = cluster_to_offset(trunc_cluster)
    disk[trunc_offset:trunc_offset + len(trunc_pdf)] = trunc_pdf
    dir_entries.extend(format_fat_dir_entry("CONTRACT.PDF", is_deleted=True, start_cluster=trunc_cluster, file_size=len(trunc_pdf)))
    ground_truth["files"].append({
        "filename": "CONTRACT.PDF",
        "recovery_method": "filesystem_undelete",
        "category": "Document",
        "expected_integrity": "PARTIAL",
        "expected_recoverability_bucket": "PARTIALLY RECOVERABLE",
        "expected_quality_score": 50,
        "is_fragmented": False,
        "is_deleted": True,
        "size_bytes": len(trunc_pdf),
        "sha256": hashlib.sha256(trunc_pdf).hexdigest(),
        "offset": trunc_offset,
        "description": "Truncated PDF missing EOF marker, demonstrating partial recoverability."
    })
    curr_cluster += (len(trunc_pdf) + CLUSTER_SIZE - 1) // CLUSTER_SIZE

    # --- Evidence Item 9: Mock Ransomware Encrypted File & Extortion Note ---
    import random
    rnd = random.Random(42)
    cipher_bytes = bytes([rnd.randint(0, 255) for _ in range(4096)])
    cipher_cluster = curr_cluster
    cipher_offset = cluster_to_offset(cipher_cluster)
    disk[cipher_offset:cipher_offset + len(cipher_bytes)] = cipher_bytes
    dir_entries.extend(format_fat_dir_entry("DATA.LOCKED", is_deleted=True, start_cluster=cipher_cluster, file_size=len(cipher_bytes)))
    ground_truth["files"].append({
        "filename": "DATA.LOCKED",
        "recovery_method": "filesystem_undelete",
        "category": "Encrypted Blobs",
        "expected_integrity": "PARTIAL",
        "expected_recoverability_bucket": "FRAGMENT ONLY",
        "expected_quality_score": 40,
        "is_fragmented": False,
        "is_deleted": True,
        "is_ransomware": True,
        "size_bytes": len(cipher_bytes),
        "sha256": hashlib.sha256(cipher_bytes).hexdigest(),
        "offset": cipher_offset,
        "description": "Ransomware-encrypted high entropy data file."
    })
    curr_cluster += (len(cipher_bytes) + CLUSTER_SIZE - 1) // CLUSTER_SIZE

    # Extortion Ransom Note
    ransom_note = (
        "!!! ALL YOUR FILES HAVE BEEN ENCRYPTED BY RECON-LOCKER !!!\n"
        "To decrypt your documents and database backups, visit our TOR portal:\n"
        "http://reconlocker2026extortion.onion/case-8849\n"
        "Send 1.5 BTC to Bitcoin Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
    ).encode('utf-8')
    note_cluster = curr_cluster
    note_offset = cluster_to_offset(note_cluster)
    disk[note_offset:note_offset + len(ransom_note)] = ransom_note
    dir_entries.extend(format_fat_dir_entry("DECRYPT.TXT", is_deleted=True, start_cluster=note_cluster, file_size=len(ransom_note)))
    ground_truth["files"].append({
        "filename": "DECRYPT.TXT",
        "recovery_method": "filesystem_undelete",
        "category": "Document",
        "expected_integrity": "INTACT",
        "expected_recoverability_bucket": "FULLY RECOVERABLE",
        "expected_quality_score": 100,
        "is_fragmented": False,
        "is_deleted": True,
        "is_ransom_note": True,
        "size_bytes": len(ransom_note),
        "sha256": hashlib.sha256(ransom_note).hexdigest(),
        "offset": note_offset,
        "description": "Ransomware extortion note left by threat actors."
    })
    curr_cluster += (len(ransom_note) + CLUSTER_SIZE - 1) // CLUSTER_SIZE

    # --- Evidence Item 10: Extension Spoofing / Anti-Forensic Masquerading ---
    # File named INVOICE.PDF but contains MZ Windows executable header
    fake_pdf = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00" + (b"\x00" * 44) + b"\x80\x00\x00\x00" + (b"\x00" * 64) + b"PE\x00\x00MaliciousPayload"
    fake_cluster = curr_cluster
    fake_offset = cluster_to_offset(fake_cluster)
    disk[fake_offset:fake_offset + len(fake_pdf)] = fake_pdf
    dir_entries.extend(format_fat_dir_entry("INVOICE.PDF", is_deleted=True, start_cluster=fake_cluster, file_size=len(fake_pdf)))
    ground_truth["files"].append({
        "filename": "INVOICE.PDF",
        "recovery_method": "filesystem_undelete",
        "category": "Executables",
        "expected_integrity": "INTACT",
        "expected_recoverability_bucket": "FULLY RECOVERABLE",
        "expected_quality_score": 100,
        "is_fragmented": False,
        "is_deleted": True,
        "is_extension_spoofed": True,
        "size_bytes": len(fake_pdf),
        "sha256": hashlib.sha256(fake_pdf).hexdigest(),
        "offset": fake_offset,
        "description": "Executable file disguised with a PDF extension to evade security filters."
    })
    curr_cluster += (len(fake_pdf) + CLUSTER_SIZE - 1) // CLUSTER_SIZE

    # --- Evidence Item 11: Wiped Disk Region (16KB zeros + 8KB 0xFF) ---
    wipe_cluster = curr_cluster
    wipe_offset = cluster_to_offset(wipe_cluster)
    disk[wipe_offset:wipe_offset + 16384] = b"\x00" * 16384
    disk[wipe_offset + 16384:wipe_offset + 24576] = b"\xFF" * 8192
    ground_truth["wiped_regions"] = [
        {"offset": wipe_offset, "size": 16384, "pattern": "0x00 NIST Clear"},
        {"offset": wipe_offset + 16384, "size": 8192, "pattern": "0xFF Solid Flash Erase"}
    ]
    curr_cluster += 8

    # 2. Write Root Directory Table into Cluster 2
    root_dir_offset = cluster_to_offset(2)
    disk[root_dir_offset:root_dir_offset + len(dir_entries)] = dir_entries

    # 3. Calculate Final Disk Image SHA-256 for Forensic Evidence Seal
    disk_bytes = bytes(disk)
    evidence_sha256 = hashlib.sha256(disk_bytes).hexdigest()
    ground_truth["disk_image_sha256"] = evidence_sha256

    # 4. Save to files
    os.makedirs(os.path.dirname(output_raw), exist_ok=True)
    os.makedirs(os.path.dirname(output_gt), exist_ok=True)

    with open(output_raw, 'wb') as f:
        f.write(disk_bytes)
    print(f"[+] Successfully wrote {len(disk_bytes)} bytes to: {output_raw}")

    with open(output_gt, 'w') as f:
        json.dump(ground_truth, f, indent=2)
    print(f"[+] Saved ground truth manifest to: {output_gt}")
    print(f"[+] Evidence SHA-256: {evidence_sha256}")
    return evidence_sha256

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    raw_path = os.path.join(base_dir, "data", "demo_evidence.raw")
    gt_path = os.path.join(base_dir, "data", "ground_truth.json")
    generate_evidence_disk(raw_path, gt_path)
