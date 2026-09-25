"""
ReconAI Signature Carving Engine (High Performance & Filesystem-Independent)
Scans raw bitstreams for known header and footer signatures (JPEG, PNG, PDF, ZIP/Office, MP4, SQLite, EXE, TXT).
Records for each carve: offset, length, detected type, and whether both header and footer were found.
Captures orphan fragments (headers without footers, or isolated trailers) across cluster slack gaps.
"""

import os
import struct
import hashlib
from typing import List, Dict, Any, Tuple, Optional
from reconai.carve.signatures import FILE_SIGNATURES

def carve_raw_image(image_path: str, known_offsets: Optional[List[int]] = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Fast, filesystem-independent signature carver.
    Returns:
        carved_items: recovered files with offset, length, detected type, has_header, has_footer.
        orphan_fragments: disconnected fragments for AI reconstruction.
    """
    if known_offsets is None:
        known_offsets = []

    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Evidence file not found: {image_path}")

    with open(image_path, 'rb') as f:
        raw_bytes = f.read()

    carved_items: List[Dict[str, Any]] = []
    orphan_fragments: List[Dict[str, Any]] = []
    total_len = len(raw_bytes)

    # 1. Standard Header-Footer Formats (JPEG, PNG, PDF, ZIP)
    for fmt_name in ["JPEG", "PNG", "PDF", "ZIP"]:
        spec = FILE_SIGNATURES[fmt_name]
        header = spec["header"]
        footer = spec["footer"]
        ext = spec["extension"]
        max_size = spec["max_size"]
        min_size = spec["min_size"]
        footer_extra = spec.get("footer_extra_len", 0)

        pos = 0
        while pos < total_len:
            idx = raw_bytes.find(header, pos)
            if idx == -1:
                break

            search_limit = min(idx + max_size, total_len)
            footer_idx = raw_bytes.find(footer, idx + len(header), search_limit) if footer else -1

            if footer_idx != -1:
                end_pos = footer_idx + len(footer) + footer_extra
                item_data = raw_bytes[idx:end_pos]

                # Check for fragmentation gap (e.g. 512+ consecutive zeros in between)
                slack_marker = b'\x00' * 512
                if slack_marker in item_data and len(item_data) > 1024:
                    slack_start = item_data.find(slack_marker)
                    hdr_data = item_data[:slack_start].rstrip(b'\x00')

                    slack_end = item_data.rfind(slack_marker) + len(slack_marker)
                    trl_data = item_data[slack_end:].lstrip(b'\x00')

                    if len(hdr_data) >= 32:
                        orphan_fragments.append({
                            "fragment_id": f"frag_hdr_{fmt_name.lower()}_{idx}",
                            "offset": idx,
                            "length": len(hdr_data),
                            "size_bytes": len(hdr_data),
                            "frag_type": "header",
                            "predicted_format": fmt_name,
                            "data": hdr_data,
                            "has_header": True,
                            "has_footer": False
                        })

                    if len(trl_data) >= 32:
                        trl_offset = idx + slack_end
                        orphan_fragments.append({
                            "fragment_id": f"frag_trl_{fmt_name.lower()}_{trl_offset}",
                            "offset": trl_offset,
                            "length": len(trl_data),
                            "size_bytes": len(trl_data),
                            "frag_type": "trailer",
                            "predicted_format": fmt_name,
                            "data": trl_data,
                            "has_header": False,
                            "has_footer": True
                        })

                    pos = end_pos
                    continue

                if len(item_data) >= min_size:
                    item_sha256 = hashlib.sha256(item_data).hexdigest()
                    carved_items.append({
                        "item_id": f"carve_{fmt_name.lower()}_{idx}",
                        "filename": f"carved_{fmt_name.lower()}_{idx}{ext}",
                        "extension": ext,
                        "source": "signature_carving",
                        "offset": idx,
                        "length": len(item_data),
                        "size_bytes": len(item_data),
                        "detected_type": fmt_name,
                        "has_header": True,
                        "has_footer": True,
                        "data": item_data,
                        "sha256": item_sha256,
                        "is_deleted": True,
                        "format": fmt_name
                    })
                    pos = max(end_pos, idx + 512)
                    continue
            else:
                # Orphan Header Fragment (Header found without matching Footer)
                frag_len = min(4096, total_len - idx)
                frag_data = raw_bytes[idx:idx + frag_len].rstrip(b'\x00')
                if len(frag_data) >= 32:
                    orphan_fragments.append({
                        "fragment_id": f"frag_hdr_{fmt_name.lower()}_{idx}",
                        "offset": idx,
                        "length": len(frag_data),
                        "size_bytes": len(frag_data),
                        "frag_type": "header",
                        "predicted_format": fmt_name,
                        "data": frag_data,
                        "has_header": True,
                        "has_footer": False
                    })

            pos = idx + len(header)

    # 2. SQLite Database Carving (Header-sized structure)
    pos = 0
    sqlite_hdr = FILE_SIGNATURES["SQLITE"]["header"]
    while pos < total_len:
        idx = raw_bytes.find(sqlite_hdr, pos)
        if idx == -1:
            break
        if idx + 100 <= total_len:
            try:
                page_size = struct.unpack(">H", raw_bytes[idx + 16:idx + 18])[0]
                if page_size == 1:
                    page_size = 65536
                page_count = struct.unpack(">I", raw_bytes[idx + 28:idx + 32])[0]
                if page_size in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536) and page_count > 0:
                    db_size = min(page_size * page_count, 50 * 1024 * 1024)
                    if idx + db_size <= total_len:
                        db_data = raw_bytes[idx:idx + db_size]
                        carved_items.append({
                            "item_id": f"carve_sqlite_{idx}",
                            "filename": f"carved_db_{idx}.sqlite",
                            "extension": ".sqlite",
                            "source": "signature_carving",
                            "offset": idx,
                            "length": len(db_data),
                            "size_bytes": len(db_data),
                            "detected_type": "SQLITE",
                            "has_header": True,
                            "has_footer": True,
                            "data": db_data,
                            "sha256": hashlib.sha256(db_data).hexdigest(),
                            "is_deleted": True,
                            "format": "SQLITE"
                        })
                        pos = idx + db_size
                        continue
            except Exception:
                pass
        pos = idx + len(sqlite_hdr)

    # 3. Windows PE / Executable Carving (MZ + e_lfanew PE\x00\x00)
    pos = 0
    while pos < total_len:
        idx = raw_bytes.find(b"MZ", pos)
        if idx == -1:
            break
        if idx + 0x40 <= total_len:
            try:
                pe_offset = struct.unpack("<I", raw_bytes[idx + 0x3C:idx + 0x40])[0]
                if 0 < pe_offset < 1024 and idx + pe_offset + 4 <= total_len:
                    if raw_bytes[idx + pe_offset:idx + pe_offset + 4] == b"PE\x00\x00":
                        pe_len = min(65536, total_len - idx)
                        pe_data = raw_bytes[idx:idx + pe_len].rstrip(b'\x00')
                        carved_items.append({
                            "item_id": f"carve_exe_{idx}",
                            "filename": f"carved_bin_{idx}.exe",
                            "extension": ".exe",
                            "source": "signature_carving",
                            "offset": idx,
                            "length": len(pe_data),
                            "size_bytes": len(pe_data),
                            "detected_type": "EXE",
                            "has_header": True,
                            "has_footer": True,
                            "data": pe_data,
                            "sha256": hashlib.sha256(pe_data).hexdigest(),
                            "is_deleted": True,
                            "format": "EXE"
                        })
                        pos = idx + pe_len
                        continue
            except Exception:
                pass
        pos = idx + 2

    # 4. Fast Sector-Aligned Text Carving (Printable UTF-8 Runs & Logs)
    carved_ranges = [(item["offset"], item["offset"] + item["length"]) for item in carved_items]
    for frag in orphan_fragments:
        carved_ranges.append((frag["offset"], frag["offset"] + frag["length"]))

    text_items = _carve_text_blocks_fast(raw_bytes, carved_ranges)
    carved_items.extend(text_items)

    return carved_items, orphan_fragments

def _carve_text_blocks_fast(raw_bytes: bytes, binary_ranges: List[Tuple[int, int]]) -> List[Dict[str, Any]]:
    """Fast sector-aligned scanner for unallocated plaintext logs, credentials, and notes."""
    text_items = []
    cluster_size = 4096
    i = 0
    total_len = len(raw_bytes)

    target_keywords = (
        b"PASSWORD", b"DATABASE_URL", b"AWS_ACCESS_KEY", b"sshd[", b"kernel:",
        b"CRITICAL", b"YOUR FILES", b"HOW TO DECRYPT", b"RESTORE", b"CONFIDENTIAL"
    )

    while i < total_len:
        skip = False
        for start, end in binary_ranges:
            if start <= i < end:
                i = end
                skip = True
                break
        if skip:
            continue

        chunk = raw_bytes[i:i + cluster_size]
        if len(chunk) < 64:
            break

        if chunk[0] == 0 and chunk[1] == 0 and chunk[2] == 0 and chunk[3] == 0:
            i += cluster_size
            continue

        has_keyword = any(kw in chunk for kw in target_keywords)

        if has_keyword:
            end_i = i + len(chunk)
            while end_i < total_len:
                next_blk = raw_bytes[end_i:end_i + 512]
                if not next_blk or next_blk[0] == 0:
                    break
                printable = sum(1 for b in next_blk[:128] if 32 <= b <= 126 or b in (9, 10, 13))
                if printable / min(128, len(next_blk)) > 0.70:
                    end_i += len(next_blk)
                else:
                    break

            text_data = raw_bytes[i:end_i].rstrip(b'\x00 \t\r\n')
            if len(text_data) >= 64:
                try:
                    decoded_str = text_data.decode('utf-8')
                    printable_count = sum(1 for c in decoded_str if c.isprintable() or c in '\r\n\t')
                    if printable_count / max(1, len(decoded_str)) >= 0.85:
                        sha256 = hashlib.sha256(text_data).hexdigest()
                        text_items.append({
                            "item_id": f"carve_txt_{i}",
                            "filename": f"carved_text_{i}.txt",
                            "extension": ".txt",
                            "source": "signature_carving",
                            "offset": i,
                            "length": len(text_data),
                            "size_bytes": len(text_data),
                            "detected_type": "TXT",
                            "has_header": True,
                            "has_footer": True,
                            "data": text_data,
                            "sha256": sha256,
                            "is_deleted": True,
                            "format": "TXT"
                        })
                except UnicodeDecodeError:
                    pass
            i = end_i
            continue

        i += cluster_size

    return text_items
