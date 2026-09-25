"""
ReconAI Filesystem Ingest & Undelete Engine
Supports pytsk3 for forensic filesystem parsing, with an automatic
pure-Python FAT16/FAT32/raw sector directory parser fallback.
"""

import os
import struct
import hashlib
from typing import List, Dict, Any, Optional

SECTOR_SIZE = 512

def _try_pytsk3_recovery(image_path: str) -> Optional[List[Dict[str, Any]]]:
    """Attempts filesystem recovery using pytsk3 if library is installed."""
    try:
        import pytsk3
    except ImportError:
        return None

    recovered = []
    try:
        img_info = pytsk3.Img_Info(image_path)
        # Attempt to open volume or directly filesystem
        try:
            fs_info = pytsk3.FS_Info(img_info)
        except Exception:
            # Try partition table
            try:
                volume = pytsk3.Volume_Info(img_info)
                for part in volume:
                    if part.len > 0 and part.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                        try:
                            fs_info = pytsk3.FS_Info(img_info, offset=part.start * 512)
                            break
                        except Exception:
                            continue
            except Exception:
                return None

        def walk_dir(directory, parent_path=""):
            for entry in directory:
                if not entry.info.name or entry.info.name.name in [b".", b".."]:
                    continue
                name = entry.info.name.name.decode('utf-8', errors='replace')
                full_path = f"{parent_path}/{name}"
                is_deleted = entry.info.meta and entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC
                if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                    size = entry.info.meta.size
                    if size > 0:
                        file_obj = entry
                        data = file_obj.read_random(0, size)
                        ext = os.path.splitext(name)[1].lower()
                        recovered.append({
                            "item_id": f"pytsk_{entry.info.meta.addr}",
                            "filename": name,
                            "path": full_path,
                            "extension": ext,
                            "source": "filesystem_undelete" if is_deleted else "filesystem_active",
                            "offset": entry.info.meta.addr * 512 if hasattr(entry.info.meta, 'addr') else 0,
                            "size_bytes": len(data),
                            "data": data,
                            "sha256": hashlib.sha256(data).hexdigest(),
                            "is_deleted": bool(is_deleted)
                        })
                elif entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    try:
                        sub_dir = entry.as_directory()
                        walk_dir(sub_dir, full_path)
                    except Exception:
                        pass

        root_dir = fs_info.open_dir(path="/")
        walk_dir(root_dir)
        return recovered
    except Exception:
        return None

def _parse_fat_boot_sector(boot: bytes) -> Optional[Dict[str, Any]]:
    """Parse standard FAT32 / FAT16 boot parameters from boot sector bytes."""
    if len(boot) < 512 or boot[510:512] != b'\x55\xAA':
        return None

    try:
        bytes_per_sec = struct.unpack_from('<H', boot, 11)[0]
        sec_per_cluster = boot[13]
        reserved_sec = struct.unpack_from('<H', boot, 14)[0]
        num_fats = boot[16]
        root_entries = struct.unpack_from('<H', boot, 17)[0]
        sec_per_fat = struct.unpack_from('<H', boot, 22)[0]
        if sec_per_fat == 0:
            # FAT32
            sec_per_fat = struct.unpack_from('<I', boot, 36)[0]
            root_cluster = struct.unpack_from('<I', boot, 44)[0]
            is_fat32 = True
        else:
            root_cluster = 2
            is_fat32 = False

        if bytes_per_sec == 0 or sec_per_cluster == 0 or num_fats == 0:
            return None

        cluster_size = bytes_per_sec * sec_per_cluster
        data_offset = (reserved_sec + num_fats * sec_per_fat) * bytes_per_sec

        return {
            "bytes_per_sector": bytes_per_sec,
            "sectors_per_cluster": sec_per_cluster,
            "cluster_size": cluster_size,
            "reserved_sectors": reserved_sec,
            "num_fats": num_fats,
            "sectors_per_fat": sec_per_fat,
            "root_cluster": root_cluster,
            "data_offset": data_offset,
            "is_fat32": is_fat32
        }
    except Exception:
        return None

def _pure_python_fat_undelete(image_path: str) -> List[Dict[str, Any]]:
    """
    Forensic sector-level FAT32/FAT16 directory crawler.
    Scans directory tables for active and deleted entries (0xE5 marker).
    """
    recovered = []
    file_size = os.path.getsize(image_path)

    with open(image_path, 'rb') as f:
        boot_bytes = f.read(512)
        bpb = _parse_fat_boot_sector(boot_bytes)
        if not bpb:
            return []

        cluster_size = bpb["cluster_size"]
        data_offset = bpb["data_offset"]

        def cluster_to_offset(c: int) -> int:
            return data_offset + (c - 2) * cluster_size

        # In FAT32, root directory is in cluster chain starting at bpb["root_cluster"]
        root_offset = cluster_to_offset(bpb["root_cluster"])
        f.seek(root_offset)
        dir_bytes = f.read(cluster_size * 4)  # Read up to 4 clusters of directory tables

        # Directory entries are 32 bytes each
        for i in range(0, len(dir_bytes), 32):
            entry = dir_bytes[i:i + 32]
            if len(entry) < 32:
                break
            first_byte = entry[0]
            if first_byte == 0x00:
                # End of directory
                break

            is_deleted = (first_byte == 0xE5)
            # Long file name entry check (attribute 0x0F)
            attr = entry[11]
            if attr == 0x0F:
                continue  # Skip LFN entries for raw 8.3 extraction

            # Extract 8.3 name
            raw_name = entry[1:8] if is_deleted else entry[0:8]
            raw_ext = entry[8:11]

            try:
                name_str = raw_name.decode('ascii', errors='ignore').strip()
                ext_str = raw_ext.decode('ascii', errors='ignore').strip()
            except Exception:
                continue

            if not name_str:
                continue

            filename = f"_{name_str}.{ext_str}" if is_deleted else f"{name_str}.{ext_str}"
            if not ext_str:
                filename = filename.rstrip('.')

            high_cluster = struct.unpack_from('<H', entry, 20)[0]
            low_cluster = struct.unpack_from('<H', entry, 26)[0]
            start_cluster = (high_cluster << 16) | low_cluster
            item_size = struct.unpack_from('<I', entry, 28)[0]

            if start_cluster >= 2 and item_size > 0:
                item_offset = cluster_to_offset(start_cluster)
                if item_offset + item_size <= file_size:
                    f.seek(item_offset)
                    data = f.read(item_size)
                    ext = f".{ext_str.lower()}" if ext_str else ""
                    recovered.append({
                        "item_id": f"fs_{'del' if is_deleted else 'act'}_{start_cluster}_{item_offset}",
                        "filename": filename,
                        "extension": ext,
                        "source": "filesystem_undelete" if is_deleted else "filesystem_active",
                        "offset": item_offset,
                        "size_bytes": len(data),
                        "data": data,
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "is_deleted": is_deleted,
                        "cluster": start_cluster
                    })

    return recovered

def recover_filesystem(image_path: str) -> List[Dict[str, Any]]:
    """
    Primary API: Attempts pytsk3 recovery, automatically falling back
    to pure-Python forensic FAT/sector undelete.
    """
    tsk_results = _try_pytsk3_recovery(image_path)
    if tsk_results is not None and len(tsk_results) > 0:
        return tsk_results

    # Fallback to pure-Python FAT crawler
    return _pure_python_fat_undelete(image_path)
