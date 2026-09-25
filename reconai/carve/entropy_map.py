"""
ReconAI Disk Sector Entropy & Cluster Map Engine
Computes Shannon entropy across the disk image to visualize cluster allocation,
fragmentation gaps, and high-entropy compressed/encrypted evidence blocks.
"""

import os
import math
from typing import List, Dict, Any

def calculate_block_entropy(data: bytes) -> float:
    """Calculates Shannon entropy (0.0 to 8.0) of a byte block."""
    if not data:
        return 0.0
    length = len(data)
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)

def generate_disk_entropy_map(image_path: str, block_size: int = 64 * 1024, max_blocks: int = 128) -> List[Dict[str, Any]]:
    """
    Samples the disk image at regular intervals to generate an entropy map.
    Returns: list of blocks with offset, entropy, and type classification.
    """
    if not os.path.exists(image_path):
        return []

    file_size = os.path.getsize(image_path)
    step = max(block_size, file_size // max_blocks)
    entropy_points = []

    with open(image_path, 'rb') as f:
        offset = 0
        block_idx = 0
        while offset < file_size and block_idx < max_blocks:
            f.seek(offset)
            chunk = f.read(block_size)
            if not chunk:
                break
            ent = calculate_block_entropy(chunk)
            
            # Classification
            if ent < 0.5:
                tag = "Zero Slack / Unallocated"
            elif ent < 5.0:
                tag = "Text / Metadata / Code"
            else:
                tag = "Compressed / Media / Frag"

            entropy_points.append({
                "block_index": block_idx,
                "offset_hex": f"0x{offset:06X}",
                "offset_mb": round(offset / (1024 * 1024), 2),
                "entropy": ent,
                "type": tag
            })
            offset += step
            block_idx += 1

    return entropy_points
