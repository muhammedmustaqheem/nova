"""
ReconAI Signature Carver - Magic Byte Signatures & Specs
Defines byte patterns for file headers, footers, and maximum search limits.
Supports JPEG, PNG, PDF, ZIP (DOCX/XLSX), MP4, SQLite, and Windows PE (EXE).
"""

from typing import Dict, Any

FILE_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "JPEG": {
        "extension": ".jpg",
        "header": b"\xFF\xD8\xFF",
        "footer": b"\xFF\xD9",
        "max_size": 15 * 1024 * 1024,
        "min_size": 32,
        "mime_type": "image/jpeg"
    },
    "PNG": {
        "extension": ".png",
        "header": b"\x89PNG\r\n\x1a\n",
        "footer": b"IEND\xaeB`\x82",
        "max_size": 15 * 1024 * 1024,
        "min_size": 64,
        "mime_type": "image/png"
    },
    "PDF": {
        "extension": ".pdf",
        "header": b"%PDF-",
        "footer": b"%%EOF",
        "max_size": 25 * 1024 * 1024,
        "min_size": 64,
        "mime_type": "application/pdf"
    },
    "ZIP": {
        "extension": ".zip",
        "header": b"PK\x03\x04",
        "footer": b"PK\x05\x06",  # End of Central Directory Record start
        "footer_extra_len": 18,    # Standard EOCD structure length is 22 bytes (header 4 + 18)
        "max_size": 30 * 1024 * 1024,
        "min_size": 64,
        "mime_type": "application/zip"
    },
    "SQLITE": {
        "extension": ".sqlite",
        "header": b"SQLite format 3\x00",
        "footer": None,  # Computed via page-size and page-count header fields
        "max_size": 50 * 1024 * 1024,
        "min_size": 100,
        "mime_type": "application/x-sqlite3"
    },
    "EXE": {
        "extension": ".exe",
        "header": b"MZ",
        "footer": None,  # Verified via PE signature at e_lfanew
        "max_size": 30 * 1024 * 1024,
        "min_size": 256,
        "mime_type": "application/x-dosexec"
    },
    "MP4": {
        "extension": ".mp4",
        "header": b"ftyp",  # Typically offset 4 in MP4/MOV container
        "footer": None,
        "max_size": 50 * 1024 * 1024,
        "min_size": 128,
        "mime_type": "video/mp4"
    }
}
