"""
ReconAI Database Layer (SQLite)
Manages forensic cases, recovered artifacts, fragments, and metadata.
"""

import sqlite3
import json
import os
from typing import List, Dict, Any, Optional

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "reconai.db")

def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: str = DEFAULT_DB_PATH):
    """Initialize SQLite tables for forensic cases and recovered artifacts."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                image_path TEXT NOT NULL,
                image_sha256 TEXT NOT NULL,
                disk_size_bytes INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                total_recovered INTEGER DEFAULT 0
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS recovered_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                item_id TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                extension TEXT NOT NULL,
                source TEXT NOT NULL,
                offset INTEGER NOT NULL,
                size_bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                category TEXT NOT NULL,
                integrity_status TEXT NOT NULL,
                integrity_score REAL NOT NULL,
                confidence_score REAL NOT NULL,
                priority_score REAL NOT NULL,
                is_fragmented INTEGER DEFAULT 0,
                details_json TEXT,
                content_preview TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(case_id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS fragments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                fragment_id TEXT UNIQUE NOT NULL,
                offset INTEGER NOT NULL,
                size_bytes INTEGER NOT NULL,
                frag_type TEXT NOT NULL,
                predicted_format TEXT NOT NULL,
                matched_to_item_id TEXT,
                confidence REAL DEFAULT 0.0,
                FOREIGN KEY(case_id) REFERENCES cases(case_id)
            )
        """)
        conn.commit()

def save_case(case_data: Dict[str, Any], db_path: str = DEFAULT_DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO cases (case_id, image_path, image_sha256, disk_size_bytes, created_at, total_recovered)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            case_data["case_id"],
            case_data["image_path"],
            case_data["image_sha256"],
            case_data["disk_size_bytes"],
            case_data["created_at"],
            case_data.get("total_recovered", 0)
        ))
        conn.commit()

def save_recovered_item(item: Dict[str, Any], db_path: str = DEFAULT_DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO recovered_items (
                case_id, item_id, filename, extension, source, offset, size_bytes,
                sha256, category, integrity_status, integrity_score, confidence_score,
                priority_score, is_fragmented, details_json, content_preview, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            item["case_id"],
            item["item_id"],
            item["filename"],
            item.get("extension", ""),
            item["source"],
            item.get("offset", 0),
            item.get("size_bytes", 0),
            item.get("sha256", ""),
            item.get("category", "Uncategorized"),
            item.get("integrity_status", "UNKNOWN"),
            item.get("integrity_score", 0.0),
            item.get("confidence_score", 100.0),
            item.get("priority_score", 0.0),
            1 if item.get("is_fragmented") else 0,
            json.dumps(item.get("details", {})),
            item.get("content_preview", ""),
            item.get("created_at", "")
        ))
        conn.commit()

def save_fragment(frag: Dict[str, Any], db_path: str = DEFAULT_DB_PATH):
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO fragments (
                case_id, fragment_id, offset, size_bytes, frag_type, predicted_format, matched_to_item_id, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            frag["case_id"],
            frag["fragment_id"],
            frag["offset"],
            frag["size_bytes"],
            frag["frag_type"],
            frag.get("predicted_format", ""),
            frag.get("matched_to_item_id"),
            frag.get("confidence", 0.0)
        ))
        conn.commit()

def get_case_items(case_id: str, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM recovered_items WHERE case_id = ? ORDER BY priority_score DESC", (case_id,))
        rows = cursor.fetchall()
        items = []
        for r in rows:
            d = dict(r)
            if d.get("details_json"):
                try:
                    d["details"] = json.loads(d["details_json"])
                except Exception:
                    d["details"] = {}
            items.append(d)
        return items

def get_case_fragments(case_id: str, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM fragments WHERE case_id = ? ORDER BY offset ASC", (case_id,))
        return [dict(r) for r in cursor.fetchall()]

def get_case_metadata(case_id: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
