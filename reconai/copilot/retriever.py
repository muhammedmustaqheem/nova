"""
ReconAI Evidence Retriever Module
Lightweight RAG retrieval layer searching recovered_items, fragments, timeline, classifications, relationships, and IOCs.
"""

import re
from typing import Dict, Any, List

def retrieve_relevant_evidence(
    question: str,
    case_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Parses the user question and retrieves relevant evidence items, timeline events, and IOC records.
    """
    if not question:
        return {
            "artifacts": [],
            "timeline_events": [],
            "iocs": [],
            "total_found": 0
        }

    q = question.strip().lower()
    items = case_data.get("recovered_items", [])
    timeline = case_data.get("timeline", {}).get("timeline_events", [])
    tampering = case_data.get("tampering_summary", {}).get("indicators", [])

    matched_artifacts = []
    matched_events = []
    matched_iocs = []

    # 0. Direct Item ID or Filename Search (Context-Aware Deep Dive)
    art_id_matches = re.findall(r"ART-\d{3}", question, re.IGNORECASE)
    if art_id_matches:
        target_art = art_id_matches[0].upper()
        for item in items:
            if item.get("item_id", "").upper() == target_art:
                matched_artifacts.append(item)

    for item in items:
        fn = (item.get("filename") or "").lower()
        title = (item.get("friendly_title") or "").lower()
        if fn and fn in q:
            if item not in matched_artifacts:
                matched_artifacts.append(item)

    # 1. IP Query / Network Address match
    ip_matches = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", q)
    if ip_matches or any(k in q for k in ["ip", "network", "host", "c2", "exfiltration"]):
        target_ip = ip_matches[0] if ip_matches else None
        for item in items:
            preview = item.get("content_preview", "")
            fn = item.get("filename", "").lower()
            cat = item.get("category", "").lower()
            if (target_ip and target_ip in preview) or "auth" in fn or "log" in cat or "ip" in cat:
                if item not in matched_artifacts:
                    matched_artifacts.append(item)
        for ev in timeline:
            desc = ev.get("description", "").lower()
            if (target_ip and target_ip in desc) or "exfiltration" in desc or "sshd" in desc:
                if ev not in matched_events:
                    matched_events.append(ev)

    # 2. Credentials / Key / Password query
    if any(k in q for k in ["credential", "password", "pass", "key", "secret", "env", "token", "auth"]):
        for item in items:
            cat = item.get("category", "")
            fn = item.get("filename", "").lower()
            use_case = item.get("use_case", "").lower()
            if "Credential" in cat or ".env" in fn or "key" in use_case or "secret" in use_case:
                if item not in matched_artifacts:
                    matched_artifacts.append(item)

    # 3. Reconstruction & Fragment Query
    if any(k in q for k in ["fragment", "reconstruct", "stitch", "join", "alignment", "confidence"]):
        for item in items:
            if item.get("source") == "fragment_reassembly" or item.get("is_fragmented"):
                if item not in matched_artifacts:
                    matched_artifacts.append(item)

    # 4. Priority / P1 / P2 / P3 Explanation Query
    if any(k in q for k in ["p1", "p2", "p3", "priority", "important", "high", "classify"]):
        for item in items:
            prio = item.get("technical_priority", "")
            if "P1" in prio or item.get("priority_score", 0) >= 80:
                if item not in matched_artifacts:
                    matched_artifacts.append(item)

    # 5. Recoverability / Bucket Explanation Query
    if any(k in q for k in ["deleted", "fully", "partially", "unrecoverable", "recoverable", "recoverability", "bucket", "why"]):
        for item in items:
            if item.get("is_deleted") or "RECOVERABLE" in item.get("recoverability_bucket", ""):
                if item not in matched_artifacts:
                    matched_artifacts.append(item)

    # 6. Timeline / Time Window Query
    time_matches = re.findall(r"\b\d{2}:\d{2}\b", q)
    if time_matches or any(k in q for k in ["time", "timeline", "before", "after", "when", "event"]):
        for ev in timeline:
            if ev not in matched_events:
                matched_events.append(ev)

    # Fallback if no specific keyword matched: return top items
    if not matched_artifacts and not matched_events:
        matched_artifacts = items[:5]
        matched_events = timeline[:5]

    total_found = len(matched_artifacts) + len(matched_events) + len(matched_iocs)
    return {
        "artifacts": matched_artifacts,
        "timeline_events": matched_events,
        "iocs": matched_iocs,
        "total_found": total_found
    }
