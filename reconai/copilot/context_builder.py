"""
ReconAI Copilot Evidence Context Builder
Converts retrieved artifacts, fragments, and timeline events into structured, ID-tagged evidence contexts.
"""

from typing import Dict, Any, List, Tuple

def build_evidence_context(
    retrieved: Dict[str, Any],
    case_id: str
) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Builds a compact structured text context with explicit IDs [ART-XXX], [EVENT-XXX].
    Returns (context_str, citation_records).
    """
    artifacts = retrieved.get("artifacts", [])
    events = retrieved.get("timeline_events", [])

    lines = []
    lines.append(f"RECONAI CASE CONTEXT: {case_id}")
    lines.append("==========================================")

    citations = []

    if artifacts:
        lines.append("\nRECOVERED ARTIFACT EVIDENCE:")
        for idx, item in enumerate(artifacts, 1):
            art_id = item.get("item_id") or f"ART-{idx:03d}"
            item_real_id = art_id
            fn = item.get("filename", "unknown.bin")
            cat = item.get("category", "Unclassified")
            prio = item.get("technical_priority", "P1")
            conf = item.get("confidence_score", 100.0)
            bucket = item.get("recoverability_bucket", "FULLY RECOVERABLE")

            citations.append({
                "id": art_id,
                "real_id": item_real_id,
                "type": "artifact",
                "name": fn
            })

            lines.append(f"\nARTIFACT:")
            lines.append(f"  ID: {art_id}")
            lines.append(f"  Name: {fn}")
            lines.append(f"  Category: {cat}")
            lines.append(f"  Priority: {prio}")
            lines.append(f"  Confidence: {conf}%")
            lines.append(f"  Status: {bucket}")
            if item.get("source") == "fragment_reassembly":
                lines.append(f"  Source: AI Fragment Reassembly Engine")
                lines.append(f"  Join Reasons: {', '.join(item.get('join_reasons', []))}")
            if item.get("use_case"):
                lines.append(f"  Use Case: {item.get('use_case')}")

    if events:
        lines.append("\nCORRELATED TIMELINE EVENTS:")
        for idx, ev in enumerate(events, 1):
            ev_id = f"EVENT-{idx:03d}"
            ts = ev.get("timestamp", "N/A")
            src = ev.get("source_artifact", "System Log")
            sev = ev.get("severity", "LOW")
            desc = ev.get("description", "")

            citations.append({
                "id": ev_id,
                "real_id": ev_id,
                "type": "timeline_event",
                "name": f"{ts} - {sev}"
            })

            lines.append(f"\nEVENT:")
            lines.append(f"  ID: {ev_id}")
            lines.append(f"  Timestamp: {ts}")
            lines.append(f"  Source: {src}")
            lines.append(f"  Severity: {sev}")
            lines.append(f"  Description: {desc}")

    context_str = "\n".join(lines)
    return context_str, citations
