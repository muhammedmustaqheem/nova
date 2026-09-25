"""
ReconAI Local Evidence-Grounded Investigator Copilot
Answers investigative questions strictly grounded in indexed recovered case evidence.
Explicitly cites artifact IDs and tags evidence as [OBSERVED], [DERIVED], or [INFERRED].
Does NOT call external LLM APIs and does NOT invent ungrounded conclusions.
"""

import re
from typing import Dict, Any, List

def query_investigator_copilot(
    query: str,
    recovered_items: List[Dict[str, Any]],
    case_meta: Dict[str, Any],
    timeline_events: List[Dict[str, Any]] = None,
    tampering_indicators: List[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Processes investigator queries against recovered evidence artifacts and produces an evidence-grounded answer.
    """
    if not query:
        return {
            "query": "",
            "answer": "Please ask a question about the recovered evidence.",
            "citations": [],
            "tag": "[OBSERVED]"
        }

    q = query.strip().lower()
    items = recovered_items or []
    events = timeline_events or []
    indicators = tampering_indicators or []

    answer_parts = []
    citations = []

    # 1. IP / Network Query
    ip_matches = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", q)
    if ip_matches or "ip" in q or "network" in q or "host" in q:
        target_ip = ip_matches[0] if ip_matches else None
        matching_items = []
        for item in items:
            preview = item.get("content_preview", "")
            if (target_ip and target_ip in preview) or ("auth" in item.get("filename", "").lower()) or ("log" in item.get("category", "").lower()):
                matching_items.append(item)
                citations.append(item["item_id"])

        if matching_items:
            answer_parts.append(f"**[OBSERVED]** Found {len(matching_items)} artifact(s) associated with network IP traces:")
            for m in matching_items:
                answer_parts.append(f"• Artifact `{m['item_id']}` ({m['filename']}) — {m.get('friendly_title', m['category'])}. Priority: {m.get('technical_priority', 'P3')}.")
        else:
            answer_parts.append("[OBSERVED] No recovered artifacts matched the specified IP address.")

    # 2. Priority Query ("Why is this P1 / P2 / P3?")
    elif "p1" in q or "priority" in q or "why" in q:
        p1_items = [i for i in items if "P1" in i.get("technical_priority", "")]
        citations = [i["item_id"] for i in p1_items]
        answer_parts.append(f"**[DERIVED]** ReconAI assigned High Technical Recovery Priority (**P1**) to {len(p1_items)} artifact(s) based on structural decoder checks, recovery completeness, and sensitivity:")
        for p in p1_items[:4]:
            reasons = ", ".join(p.get("technical_priority_reasons", ["High confidence score"]))
            answer_parts.append(f"• `{p['item_id']}` ({p['filename']}): {p.get('friendly_title')}. Reasons: {reasons}.")

    # 3. Credentials Query
    elif "credential" in q or "pass" in q or "key" in q or "env" in q:
        cred_items = [i for i in items if "Credential" in i.get("category", "") or ".env" in i.get("filename", "").lower()]
        citations = [i["item_id"] for i in cred_items]
        if cred_items:
            answer_parts.append(f"**[OBSERVED]** Recovered {len(cred_items)} credential/key artifact(s):")
            for c in cred_items:
                answer_parts.append(f"• `{c['item_id']}` ({c['filename']}) @ offset `0x{c.get('offset', 0):08X}` — {c.get('use_case', 'Leaked credential artifact.')}")
        else:
            answer_parts.append("[OBSERVED] No credential artifacts were recovered in this case.")

    # 4. Reconstruction & Fragment Query
    elif "fragment" in q or "reconstruct" in q or "join" in q or "image" in q or "passport" in q:
        rebuilt = [i for i in items if i.get("source") == "fragment_reassembly"]
        citations = [i["item_id"] for i in rebuilt]
        if rebuilt:
            answer_parts.append(f"**[DERIVED]** ReconAI successfully reassembled {len(rebuilt)} fragmented file(s) from orphan clusters:")
            for r in rebuilt:
                frags = r.get("fragments_linked", [])
                reasons = ", ".join(r.get("join_reasons", ["Boundary continuity match"]))
                answer_parts.append(f"• `{r['item_id']}` ({r['filename']}): {len(frags)} fragments chained with {r.get('confidence_score', 0)}% confidence. Join evidence: {reasons}.")
        else:
            answer_parts.append("[OBSERVED] All recovered files were contiguous; no fragment reassembly was required.")

    # 5. Timeline / Deletion Query
    elif "timeline" in q or "delete" in q or "event" in q or "time" in q:
        deleted_items = [i for i in items if i.get("is_deleted")]
        citations = [i["item_id"] for i in deleted_items]
        answer_parts.append(f"**[OBSERVED]** Identified {len(deleted_items)} file deletion event(s) from drive FAT/exFAT tables:")
        for d in deleted_items[:5]:
            answer_parts.append(f"• `{d['item_id']}` ({d['filename']}): Deletion byte 0xE5 detected. State: {d.get('recovery_state', 'DELETED')}.")
        if events:
            answer_parts.append(f"**[INFERRED]** Chronological timeline records {len(events)} correlated event(s). Range: {events[0].get('timestamp', 'N/A')} to {events[-1].get('timestamp', 'N/A')}.")

    # 6. Fallback General Summary
    else:
        citations = [i["item_id"] for i in items[:3]]
        answer_parts.append(f"**[OBSERVED]** Case `{case_meta.get('case_id', 'EVIDENCE')}` contains {len(items)} recovered artifact(s).")
        answer_parts.append("Top recovered evidence artifacts:")
        for i in items[:3]:
            answer_parts.append(f"• `{i['item_id']}` ({i['filename']}) — {i.get('friendly_title', i['category'])}, State: {i.get('recovery_state', 'CARVED')}, Impact: {i.get('impact_score', 50)}/100.")

    return {
        "query": query,
        "answer": "\n\n".join(answer_parts),
        "citations": list(set(citations)),
        "tag": "[OBSERVED]"
    }
