"""
ReconAI Relationship Graph Engine
Constructs a forensic NetworkX relationship graph linking fragments, recovered files,
extraction sources, and cross-artifact investigative entities (IPs, Wallets, Credentials).
Exports to an interactive dark-themed Pyvis visualization for Streamlit.
"""

import re
import networkx as nx
from typing import List, Dict, Any, Optional

def build_forensic_graph(
    case_meta: Dict[str, Any],
    recovered_items: List[Dict[str, Any]],
    fragments: List[Dict[str, Any]]
) -> nx.Graph:
    """
    Constructs a multi-layer forensic knowledge graph linking:
    Evidence Disk -> Recovery Sources -> Recovered Files -> Fragments & Extracted Entities.
    """
    G = nx.Graph()

    # 1. Evidence Root Node
    case_id = case_meta.get("case_id", "EVIDENCE_DISK")
    image_name = case_meta.get("filename", "Evidence Image")
    G.add_node(
        "evidence_root",
        label=image_name,
        title=f"Case: {case_id}\nSHA-256: {case_meta.get('image_sha256', '')[:16]}...",
        color="#F59E0B",
        shape="star",
        size=35,
        group="root"
    )

    # 2. Source Clusters
    sources = {
        "filesystem_undelete": ("Filesystem Metadata", "#3B82F6"),
        "signature_carving": ("Raw Sector Carver", "#6366F1"),
        "fragment_reassembly": ("AI Reassembler", "#EC4899")
    }

    for src_key, (src_label, src_color) in sources.items():
        node_id = f"src_{src_key}"
        G.add_node(
            node_id,
            label=src_label,
            title=f"Source Pipeline: {src_label}",
            color=src_color,
            shape="hexagon",
            size=22,
            group="source"
        )
        G.add_edge("evidence_root", node_id, label="INGESTED_FROM", color="#4B5563")

    # 3. Recovered Artifacts
    for item in recovered_items:
        item_id = item.get("item_id", "")
        fn = item.get("filename", "unknown")
        status = item.get("integrity_status", "UNKNOWN")
        source = item.get("source", "filesystem_undelete")
        score = item.get("integrity_score", 0.0)
        p_score = item.get("priority_score", 0.0)
        cat = item.get("category", "General")

        # Color based on integrity status
        if status == "INTACT":
            node_color = "#10B981"  # Emerald
        elif status == "PARTIAL":
            node_color = "#F59E0B"  # Amber
        else:
            node_color = "#EF4444"  # Crimson

        scope = item.get("artifact_scope", "User Evidence File")
        is_user = (scope == "User Evidence File")

        tooltip = (
            f"[{scope.upper()}]\n"
            f"File: {fn}\n"
            f"Category: {cat}\n"
            f"Status: {status} ({score}%)\n"
            f"Priority Score: {p_score}\n"
            f"Size: {item.get('size_bytes', 0)} bytes\n"
            f"Offset: 0x{item.get('offset', 0):08X}"
        )

        G.add_node(
            item_id,
            label=f"{'👤 ' if is_user else '🖥️ '}{fn}",
            title=tooltip,
            color=node_color,
            shape="dot" if is_user else "box",
            size=22 if is_user else 15,
            group="user_evidence" if is_user else "system_file"
        )

        # Edge from source cluster
        src_node = f"src_{source}"
        if src_node in G:
            G.add_edge(src_node, item_id, label="EXTRACTED", color="#6B7280")

        # 4. Check if item was reassembled from fragments
        details = item.get("details", {})
        linked_frags = item.get("fragments_linked") or details.get("fragments_linked", [])
        for lf in linked_frags:
            fid = lf.get("fragment_id")
            if fid:
                frag_node = f"frag_{fid}"
                G.add_node(
                    frag_node,
                    label=f"Frag 0x{lf.get('offset', 0):X}",
                    title=f"Fragment: {fid}\nType: {lf.get('type')}\nOffset: 0x{lf.get('offset', 0):X}\nSize: {lf.get('size')} B",
                    color="#00F2FE",  # Cyan
                    shape="diamond",
                    size=14,
                    group="fragment"
                )
                conf = item.get("confidence_score", 100.0)
                G.add_edge(item_id, frag_node, label=f"REASSEMBLED ({conf}%)", color="#00F2FE", dashes=True)

        # 5. Extract forensic entities (Wallets, IPs, Credentials) from preview to create relationship links
        preview = item.get("content_preview", "")
        # Crypto wallet link
        wallets = re.findall(r"0x[a-fA-F0-9]{40}", preview)
        for w in set(wallets):
            w_node = f"ent_wallet_{w[:10]}"
            G.add_node(w_node, label=f"Wallet {w[:8]}..", title=f"Crypto Wallet: {w}", color="#A855F7", shape="square", size=15)
            G.add_edge(item_id, w_node, label="REFERENCES", color="#A855F7")

        # IP address link
        ips = re.findall(r"\b(?:(?:198\.51|203\.0|10\.)[0-9]{1,3}\.[0-9]{1,3})\b", preview)
        for ip in set(ips):
            ip_node = f"ent_ip_{ip}"
            G.add_node(ip_node, label=f"IP: {ip}", title=f"Forensic IP Node: {ip}", color="#EC4899", shape="triangle", size=15)
            G.add_edge(item_id, ip_node, label="NETWORK_HOST", color="#EC4899")

    # 6. Unmatched orphan fragments
    for frag in fragments:
        fid = frag.get("fragment_id", "")
        frag_node = f"frag_{fid}"
        if frag_node not in G:
            G.add_node(
                frag_node,
                label=f"Orphan {frag.get('frag_type', '')}",
                title=f"Unmatched Orphan Fragment: {fid}\nOffset: 0x{frag.get('offset', 0):X}\nFormat: {frag.get('predicted_format')}",
                color="#94A3B8",
                shape="diamond",
                size=12,
                group="orphan"
            )
            src_node = "src_signature_carving"
            if src_node in G:
                G.add_edge(src_node, frag_node, label="ORPHAN", color="#475569", dashes=True)

    return G

def generate_interactive_pyvis_html(G: nx.Graph, height: str = "600px") -> str:
    """
    Renders NetworkX graph into an interactive Pyvis visualization
    styled with ReconAI's dark cyber forensic theme.
    """
    from pyvis.network import Network

    net = Network(height=height, width="100%", bgcolor="#0B0F19", font_color="#E2E8F0")
    net.from_nx(G)

    # Configure physics for smooth layout
    options = {
        "nodes": {
            "font": {"size": 13, "face": "Courier New, monospace", "color": "#F8FAFC"},
            "borderWidth": 2,
            "shadow": True
        },
        "edges": {
            "color": {"inherit": False, "opacity": 0.7},
            "smooth": {"type": "continuous"},
            "font": {"size": 10, "color": "#94A3B8", "strokeWidth": 0}
        },
        "physics": {
            "forceAtlas2Based": {
                "gravitationalConstant": -50,
                "centralGravity": 0.01,
                "springLength": 100,
                "springConstant": 0.08,
                "damping": 0.4
            },
            "minVelocity": 0.75,
            "solver": "forceAtlas2Based"
        },
        "interaction": {
            "hover": True,
            "navigationButtons": True,
            "tooltipDelay": 100
        }
    }
    import json
    net.set_options(json.dumps(options))
    return net.generate_html()
