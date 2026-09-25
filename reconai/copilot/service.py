"""
ReconAI Copilot Service Orchestrator
Main entry point for evidence-grounded queries.
"""

from typing import Dict, Any, List
from reconai.copilot.retriever import retrieve_relevant_evidence
from reconai.copilot.context_builder import build_evidence_context
from reconai.copilot.provider import get_configured_ai_provider

def ask_copilot(
    question: str,
    case_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Executes end-to-end evidence retrieval, context formatting, and AI provider answer generation.
    Returns structured JSON output.
    """
    if not question or not question.strip():
        return {
            "success": False,
            "answer": "Please provide a valid question regarding the indexed forensic evidence.",
            "citations": [],
            "evidence_count": 0,
            "grounded": False
        }

    # 1. Evidence Retrieval Layer
    retrieved = retrieve_relevant_evidence(question, case_data)
    if retrieved["total_found"] == 0:
        return {
            "success": True,
            "answer": "Insufficient indexed evidence to answer this question.",
            "citations": [],
            "evidence_count": 0,
            "grounded": False
        }

    # 2. Context Builder Layer
    case_id = case_data.get("case", {}).get("case_id", "EVIDENCE-CASE")
    context_str, citations = build_evidence_context(retrieved, case_id)

    # 3. Provider Layer Selection
    provider, provider_name = get_configured_ai_provider()

    try:
        raw_answer = provider.generate_grounded_answer(
            question=question,
            context_str=context_str,
            citations=citations
        )
    except Exception as err:
        return {
            "success": False,
            "answer": f"AI provider error: {str(err)[:120]}. Configure an AI API key (OPENAI_API_KEY, GEMINI_API_KEY, ANTHROPIC_API_KEY) or check network connection.",
            "citations": citations,
            "evidence_count": len(citations),
            "grounded": False
        }

    return {
        "success": True,
        "answer": raw_answer,
        "citations": citations,
        "evidence_count": len(citations),
        "grounded": True,
        "provider": provider_name
    }
