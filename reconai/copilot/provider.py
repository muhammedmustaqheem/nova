"""
ReconAI AI Provider Abstraction Module
Supports OpenAI, Gemini, Claude (Anthropic), and Local Grounded Fallback Provider.
Reads credentials safely from environment variables.
"""

import os
import json
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional, Tuple
from reconai.copilot.prompts import COPILOT_SYSTEM_PROMPT

class AIProvider:
    def generate_grounded_answer(
        self,
        question: str,
        context_str: str,
        citations: List[Dict[str, Any]]
    ) -> str:
        raise NotImplementedError

class OpenAIProvider(AIProvider):
    def __init__(self, api_key: str):
        self.api_key = api_key

    def generate_grounded_answer(
        self,
        question: str,
        context_str: str,
        citations: List[Dict[str, Any]]
    ) -> str:
        url = "https://api.openai.com/v1/chat/completions"
        payload = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": COPILOT_SYSTEM_PROMPT},
                {"role": "user", "content": f"USER QUESTION: {question}\n\nEVIDENCE CONTEXT:\n{context_str}"}
            ],
            "temperature": 0.1
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]

class GeminiProvider(AIProvider):
    def __init__(self, api_key: str):
        self.api_key = api_key

    def generate_grounded_answer(
        self,
        question: str,
        context_str: str,
        citations: List[Dict[str, Any]]
    ) -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.api_key}"
        prompt = f"{COPILOT_SYSTEM_PROMPT}\n\nUSER QUESTION: {question}\n\nEVIDENCE CONTEXT:\n{context_str}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}]
        }
        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["candidates"][0]["content"]["parts"][0]["text"]

class ClaudeProvider(AIProvider):
    def __init__(self, api_key: str):
        self.api_key = api_key

    def generate_grounded_answer(
        self,
        question: str,
        context_str: str,
        citations: List[Dict[str, Any]]
    ) -> str:
        url = "https://api.anthropic.com/v1/messages"
        payload = {
            "model": "claude-3-haiku-20240307",
            "max_tokens": 1024,
            "system": COPILOT_SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": f"USER QUESTION: {question}\n\nEVIDENCE CONTEXT:\n{context_str}"}
            ]
        }
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01"
        }
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["content"][0]["text"]

class LocalGroundedRAGProvider(AIProvider):
    """
    Deterministic evidence-grounded RAG provider used when external API keys are not provided.
    Ensures 100% demo functionality without inventing fake data or calling external servers.
    """
    def generate_grounded_answer(
        self,
        question: str,
        context_str: str,
        citations: List[Dict[str, Any]]
    ) -> str:
        if not citations:
            return "Insufficient indexed evidence to answer this question."

        q = question.lower()
        parts = []

        if "credential" in q or "pass" in q or "key" in q or "env" in q:
            arts = [c for c in citations if c["type"] == "artifact"]
            parts.append(f"[OBSERVED] Identified {len(arts)} recovered evidence artifact(s) containing credentials or access keys:")
            for a in arts:
                parts.append(f"• [{a['id']}] — {a['name']}")

        elif "ip" in q or "network" in q or "c2" in q:
            arts = [c for c in citations if c["type"] == "artifact"]
            evs = [c for c in citations if c["type"] == "timeline_event"]
            parts.append(f"[OBSERVED] Network intelligence correlation found {len(arts)} artifact(s) and {len(evs)} timeline event(s):")
            for a in arts:
                parts.append(f"• [{a['id']}] — {a['name']}")
            for e in evs:
                parts.append(f"• [{e['id']}] — {e['name']}")

        elif "reconstruct" in q or "fragment" in q or "stitch" in q:
            arts = [c for c in citations if c["type"] == "artifact"]
            parts.append(f"[DERIVED] ReconAI reassembled {len(arts)} fragmented file(s) with structural integrity checks:")
            for a in arts:
                parts.append(f"• [{a['id']}] — {a['name']}")

        else:
            parts.append(f"[OBSERVED] Retrieved {len(citations)} indexed evidence record(s) matching your query:")
            for c in citations[:4]:
                parts.append(f"• [{c['id']}] — {c['name']}")

        return "\n\n".join(parts)


def get_configured_ai_provider() -> Tuple[AIProvider, str]:
    """
    Instantiates the configured AI provider based on AI_PROVIDER environment variable or available keys.
    Returns (provider_instance, provider_name).
    """
    pref_provider = os.getenv("AI_PROVIDER", "").lower()
    openai_key = os.getenv("OPENAI_API_KEY", "")
    gemini_key = os.getenv("GEMINI_API_KEY", "")
    claude_key = os.getenv("ANTHROPIC_API_KEY", "")

    if pref_provider == "openai" and openai_key:
        return OpenAIProvider(openai_key), "OpenAI (GPT-4o-mini)"
    elif pref_provider == "gemini" and gemini_key:
        return GeminiProvider(gemini_key), "Google Gemini 1.5"
    elif pref_provider == "anthropic" and claude_key:
        return ClaudeProvider(claude_key), "Anthropic Claude 3"

    # Automatic Key Discovery
    if openai_key:
        return OpenAIProvider(openai_key), "OpenAI (GPT-4o-mini)"
    if gemini_key:
        return GeminiProvider(gemini_key), "Google Gemini 1.5"
    if claude_key:
        return ClaudeProvider(claude_key), "Anthropic Claude 3"

    # Local Grounded RAG Fallback
    return LocalGroundedRAGProvider(), "ReconAI Local Evidence-Grounded Engine"
