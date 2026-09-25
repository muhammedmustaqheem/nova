"""
ReconAI Natural Language Semantic Search Engine
Embeds recovered artifacts and re-ranks search results by relevance × integrity score.
Supports sentence-transformers (all-MiniLM-L6-v2) when cached, with a fast,
high-precision TF-IDF + semantic vectorizer fallback for instant offline execution.
"""

import os
import re
import numpy as np
from typing import List, Dict, Any, Optional

_SENTENCE_MODEL = None
_MODEL_LOAD_FAILED = False

def get_sentence_transformer():
    """Lazily load sentence-transformers model ONLY if cached locally to avoid network stalls."""
    global _SENTENCE_MODEL, _MODEL_LOAD_FAILED
    if _MODEL_LOAD_FAILED:
        return None
    if _SENTENCE_MODEL is not None:
        return _SENTENCE_MODEL

    # Check if user explicitly disabled or if local cache doesn't exist
    hf_cache = os.path.expanduser("~/.cache/huggingface/hub")
    has_cached_model = False
    if os.path.exists(hf_cache):
        for root, dirs, files in os.walk(hf_cache):
            if "all-MiniLM-L6-v2" in root and any(f.endswith(".bin") or f.endswith(".safetensors") for f in files):
                has_cached_model = True
                break

    if not has_cached_model:
        # Avoid hanging on network requests; use instant high-precision TF-IDF
        _MODEL_LOAD_FAILED = True
        return None

    try:
        from sentence_transformers import SentenceTransformer
        _SENTENCE_MODEL = SentenceTransformer('all-MiniLM-L6-v2', local_files_only=True)
        return _SENTENCE_MODEL
    except Exception:
        _MODEL_LOAD_FAILED = True
        return None

def _cosine_similarity(v1: np.ndarray, v2: np.ndarray) -> float:
    dot = np.dot(v1, v2)
    norm1 = np.linalg.norm(v1)
    norm2 = np.linalg.norm(v2)
    if norm1 == 0 or norm2 == 0:
        return 0.0
    return float(dot / (norm1 * norm2))

def search_recovered_items(query: str, items: List[Dict[str, Any]], top_k: int = 20) -> List[Dict[str, Any]]:
    """
    Performs natural language semantic search across recovered items
    and re-ranks candidates by relevance × integrity score.
    """
    if not query or not query.strip() or not items:
        return []

    query = query.strip()
    corpus_texts = []
    for item in items:
        fn = item.get("filename", "")
        cat = item.get("category", "")
        preview = item.get("content_preview", "")
        details = item.get("details", {})
        det_str = " ".join(f"{k}:{v}" for k, v in details.items() if isinstance(v, (str, int, float)))
        full_text = f"{fn} {cat} {det_str} {preview}"
        corpus_texts.append(full_text)

    model = get_sentence_transformer()
    relevance_scores = []
    engine_name = "Neural (all-MiniLM-L6-v2)" if model is not None else "Semantic TF-IDF Vectorizer"

    if model is not None:
        try:
            query_emb = model.encode(query, convert_to_numpy=True)
            doc_embs = model.encode(corpus_texts, convert_to_numpy=True)
            for doc_emb in doc_embs:
                score = _cosine_similarity(query_emb, doc_emb)
                relevance_scores.append(max(0.0, score))
        except Exception:
            model = None
            engine_name = "Semantic TF-IDF Vectorizer"

    if model is None:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity

        vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words='english', token_pattern=r"(?u)\b\w+\b|[^\s\w]")
        try:
            all_texts = [query] + corpus_texts
            tfidf_matrix = vectorizer.fit_transform(all_texts)
            query_vec = tfidf_matrix[0:1]
            doc_vecs = tfidf_matrix[1:]
            sims = cosine_similarity(query_vec, doc_vecs)[0]
            relevance_scores = [float(s) for s in sims]
        except Exception:
            q_words = query.lower().split()
            relevance_scores = []
            for text in corpus_texts:
                t_lower = text.lower()
                matches = sum(1 for w in q_words if w in t_lower)
                relevance_scores.append(matches / max(1, len(q_words)))

    # Re-rank candidates: Relevance × Integrity
    ranked_results = []
    for i, item in enumerate(items):
        raw_rel = relevance_scores[i] if i < len(relevance_scores) else 0.0
        integrity = float(item.get("integrity_score", 50.0))

        # Re-ranking equation: Relevance × (0.4 + 0.6 * (Integrity / 100))
        integrity_multiplier = 0.4 + 0.6 * (integrity / 100.0)
        final_rank_score = round(raw_rel * integrity_multiplier * 100.0, 1)

        preview = item.get("content_preview", "")
        highlight = _find_best_snippet(query, preview)

        ranked_results.append({
            "item": item,
            "relevance_score": round(raw_rel * 100.0, 1),
            "final_rank_score": final_rank_score,
            "snippet": highlight,
            "engine": engine_name
        })

    # Sort descending by final rank score and filter out zero-relevance items
    ranked_results.sort(key=lambda x: x["final_rank_score"], reverse=True)
    matching_results = [r for r in ranked_results if r["final_rank_score"] > 0.0]
    return matching_results[:top_k]

def _find_best_snippet(query: str, text: str, max_chars: int = 240) -> str:
    """Finds best matching snippet around query keywords."""
    if not text:
        return "No text preview available."

    words = [re.escape(w) for w in query.split() if len(w) > 2]
    if not words:
        return text[:max_chars]

    pattern = re.compile("|".join(words), re.IGNORECASE)
    match = pattern.search(text)
    if not match:
        return text[:max_chars]

    start = max(0, match.start() - 60)
    end = min(len(text), match.end() + 140)
    snippet = text[start:end].replace('\n', ' ')
    if start > 0:
        snippet = "..." + snippet
    if end < len(text):
        snippet = snippet + "..."
    return snippet
