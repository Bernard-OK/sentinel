"""Day 9 — guardrails: refuse on low confidence, enforce citations.

Two trust mechanisms that make Sentinel safe to act on:

  confidence gate    : if the best retrieval similarity is below MIN_CONFIDENCE, refuse to answer
                       (the question is out-of-corpus) instead of letting the LLM improvise.
  citation enforcement: after generation, any cited CVE id that was NOT in the retrieved context is
                        stripped and flagged — the model cannot "cite" something it never saw.

"It refuses to guess" is the property that lets a security team trust the output.
"""

from __future__ import annotations

from retrieval.search import search

# Calibrated from data: in-corpus queries score 0.77-0.86, out-of-corpus 0.48-0.51 → 0.60 splits cleanly.
MIN_CONFIDENCE = 0.60


def retrieval_confidence(query: str) -> float:
    """Top vector-similarity score for the query — a cheap out-of-corpus detector."""
    hits = search(query, 1)
    return hits[0]["score"] if hits else 0.0


def confidence_gate(query: str) -> tuple[bool, float]:
    """(passes, score). passes=False → the corpus likely can't answer this; refuse."""
    score = retrieval_confidence(query)
    return score >= MIN_CONFIDENCE, score


def enforce_citations(citations: list[str], retrieved_ids: list[str]) -> tuple[list[str], list[str]]:
    """Split cited ids into (valid = actually retrieved, invalid = fabricated/not in context)."""
    retrieved = set(retrieved_ids)
    valid = [c for c in citations if c in retrieved]
    invalid = [c for c in citations if c not in retrieved]
    return valid, invalid
