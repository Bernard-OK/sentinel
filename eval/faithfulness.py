"""Faithfulness + citation + hallucination — Day 5.

LLM-as-judge (Claude Haiku 4.5) scores each generated answer against its retrieved context:
  faithfulness     : is every claim supported by the context?  (0-1)
  citation_accuracy: do cited CVE ids exist in the retrieved set and support the claim?
  hallucination    : any claim with no support → flagged

You write the judge prompt yourself (so you can defend it in an interview); ragas is the
industry comparison.
"""
