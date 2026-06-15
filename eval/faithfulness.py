"""Faithfulness + citation + hallucination — Day 5. The headline trust metrics.

LLM-as-judge (Claude Haiku 4.5 — cheap, fast) decomposes a generated answer into atomic
factual claims and checks each against the retrieved context:

  faithfulness   : supported_claims / total_claims          (per answer; mean over the set)
  hallucinated   : the answer has >= 1 unsupported claim     (→ hallucination rate over the set)

Citation accuracy is computed deterministically in run_eval (no LLM needed): every cited CVE id
must be one that was actually retrieved.

You write the judge prompt yourself, so you can defend every design choice in an interview; ragas
is the industry comparison. We use a SEPARATE, cheaper model as judge (not the generator) so the
judge isn't graded by the same model that wrote the answer.
"""

from __future__ import annotations

import os

import anthropic
from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()
JUDGE_MODEL = os.getenv("JUDGE_MODEL", "claude-haiku-4-5-20251001")


class ClaimCheck(BaseModel):
    claim: str = Field(description="One atomic factual claim extracted from the answer.")
    supported: bool = Field(description="True only if directly supported by the context.")
    note: str = Field(description="Brief reason — which CVE supports it, or why it isn't supported.")


class FaithfulnessVerdict(BaseModel):
    claims: list[ClaimCheck]


JUDGE_SYSTEM = (
    "You are a strict evaluation judge. You are given CONTEXT (CVE records) and an ANSWER produced "
    "from that context. Break the ANSWER into atomic factual claims. For each claim, decide whether "
    "it is DIRECTLY supported by the CONTEXT. Be strict: a claim that adds a detail, number, "
    "product, or remediation not present in the CONTEXT is NOT supported. General phrasing that "
    "merely restates the question is not a factual claim — skip it. Judge only against the CONTEXT, "
    "never your own knowledge."
)


def judge_faithfulness(context: str, answer_summary: str) -> dict:
    client = anthropic.Anthropic()
    resp = client.messages.parse(
        model=JUDGE_MODEL,
        max_tokens=1500,
        system=JUDGE_SYSTEM,
        messages=[
            {"role": "user", "content": f"CONTEXT:\n{context}\n\n---\n\nANSWER:\n{answer_summary}"}
        ],
        output_format=FaithfulnessVerdict,
    )
    verdict: FaithfulnessVerdict | None = resp.parsed_output
    claims = verdict.claims if verdict else []
    n = len(claims)
    supported = sum(1 for c in claims if c.supported)

    return {
        "n_claims": n,
        "n_supported": supported,
        "faithfulness": (supported / n) if n else 1.0,  # no claims → nothing to be unfaithful about
        "hallucinated": any(not c.supported for c in claims),
        "unsupported": [c.claim for c in claims if not c.supported],
    }
