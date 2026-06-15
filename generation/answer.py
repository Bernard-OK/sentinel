"""Day 4 — grounded, cited answer generation with Claude.

Pipeline:  question → retrieve top-k CVE context → Claude (Sonnet 4.6) → structured cited answer

We use the Anthropic SDK's `messages.parse()` with a Pydantic schema, so the model is *forced*
to return valid structured output — no fragile JSON parsing. The system prompt instructs the
model to answer ONLY from the retrieved context and to cite CVE ids (the seed of the guardrail
we harden later). Token usage + latency are captured per call to seed the cost dashboard.

Model choice (deliberate, for the cost story): Sonnet 4.6 for generation — strong grounded-answer
quality at $3/$15 per 1M tokens. Haiku 4.5 ($1/$5) is reserved for the LLM-judge on Day 5.

CLI:
    python -m generation.answer "What is the risk of an authentication bypass in OpenEMR?"
"""

from __future__ import annotations

import argparse
import os
import time

import anthropic
import psycopg
from dotenv import load_dotenv
from pydantic import BaseModel, Field

from retrieval.search import search

load_dotenv()

GEN_MODEL = os.getenv("GEN_MODEL", "claude-sonnet-4-6")
DATABASE_URL = os.environ["DATABASE_URL"]

# $ per 1M tokens (input, output) — authoritative rates, for the cost dashboard
PRICING = {
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5-20251001": (1.0, 5.0),
}


class CitedAnswer(BaseModel):
    """The structured shape Claude must return."""

    summary: str = Field(description="2-4 sentence grounded answer to the question.")
    severity: str = Field(description="Critical / High / Medium / Low / Unknown.")
    exploitation_status: str = Field(
        description="actively-exploited / proof-of-concept / none-known / unknown."
    )
    affected_products: list[str] = Field(description="Products/versions named in the context.")
    remediation: str = Field(description="Concrete remediation if the context states one.")
    citations: list[str] = Field(
        description="CVE ids actually used to support the answer. MUST come from the context."
    )


SYSTEM = (
    "You are a security analyst assistant. Answer the user's question using ONLY the CVE context "
    "provided in the user message. Every claim must be supported by that context. Cite the CVE "
    "ids you used. If the context does not contain enough information to answer, say so plainly in "
    "the summary, set severity and exploitation_status to 'unknown', and return an empty citations "
    "list. Never invent CVE ids, products, or remediations that are not in the context."
)


def build_context(query: str, k: int = 5) -> tuple[str, list[str]]:
    """Retrieve top-k CVEs and format them as grounding context (full descriptions)."""
    hits = search(query, k)
    ids = [h["cve_id"] for h in hits]
    if not ids:
        return "", []

    with psycopg.connect(DATABASE_URL) as conn:
        rows = conn.execute(
            """SELECT cve_id, description, cvss_score, epss, in_kev, cpes
               FROM cves WHERE cve_id = ANY(%s)""",
            (ids,),
        ).fetchall()
    by_id = {r[0]: r for r in rows}

    blocks = []
    for cid in ids:  # preserve retrieval order
        r = by_id.get(cid)
        if not r:
            continue
        _, desc, cvss, epss, in_kev, cpes = r
        flags = []
        if in_kev:
            flags.append("ACTIVELY EXPLOITED (CISA KEV)")
        if cvss is not None:
            flags.append(f"CVSS {cvss}")
        if epss is not None:
            flags.append(f"EPSS {epss}")
        header = f"[{cid}]" + (f" ({', '.join(flags)})" if flags else "")
        blocks.append(f"{header}\n{desc}")

    return "\n\n".join(blocks), ids


def answer(query: str, k: int = 5) -> dict:
    context, retrieved_ids = build_context(query, k)
    if not context:
        return {"error": "no context retrieved"}

    client = anthropic.Anthropic()
    user_msg = f"CVE context:\n\n{context}\n\n---\n\nQuestion: {query}"

    t0 = time.monotonic()
    resp = client.messages.parse(
        model=GEN_MODEL,
        max_tokens=2000,
        system=SYSTEM,
        messages=[{"role": "user", "content": user_msg}],
        output_format=CitedAnswer,
    )
    latency_ms = round((time.monotonic() - t0) * 1000)

    parsed: CitedAnswer | None = resp.parsed_output
    usage = resp.usage
    in_rate, out_rate = PRICING.get(GEN_MODEL, (0, 0))
    cost = (usage.input_tokens * in_rate + usage.output_tokens * out_rate) / 1_000_000

    return {
        "answer": parsed,
        "retrieved_ids": retrieved_ids,
        "usage": {"input": usage.input_tokens, "output": usage.output_tokens},
        "cost_usd": round(cost, 6),
        "latency_ms": latency_ms,
        "stop_reason": resp.stop_reason,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("query")
    ap.add_argument("-k", type=int, default=5)
    args = ap.parse_args()

    r = answer(args.query, args.k)
    if "error" in r:
        print(r["error"])
        return

    a: CitedAnswer = r["answer"]
    print(f"\n\033[1mSUMMARY\033[0m\n{a.summary}\n")
    print(f"Severity     : {a.severity}")
    print(f"Exploitation : {a.exploitation_status}")
    print(f"Affected     : {', '.join(a.affected_products) or '—'}")
    print(f"Remediation  : {a.remediation}")
    print(f"Citations    : {', '.join(a.citations) or '— (insufficient context)'}")
    print(
        f"\n\033[2mretrieved={r['retrieved_ids']}  "
        f"tokens={r['usage']['input']}+{r['usage']['output']}  "
        f"cost=${r['cost_usd']}  {r['latency_ms']}ms  stop={r['stop_reason']}\033[0m"
    )


if __name__ == "__main__":
    main()
