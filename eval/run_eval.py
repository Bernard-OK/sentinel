"""The full eval report — Sentinel's headline artifact.

Runs the WHOLE pipeline over the golden set and prints the table the README opens with:

  retrieval : recall@k, MRR                       (retrieval quality, in isolation)
  answers   : faithfulness, hallucination rate    (LLM-judge — are claims grounded?)
              citation accuracy                    (deterministic — are cited CVEs real & retrieved?)
  ops       : mean cost/query, mean latency        (production economics)

Each question costs 2 LLM calls (generate + judge), so this samples by default. The retrieval-only
metrics are fast and live in retrieval_eval.py; CI runs a fixed slice of this.

Run:
    python -m eval.run_eval --sample 10
    python -m eval.run_eval                 # whole golden set (slow + costs tokens)
"""

from __future__ import annotations

import argparse

from eval.faithfulness import judge_faithfulness
from eval.retrieval_eval import KS, MAXK, load_golden
from generation.answer import answer
from retrieval.search import search


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--golden", default="eval/golden_set.jsonl")
    ap.add_argument("--sample", type=int, default=10, help="0 = whole set")
    ap.add_argument("-k", type=int, default=5)
    args = ap.parse_args()

    golden = load_golden(args.golden)
    if args.sample:
        golden = golden[: args.sample]
    print(f"Full pipeline eval on {len(golden)} questions (k={args.k})…\n")

    recall_hits = {k: 0 for k in KS}
    rr_sum = 0.0
    faith_sum = 0.0
    halluc = 0
    cite_acc_sum = 0.0
    cost_sum = 0.0
    lat_sum = 0.0
    n = 0

    for row in golden:
        q = row["question"]
        expected = set(row["expected_cve_ids"])

        # --- retrieval metrics ---
        ranked = [h["cve_id"] for h in search(q, MAXK)]
        first = next((i + 1 for i, c in enumerate(ranked) if c in expected), None)
        rr_sum += 1.0 / first if first else 0.0
        for k in KS:
            if first and first <= k:
                recall_hits[k] += 1

        # --- generate + judge ---
        r = answer(q, args.k)
        if "error" in r:
            continue
        ans = r["answer"]
        verdict = judge_faithfulness(r["context"], ans.summary)

        faith_sum += verdict["faithfulness"]
        halluc += 1 if verdict["hallucinated"] else 0

        # citation accuracy: cited CVEs that were actually retrieved (deterministic)
        cites = ans.citations
        retrieved = set(r["retrieved_ids"])
        cite_acc = (sum(1 for c in cites if c in retrieved) / len(cites)) if cites else 1.0
        cite_acc_sum += cite_acc

        cost_sum += r["cost_usd"]
        lat_sum += r["latency_ms"]
        n += 1

        flag = "  ⚠ hallucination" if verdict["hallucinated"] else ""
        print(f"  ✓ {q[:54]:54}  faith={verdict['faithfulness']:.2f}{flag}")

    print("\n  ── Sentinel eval ─────────────────────────────")
    for k in KS:
        print(f"  retrieval recall@{k:<2} : {recall_hits[k]/len(golden):.3f}")
    print(f"  retrieval MRR       : {rr_sum/len(golden):.3f}")
    print(f"  answer faithfulness : {faith_sum/n:.3f}")
    print(f"  hallucination rate  : {halluc/n:.3f}  ({halluc}/{n} answers)")
    print(f"  citation accuracy   : {cite_acc_sum/n:.3f}")
    print(f"  mean cost / query   : ${cost_sum/n:.5f}")
    print(f"  mean latency        : {lat_sum/n:.0f} ms")


if __name__ == "__main__":
    main()
