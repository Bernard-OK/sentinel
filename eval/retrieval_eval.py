"""Retrieval metrics — Day 3. The first real numbers Sentinel can stand behind.

For each golden row, retrieve top-k and check whether the expected CVE id(s) show up.

  recall@k : did an expected id appear anywhere in the top-k?      (averaged over questions)
  MRR      : mean of 1/rank of the first correct hit                (rewards ranking it high)

We also print the worst misses — error analysis is how you actually improve retrieval, and
"here's what my system gets wrong and why" is a strong interview signal.

Run:
    python -m eval.retrieval_eval
    python -m eval.retrieval_eval --golden eval/golden_set.jsonl
"""

from __future__ import annotations

import argparse
import json

from retrieval.search import search

KS = (1, 3, 5, 10)
MAXK = max(KS)


def retrieve(query: str, k: int, mode: str) -> list[str]:
    """Return ranked CVE ids for the chosen retrieval mode."""
    if mode == "vector":
        return [h["cve_id"] for h in search(query, k)]
    from retrieval.hybrid import hybrid_search

    return [h["cve_id"] for h in hybrid_search(query, k, rerank=(mode == "rerank"))]


def load_golden(path: str) -> list[dict]:
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if "_comment" in obj or not obj.get("expected_cve_ids"):
                continue
            rows.append(obj)
    return rows


def evaluate(golden: list[dict], mode: str = "vector") -> dict:
    recall_hits = {k: 0 for k in KS}
    reciprocal_ranks = []
    misses = []

    for row in golden:
        expected = set(row["expected_cve_ids"])
        ranked = retrieve(row["question"], MAXK, mode)

        # first rank at which we hit an expected id
        first_rank = next((i + 1 for i, cid in enumerate(ranked) if cid in expected), None)
        reciprocal_ranks.append(1.0 / first_rank if first_rank else 0.0)
        for k in KS:
            if first_rank and first_rank <= k:
                recall_hits[k] += 1
        if first_rank is None:
            misses.append((row["question"], list(expected)[0], ranked[:3]))

    n = len(golden)
    return {
        "n": n,
        "recall": {k: round(recall_hits[k] / n, 3) for k in KS},
        "mrr": round(sum(reciprocal_ranks) / n, 3),
        "misses": misses,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--golden", default="eval/golden_set.jsonl")
    ap.add_argument("--mode", choices=["vector", "hybrid", "rerank", "compare"], default="vector")
    args = ap.parse_args()

    golden = load_golden(args.golden)

    if args.mode == "compare":
        print(f"Comparing retrieval modes on {len(golden)} questions …\n")
        header = f"  {'mode':8} " + "  ".join(f"R@{k}" for k in KS) + "   MRR"
        print(header)
        print("  " + "─" * (len(header) - 2))
        for mode in ("vector", "hybrid", "rerank"):
            r = evaluate(golden, mode)
            cells = "  ".join(f"{r['recall'][k]:.2f}" for k in KS)
            print(f"  {mode:8} {cells}   {r['mrr']:.2f}")
        return

    print(f"Evaluating retrieval ({args.mode}) on {len(golden)} golden questions …\n")
    r = evaluate(golden, args.mode)
    print("  Retrieval results")
    print("  ─────────────────")
    for k in KS:
        print(f"  recall@{k:<2} : {r['recall'][k]}")
    print(f"  MRR     : {r['mrr']}")

    if r["misses"]:
        print(f"\n  {len(r['misses'])} misses (expected CVE not in top-{MAXK}):")
        for q, expected, got in r["misses"][:8]:
            print(f"   ✗ {q}")
            print(f"     expected {expected}, got {got}")


if __name__ == "__main__":
    main()
