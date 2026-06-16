"""Day 10 — cost & latency dashboard.

Runs a sample of real questions through the full RAG pipeline and reports the production economics
hiring managers ask about: latency p50/p95, cost per query, and projected cost at scale. Reads the
per-call metrics the generator already emits (tokens, cost, latency) — no new instrumentation.

Run:
    python -m ops.cost_report --sample 12
"""

from __future__ import annotations

import argparse
import json
import statistics as stats

from eval.retrieval_eval import load_golden
from generation.answer import answer


def pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    i = min(len(s) - 1, int(round((p / 100) * (len(s) - 1))))
    return s[i]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--golden", default="eval/golden_set.jsonl")
    ap.add_argument("--sample", type=int, default=12)
    args = ap.parse_args()

    golden = load_golden(args.golden)[: args.sample]
    latencies, costs, in_toks, out_toks = [], [], [], []
    refused = 0

    print(f"Profiling {len(golden)} queries through the full pipeline…\n")
    for row in golden:
        r = answer(row["question"])
        if r.get("refused"):
            refused += 1
            continue
        if "error" in r:
            continue
        latencies.append(r["latency_ms"])
        costs.append(r["cost_usd"])
        in_toks.append(r["usage"]["input"])
        out_toks.append(r["usage"]["output"])
        print(f"  {r['latency_ms']:>5}ms  ${r['cost_usd']:.5f}  {row['question'][:48]}")

    n = len(costs)
    if not n:
        print("\nNo successful queries to profile.")
        return

    mean_cost = sum(costs) / n
    report = {
        "queries": n,
        "refused": refused,
        "latency_ms": {"p50": pct(latencies, 50), "p95": pct(latencies, 95),
                       "mean": round(stats.mean(latencies))},
        "cost_usd": {"mean": round(mean_cost, 6), "total": round(sum(costs), 5)},
        "tokens": {"in_mean": round(stats.mean(in_toks)), "out_mean": round(stats.mean(out_toks))},
        "projected_usd_per_1k": round(mean_cost * 1000, 2),
    }

    print("\n  ── Sentinel cost & latency ───────────────────")
    print(f"  queries profiled    : {n}  (refused {refused})")
    print(f"  latency p50 / p95   : {report['latency_ms']['p50']} / {report['latency_ms']['p95']} ms")
    print(f"  latency mean        : {report['latency_ms']['mean']} ms")
    print(f"  cost / query (mean) : ${report['cost_usd']['mean']}")
    print(f"  tokens in / out     : {report['tokens']['in_mean']} / {report['tokens']['out_mean']}")
    print(f"  projected / 1k q’s  : ${report['projected_usd_per_1k']}")

    out = "eval/reports/cost_report.json"
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  saved → {out}")


if __name__ == "__main__":
    main()
