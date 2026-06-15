"""The full eval report — the headline artifact of Sentinel.

Run:  python -m eval.run_eval

Pulls together (built across Week 1):
  - retrieval_eval.py   recall@k, MRR              (Day 3)
  - faithfulness.py     LLM-judge groundedness     (Day 5)
  - citation accuracy + hallucination rate         (Day 5)
  - cost + latency      from Langfuse traces        (Week 2)

Prints a table and writes eval/reports/<timestamp>.json so results are tracked over time.
CI (.github/workflows/eval.yml) runs a fixed slice of this on every PR and fails on regression.
"""

from __future__ import annotations


def main() -> None:
    raise NotImplementedError("Built across Week 1 — starts Day 3 with retrieval metrics")


if __name__ == "__main__":
    main()
