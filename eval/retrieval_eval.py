"""Retrieval metrics — Day 3 (this is where the first real numbers come from).

For each row in golden_set.jsonl, run retrieval and check whether the expected CVE ids
appear in the top-k results.

  recall@k : fraction of expected ids found in top-k
  MRR      : mean reciprocal rank of the first correct hit

Built BEFORE the generator (eval-first) so retrieval quality is measured in isolation.
"""
