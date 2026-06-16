"""Day 7 — hybrid retrieval: vector + keyword, fused, then reranked.

Vector search alone misses exact identifiers (product names, CWE phrasing). Keyword search alone
misses paraphrase. We run BOTH, fuse with Reciprocal Rank Fusion (RRF), then optionally rerank the
fused pool with a cross-encoder for the final ordering.

  vector  : bge-small cosine over pgvector              (semantic)
  keyword : Postgres full-text (ts_rank)                 (lexical / exact terms)
  fuse    : RRF — score = Σ 1/(K + rank_in_list)         (rank-based, scale-free)
  rerank  : cross-encoder scores (query, passage) pairs  (precision at the top)

CLI:
    python -m retrieval.hybrid "remote code execution in apache" -k 5
"""

from __future__ import annotations

import argparse
import functools
import os

import psycopg
from dotenv import load_dotenv
from pgvector.psycopg import register_vector
from sentence_transformers import CrossEncoder

from retrieval.search import QUERY_PREFIX, _model

load_dotenv()
DATABASE_URL = os.environ["DATABASE_URL"]
RRF_K = 60          # standard RRF constant
CANDIDATE_POOL = 25  # how many fused candidates to feed the reranker
RERANK_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"


@functools.lru_cache(maxsize=1)
def _reranker() -> CrossEncoder:
    return CrossEncoder(RERANK_MODEL)


def vector_rank(conn, query: str, k: int) -> list[str]:
    qvec = _model().encode(QUERY_PREFIX + query, normalize_embeddings=True)
    rows = conn.execute(
        "SELECT cve_id FROM chunks ORDER BY embedding <=> %s LIMIT %s", (qvec, k)
    ).fetchall()
    return [r[0] for r in rows]


def keyword_rank(conn, query: str, k: int) -> list[str]:
    rows = conn.execute(
        """SELECT cve_id
           FROM chunks
           WHERE ts @@ websearch_to_tsquery('english', %s)
           ORDER BY ts_rank(ts, websearch_to_tsquery('english', %s)) DESC
           LIMIT %s""",
        (query, query, k),
    ).fetchall()
    return [r[0] for r in rows]


def rrf(rankings: list[list[str]], k: int) -> list[str]:
    """Reciprocal Rank Fusion — combine ranked lists by rank, not raw score."""
    scores: dict[str, float] = {}
    for ranking in rankings:
        for rank, cve_id in enumerate(ranking, start=1):
            scores[cve_id] = scores.get(cve_id, 0.0) + 1.0 / (RRF_K + rank)
    return sorted(scores, key=scores.get, reverse=True)[:k]


def hybrid_search(query: str, k: int = 5, rerank: bool = True) -> list[dict]:
    with psycopg.connect(DATABASE_URL) as conn:
        register_vector(conn)
        vec = vector_rank(conn, query, CANDIDATE_POOL)
        kw = keyword_rank(conn, query, CANDIDATE_POOL)
        fused = rrf([vec, kw], CANDIDATE_POOL if rerank else k)

        if rerank and fused:
            rows = conn.execute(
                "SELECT cve_id, chunk_text FROM chunks WHERE cve_id = ANY(%s)", (fused,)
            ).fetchall()
            text = {r[0]: r[1] for r in rows}
            pairs = [(query, text.get(cid, "")) for cid in fused]
            scores = _reranker().predict(pairs)
            ranked = [cid for cid, _ in sorted(zip(fused, scores), key=lambda x: x[1], reverse=True)]
            final_ids = ranked[:k]
        else:
            final_ids = fused[:k]

        meta = conn.execute(
            """SELECT cve_id, cvss_score, epss, in_kev, substring(description for 160)
               FROM cves WHERE cve_id = ANY(%s)""",
            (final_ids,),
        ).fetchall()
    by_id = {m[0]: m for m in meta}
    out = []
    for cid in final_ids:
        m = by_id.get(cid)
        out.append(
            {"cve_id": cid, "cvss": m[1] if m else None, "epss": m[2] if m else None,
             "kev": m[3] if m else None, "snippet": m[4] if m else ""}
        )
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("query")
    ap.add_argument("-k", type=int, default=5)
    ap.add_argument("--no-rerank", action="store_true")
    args = ap.parse_args()
    for i, h in enumerate(hybrid_search(args.query, args.k, rerank=not args.no_rerank), 1):
        flags = []
        if h["kev"]:
            flags.append("KEV")
        if h["cvss"] and h["cvss"] >= 9:
            flags.append("CRIT")
        tag = f" [{' '.join(flags)}]" if flags else ""
        print(f"{i}. {h['cve_id']}  cvss={h['cvss']}{tag}\n   {h['snippet']}…\n")


if __name__ == "__main__":
    main()
