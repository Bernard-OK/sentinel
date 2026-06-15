"""Day 2 — vector search over the CVE corpus.  (Week 2: + keyword/hybrid + rerank.)

Embed the query (with bge's retrieval instruction prefix), cosine-search pgvector, return the
top-k CVEs joined with their metadata.  No LLM involved — this is pure retrieval.

CLI:
    python -m retrieval.search "remote code execution in apache" -k 5
"""

from __future__ import annotations

import argparse
import functools
import os

import psycopg
from dotenv import load_dotenv
from pgvector.psycopg import register_vector
from sentence_transformers import SentenceTransformer

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]
EMBED_MODEL = os.getenv("EMBED_MODEL", "BAAI/bge-small-en-v1.5")
# bge retrieval models expect this prefix on the QUERY side only:
QUERY_PREFIX = "Represent this sentence for searching relevant passages: "


@functools.lru_cache(maxsize=1)
def _model() -> SentenceTransformer:
    return SentenceTransformer(EMBED_MODEL)


def search(query: str, k: int = 5) -> list[dict]:
    qvec = _model().encode(
        QUERY_PREFIX + query, normalize_embeddings=True
    )
    with psycopg.connect(DATABASE_URL) as conn:
        register_vector(conn)
        rows = conn.execute(
            """
            SELECT c.cve_id,
                   1 - (ch.embedding <=> %s) AS score,   -- cosine similarity
                   c.cvss_score, c.epss, c.in_kev,
                   substring(c.description for 160) AS snippet
            FROM chunks ch
            JOIN cves c ON c.cve_id = ch.cve_id
            ORDER BY ch.embedding <=> %s                  -- <=> = cosine distance
            LIMIT %s
            """,
            (qvec, qvec, k),
        ).fetchall()

    return [
        {
            "cve_id": r[0], "score": round(r[1], 3), "cvss": r[2],
            "epss": r[3], "kev": r[4], "snippet": r[5],
        }
        for r in rows
    ]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("query")
    ap.add_argument("-k", type=int, default=5)
    args = ap.parse_args()

    for i, hit in enumerate(search(args.query, args.k), 1):
        flags = []
        if hit["kev"]:
            flags.append("KEV")
        if hit["cvss"] and hit["cvss"] >= 9:
            flags.append("CRIT")
        tag = f" [{' '.join(flags)}]" if flags else ""
        print(f"{i}. {hit['cve_id']}  sim={hit['score']}  cvss={hit['cvss']}{tag}")
        print(f"   {hit['snippet']}…\n")


if __name__ == "__main__":
    main()
