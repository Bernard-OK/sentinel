"""Day 2 — embed the CVE corpus and load it into pgvector.

  SQLite (raw)  ──►  build chunk text  ──►  bge-small embeddings  ──►  Postgres + pgvector

CVE descriptions are short (≈1 paragraph), so for now it's one chunk per CVE — but we use a
generic `chunks` table so multi-chunk documents (advisories) drop in later without a reschema.

Run:
    python -m ingestion.embed_load
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import psycopg
from dotenv import load_dotenv
from pgvector.psycopg import register_vector
from rich.console import Console
from rich.progress import track
from sentence_transformers import SentenceTransformer

load_dotenv()
console = Console()

SQLITE_PATH = Path("data/sentinel.sqlite")
DATABASE_URL = os.environ["DATABASE_URL"]
EMBED_MODEL = os.getenv("EMBED_MODEL", "BAAI/bge-small-en-v1.5")
EMBED_DIM = 384  # bge-small-en-v1.5

DDL = f"""
CREATE TABLE IF NOT EXISTS cves (
    cve_id          TEXT PRIMARY KEY,
    published       TEXT,
    description     TEXT,
    cvss_score      REAL,
    cvss_vector     TEXT,
    cwes            JSONB,
    cpes            JSONB,
    in_kev          BOOLEAN,
    kev_ransomware  TEXT,
    epss            REAL,
    epss_percentile REAL
);

CREATE TABLE IF NOT EXISTS chunks (
    id         SERIAL PRIMARY KEY,
    cve_id     TEXT NOT NULL REFERENCES cves(cve_id),
    chunk_text TEXT NOT NULL,
    embedding  vector({EMBED_DIM}),
    ts         tsvector GENERATED ALWAYS AS (to_tsvector('english', chunk_text)) STORED
);
CREATE INDEX IF NOT EXISTS chunks_ts_gin ON chunks USING GIN (ts);
"""


def build_chunk_text(row: sqlite3.Row) -> str:
    """What we actually embed. Description carries the meaning; we fold in CWE + affected
    products so a search like 'apache rce' can match on product names too."""
    cwes = ", ".join(json.loads(row["cwes"] or "[]"))
    # CPE looks like cpe:2.3:a:vendor:product:version:... — pull vendor/product for readability
    products = set()
    for cpe in json.loads(row["cpes"] or "[]"):
        parts = cpe.split(":")
        if len(parts) > 5:
            products.add(f"{parts[3]} {parts[4]}".replace("_", " "))
    prod_str = ", ".join(sorted(products)[:10])

    return (
        f"{row['cve_id']}: {row['description']}"
        + (f"\nWeakness: {cwes}" if cwes else "")
        + (f"\nAffected: {prod_str}" if prod_str else "")
    )


def main() -> None:
    # 1) read corpus from SQLite
    lite = sqlite3.connect(SQLITE_PATH)
    lite.row_factory = sqlite3.Row
    rows = lite.execute("SELECT * FROM cves").fetchall()
    console.log(f"read {len(rows)} CVEs from SQLite")

    # 2) embed (bge passages need NO instruction prefix — only queries do)
    model = SentenceTransformer(EMBED_MODEL)
    texts = [build_chunk_text(r) for r in rows]
    console.log(f"embedding with {EMBED_MODEL} …")
    vectors = model.encode(
        texts, batch_size=64, normalize_embeddings=True, show_progress_bar=True
    )

    # 3) load into Postgres
    with psycopg.connect(DATABASE_URL) as conn:
        conn.execute("CREATE EXTENSION IF NOT EXISTS vector")  # idempotent; needed on a fresh DB
        conn.commit()
        register_vector(conn)
        with conn.cursor() as cur:
            cur.execute(DDL)
            cur.execute("TRUNCATE chunks, cves RESTART IDENTITY;")  # idempotent reloads

            for r in track(rows, description="insert cves"):
                cur.execute(
                    """INSERT INTO cves (cve_id, published, description, cvss_score, cvss_vector,
                                         cwes, cpes, in_kev, kev_ransomware, epss, epss_percentile)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (cve_id) DO NOTHING""",
                    (
                        r["cve_id"], r["published"], r["description"], r["cvss_score"],
                        r["cvss_vector"], r["cwes"], r["cpes"], bool(r["in_kev"]),
                        r["kev_ransomware"], r["epss"], r["epss_percentile"],
                    ),
                )

            for r, vec in track(zip(rows, vectors), total=len(rows), description="insert chunks"):
                cur.execute(
                    "INSERT INTO chunks (cve_id, chunk_text, embedding) VALUES (%s,%s,%s)",
                    (r["cve_id"], build_chunk_text(r), vec),
                )

            # HNSW index for fast cosine search (build AFTER bulk insert)
            console.log("building HNSW index …")
            cur.execute(
                "CREATE INDEX IF NOT EXISTS chunks_embedding_hnsw "
                "ON chunks USING hnsw (embedding vector_cosine_ops)"
            )
        conn.commit()

    console.print(f"[green]✓ loaded {len(rows)} chunks into pgvector[/]")


if __name__ == "__main__":
    main()
