"""Day 8 — tools the agent can call against the live CVE database.

These turn Sentinel from "answer from retrieved text" into an agent that can look things up on
demand: search the corpus, pull a CVE's full record, and check live exploitation signals
(CISA KEV + EPSS). Each tool is a plain function over Postgres; the agent loop (agent.py) decides
when to call them.

Tool schemas follow the Anthropic tool-use format (name, description, input_schema).
"""

from __future__ import annotations

import os

import psycopg
from dotenv import load_dotenv

from retrieval.hybrid import hybrid_search

load_dotenv()
DATABASE_URL = os.environ["DATABASE_URL"]

TOOLS = [
    {
        "name": "search_cves",
        "description": "Search the CVE corpus by natural-language query (hybrid retrieval + rerank). "
        "Use this first to find relevant CVE ids for a question.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "What to search for."},
                "k": {"type": "integer", "description": "How many results (default 5)."},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_cve_details",
        "description": "Get the full record for a specific CVE id: description, CVSS, affected products.",
        "input_schema": {
            "type": "object",
            "properties": {"cve_id": {"type": "string", "description": "e.g. CVE-2026-12345"}},
            "required": ["cve_id"],
        },
    },
    {
        "name": "check_exploitation",
        "description": "Check live exploitation signals for a CVE: whether it is on the CISA KEV "
        "(actively-exploited) catalog, ransomware association, and its EPSS exploit-probability score.",
        "input_schema": {
            "type": "object",
            "properties": {"cve_id": {"type": "string"}},
            "required": ["cve_id"],
        },
    },
]


def _query(sql: str, params: tuple) -> list[tuple]:
    with psycopg.connect(DATABASE_URL) as conn:
        return conn.execute(sql, params).fetchall()


def search_cves(query: str, k: int = 5) -> str:
    hits = hybrid_search(query, k, rerank=True)
    if not hits:
        return "No matching CVEs found."
    return "\n".join(
        f"{h['cve_id']} (CVSS {h['cvss']}): {h['snippet']}…" for h in hits
    )


def get_cve_details(cve_id: str) -> str:
    rows = _query(
        "SELECT cve_id, description, cvss_score, cvss_vector, cpes FROM cves WHERE cve_id=%s",
        (cve_id,),
    )
    if not rows:
        return f"{cve_id} not found in corpus."
    cid, desc, cvss, vec, cpes = rows[0]
    products = ", ".join(
        f"{c.split(':')[3]} {c.split(':')[4]}".replace("_", " ")
        for c in (cpes or [])[:8]
        if len(c.split(":")) > 5
    )
    return (
        f"{cid}\nCVSS: {cvss} ({vec})\nAffected: {products or 'n/a'}\nDescription: {desc}"
    )


def check_exploitation(cve_id: str) -> str:
    rows = _query(
        "SELECT in_kev, kev_ransomware, epss, epss_percentile FROM cves WHERE cve_id=%s",
        (cve_id,),
    )
    if not rows:
        return f"{cve_id} not found in corpus."
    in_kev, ransom, epss, pct = rows[0]
    parts = [
        f"CISA KEV (actively exploited): {'YES' if in_kev else 'no'}",
        f"Known ransomware use: {ransom or 'unknown'}",
    ]
    if epss is not None:
        parts.append(f"EPSS exploit-probability: {epss} (percentile {pct})")
    return " | ".join(parts)


DISPATCH = {
    "search_cves": search_cves,
    "get_cve_details": get_cve_details,
    "check_exploitation": check_exploitation,
}


def run_tool(name: str, tool_input: dict) -> str:
    try:
        return DISPATCH[name](**tool_input)
    except Exception as e:  # surface errors back to the model, don't crash the loop
        return f"Error running {name}: {e}"
