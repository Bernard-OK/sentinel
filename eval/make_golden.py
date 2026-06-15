"""Day 3 — bootstrap CANDIDATE golden questions for the retrieval eval.

Design choice for an honest eval: questions are built from each CVE's *structured* fields
(affected product + CWE weakness type), NOT from its description prose. If we paraphrased the
description, the embedder would match it trivially and recall would be a meaningless ~1.0.
By phrasing from product+weakness, retrieval must pick the RIGHT CVE out of many similar ones.

Output: eval/golden_candidates.jsonl  →  YOU then curate it down to eval/golden_set.jsonl
(prune ambiguous ones, fix awkward phrasing). The eval is only as trustworthy as that curation.

Run:
    python -m eval.make_golden --n 60
"""

from __future__ import annotations

import argparse
import json
import os

import psycopg
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.environ["DATABASE_URL"]

# Map common CWE ids to human weakness phrases. Unmapped → skipped (keeps questions clean).
CWE_PHRASE = {
    "CWE-89": "SQL injection",
    "CWE-79": "cross-site scripting (XSS)",
    "CWE-94": "code injection",
    "CWE-77": "command injection",
    "CWE-78": "OS command injection",
    "CWE-22": "path traversal",
    "CWE-352": "cross-site request forgery (CSRF)",
    "CWE-287": "authentication bypass",
    "CWE-862": "missing authorization",
    "CWE-863": "incorrect authorization",
    "CWE-434": "unrestricted file upload",
    "CWE-918": "server-side request forgery (SSRF)",
    "CWE-502": "insecure deserialization",
    "CWE-416": "use-after-free",
    "CWE-787": "out-of-bounds write",
    "CWE-125": "out-of-bounds read",
    "CWE-190": "integer overflow",
    "CWE-798": "use of hard-coded credentials",
    "CWE-269": "improper privilege management",
}

TEMPLATES = [
    "Which vulnerability allows {weakness} in {product}?",
    "Is there a {weakness} flaw affecting {product}?",
    "{product} {weakness} vulnerability",
]


def product_from_cpe(cpes: list[str]) -> str | None:
    for cpe in cpes:
        parts = cpe.split(":")
        if len(parts) > 5 and parts[3] not in ("*", "") and parts[4] not in ("*", ""):
            vendor = parts[3].replace("_", " ")
            product = parts[4].replace("_", " ")
            # avoid redundant "apache apache"
            return product if vendor in product else f"{vendor} {product}"
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=60)
    args = ap.parse_args()

    with psycopg.connect(DATABASE_URL) as conn:
        rows = conn.execute(
            """SELECT cve_id, description, cwes, cpes, cvss_score, in_kev
               FROM cves
               WHERE cwes IS NOT NULL AND cpes IS NOT NULL
               ORDER BY (in_kev) DESC, cvss_score DESC NULLS LAST"""
        ).fetchall()

    candidates, seen_products = [], set()
    ti = 0
    for cve_id, descr, cwes, cpes, cvss, in_kev in rows:
        cwe_ids = cwes if isinstance(cwes, list) else json.loads(cwes or "[]")
        cpe_list = cpes if isinstance(cpes, list) else json.loads(cpes or "[]")

        weakness = next((CWE_PHRASE[c] for c in cwe_ids if c in CWE_PHRASE), None)
        product = product_from_cpe(cpe_list)
        if not weakness or not product:
            continue
        # diversity: don't pile up many questions on the same product
        if product in seen_products:
            continue
        seen_products.add(product)

        template = TEMPLATES[ti % len(TEMPLATES)]
        ti += 1
        candidates.append(
            {
                "question": template.format(weakness=weakness, product=product),
                "expected_cve_ids": [cve_id],
                "reference_answer": descr[:240],
                "tags": [c for c in cwe_ids if c in CWE_PHRASE][:1],
            }
        )
        if len(candidates) >= args.n:
            break

    out = "eval/golden_candidates.jsonl"
    with open(out, "w") as f:
        for c in candidates:
            f.write(json.dumps(c) + "\n")
    print(f"wrote {len(candidates)} candidates → {out}")
    print("Next: review/curate them into eval/golden_set.jsonl")


if __name__ == "__main__":
    main()
