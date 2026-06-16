"""Day 6 — validate the faithfulness judge (meta-evaluation).

A faithfulness score of 1.00 is only meaningful if the judge actually catches hallucinations.
So we test the judge as a classifier on cases where we KNOW the ground truth:

  clean    answer = the CVE's real description     → judge should find NO hallucination
  poisoned answer = real description + fake claims  → judge should FLAG hallucination

We then report detection rate (poisoned caught) and false-alarm rate (clean wrongly flagged).
If the judge catches the planted lies, the 0% hallucination rate on real answers is trustworthy.

Run:
    python -m eval.validate_judge
"""

from __future__ import annotations

import os

import psycopg
from dotenv import load_dotenv

from eval.faithfulness import judge_faithfulness

load_dotenv()
DATABASE_URL = os.environ["DATABASE_URL"]

# Fabricated claims that should NOT be supported by any single CVE's description.
POISON = (
    " This vulnerability is rated CVSS 10.0 and is being actively exploited by the Lazarus "
    "ransomware group. It also affects Microsoft Windows Server 2022, and there is no patch "
    "available. NASA has confirmed exploitation in the wild."
)


def sample_contexts(n: int) -> list[tuple[str, str]]:
    """Grab n real CVEs with substantial descriptions to use as ground-truth context."""
    with psycopg.connect(DATABASE_URL) as conn:
        rows = conn.execute(
            """SELECT cve_id, description FROM cves
               WHERE length(description) > 200
               ORDER BY cvss_score DESC NULLS LAST LIMIT %s""",
            (n,),
        ).fetchall()
    return [(r[0], r[1]) for r in rows]


def main() -> None:
    cases = sample_contexts(5)
    caught, missed = 0, 0
    false_alarms, clean_ok = 0, 0

    print("Validating the judge on planted hallucinations…\n")
    for cve_id, desc in cases:
        context = f"[{cve_id}]\n{desc}"

        # 1) CLEAN — the answer is just the real description → should be faithful
        clean = judge_faithfulness(context, desc)
        if clean["hallucinated"]:
            false_alarms += 1
            print(f"  ✗ {cve_id} CLEAN wrongly flagged: {clean['unsupported']}")
        else:
            clean_ok += 1
            print(f"  ✓ {cve_id} CLEAN  → faithful ({clean['n_supported']}/{clean['n_claims']})")

        # 2) POISONED — real description + fabricated claims → should be flagged
        poisoned = judge_faithfulness(context, desc + POISON)
        if poisoned["hallucinated"]:
            caught += 1
            print(f"  ✓ {cve_id} POISON → caught {len(poisoned['unsupported'])} fake claim(s)")
        else:
            missed += 1
            print(f"  ✗ {cve_id} POISON → MISSED the fake claims!")

    n = len(cases)
    print("\n  ── Judge validation ──────────────────────────")
    print(f"  detection rate (poison caught) : {caught}/{n} = {caught/n:.0%}")
    print(f"  false-alarm rate (clean flagged): {false_alarms}/{n} = {false_alarms/n:.0%}")
    verdict = "TRUSTWORTHY" if caught == n and false_alarms == 0 else "needs tuning"
    print(f"  → judge is {verdict}")


if __name__ == "__main__":
    main()
