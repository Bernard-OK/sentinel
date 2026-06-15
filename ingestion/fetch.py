"""Day 1 — pull real vulnerability data into a local store.

Sources (all free):
  - NVD CVE API 2.0      https://services.nvd.nist.gov/rest/json/cves/2.0
  - CISA KEV catalog     https://www.cisa.gov/.../known_exploited_vulnerabilities.json
  - EPSS (FIRST.org)     https://api.first.org/data/v1/epss

Goal for Day 1: fetch N recent CVEs (+ KEV + EPSS) to a local SQLite/JSON store and
*read the raw data* until its shape is obvious. We do NOT embed or call an LLM yet.

We'll write this together. Leaving the skeleton here.
"""

from __future__ import annotations


def main() -> None:
    raise NotImplementedError("Day 1: implement NVD/KEV/EPSS fetch → local store")


if __name__ == "__main__":
    main()
