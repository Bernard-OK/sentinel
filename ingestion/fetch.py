"""Day 1 — pull real vulnerability data into a local SQLite store.

Pipeline:
  1. NVD  : fetch CVEs published in the last --days (paginated)
  2. KEV  : download CISA's actively-exploited catalog once → lookup dict
  3. EPSS : batch-fetch exploit-probability for the CVEs we pulled
  4. Store: normalise the fields we care about + keep raw JSON, write to SQLite

Run:
    python -m ingestion.fetch --days 60 --limit 800

No DB server needed today (SQLite file). Postgres/pgvector arrives Day 2.

Sources (all free):
  NVD   https://services.nvd.nist.gov/rest/json/cves/2.0   (key optional, 10x faster with one)
  KEV   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  EPSS  https://api.first.org/data/v1/epss
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import track

load_dotenv()
console = Console()

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

DATA_DIR = Path("data")
DB_PATH = DATA_DIR / "sentinel.sqlite"

NVD_PAGE_SIZE = 2000          # NVD max per page
NVD_KEY = os.getenv("NVD_API_KEY") or ""
# NVD rate limit: 5 req / 30s without a key, 50 req / 30s with one. Sleep to stay under.
NVD_SLEEP = 0.7 if NVD_KEY else 6.5


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #
def init_db() -> sqlite3.Connection:
    DATA_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cves (
            cve_id          TEXT PRIMARY KEY,
            published       TEXT,
            last_modified   TEXT,
            description     TEXT,
            cvss_version    TEXT,
            cvss_score      REAL,
            cvss_vector     TEXT,
            cwes            TEXT,   -- json array
            cpes            TEXT,   -- json array (affected products)
            refs            TEXT,   -- json array of urls
            in_kev          INTEGER DEFAULT 0,
            kev_date_added  TEXT,
            kev_ransomware  TEXT,
            epss            REAL,
            epss_percentile REAL,
            raw_json        TEXT    -- full NVD object, so we never lose data
        )
        """
    )
    conn.commit()
    return conn


# --------------------------------------------------------------------------- #
# 1) NVD
# --------------------------------------------------------------------------- #
def _nvd_headers() -> dict[str, str]:
    return {"apiKey": NVD_KEY} if NVD_KEY else {}


def parse_cve(item: dict) -> dict:
    """Pull the fields we care about out of one NVD vulnerability object."""
    cve = item["cve"]
    descr = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )

    # CVSS: prefer v3.1, fall back to v3.0, then v2
    metrics = cve.get("metrics", {})
    cvss_data, version = None, None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            cvss_data = metrics[key][0]["cvssData"]
            version = cvss_data.get("version")
            break

    cwes = [
        d["value"]
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if d.get("value")
    ]

    cpes = [
        m["criteria"]
        for conf in cve.get("configurations", [])
        for node in conf.get("nodes", [])
        for m in node.get("cpeMatch", [])
        if m.get("criteria")
    ]

    refs = [r["url"] for r in cve.get("references", []) if r.get("url")]

    return {
        "cve_id": cve["id"],
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": descr,
        "cvss_version": version,
        "cvss_score": cvss_data.get("baseScore") if cvss_data else None,
        "cvss_vector": cvss_data.get("vectorString") if cvss_data else None,
        "cwes": json.dumps(cwes),
        "cpes": json.dumps(cpes[:50]),  # cap: some CVEs list thousands of CPEs
        "refs": json.dumps(refs[:20]),
        "raw_json": json.dumps(cve),
    }


def fetch_nvd(days: int, limit: int) -> list[dict]:
    """Fetch CVEs published in the last `days`, up to `limit` rows."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    # NVD wants extended ISO-8601 with milliseconds
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    rows: list[dict] = []
    start_index = 0

    with httpx.Client(timeout=40) as client:
        while len(rows) < limit:
            params = {
                "pubStartDate": start.strftime(fmt),
                "pubEndDate": end.strftime(fmt),
                "resultsPerPage": min(NVD_PAGE_SIZE, limit - len(rows)),
                "startIndex": start_index,
            }
            resp = client.get(NVD_URL, params=params, headers=_nvd_headers())
            resp.raise_for_status()
            payload = resp.json()

            batch = payload.get("vulnerabilities", [])
            if not batch:
                break
            rows.extend(parse_cve(v) for v in batch)

            total = payload.get("totalResults", 0)
            start_index += len(batch)
            console.log(f"NVD: {len(rows)}/{min(limit, total)} fetched")
            if start_index >= total:
                break
            time.sleep(NVD_SLEEP)  # respect rate limit

    return rows[:limit]


# --------------------------------------------------------------------------- #
# 2) CISA KEV
# --------------------------------------------------------------------------- #
def fetch_kev() -> dict[str, dict]:
    """Download the KEV catalog once → {cve_id: entry}."""
    with httpx.Client(timeout=40) as client:
        data = client.get(KEV_URL).raise_for_status().json()
    kev = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
    console.log(f"KEV: {len(kev)} actively-exploited CVEs in catalog")
    return kev


# --------------------------------------------------------------------------- #
# 3) EPSS
# --------------------------------------------------------------------------- #
def fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    """Batch-fetch EPSS scores. The API accepts comma-separated ids; we chunk to be safe."""
    out: dict[str, dict] = {}
    with httpx.Client(timeout=40) as client:
        for i in track(range(0, len(cve_ids), 100), description="EPSS"):
            chunk = cve_ids[i : i + 100]
            resp = client.get(EPSS_URL, params={"cve": ",".join(chunk)})
            resp.raise_for_status()
            for row in resp.json().get("data", []):
                out[row["cve"]] = row
    console.log(f"EPSS: scores for {len(out)} CVEs")
    return out


# --------------------------------------------------------------------------- #
# Orchestrate
# --------------------------------------------------------------------------- #
def main() -> None:
    ap = argparse.ArgumentParser(description="Fetch CVE/KEV/EPSS into local SQLite.")
    ap.add_argument("--days", type=int, default=60, help="how far back to pull CVEs")
    ap.add_argument("--limit", type=int, default=800, help="max CVEs to fetch")
    args = ap.parse_args()

    if not NVD_KEY:
        console.print("[yellow]No NVD_API_KEY set — running at 5 req/30s (slow but fine).[/]")

    conn = init_db()

    cves = fetch_nvd(args.days, args.limit)
    kev = fetch_kev()
    epss = fetch_epss([c["cve_id"] for c in cves])

    # enrich + write
    for c in cves:
        cid = c["cve_id"]
        if cid in kev:
            c["in_kev"] = 1
            c["kev_date_added"] = kev[cid].get("dateAdded")
            c["kev_ransomware"] = kev[cid].get("knownRansomwareCampaignUse")
        else:
            c["in_kev"] = 0
            c["kev_date_added"] = None
            c["kev_ransomware"] = None
        if cid in epss:
            c["epss"] = float(epss[cid]["epss"])
            c["epss_percentile"] = float(epss[cid]["percentile"])
        else:
            c["epss"] = None
            c["epss_percentile"] = None

    cols = [
        "cve_id", "published", "last_modified", "description",
        "cvss_version", "cvss_score", "cvss_vector", "cwes", "cpes", "refs",
        "in_kev", "kev_date_added", "kev_ransomware", "epss", "epss_percentile", "raw_json",
    ]
    placeholders = ",".join("?" * len(cols))
    conn.executemany(
        f"INSERT OR REPLACE INTO cves ({','.join(cols)}) VALUES ({placeholders})",
        [tuple(c[col] for col in cols) for c in cves],
    )
    conn.commit()

    # quick summary so you SEE what landed
    n = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    kev_n = conn.execute("SELECT COUNT(*) FROM cves WHERE in_kev=1").fetchone()[0]
    hi = conn.execute("SELECT COUNT(*) FROM cves WHERE cvss_score>=9").fetchone()[0]
    console.print(
        f"\n[green]✓ stored {len(cves)} CVEs[/] → {DB_PATH}\n"
        f"  total rows in db : {n}\n"
        f"  actively exploited (KEV): {kev_n}\n"
        f"  critical (CVSS ≥ 9): {hi}"
    )
    conn.close()


if __name__ == "__main__":
    main()
