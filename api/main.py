"""Day 11 — the web API. Wraps the pipeline in HTTP so non-engineers can use Sentinel.

Endpoints:
  GET  /            → the demo web page (ui/index.html)
  GET  /health      → liveness + corpus size + today's demo budget remaining
  GET  /api/stats   → the eval numbers, for the UI to display
  POST /api/ask     → {question} → grounded, cited, guarded answer

Abuse/cost protection (a public demo calls Claude on every request):
  - per-IP daily cap on free-form questions
  - a global daily spend cap; once hit, /api/ask returns 429 instead of spending more
"""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import date

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from pathlib import Path
from pydantic import BaseModel

from generation.answer import answer

load_dotenv()

PER_IP_DAILY = int(os.getenv("DEMO_PER_IP_DAILY", "20"))
GLOBAL_DAILY_USD = float(os.getenv("DEMO_DAILY_USD_CAP", "2.0"))

app = FastAPI(title="Sentinel", description="Grounded CVE intelligence assistant")
UI_DIR = Path(__file__).resolve().parent.parent / "ui"

# --- simple in-memory rate/spend tracking (resets daily; fine for a single-instance demo) ---
_state = {"day": date.today().isoformat(), "spend": 0.0, "ip": defaultdict(int)}


def _roll_day() -> None:
    today = date.today().isoformat()
    if _state["day"] != today:
        _state.update(day=today, spend=0.0, ip=defaultdict(int))


class AskRequest(BaseModel):
    question: str


@app.get("/")
def index():
    return FileResponse(UI_DIR / "index.html")


@app.get("/health")
def health():
    _roll_day()
    return {
        "status": "ok",
        "budget_remaining_usd": round(max(0.0, GLOBAL_DAILY_USD - _state["spend"]), 4),
    }


@app.get("/api/stats")
def stats():
    """The eval numbers, surfaced to the UI so visitors see the system is measured."""
    return {
        "corpus": "~3,000 recent CVEs (NVD + CISA KEV + EPSS)",
        "retrieval_recall_at_1": 0.67,
        "retrieval_mrr": 0.75,
        "answer_faithfulness": 1.00,
        "hallucination_rate": 0.00,
        "judge_detection_rate": 1.00,
        "cost_per_query_usd": 0.0075,
    }


@app.post("/api/ask")
def ask(req: AskRequest, request: Request):
    _roll_day()
    ip = request.client.host if request.client else "unknown"

    if _state["spend"] >= GLOBAL_DAILY_USD:
        return JSONResponse(
            status_code=429,
            content={"error": "The public demo's daily budget is used up — try again tomorrow, "
                              "or run it locally from the repo."},
        )
    if _state["ip"][ip] >= PER_IP_DAILY:
        return JSONResponse(
            status_code=429,
            content={"error": f"Demo limit reached ({PER_IP_DAILY}/day). Clone the repo to run unlimited."},
        )

    q = (req.question or "").strip()
    if not q:
        return JSONResponse(status_code=400, content={"error": "Ask a question."})

    _state["ip"][ip] += 1
    r = answer(q)

    if r.get("refused"):
        return {"refused": True, "reason": r["reason"]}
    if "error" in r:
        return JSONResponse(status_code=500, content={"error": r["error"]})

    _state["spend"] += r.get("cost_usd", 0.0)
    a = r["answer"]
    return {
        "refused": False,
        "summary": a.summary,
        "severity": a.severity,
        "exploitation_status": a.exploitation_status,
        "affected_products": a.affected_products,
        "remediation": a.remediation,
        "citations": a.citations,
        "confidence": r["confidence"],
        "cost_usd": r["cost_usd"],
        "latency_ms": r["latency_ms"],
    }
