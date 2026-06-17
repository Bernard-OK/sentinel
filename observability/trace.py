"""Day 12 — lightweight observability.

Every query appends one JSON line to data/traces.jsonl: the question, what was retrieved, what
was cited, confidence, tokens, cost, latency. This is real, dependency-free tracing you can grep,
aggregate (ops/cost_report.py), or replay — and the integration point for Langfuse later.

To add Langfuse (managed tracing UI): set LANGFUSE_* keys in .env and extend `log_trace` to also
emit a generation; the local log keeps working either way.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

TRACE_PATH = Path(os.getenv("TRACE_PATH", "data/traces.jsonl"))


def log_trace(event: str, payload: dict) -> None:
    """Append one trace record. Never raises — observability must not break the request."""
    try:
        TRACE_PATH.parent.mkdir(parents=True, exist_ok=True)
        record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **payload}
        with TRACE_PATH.open("a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass
