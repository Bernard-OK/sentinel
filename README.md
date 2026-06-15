# Sentinel

**Production-grade RAG + agent for CVE / security-advisory triage — built eval-first.**

Ask a security question; Sentinel retrieves from real CVE/advisory data and returns a **cited**
answer (severity, exploitation status, affected products, remediation). It refuses to guess when
retrieval confidence is low, and every change is gated by an evaluation regression suite.

---

## 📊 Evaluation results

> _Baseline numbers land at the end of Week 1. This table is the first thing a reader should see —
> it's the point of the project._

_Retrieval = vector-only (bge-small-en-v1.5), 60-question golden set. Answer-level metrics from
the full-pipeline run (Claude Sonnet 4.6 generation, Haiku 4.5 judge)._

| Metric | Baseline | Current |
|---|---|---|
| Retrieval recall@1 | 0.60 | 0.60 |
| Retrieval recall@5 | 0.82 | 0.82 |
| Retrieval recall@10 | 0.90 | 0.90 |
| Retrieval MRR | 0.70 | 0.70 |
| Answer faithfulness (LLM-judge) | 1.00 | 1.00 |
| Citation accuracy | 1.00 | 1.00 |
| Hallucination rate | 0.00 | 0.00 |
| Cost / query (USD) | $0.0074 | $0.0074 |
| Mean latency | 5.2 s | 5.2 s |

Run it yourself: `python -m eval.run_eval`

---

## What makes this different

Most LLM portfolio projects can't answer *"how do you know it works?"* Sentinel's headline artifact
is its **evaluation harness** — retrieval metrics, faithfulness, citation accuracy, hallucination
rate, and cost — wired into CI so quality can't silently regress.

## Architecture

```
User Q ──► Retriever (vector + keyword → rerank)
                │
                ▼
        Retrieved CVE/advisory chunks
                │
   ┌────────────┴────────────┐
   ▼                         ▼
Agent (tools:           Generator (Claude Sonnet 4.6)
 KEV / EPSS / CPE)   ──► cited, structured answer
                │
                ▼
        Guardrail (citation-required, low-confidence refusal)
                │
        Langfuse tracing → ⭐ Eval harness
```

## Stack

Python · Claude Sonnet 4.6 (generation) · Claude Haiku 4.5 (LLM-judge) · `bge-large` embeddings ·
pgvector · FastAPI · Langfuse · Next.js (thin UI) · GitHub Actions (eval CI)

## Data sources (real, free)

- [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
- [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [EPSS — FIRST.org](https://www.first.org/epss/)
- [GitHub Security Advisories](https://github.com/advisories)

## Setup

```bash
cp .env.example .env        # fill in keys
pip install -e ".[dev]"
# start Postgres+pgvector (see docs), then:
python -m ingestion.fetch   # Day 1
```

## Project layout

| Dir | Purpose |
|---|---|
| `ingestion/` | fetch → normalize → chunk → embed |
| `retrieval/` | vector, hybrid, rerank |
| `agent/` | tools: KEV, EPSS, CPE filter |
| `generation/` | cited, structured answers |
| `guardrails/` | citation-required, low-confidence refusal |
| `eval/` | golden set + metrics + full report ⭐ |
| `api/` | FastAPI service |
| `ui/` | thin Next.js frontend |

## Status

🚧 Week 1 — eval-first baseline. See the build log in [`docs/`](docs/) (coming).
