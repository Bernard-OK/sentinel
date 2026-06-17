# How I evaluated a RAG system in production (draft)

> **Draft for Bernard to personalise.** Numbers are real (from this repo's eval runs). Replace the
> _[in your words]_ blocks with your own reflection — don't let me put words in your mouth.

---

## The problem most RAG demos ignore

Anyone can wire an LLM to a vector database and get plausible answers. The hard part — the part that
separates a demo from something a team can trust — is **proving it works**. So I built Sentinel, a
CVE/security-advisory assistant, **eval-first**: I built the measurement before the thing being
measured.

_[in your words: why security/CVEs — your EPITA background, why grounding matters here]_

## What it does

Ask a security question; Sentinel retrieves from ~3,000 real CVEs (NVD + CISA KEV + EPSS), returns a
**cited** answer (severity, exploitation status, affected products, remediation), and **refuses** when
the question is outside its corpus.

## The build, and what each step taught me

**Retrieval, measured.** I started with vector search (bge-small + pgvector) and a 60-question golden
set. Baseline: `recall@1 = 0.60`, `MRR = 0.70`. Then I added hybrid retrieval (vector + Postgres
full-text, fused with Reciprocal Rank Fusion) and a cross-encoder reranker:

| | recall@1 | recall@5 | MRR |
|---|---|---|---|
| vector | 0.60 | 0.82 | 0.70 |
| hybrid + rerank | **0.67** | **0.87** | **0.75** |

**Grounded, structured generation.** Claude Sonnet 4.6 with forced structured output (no fragile JSON
parsing) and a strict "answer only from context, cite CVE ids" prompt.

**An LLM judge — and validating it.** I measure answer faithfulness, citation accuracy, and a
hallucination rate with a Haiku-4.5 judge. But a 0% hallucination rate is meaningless if the judge is
lenient — so I **meta-evaluated the judge**: I fed it answers I'd deliberately poisoned with fake
claims. It caught **5/5** planted hallucinations with **0** false alarms. Only then did I trust the
metric.

_[in your words: the moment you realised the judge itself needed testing]_

**Guardrails.** A confidence gate (calibrated from data — in-corpus queries score 0.77–0.86,
out-of-corpus 0.48–0.51, so 0.60 splits them) refuses off-topic questions before spending a token.
Citation enforcement strips any CVE id the model didn't actually retrieve.

**An agent.** A tool-using mode (search / details / live KEV+EPSS lookup) that autonomously builds a
prioritised patching brief.

**Production economics.** Every query is traced; p50 latency 5.0s, ~$0.0075/query, ~$7.53 per 1,000
queries.

## What I'd do next

_[in your words: e.g. fine-tune the embedder on security text, batch the reranker, add streaming,
expand the corpus]_

## Takeaway

The eval harness — not the model — is the hard part and the real signal. Retrieval metrics, a
**validated** judge, guardrails, and cost tracking wired into CI are what turn "I used an LLM" into
"I shipped a system I can stand behind."

Repo: _[link]_ · Live demo: _[link]_
