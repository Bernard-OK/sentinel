# Sentinel — single-image API + models. Postgres/pgvector runs as a separate service (compose).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    HF_HOME=/models \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps (psycopg[binary] bundles libpq; only need build basics for some wheels)
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY ingestion ./ingestion
COPY retrieval ./retrieval
COPY generation ./generation
COPY guardrails ./guardrails
COPY agent ./agent
COPY eval ./eval
COPY api ./api
COPY ui ./ui

RUN pip install -e .

# Pre-bake the embedder + reranker into the image so first request isn't slow.
RUN python -c "from sentence_transformers import SentenceTransformer, CrossEncoder; \
SentenceTransformer('BAAI/bge-small-en-v1.5'); \
CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2')"

EXPOSE 8900
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8900"]
