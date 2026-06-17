# Deploying Sentinel

Sentinel is one Docker app + a Postgres/pgvector service. Pick a host below.

## Prereqs (both paths)
- An `ANTHROPIC_API_KEY`
- (optional) an `NVD_API_KEY` for faster corpus refresh

---

## Option A — Your own server (Berny / any Linux VPS)

Needs ~2.5 GB free RAM (PyTorch + models) and a few GB disk.

```bash
git clone https://github.com/Bernard-OK/sentinel.git && cd sentinel
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
docker compose up -d --build

# one-time seed of the corpus
docker compose exec app python -m ingestion.fetch --days 120 --limit 3000
docker compose exec app python -m ingestion.embed_load
```

App is on `:8900`. Expose it publicly with your existing Cloudflare tunnel:

```bash
cloudflared tunnel --url http://localhost:8900   # quick tunnel
# or add a hostname (e.g. sentinel.okwampah.com) to a named tunnel's config
```

---

## Option B — Fly.io (managed, isolated)

```bash
fly launch --no-deploy            # uses fly.toml in this repo
fly postgres create               # managed Postgres
fly postgres attach <pg-app>      # sets DATABASE_URL
fly secrets set ANTHROPIC_API_KEY=sk-ant-...
fly deploy

# enable pgvector + seed (one-time)
fly postgres connect -a <pg-app> -c "CREATE EXTENSION IF NOT EXISTS vector;"
fly ssh console -C "python -m ingestion.fetch --days 120 --limit 3000"
fly ssh console -C "python -m ingestion.embed_load"
```

---

## Abuse / cost controls (public demo)
Set in the environment to bound spend:
- `DEMO_PER_IP_DAILY` (default 20) — free-form questions per visitor/day
- `DEMO_DAILY_USD_CAP` (default 2.0) — global daily Claude spend before `/api/ask` returns 429

## Health
`GET /health` → status + remaining daily budget. `GET /api/stats` → eval numbers.
