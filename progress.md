# Migration Progress — SQLite → Supabase + CF Workers + GitHub Actions

**Started:** 2026-04-04
**Plan:** `/home/jacobs/.claude/plans/vectorized-leaping-alpaca.md`

## Supabase Credentials
- URL: `https://nsjkrclfmetmjzpnqjjm.supabase.co`
- Anon key: configured in `web/index.html` (public, RLS-gated)
- Service key: env var only — never in code

## Checklist

- [DONE] Project created at supabase.com
- [DONE] Credentials obtained (URL + anon + service_role)
- [DONE] `supabase/migrations/001_initial.sql` — DDL written, needs Jacob to run in SQL Editor
- [DONE] `migrate_sqlite_to_supabase.py` — migration script written

### Step 1 — Data Migration (SQLite → Supabase)
- [TODO] Jacob runs `001_initial.sql` in Supabase SQL Editor
- [TODO] Jacob installs supabase python: `pip install supabase`
- [TODO] Jacob runs: `SUPABASE_URL=... SUPABASE_SERVICE_KEY=... python migrate_sqlite_to_supabase.py`
- [TODO] Jacob runs post-migration verification SQL in Supabase SQL Editor
- [TODO] Jacob confirms row counts (expect ~33 findings, ~4 scans)

### Step 2 — Rewrite db.py (supabase-py AsyncClient)
- [TODO]

### Step 3 — Edit scanner.py (3 lines only)
- [TODO] Remove `import aiosqlite` (line 12)
- [TODO] Remove `await database.commit()` (line 374)
- [TODO] Remove `await database.close()` (line 414)

### Step 4 — Update config.py
- [TODO] Add SUPABASE_URL, SUPABASE_SERVICE_KEY
- [TODO] Remove DB_PATH, DASHBOARD_PORT, AUTO_SCAN_INTERVAL_MINUTES

### Step 5 — Update requirements.txt
- [TODO] Drop: fastapi, uvicorn, jinja2, aiosqlite
- [TODO] Add: supabase>=2.4.0

### Step 6 — Create run_scan.py
- [TODO]

### Step 7 — Create .github/workflows/scan.yml
- [TODO]

### Step 8 — Build web/index.html (static dashboard)
- [TODO] Largest step — convert Jinja2 template to vanilla JS + Supabase ESM

### Step 9 — Create web/_headers (CSP)
- [TODO]

### Step 10 — Create wrangler.toml
- [TODO]

### Step 11 — Delete old files
- [TODO] app.py, Dockerfile, Procfile, railway.toml, templates/, lure_monitor.db

### Step 12 — Commit + Push + GH Secrets + CF Deploy
- [TODO]

## Decisions Made
- Drop "Scan Now" button from dashboard (GH Actions manual dispatch instead)
- Drop Settings modal (schedule is in YAML)
- Drop no-op db wrapper — edit scanner.py directly (3 lines)
- Direct anon UPDATE with `WITH CHECK (dismissed = true)` — no RPC needed
- Supabase Realtime for scan status updates (no polling)
- Cloudflare Workers (not Pages — Pages deprecated April 2025)
- `textContent`/`escHtml()` for XSS prevention in dashboard

## Files Changed
- Created: `supabase/migrations/001_initial.sql`
- Created: `migrate_sqlite_to_supabase.py`
- Created: `progress.md`
