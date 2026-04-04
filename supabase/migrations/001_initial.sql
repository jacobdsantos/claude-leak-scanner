-- ═══════════════════════════════════════════════════════════════════════════
-- Claude Code Lure Monitor — Supabase Schema
-- Run once in: Supabase Dashboard → SQL Editor → New query → Run
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE findings (
    id               TEXT PRIMARY KEY,
    platform         TEXT NOT NULL,
    repo_name        TEXT NOT NULL,
    repo_url         TEXT NOT NULL,
    description      TEXT DEFAULT '',
    owner_login      TEXT DEFAULT '',
    owner_age_days   INTEGER,
    owner_pub_repos  INTEGER,
    stars            INTEGER DEFAULT 0,
    forks            INTEGER DEFAULT 0,
    score            INTEGER NOT NULL,
    severity         TEXT NOT NULL,
    reasons          JSONB DEFAULT '[]'::jsonb,
    release_assets   JSONB DEFAULT '[]'::jsonb,
    suspicious_files JSONB DEFAULT '[]'::jsonb,
    repo_created_at  TEXT,
    first_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scan_count       INTEGER DEFAULT 1,
    dismissed        BOOLEAN DEFAULT false
);

CREATE INDEX idx_findings_platform   ON findings(platform);
CREATE INDEX idx_findings_severity   ON findings(severity);
CREATE INDEX idx_findings_first_seen ON findings(first_seen DESC);
CREATE INDEX idx_findings_score      ON findings(score DESC);
CREATE INDEX idx_findings_dismissed  ON findings(dismissed) WHERE dismissed = false;

CREATE TABLE scans (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    started_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at     TIMESTAMPTZ,
    platforms        JSONB DEFAULT '[]'::jsonb,
    total_found      INTEGER DEFAULT 0,
    new_found        INTEGER DEFAULT 0,
    duration_seconds REAL,
    status           TEXT DEFAULT 'running'
);

CREATE INDEX idx_scans_started ON scans(started_at DESC);

-- ── Row Level Security ───────────────────────────────────────────────────────

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans    ENABLE ROW LEVEL SECURITY;

-- Anon can read non-dismissed findings only
CREATE POLICY "anon_read_findings" ON findings
    FOR SELECT TO anon USING (dismissed = false);

-- Anon can only flip dismissed=true (column-restricted, no other updates allowed)
CREATE POLICY "anon_dismiss_findings" ON findings
    FOR UPDATE TO anon USING (true) WITH CHECK (dismissed = true);

-- Anon can read all scans (scan history on dashboard)
CREATE POLICY "anon_read_scans" ON scans
    FOR SELECT TO anon USING (true);

-- ── Realtime ─────────────────────────────────────────────────────────────────

ALTER PUBLICATION supabase_realtime ADD TABLE findings;
ALTER PUBLICATION supabase_realtime ADD TABLE scans;
