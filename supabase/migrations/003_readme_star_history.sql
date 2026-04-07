-- ═══════════════════════════════════════════════════════════════════════════
-- Migration 003 — README download URLs + star history
-- Run in: Supabase Dashboard → SQL Editor → New query → Run
-- ═══════════════════════════════════════════════════════════════════════════

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS readme_download_urls JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS star_history         JSONB NOT NULL DEFAULT '[]'::jsonb;

-- Index for finding repos that have star history (for sparkline rendering)
CREATE INDEX IF NOT EXISTS idx_findings_star_history
    ON findings USING gin(star_history)
    WHERE star_history != '[]'::jsonb;
