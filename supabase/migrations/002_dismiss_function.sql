-- Fix dismiss: RLS UPDATE policy doesn't work reliably with PostgREST.
-- Use SECURITY DEFINER function instead — runs as the function owner (postgres),
-- bypassing RLS so the anon key can dismiss findings.

CREATE OR REPLACE FUNCTION dismiss_finding(finding_id TEXT)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    UPDATE findings SET dismissed = true WHERE id = finding_id;
END;
$$;

-- Allow anon role to call it
GRANT EXECUTE ON FUNCTION dismiss_finding(TEXT) TO anon;
