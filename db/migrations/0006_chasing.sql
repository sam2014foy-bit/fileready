-- Automatic chasing: reminder schedule per case, a per-firm limit, and a
-- cross-firm lookup of cases that are due (the only cross-firm query the
-- reminder worker runs; everything else it does is firm-scoped).

ALTER TABLE firms ADD COLUMN max_reminders integer NOT NULL DEFAULT 6 CHECK (max_reminders BETWEEN 1 AND 20);

ALTER TABLE cases
  ADD COLUMN chasing_started_at timestamptz,
  ADD COLUMN next_reminder_at   timestamptz,
  ADD COLUMN reminders_sent     integer NOT NULL DEFAULT 0 CHECK (reminders_sent >= 0),
  ADD COLUMN chasing_stopped    text CHECK (chasing_stopped IN ('limit_reached', 'no_email'));
CREATE INDEX cases_next_reminder_idx ON cases (next_reminder_at) WHERE next_reminder_at IS NOT NULL;

ALTER TABLE reminders
  ADD COLUMN kind text NOT NULL DEFAULT 'reminder' CHECK (kind IN ('first', 'reminder', 'manual')),
  ADD COLUMN recipient text,
  ADD COLUMN outstanding integer;
CREATE INDEX reminders_case_idx ON reminders (firm_id, case_id, created_at DESC);

CREATE FUNCTION reminders_due(p_limit integer)
RETURNS TABLE (firm_id uuid, case_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT c.firm_id, c.id
    FROM cases c
   WHERE c.status = 'open'
     AND NOT c.reminders_paused
     AND c.next_reminder_at IS NOT NULL
     AND c.next_reminder_at <= now()
   ORDER BY c.next_reminder_at
   LIMIT least(greatest(p_limit, 1), 200)
$$;
REVOKE ALL ON FUNCTION reminders_due(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION reminders_due(integer) TO fileready_app;
