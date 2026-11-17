-- Supabase-only setup for scheduled reminders (not a migration: needs
-- pg_cron, pg_net and Vault, which local PGlite doesn't have).
-- Run once in the Supabase SQL editor, replacing the two placeholder values.
-- Applied to project xrhzdbvtxrjjupdsgmxl on 16 Nov 2026.

CREATE EXTENSION IF NOT EXISTS pg_net WITH SCHEMA extensions;
CREATE EXTENSION IF NOT EXISTS pg_cron;

SELECT vault.create_secret('<same value as REMINDERS_SECRET in Render>', 'fileready_reminders_secret');
SELECT vault.create_secret('<https://your-app.onrender.com>', 'fileready_app_url');

CREATE OR REPLACE FUNCTION public.fileready_trigger_reminders() RETURNS bigint
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT net.http_post(
    url := (SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name = 'fileready_app_url') || '/internal/reminders/run',
    headers := jsonb_build_object(
      'Authorization', 'Bearer ' || (SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name = 'fileready_reminders_secret'),
      'Content-Type', 'application/json'
    ),
    body := '{}'::jsonb,
    timeout_milliseconds := 60000
  );
$$;
REVOKE ALL ON FUNCTION public.fileready_trigger_reminders() FROM PUBLIC, anon, authenticated;

-- Every 10 minutes, 08:00-18:59 UTC, Mon-Sat (covers 9am-7pm Irish time all year;
-- the app enforces the exact hours).
SELECT cron.schedule('fileready-reminders', '*/10 8-18 * * 1-6', $$SELECT public.fileready_trigger_reminders()$$);

-- To change the app address later:
--   UPDATE vault.secrets SET secret = '<new url>' WHERE name = 'fileready_app_url';
-- To check recent runs:
--   SELECT status_code, content, created FROM net._http_response ORDER BY id DESC LIMIT 5;

-- ---------------------------------------------------------------- daily job
-- Morning summaries and retention clean-up. Same Vault secrets as above.
CREATE OR REPLACE FUNCTION public.fileready_trigger_daily()
RETURNS bigint
LANGUAGE sql SECURITY DEFINER SET search_path TO 'public', 'pg_temp'
AS $function$
  SELECT net.http_post(
    url := (SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name = 'fileready_app_url') || '/internal/daily/run',
    headers := jsonb_build_object(
      'Authorization', 'Bearer ' || (SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name = 'fileready_reminders_secret'),
      'Content-Type', 'application/json'
    ),
    body := '{}'::jsonb,
    timeout_milliseconds := 60000
  );
$function$;
REVOKE ALL ON FUNCTION public.fileready_trigger_daily() FROM PUBLIC, anon, authenticated;
-- Weekdays 07:30 and 08:30 UTC. The second run catches a sleeping server; summaries only go once a day.
SELECT cron.schedule('fileready-daily', '30 7,8 * * 1-5', 'SELECT public.fileready_trigger_daily()');
