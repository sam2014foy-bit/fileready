-- Feature pack: case due dates and notes, advisers-own-cases option, two-step
-- login, daily summaries, text reminders, retention clean-up, billing and
-- self sign-up.

-- ---------------------------------------------------------------- firms
ALTER TABLE firms
  ADD COLUMN advisers_see_all  boolean NOT NULL DEFAULT true,
  ADD COLUMN sms_enabled       boolean NOT NULL DEFAULT false,
  ADD COLUMN billing_status    text NOT NULL DEFAULT 'none'
    CHECK (billing_status IN ('none', 'trial', 'active', 'past_due', 'cancelled')),
  ADD COLUMN trial_ends_at     timestamptz,
  ADD COLUMN stripe_customer_id     text UNIQUE,
  ADD COLUMN stripe_subscription_id text UNIQUE;

-- ---------------------------------------------------------------- users
ALTER TABLE users
  ADD COLUMN totp_secret_enc  text,            -- AES-256-GCM, key only in the app's environment
  ADD COLUMN totp_enabled_at  timestamptz,
  ADD COLUMN totp_recovery    text[],          -- sha256 hashes of one-time recovery codes
  ADD COLUMN totp_last_step   bigint,          -- last accepted 30-second step, so a code can't be replayed
  ADD COLUMN daily_summary    boolean NOT NULL DEFAULT true,
  ADD COLUMN last_summary_on  date;

-- ---------------------------------------------------------------- clients, cases
ALTER TABLE clients ADD COLUMN sms_opt_out boolean NOT NULL DEFAULT false;
ALTER TABLE cases ADD COLUMN due_date date;
CREATE INDEX cases_due_idx ON cases (firm_id, due_date) WHERE due_date IS NOT NULL;

CREATE TABLE case_notes (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  firm_id     uuid NOT NULL,
  case_id     uuid NOT NULL,
  user_id     uuid,
  body        text NOT NULL CHECK (length(trim(body)) > 0 AND length(body) <= 2000),
  created_at  timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (firm_id, case_id) REFERENCES cases (firm_id, id) ON DELETE CASCADE,
  FOREIGN KEY (firm_id, user_id) REFERENCES users (firm_id, id) ON DELETE SET NULL (user_id)
);
CREATE INDEX case_notes_case_idx ON case_notes (firm_id, case_id, created_at DESC);
ALTER TABLE case_notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY firm_isolation ON case_notes TO fileready_app USING (firm_id = current_firm_id()) WITH CHECK (firm_id = current_firm_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON case_notes TO fileready_app;

-- ---------------------------------------------------------------- sessions: two-step login
ALTER TABLE sessions ADD COLUMN mfa_pending boolean NOT NULL DEFAULT false;

CREATE FUNCTION session_create_v2(p_token_hash text, p_user_id uuid, p_ttl_hours integer, p_mfa_pending boolean)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  IF p_ttl_hours NOT BETWEEN 1 AND 720 THEN RAISE EXCEPTION 'invalid session length'; END IF;
  INSERT INTO sessions (token_hash, user_id, firm_id, expires_at, mfa_pending)
  SELECT p_token_hash, u.id, u.firm_id, now() + make_interval(hours => CASE WHEN p_mfa_pending THEN 1 ELSE p_ttl_hours END), p_mfa_pending
    FROM users u WHERE u.id = p_user_id AND u.disabled_at IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'user not found or disabled'; END IF;
  IF NOT p_mfa_pending THEN UPDATE users SET last_login_at = now() WHERE id = p_user_id; END IF;
END $$;

-- Second step passed: the session becomes a full one for the normal length.
CREATE FUNCTION session_mfa_complete(p_token_hash text, p_ttl_hours integer)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE uid uuid;
BEGIN
  UPDATE sessions SET mfa_pending = false, expires_at = now() + make_interval(hours => p_ttl_hours)
   WHERE token_hash = p_token_hash AND mfa_pending AND revoked_at IS NULL AND expires_at > now()
  RETURNING user_id INTO uid;
  IF uid IS NULL THEN RETURN false; END IF;
  UPDATE users SET last_login_at = now() WHERE id = uid;
  RETURN true;
END $$;

DROP FUNCTION session_resolve(text);
CREATE FUNCTION session_resolve(p_token_hash text)
RETURNS TABLE (user_id uuid, firm_id uuid, full_name text, email text, role user_role, firm_name text,
               mfa_pending boolean, totp_enabled boolean, advisers_see_all boolean, billing_status text, trial_ends_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT u.id, u.firm_id, u.full_name, u.email, u.role, f.name,
         s.mfa_pending, u.totp_enabled_at IS NOT NULL, f.advisers_see_all, f.billing_status, f.trial_ends_at
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    JOIN firms f ON f.id = s.firm_id
   WHERE s.token_hash = p_token_hash AND s.revoked_at IS NULL AND s.expires_at > now() AND u.disabled_at IS NULL
$$;

-- ---------------------------------------------------------------- advisers see only their own cases (optional per firm)
-- The app sets app.user_id and app.restrict = '1' for an adviser when the
-- firm has advisers_see_all = false. Restrictive policies then hide other
-- advisers' cases and everything under them. Workers and client links set neither.
CREATE FUNCTION current_app_user() RETURNS uuid LANGUAGE sql STABLE SET search_path = public, pg_temp AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
$$;
CREATE FUNCTION app_restricted() RETURNS boolean LANGUAGE sql STABLE SET search_path = public, pg_temp AS $$
  SELECT coalesce(current_setting('app.restrict', true), '') = '1'
$$;

CREATE POLICY own_cases ON cases AS RESTRICTIVE TO fileready_app
  USING (NOT app_restricted() OR adviser_id = current_app_user())
  WITH CHECK (NOT app_restricted() OR adviser_id = current_app_user());
CREATE POLICY own_cases ON document_requests AS RESTRICTIVE TO fileready_app
  USING (NOT app_restricted() OR EXISTS (SELECT 1 FROM cases c WHERE c.id = case_id));
CREATE POLICY own_cases ON documents AS RESTRICTIVE TO fileready_app
  USING (NOT app_restricted() OR EXISTS (SELECT 1 FROM document_requests r WHERE r.id = request_id));
CREATE POLICY own_cases ON upload_links AS RESTRICTIVE TO fileready_app
  USING (NOT app_restricted() OR EXISTS (SELECT 1 FROM cases c WHERE c.id = case_id));
CREATE POLICY own_cases ON reminders AS RESTRICTIVE TO fileready_app
  USING (NOT app_restricted() OR EXISTS (SELECT 1 FROM cases c WHERE c.id = case_id));
CREATE POLICY own_cases ON case_notes AS RESTRICTIVE TO fileready_app
  USING (NOT app_restricted() OR EXISTS (SELECT 1 FROM cases c WHERE c.id = case_id));

-- case_progress is security_invoker, so it follows the policies above.

-- ---------------------------------------------------------------- daily jobs (cross-firm lookups)
-- Closed cases past the firm's retention period.
CREATE FUNCTION retention_due(p_limit integer)
RETURNS TABLE (firm_id uuid, case_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT c.firm_id, c.id FROM cases c JOIN firms f ON f.id = c.firm_id
   WHERE c.status = 'closed' AND c.closed_at IS NOT NULL
     AND c.closed_at < now() - make_interval(days => f.data_retention_days)
   ORDER BY c.closed_at LIMIT least(greatest(p_limit, 1), 500)
$$;

-- People due their morning summary today.
CREATE FUNCTION summary_due(p_today date)
RETURNS TABLE (firm_id uuid, user_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT u.firm_id, u.id FROM users u
   WHERE u.daily_summary AND u.disabled_at IS NULL AND u.password_hash IS NOT NULL
     AND (u.last_summary_on IS NULL OR u.last_summary_on < p_today)
$$;

-- ---------------------------------------------------------------- self sign-up
CREATE FUNCTION signup_create_firm(p_firm text, p_name text, p_email text, p_password_hash text, p_trial_days integer)
RETURNS TABLE (firm_id uuid, user_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE f uuid; u uuid;
BEGIN
  IF p_password_hash NOT LIKE 'scrypt$%' THEN RAISE EXCEPTION 'invalid password hash'; END IF;
  IF p_trial_days NOT BETWEEN 0 AND 90 THEN RAISE EXCEPTION 'invalid trial'; END IF;
  INSERT INTO firms (name, billing_status, trial_ends_at)
  VALUES (p_firm, 'trial', now() + make_interval(days => p_trial_days)) RETURNING id INTO f;
  INSERT INTO users (firm_id, email, full_name, role, password_hash)
  VALUES (f, lower(trim(p_email)), p_name, 'owner', p_password_hash) RETURNING id INTO u;
  INSERT INTO audit_log (firm_id, actor_type, actor_user_id, action, entity_type, entity_id)
  VALUES (f, 'user', u, 'firm.signed_up', 'firm', f);
  RETURN QUERY SELECT f, u;
END $$;

-- ---------------------------------------------------------------- billing (Stripe webhook, no firm context)
CREATE FUNCTION billing_update(p_firm_id uuid, p_customer text, p_subscription text, p_status text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  IF p_status NOT IN ('trial', 'active', 'past_due', 'cancelled') THEN RAISE EXCEPTION 'invalid status'; END IF;
  UPDATE firms SET billing_status = p_status,
         stripe_customer_id = coalesce(p_customer, stripe_customer_id),
         stripe_subscription_id = coalesce(p_subscription, stripe_subscription_id)
   WHERE (p_firm_id IS NOT NULL AND id = p_firm_id)
      OR (p_firm_id IS NULL AND p_subscription IS NOT NULL AND stripe_subscription_id = p_subscription);
  IF NOT FOUND THEN RETURN false; END IF;
  INSERT INTO audit_log (firm_id, actor_type, action, entity_type, entity_id, details)
  SELECT id, 'system', 'billing.updated', 'firm', id, jsonb_build_object('status', p_status) FROM firms
   WHERE (p_firm_id IS NOT NULL AND id = p_firm_id) OR (p_firm_id IS NULL AND stripe_subscription_id = p_subscription);
  RETURN true;
END $$;

-- ---------------------------------------------------------------- grants
DO $$
DECLARE f text;
BEGIN
  FOREACH f IN ARRAY ARRAY[
    'session_create_v2(text, uuid, integer, boolean)', 'session_mfa_complete(text, integer)', 'session_resolve(text)',
    'retention_due(integer)', 'summary_due(date)',
    'signup_create_firm(text, text, text, text, integer)', 'billing_update(uuid, text, text, text)'
  ] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO fileready_app', f);
  END LOOP;
  FOREACH f IN ARRAY ARRAY['anon', 'authenticated'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = f) THEN
      EXECUTE format('REVOKE ALL ON TABLE case_notes FROM %I', f);
      EXECUTE format('REVOKE ALL ON FUNCTION current_app_user() FROM %I', f);
      EXECUTE format('REVOKE ALL ON FUNCTION app_restricted() FROM %I', f);
      EXECUTE format('REVOKE ALL ON FUNCTION session_create_v2(text, uuid, integer, boolean) FROM %I', f);
      EXECUTE format('REVOKE ALL ON FUNCTION session_mfa_complete(text, integer) FROM %I', f);
      EXECUTE format('REVOKE ALL ON FUNCTION session_resolve(text) FROM %I', f);
      EXECUTE format('REVOKE ALL ON FUNCTION retention_due(integer) FROM %I', f);
      EXECUTE format('REVOKE ALL ON FUNCTION summary_due(date) FROM %I', f);
      EXECUTE format('REVOKE ALL ON FUNCTION signup_create_firm(text, text, text, text, integer) FROM %I', f);
      EXECUTE format('REVOKE ALL ON FUNCTION billing_update(uuid, text, text, text) FROM %I', f);
    END IF;
  END LOOP;
END $$;
