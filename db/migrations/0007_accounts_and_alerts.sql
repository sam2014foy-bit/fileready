-- Password resets and staff invites (same mechanism: a one-time link whose
-- token is stored only as a hash), signing out other sessions after a
-- password change, and throttled "client uploaded" emails to the adviser.

CREATE TABLE password_resets (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  purpose     text NOT NULL CHECK (purpose IN ('reset', 'invite')),
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX password_resets_user_idx ON password_resets (user_id);
-- No policies: reachable only through the functions below.
ALTER TABLE password_resets ENABLE ROW LEVEL SECURITY;

ALTER TABLE cases ADD COLUMN last_upload_alert_at timestamptz;

-- Forgot password: creates a reset for an active user with this email.
-- Returns nothing (not an error) for unknown emails, so callers can't probe.
CREATE FUNCTION reset_create(p_email text, p_token_hash text, p_minutes integer)
RETURNS TABLE (user_id uuid, full_name text, email text, firm_name text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE u record;
BEGIN
  IF p_minutes NOT BETWEEN 5 AND 4320 THEN RAISE EXCEPTION 'invalid expiry'; END IF;
  SELECT us.id, us.full_name, us.email, f.name AS firm_name INTO u
    FROM users us JOIN firms f ON f.id = us.firm_id
   WHERE us.email = lower(trim(p_email)) AND us.disabled_at IS NULL;
  IF NOT FOUND THEN RETURN; END IF;
  -- Older unused links stop working.
  UPDATE password_resets SET used_at = now() WHERE password_resets.user_id = u.id AND used_at IS NULL;
  INSERT INTO password_resets (user_id, token_hash, purpose, expires_at)
  VALUES (u.id, p_token_hash, 'reset', now() + make_interval(mins => p_minutes));
  RETURN QUERY SELECT u.id, u.full_name, u.email, u.firm_name;
END $$;

-- Staff invite: only for a user in the caller's own firm (app.firm_id).
CREATE FUNCTION invite_create(p_user_id uuid, p_token_hash text, p_minutes integer)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  IF p_minutes NOT BETWEEN 5 AND 10080 THEN RAISE EXCEPTION 'invalid expiry'; END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_user_id AND firm_id = current_firm_id() AND disabled_at IS NULL) THEN
    RETURN false;
  END IF;
  UPDATE password_resets SET used_at = now() WHERE user_id = p_user_id AND used_at IS NULL;
  INSERT INTO password_resets (user_id, token_hash, purpose, expires_at)
  VALUES (p_user_id, p_token_hash, 'invite', now() + make_interval(mins => p_minutes));
  RETURN true;
END $$;

-- Is this link still usable? Returns who it's for, without using it up.
CREATE FUNCTION reset_check(p_token_hash text)
RETURNS TABLE (full_name text, email text, purpose text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT u.full_name, u.email, r.purpose
    FROM password_resets r JOIN users u ON u.id = r.user_id
   WHERE r.token_hash = p_token_hash AND r.used_at IS NULL AND r.expires_at > now() AND u.disabled_at IS NULL
$$;

-- Use the link: set the password, use up the link, sign out every session, log it.
CREATE FUNCTION reset_consume(p_token_hash text, p_password_hash text)
RETURNS TABLE (user_id uuid, firm_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE r record;
BEGIN
  IF p_password_hash IS NULL OR p_password_hash NOT LIKE 'scrypt$%' THEN RAISE EXCEPTION 'invalid password hash'; END IF;
  SELECT pr.id, pr.purpose, u.id AS uid, u.firm_id INTO r
    FROM password_resets pr JOIN users u ON u.id = pr.user_id
   WHERE pr.token_hash = p_token_hash AND pr.used_at IS NULL AND pr.expires_at > now() AND u.disabled_at IS NULL
   FOR UPDATE OF pr;
  IF NOT FOUND THEN RETURN; END IF;
  UPDATE password_resets SET used_at = now() WHERE id = r.id;
  UPDATE users SET password_hash = p_password_hash WHERE id = r.uid;
  UPDATE sessions SET revoked_at = now() WHERE sessions.user_id = r.uid AND revoked_at IS NULL;
  INSERT INTO audit_log (firm_id, actor_type, actor_user_id, action, entity_type, entity_id)
  VALUES (r.firm_id, 'user', r.uid, CASE WHEN r.purpose = 'invite' THEN 'user.invite_accepted' ELSE 'user.password_reset' END, 'user', r.uid);
  RETURN QUERY SELECT r.uid, r.firm_id;
END $$;

-- After a password change: sign out the user's other sessions, keep this one.
CREATE FUNCTION session_revoke_others(p_keep_token_hash text)
RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  UPDATE sessions s SET revoked_at = now()
   WHERE s.revoked_at IS NULL
     AND s.user_id = (SELECT user_id FROM sessions WHERE token_hash = p_keep_token_hash)
     AND s.token_hash <> p_keep_token_hash
$$;

-- Disabling a staff member signs them out at once (own firm only).
CREATE FUNCTION sessions_revoke_user(p_user_id uuid)
RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  UPDATE sessions SET revoked_at = now()
   WHERE user_id = p_user_id AND firm_id = current_firm_id() AND revoked_at IS NULL
$$;

DO $$
DECLARE f text;
BEGIN
  FOREACH f IN ARRAY ARRAY[
    'reset_create(text, text, integer)', 'invite_create(uuid, text, integer)', 'reset_check(text)',
    'reset_consume(text, text)', 'session_revoke_others(text)', 'sessions_revoke_user(uuid)'
  ] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO fileready_app', f);
  END LOOP;
  FOREACH f IN ARRAY ARRAY['anon', 'authenticated'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = f) THEN
      EXECUTE format('REVOKE ALL ON TABLE password_resets FROM %I', f);
    END IF;
  END LOOP;
END $$;
