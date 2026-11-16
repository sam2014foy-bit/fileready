-- Login sessions, plus the few lookups that must happen BEFORE we know
-- which firm a request belongs to (login, session check, client upload link).
-- These run as SECURITY DEFINER functions with fixed search_path, return only
-- what's needed, and can be called by fileready_app only.

CREATE TABLE sessions (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash  text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  firm_id     uuid NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  revoked_at  timestamptz
);
CREATE INDEX sessions_user_idx ON sessions (user_id);
-- RLS on with no policies: the app can only reach sessions via the functions below.
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;

-- Login: find a user by email across all firms.
CREATE FUNCTION auth_find_user(p_email text)
RETURNS TABLE (user_id uuid, firm_id uuid, password_hash text, disabled boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT u.id, u.firm_id, u.password_hash, u.disabled_at IS NOT NULL
    FROM users u
   WHERE u.email = lower(trim(p_email))
$$;

CREATE FUNCTION session_create(p_token_hash text, p_user_id uuid, p_ttl_hours integer)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  IF p_ttl_hours NOT BETWEEN 1 AND 720 THEN
    RAISE EXCEPTION 'invalid session length';
  END IF;
  INSERT INTO sessions (token_hash, user_id, firm_id, expires_at)
  SELECT p_token_hash, u.id, u.firm_id, now() + make_interval(hours => p_ttl_hours)
    FROM users u WHERE u.id = p_user_id AND u.disabled_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'user not found or disabled';
  END IF;
  UPDATE users SET last_login_at = now() WHERE id = p_user_id;
END $$;

CREATE FUNCTION session_resolve(p_token_hash text)
RETURNS TABLE (user_id uuid, firm_id uuid, full_name text, email text, role user_role, firm_name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT u.id, u.firm_id, u.full_name, u.email, u.role, f.name
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    JOIN firms f ON f.id = s.firm_id
   WHERE s.token_hash = p_token_hash
     AND s.revoked_at IS NULL
     AND s.expires_at > now()
     AND u.disabled_at IS NULL
$$;

CREATE FUNCTION session_revoke(p_token_hash text)
RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  UPDATE sessions SET revoked_at = now() WHERE token_hash = p_token_hash AND revoked_at IS NULL
$$;

-- Client upload link: returns the firm and case if the link is valid.
CREATE FUNCTION upload_link_resolve(p_token_hash text)
RETURNS TABLE (link_id uuid, firm_id uuid, case_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  RETURN QUERY
  UPDATE upload_links l SET last_used_at = now()
   WHERE l.token_hash = p_token_hash
     AND l.revoked_at IS NULL
     AND l.expires_at > now()
     AND EXISTS (SELECT 1 FROM cases c WHERE c.id = l.case_id AND c.firm_id = l.firm_id
                 AND c.status IN ('open', 'complete'))
  RETURNING l.id, l.firm_id, l.case_id;
END $$;

REVOKE ALL ON FUNCTION auth_find_user(text)                   FROM PUBLIC;
REVOKE ALL ON FUNCTION session_create(text, uuid, integer)    FROM PUBLIC;
REVOKE ALL ON FUNCTION session_resolve(text)                  FROM PUBLIC;
REVOKE ALL ON FUNCTION session_revoke(text)                   FROM PUBLIC;
REVOKE ALL ON FUNCTION upload_link_resolve(text)              FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_find_user(text)                TO fileready_app;
GRANT EXECUTE ON FUNCTION session_create(text, uuid, integer) TO fileready_app;
GRANT EXECUTE ON FUNCTION session_resolve(text)               TO fileready_app;
GRANT EXECUTE ON FUNCTION session_revoke(text)                TO fileready_app;
GRANT EXECUTE ON FUNCTION upload_link_resolve(text)           TO fileready_app;

-- Same lock-down as 0002 for the new table.
DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE ALL ON TABLE sessions FROM %I', r);
    END IF;
  END LOOP;
END $$;
