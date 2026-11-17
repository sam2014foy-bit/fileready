-- Security review: helper and trigger functions don't need to be callable by
-- Supabase's public API roles. Revoke them (they only ever ran as the app's role
-- or as triggers).
DO $$
DECLARE f record; r text;
BEGIN
  FOR f IN SELECT p.oid::regprocedure AS sig FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.proname IN ('current_firm_id', 'set_updated_at', 'audit_log_block_changes', 'refresh_case_completion', 'current_app_user', 'app_restricted')
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f.sig);
    FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I', f.sig, r); END IF;
    END LOOP;
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO fileready_app', f.sig);
  END LOOP;
END $$;
