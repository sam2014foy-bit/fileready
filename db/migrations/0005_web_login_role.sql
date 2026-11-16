-- The login role the hosted web app connects as. It can do exactly what
-- fileready_app can do (firm-scoped by Row Level Security) and nothing more.
-- Created without a password: set one by hand, never in a migration file:
--   ALTER ROLE fileready_web WITH LOGIN PASSWORD '<long random password>';
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fileready_web') THEN
    CREATE ROLE fileready_web NOLOGIN NOINHERIT;
  END IF;
END $$;
GRANT fileready_app TO fileready_web;
