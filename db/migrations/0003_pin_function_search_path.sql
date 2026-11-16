-- Pin search_path on every Fileready function so a caller can't make them
-- resolve table names against a schema it controls (Supabase lint 0011).
ALTER FUNCTION public.current_firm_id()          SET search_path = public, pg_temp;
ALTER FUNCTION public.set_updated_at()           SET search_path = public, pg_temp;
ALTER FUNCTION public.audit_log_block_changes()  SET search_path = public, pg_temp;
ALTER FUNCTION public.refresh_case_completion()  SET search_path = public, pg_temp;
