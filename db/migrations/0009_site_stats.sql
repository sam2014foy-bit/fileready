-- Cookieless website statistics. Only aggregate counts are stored: no IP
-- addresses, no cookies, no identifiers. Read and written only through the
-- functions below; the tables have RLS on and no policies.

CREATE TABLE site_stats (
  day       date NOT NULL,
  path      text NOT NULL,
  referrer  text NOT NULL DEFAULT '',   -- referring site's host name, '' for direct/internal
  source    text NOT NULL DEFAULT '',   -- ?utm_source= or ?ref=
  cta       text NOT NULL DEFAULT '',   -- ?from= on /demo and /signup: which button was clicked
  device    text NOT NULL DEFAULT '',   -- mobile, tablet or desktop
  views     integer NOT NULL DEFAULT 0,
  visitors  integer NOT NULL DEFAULT 0,
  PRIMARY KEY (day, path, referrer, source, cta, device)
);
CREATE TABLE site_events (
  day    date NOT NULL,
  name   text NOT NULL,                -- e.g. demo_requested, signup_completed, spam_blocked
  count  integer NOT NULL DEFAULT 0,
  PRIMARY KEY (day, name)
);
ALTER TABLE site_stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE site_events ENABLE ROW LEVEL SECURITY;

CREATE FUNCTION stats_hit(p_day date, p_path text, p_referrer text, p_source text, p_cta text, p_device text, p_new_visitor boolean)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  INSERT INTO site_stats (day, path, referrer, source, cta, device, views, visitors)
  VALUES (p_day, left(p_path, 100), left(coalesce(p_referrer, ''), 100), left(coalesce(p_source, ''), 40),
          left(coalesce(p_cta, ''), 40), left(coalesce(p_device, ''), 10), 1, CASE WHEN p_new_visitor THEN 1 ELSE 0 END)
  ON CONFLICT (day, path, referrer, source, cta, device)
  DO UPDATE SET views = site_stats.views + 1, visitors = site_stats.visitors + CASE WHEN p_new_visitor THEN 1 ELSE 0 END
$$;

CREATE FUNCTION stats_event(p_day date, p_name text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  INSERT INTO site_events (day, name, count) VALUES (p_day, left(p_name, 40), 1)
  ON CONFLICT (day, name) DO UPDATE SET count = site_events.count + 1
$$;

CREATE FUNCTION stats_report(p_since date)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT jsonb_build_object(
    'totals', (SELECT jsonb_build_object('views', coalesce(sum(views), 0), 'visitors', coalesce(sum(visitors), 0)) FROM site_stats WHERE day >= p_since),
    'events', (SELECT coalesce(jsonb_object_agg(name, n), '{}'::jsonb) FROM (SELECT name, sum(count) AS n FROM site_events WHERE day >= p_since GROUP BY name) e),
    'daily', (SELECT coalesce(jsonb_agg(jsonb_build_object('day', d, 'views', v, 'visitors', u) ORDER BY d), '[]'::jsonb)
                FROM (SELECT day AS d, sum(views) AS v, sum(visitors) AS u FROM site_stats WHERE day >= p_since GROUP BY day) x),
    'daily_events', (SELECT coalesce(jsonb_agg(jsonb_build_object('day', day, 'name', name, 'n', count)), '[]'::jsonb) FROM site_events WHERE day >= p_since),
    'pages', (SELECT coalesce(jsonb_agg(jsonb_build_object('k', path, 'v', v, 'u', u) ORDER BY v DESC), '[]'::jsonb)
                FROM (SELECT path, sum(views) AS v, sum(visitors) AS u FROM site_stats WHERE day >= p_since GROUP BY path) x),
    'referrers', (SELECT coalesce(jsonb_agg(jsonb_build_object('k', referrer, 'v', v) ORDER BY v DESC), '[]'::jsonb)
                FROM (SELECT referrer, sum(visitors) AS v FROM site_stats WHERE day >= p_since AND referrer <> '' GROUP BY referrer ORDER BY 2 DESC LIMIT 15) x),
    'sources', (SELECT coalesce(jsonb_agg(jsonb_build_object('k', source, 'v', v) ORDER BY v DESC), '[]'::jsonb)
                FROM (SELECT source, sum(visitors) AS v FROM site_stats WHERE day >= p_since AND source <> '' GROUP BY source ORDER BY 2 DESC LIMIT 15) x),
    'ctas', (SELECT coalesce(jsonb_agg(jsonb_build_object('k', cta, 'v', v) ORDER BY v DESC), '[]'::jsonb)
                FROM (SELECT cta, sum(views) AS v FROM site_stats WHERE day >= p_since AND cta <> '' GROUP BY cta) x),
    'devices', (SELECT coalesce(jsonb_agg(jsonb_build_object('k', device, 'v', v) ORDER BY v DESC), '[]'::jsonb)
                FROM (SELECT device, sum(visitors) AS v FROM site_stats WHERE day >= p_since AND device <> '' GROUP BY device) x)
  )
$$;

DO $$
DECLARE f text; r text;
BEGIN
  FOREACH f IN ARRAY ARRAY['stats_hit(date, text, text, text, text, text, boolean)', 'stats_event(date, text)', 'stats_report(date)'] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO fileready_app', f);
    FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I', f, r); END IF;
    END LOOP;
  END LOOP;
  FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE ALL ON TABLE site_stats, site_events FROM %I', r);
    END IF;
  END LOOP;
END $$;
