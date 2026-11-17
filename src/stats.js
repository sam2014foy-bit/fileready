// Cookieless website statistics.
//
// Nothing is stored on the visitor's device and no IP address is stored. To
// count visitors (not just page views) we keep, in memory only, a hash of
// IP + browser + a random salt that changes every day. The salt is never
// written down, so yesterday's hashes can't be linked to today's, and a
// restart simply starts a fresh set.
import crypto from 'node:crypto';

const BOT = /bot|crawl|spider|slurp|preview|facebookexternalhit|whatsapp|telegram|discord|curl|wget|python|node-fetch|axios|headless|lighthouse|pingdom|uptime|monitor/i;
export const TRACKED = new Set(['/', '/security', '/privacy', '/terms', '/dpa', '/demo', '/signup']);

export const dublinDay = (d = new Date()) =>
  new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Dublin', year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);

export function deviceOf(ua = '') {
  if (/iPad|Tablet|PlayBook|Silk|(Android(?!.*Mobile))/i.test(ua)) return 'tablet';
  if (/Mobi|iPhone|Android/i.test(ua)) return 'mobile';
  return 'desktop';
}

const clean = (v, max) => String(v || '').toLowerCase().replace(/[^a-z0-9._-]/g, '').slice(0, max);

export function createStats({ db, siteHost }) {
  let day = null, salt = null, seen = new Set();
  const rotate = (today) => { if (today !== day) { day = today; salt = crypto.randomBytes(16); seen = new Set(); } };

  async function safely(fn) { try { await db.asApp(fn); } catch (err) { console.error('stats:', err.message); } }

  return {
    // Express middleware: counts successful GETs of public pages by people (not bots or logged-in staff).
    middleware() {
      return (req, res, next) => {
        if (req.method !== 'GET' || !TRACKED.has(req.path)) return next();
        const ua = req.get('user-agent') || '';
        if (!ua || BOT.test(ua) || req.get('purpose') === 'prefetch' || req.get('sec-purpose')?.includes('prefetch')) return next();
        res.on('finish', () => {
          if (res.statusCode !== 200 || req.user) return;
          const today = dublinDay(); rotate(today);
          const h = crypto.createHmac('sha256', salt).update(`${req.clientIp || req.ip}|${ua}`).digest('base64url').slice(0, 22);
          const isNew = !seen.has(h); if (isNew) seen.add(h);
          let referrer = '';
          try { const r = new URL(req.get('referer') || ''); if (r.hostname !== siteHost) referrer = r.hostname.replace(/^www\./, '').slice(0, 100); } catch { /* none */ }
          const source = clean(req.query.utm_source || req.query.ref, 40);
          const cta = (req.path === '/demo' || req.path === '/signup') ? clean(req.query.from, 40) : '';
          safely((q) => q('SELECT stats_hit($1, $2, $3, $4, $5, $6, $7)', [today, req.path, referrer, source, cta, deviceOf(ua), isNew]));
        });
        next();
      };
    },
    event(name) { return safely((q) => q('SELECT stats_event($1, $2)', [dublinDay(), name])); },
    async report(days) {
      const since = dublinDay(new Date(Date.now() - (days - 1) * 86400000));
      let out = null;
      await db.asApp(async (q) => { out = (await q('SELECT stats_report($1) AS r', [since]))[0].r; });
      return { since, ...out };
    },
  };
}
