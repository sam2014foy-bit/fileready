import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { audit } from './db.js';
import { sendCaseReminder, runReminders } from './reminders.js';
import { accountEmail, uploadAlertEmail } from './emails.js';
import {
  verifyPassword, burnPasswordCheck, hashPassword, MIN_PASSWORD_LENGTH, randomToken, sha256,
  csrfTokenFor, safeEqual, createLoginLimiter, detectFileType,
} from './security.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const SESSION_COOKIE = 'fr_session';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;

/**
 * @param {object} opts
 * @param {ReturnType<import('./db.js').createDb>} opts.db
 * @param {{put: Function, get: Function}} opts.storage
 * @param {object} opts.config  baseUrl, secureCookies, sessionHours, linkDays
 */
export function createApp({ db, storage, mailer, config }) {
  const cfg = { sessionHours: 12, linkDays: 14, secureCookies: false, remindersSecret: null, devOutbox: false, ...config };
  const app = express();
  const limiter = createLoginLimiter();
  const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_UPLOAD_BYTES, files: 1, fields: 5 } });

  app.set('view engine', 'ejs');
  app.set('views', path.join(ROOT, 'views'));
  app.set('trust proxy', 1);
  app.disable('x-powered-by');

  // Referrer-Policy 'same-origin': browsers send Origin "null" on our own form
  // posts under 'no-referrer' (helmet's default), which the check below would
  // reject. 'same-origin' still never leaks upload-link URLs to other sites.
  app.use(helmet({
    contentSecurityPolicy: { directives: { 'form-action': ["'self'"] } },
    referrerPolicy: { policy: 'same-origin' },
  }));
  app.use('/static', express.static(path.join(ROOT, 'public'), { maxAge: '1h' }));
  app.get('/healthz', (req, res) => res.type('text').send('ok'));

  // Called by the scheduler (Supabase pg_cron) to send due reminders.
  app.post('/internal/reminders/run', async (req, res) => {
    const auth = req.get('authorization') || '';
    if (!cfg.remindersSecret || !safeEqual(auth, `Bearer ${cfg.remindersSecret}`)) return res.status(401).json({ error: 'unauthorised' });
    res.json(await runReminders({ db, mailer, baseUrl: cfg.baseUrl }));
  });

  if (cfg.devOutbox && mailer.outbox) {
    app.get('/dev/outbox', (req, res) => res.render('outbox', { emails: [...mailer.outbox].reverse() }));
  }
  app.use(cookieParser());
  app.use(express.urlencoded({ extended: false, limit: '100kb' }));

  // Reject cross-site form posts.
  app.use((req, res, next) => {
    if (req.method !== 'POST') return next();
    const origin = req.get('origin');
    if (origin && origin !== new URL(cfg.baseUrl).origin) return res.status(403).send('Forbidden');
    next();
  });

  // Load the logged-in user, if any.
  app.use(async (req, res, next) => {
    res.locals.user = null;
    res.locals.flash = null;
    res.locals.path = req.path;
    const token = req.cookies[SESSION_COOKIE];
    if (token && token.length < 100) {
      const [row] = await db.asApp((q) => q('SELECT * FROM session_resolve($1)', [sha256(token)]));
      if (row) {
        req.user = row;
        req.sessionToken = token;
        res.locals.user = row;
        res.locals.csrf = csrfTokenFor(token);
      }
    }
    next();
  });

  const requireUser = (req, res, next) => (req.user ? next() : res.redirect('/login'));
  const requireCsrf = (req, res, next) =>
    req.user && safeEqual(req.body?._csrf ?? '', csrfTokenFor(req.sessionToken)) ? next() : res.status(403).send('Forbidden');
  const checkId = (...names) => (req, res, next) =>
    names.every((n) => UUID.test(req.params[n])) ? next() : res.status(404).render('error', { message: 'Not found.' });
  const inFirm = (req, fn) => db.asFirm(req.user.firm_id, fn);
  const actor = (req) => ({ firmId: req.user.firm_id, actorType: 'user', userId: req.user.user_id, ip: req.ip });

  // ---------------------------------------------------------------- auth
  app.get('/login', (req, res) => (req.user ? res.redirect('/') : res.render('login', {
    error: null, email: '', notice: req.query.reset ? 'Your password is set. Log in with it now.' : null,
  })));

  app.post('/login', async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase().slice(0, 200);
    const password = String(req.body.password || '').slice(0, 200);
    const key = `${req.ip}|${email}`;
    const fail = (status = 401, error = 'Email or password is wrong.') => res.status(status).render('login', { error, email, notice: null });

    if (limiter.blocked(key)) return fail(429, 'Too many attempts. Wait 15 minutes and try again.');
    const [found] = await db.asApp((q) => q('SELECT * FROM auth_find_user($1)', [email]));
    const ok = found && !found.disabled && found.password_hash
      ? await verifyPassword(password, found.password_hash)
      : await burnPasswordCheck(password);
    if (!ok) {
      limiter.fail(key);
      return fail();
    }
    limiter.reset(key);
    const token = randomToken();
    await db.asApp((q) => q('SELECT session_create($1, $2, $3)', [sha256(token), found.user_id, cfg.sessionHours]));
    await db.asFirm(found.firm_id, (q) =>
      audit(q, { firmId: found.firm_id, actorType: 'user', userId: found.user_id, action: 'user.login', entityType: 'user', entityId: found.user_id, ip: req.ip })
    );
    res.cookie(SESSION_COOKIE, token, {
      httpOnly: true, sameSite: 'strict', secure: cfg.secureCookies, maxAge: cfg.sessionHours * 3600 * 1000, path: '/',
    });
    res.redirect('/');
  });

  app.post('/logout', requireUser, requireCsrf, async (req, res) => {
    await db.asApp((q) => q('SELECT session_revoke($1)', [sha256(req.sessionToken)]));
    res.clearCookie(SESSION_COOKIE, { path: '/' });
    res.redirect('/login');
  });

  app.get('/account/password', requireUser, (req, res) => res.render('password', { error: null, done: false }));

  app.post('/account/password', requireUser, requireCsrf, async (req, res) => {
    const current = String(req.body.current || '').slice(0, 200);
    const next = String(req.body.new_password || '').slice(0, 200);
    const confirm = String(req.body.confirm || '').slice(0, 200);
    const fail = (error) => res.status(400).render('password', { error, done: false });
    if (next.length < MIN_PASSWORD_LENGTH) return fail(`New password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
    if (next !== confirm) return fail('The two new passwords don\'t match.');
    if (next === current) return fail('Choose a password different from your current one.');
    const [found] = await db.asApp((q) => q('SELECT * FROM auth_find_user($1)', [req.user.email]));
    if (!found || !(await verifyPassword(current, found.password_hash))) return fail('Your current password is wrong.');
    const hash = await hashPassword(next);
    await inFirm(req, async (q) => {
      await q('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.user.user_id]);
      await audit(q, { ...actor(req), action: 'user.password_changed', entityType: 'user', entityId: req.user.user_id });
    });
    await db.asApp((q) => q('SELECT session_revoke_others($1)', [sha256(req.sessionToken)]));
    res.render('password', { error: null, done: true });
  });

  // ----------------------------------------------------------- dashboard
  app.get('/', requireUser, async (req, res) => {
    const filter = ['open', 'complete', 'all'].includes(req.query.show) ? req.query.show : 'open';
    const cases = await inFirm(req, (q) =>
      q(
        `SELECT c.id, c.title, c.lender, c.status, c.created_at, c.completed_at,
                c.chasing_started_at, c.next_reminder_at, c.reminders_paused, c.chasing_stopped, c.reminders_sent,
                cl.first_name, cl.last_name,
                p.required_total::int, p.required_done::int, p.awaiting_review::int, p.rejected::int
           FROM cases c
           JOIN clients cl ON cl.firm_id = c.firm_id AND cl.id = c.client_id
           JOIN case_progress p ON p.case_id = c.id
          WHERE ($1 = 'all' OR c.status::text = $1)
          ORDER BY p.awaiting_review DESC, c.created_at DESC
          LIMIT 200`,
        [filter]
      )
    );
    const [counts] = await inFirm(req, (q) =>
      q(`SELECT count(*) FILTER (WHERE c.status = 'open')::int AS open,
                count(*) FILTER (WHERE c.status = 'complete')::int AS complete,
                count(*)::int AS all,
                count(*) FILTER (WHERE c.status = 'open' AND p.awaiting_review > 0)::int AS review
           FROM cases c JOIN case_progress p ON p.case_id = c.id`)
    );
    res.render('dashboard', { cases, filter, counts });
  });

  // ------------------------------------------------------------- clients
  app.get('/clients', requireUser, async (req, res) => {
    const archived = req.query.show === 'archived';
    const clients = await inFirm(req, (q) =>
      q(`SELECT c.*, (SELECT count(*)::int FROM cases k WHERE k.client_id = c.id) AS case_count
           FROM clients c WHERE (archived_at IS NOT NULL) = $1 ORDER BY last_name, first_name LIMIT 500`, [archived])
    );
    const flash = req.query.deleted ? { ok: true, text: 'Client and all their documents deleted.' }
      : req.query.archived ? { ok: true, text: 'Client archived. Find them under Archived.' } : null;
    res.render('clients', { clients, archived, flash });
  });

  app.get('/clients/new', requireUser, (req, res) => res.render('client_new', { error: null, values: {} }));

  app.post('/clients', requireUser, requireCsrf, async (req, res) => {
    const v = {
      first_name: clean(req.body.first_name, 100),
      last_name: clean(req.body.last_name, 100),
      email: clean(req.body.email, 200).toLowerCase() || null,
      phone: clean(req.body.phone, 40) || null,
    };
    let error = null;
    if (!v.first_name || !v.last_name) error = 'First and last name are needed.';
    else if (!v.email && !v.phone) error = 'Add an email or phone number so reminders can reach them.';
    else if (v.email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v.email)) error = 'That email address doesn\'t look right.';
    if (error) return res.status(400).render('client_new', { error, values: v });

    const id = await inFirm(req, async (q) => {
      const [row] = await q(
        `INSERT INTO clients (firm_id, first_name, last_name, email, phone) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
        [req.user.firm_id, v.first_name, v.last_name, v.email, v.phone]
      );
      await audit(q, { ...actor(req), action: 'client.created', entityType: 'client', entityId: row.id });
      return row.id;
    });
    res.redirect(`/cases/new?client=${id}`);
  });

  // --------------------------------------------------------------- cases
  app.get('/cases/new', requireUser, async (req, res) => {
    const data = await inFirm(req, async (q) => ({
      clients: await q(`SELECT id, first_name, last_name FROM clients WHERE archived_at IS NULL ORDER BY last_name, first_name LIMIT 500`),
      templates: await q(`SELECT id, name FROM checklist_templates ORDER BY firm_id NULLS FIRST, name`),
    }));
    res.render('case_new', { ...data, selected: req.query.client, error: null });
  });

  app.post('/cases', requireUser, requireCsrf, async (req, res) => {
    const clientId = String(req.body.client_id || '');
    const templateId = String(req.body.template_id || '');
    const title = clean(req.body.title, 150) || 'Mortgage application';
    const lender = clean(req.body.lender, 100) || null;
    if (!UUID.test(clientId)) return res.redirect('/cases/new');

    const caseId = await inFirm(req, async (q) => {
      const [client] = await q('SELECT id FROM clients WHERE id = $1', [clientId]);
      if (!client) return null;
      const [k] = await q(
        `INSERT INTO cases (firm_id, client_id, adviser_id, title, lender) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
        [req.user.firm_id, clientId, req.user.user_id, title, lender]
      );
      if (UUID.test(templateId)) {
        await q(
          `INSERT INTO document_requests (firm_id, case_id, label, help_text, required, sort_order)
           SELECT $1, $2, label, help_text, required, sort_order FROM checklist_template_items WHERE template_id = $3`,
          [req.user.firm_id, k.id, templateId]
        );
      }
      await audit(q, { ...actor(req), action: 'case.created', entityType: 'case', entityId: k.id, details: { template_id: templateId || null } });
      return k.id;
    });
    if (!caseId) return res.status(404).render('error', { message: 'Client not found.' });
    res.redirect(`/cases/${caseId}`);
  });

  async function loadCase(req, caseId) {
    return inFirm(req, async (q) => {
      const [kase] = await q(
        `SELECT c.*, cl.first_name, cl.last_name, cl.email AS client_email, cl.phone AS client_phone, u.full_name AS adviser_name
           FROM cases c
           JOIN clients cl ON cl.firm_id = c.firm_id AND cl.id = c.client_id
           LEFT JOIN users u ON u.firm_id = c.firm_id AND u.id = c.adviser_id
          WHERE c.id = $1`,
        [caseId]
      );
      if (!kase) return null;
      const requests = await q(`SELECT * FROM document_requests WHERE case_id = $1 ORDER BY sort_order, created_at`, [caseId]);
      const documents = await q(
        `SELECT id, request_id, original_filename, mime_type, size_bytes, uploaded_at, uploaded_by_user_id
           FROM documents WHERE request_id IN (SELECT id FROM document_requests WHERE case_id = $1) AND deleted_at IS NULL
          ORDER BY uploaded_at DESC`,
        [caseId]
      );
      const links = await q(
        `SELECT id, expires_at, last_used_at, created_at FROM upload_links
          WHERE case_id = $1 AND revoked_at IS NULL AND expires_at > now() ORDER BY created_at DESC`,
        [caseId]
      );
      const history = await q(
        `SELECT a.action, a.actor_type, a.created_at, a.details, u.full_name
           FROM audit_log a LEFT JOIN users u ON u.id = a.actor_user_id
          WHERE a.entity_id = $1 OR a.entity_id IN (SELECT id FROM document_requests WHERE case_id = $1)
                OR (a.entity_type = 'document' AND a.details->>'case_id' = $1::text)
          ORDER BY a.created_at DESC LIMIT 50`,
        [caseId]
      );
      const reminders = await q(
        `SELECT kind, status, recipient, outstanding, sent_at, created_at, error FROM reminders
          WHERE case_id = $1 ORDER BY created_at DESC LIMIT 20`,
        [caseId]
      );
      const [firm] = await q('SELECT reminder_every_days, max_reminders FROM firms');
      for (const r of requests) r.documents = documents.filter((d) => d.request_id === r.id);
      return { kase, requests, links, history, reminders, firm };
    });
  }

  app.get('/cases/:id', requireUser, checkId('id'), async (req, res) => {
    const data = await loadCase(req, req.params.id);
    if (!data) return res.status(404).render('error', { message: 'Case not found.' });
    const flash = req.query.sent ? { ok: true, text: 'Email sent to your client.' } : null;
    res.render('case', { ...data, newLink: null, flash });
  });

  const ACTIONS = {
    accept: { status: 'accepted', from: ['received'] },
    reject: { status: 'rejected', from: ['received', 'accepted'] },
    waive: { status: 'waived', from: ['requested', 'received', 'rejected'] },
    reopen: { status: 'requested', from: ['accepted', 'waived', 'rejected', 'received'] },
  };

  app.post('/cases/:id/requests/:rid', requireUser, requireCsrf, checkId('id', 'rid'), async (req, res) => {
    const act = ACTIONS[req.body.action];
    if (!act) return res.status(400).render('error', { message: 'Unknown action.' });
    const reason = clean(req.body.reason, 300) || null;
    if (act.status === 'rejected' && !reason) {
      return res.status(400).render('error', { message: 'Add a reason when rejecting a document, so the client knows what to fix.' });
    }
    const ok = await inFirm(req, async (q) => {
      const rows = await q(
        `UPDATE document_requests SET status = $1, rejected_reason = $2
          WHERE id = $3 AND case_id = $4 AND status::text = ANY($5) RETURNING id`,
        [act.status, act.status === 'rejected' ? reason : null, req.params.rid, req.params.id, act.from]
      );
      if (!rows.length) return false;
      if (act.status === 'rejected') {
        // If we're chasing this client, tell them what to fix within minutes.
        await q(
          `UPDATE cases SET next_reminder_at = now() + interval '10 minutes'
            WHERE id = $1 AND chasing_started_at IS NOT NULL AND NOT reminders_paused`,
          [req.params.id]
        );
      }
      await resumeChasingIfNeeded(q, req.params.id);
      await audit(q, { ...actor(req), action: `request.${act.status}`, entityType: 'document_request', entityId: req.params.rid, details: reason ? { reason } : {} });
      return true;
    });
    if (!ok) return res.status(409).render('error', { message: 'That document can\'t be changed that way right now. Reload the case and try again.' });
    res.redirect(`/cases/${req.params.id}`);
  });

  app.post('/cases/:id/requests', requireUser, requireCsrf, checkId('id'), async (req, res) => {
    const label = clean(req.body.label, 150);
    if (!label) return res.redirect(`/cases/${req.params.id}`);
    const ok = await inFirm(req, async (q) => {
      const [k] = await q('SELECT id FROM cases WHERE id = $1', [req.params.id]);
      if (!k) return false;
      const [r] = await q(
        `INSERT INTO document_requests (firm_id, case_id, label, help_text, required, sort_order)
         VALUES ($1, $2, $3, $4, $5, (SELECT coalesce(max(sort_order), 0) + 1 FROM document_requests WHERE case_id = $2)) RETURNING id`,
        [req.user.firm_id, req.params.id, label, clean(req.body.help_text, 300) || null, req.body.required === 'on']
      );
      await resumeChasingIfNeeded(q, req.params.id);
      await audit(q, { ...actor(req), action: 'request.added', entityType: 'document_request', entityId: r.id, details: { label } });
      return true;
    });
    if (!ok) return res.status(404).render('error', { message: 'Case not found.' });
    res.redirect(`/cases/${req.params.id}`);
  });

  async function caseExists(req) {
    return inFirm(req, async (q) => (await q('SELECT id FROM cases WHERE id = $1', [req.params.id])).length > 0);
  }

  async function chaseMessage(req, res, result) {
    // Redirect after a successful send so refreshing the page can't email the client twice.
    if (result.status === 'sent') return res.redirect(303, `/cases/${req.params.id}?sent=1`);
    const data = await loadCase(req, req.params.id);
    const messages = {
      sent: 'Email sent to your client.',
      'client has no email': 'This client has no email address, so nothing was sent. Add one on the client first.',
      'case not open': 'This case isn\'t open, so nothing was sent.',
      'nothing outstanding from the client': 'Nothing is outstanding from the client, so nothing was sent.',
      'busy or not found': 'Another email for this case is being sent right now. Try again in a minute.',
    };
    const text = result.status === 'failed' ? `The email couldn't be sent (${result.reason}). It will be retried in 2 hours.` : messages[result.status === 'sent' ? 'sent' : result.reason] || 'Nothing was sent.';
    res.status(result.status === 'sent' ? 200 : 400).render('case', { ...data, newLink: null, flash: { ok: result.status === 'sent', text } });
  }

  app.post('/cases/:id/chase/start', requireUser, requireCsrf, checkId('id'), async (req, res) => {
    if (!(await caseExists(req))) return res.status(404).render('error', { message: 'Case not found.' });
    const result = await sendCaseReminder({ db, mailer, baseUrl: cfg.baseUrl, firmId: req.user.firm_id, caseId: req.params.id, kind: 'first', force: true, userId: req.user.user_id, linkDays: cfg.linkDays });
    await chaseMessage(req, res, result);
  });

  app.post('/cases/:id/chase/now', requireUser, requireCsrf, checkId('id'), async (req, res) => {
    if (!(await caseExists(req))) return res.status(404).render('error', { message: 'Case not found.' });
    const result = await sendCaseReminder({ db, mailer, baseUrl: cfg.baseUrl, firmId: req.user.firm_id, caseId: req.params.id, kind: 'manual', force: true, userId: req.user.user_id, linkDays: cfg.linkDays });
    await chaseMessage(req, res, result);
  });

  app.post('/cases/:id/chase/:action', requireUser, requireCsrf, checkId('id'), async (req, res) => {
    const action = req.params.action;
    if (!['pause', 'resume'].includes(action)) return res.status(404).render('error', { message: 'Not found.' });
    const ok = await inFirm(req, async (q) => {
      const rows = action === 'pause'
        ? await q(`UPDATE cases SET reminders_paused = true WHERE id = $1 AND chasing_started_at IS NOT NULL RETURNING id`, [req.params.id])
        : await q(
            `UPDATE cases SET reminders_paused = false, chasing_stopped = NULL, reminders_sent = CASE WHEN chasing_stopped = 'limit_reached' THEN 1 ELSE reminders_sent END,
                    next_reminder_at = coalesce(least(next_reminder_at, now() + interval '1 day'), now() + interval '1 day')
              WHERE id = $1 AND chasing_started_at IS NOT NULL AND status = 'open' RETURNING id`,
            [req.params.id]
          );
      if (rows.length) await audit(q, { ...actor(req), action: `chasing.${action === 'pause' ? 'paused' : 'resumed'}`, entityType: 'case', entityId: req.params.id });
      return rows.length > 0;
    });
    if (!ok) return res.status(409).render('error', { message: 'Chasing can\'t be changed on this case right now.' });
    res.redirect(`/cases/${req.params.id}`);
  });

  app.post('/cases/:id/links', requireUser, requireCsrf, checkId('id'), async (req, res) => {
    const token = randomToken();
    const ok = await inFirm(req, async (q) => {
      const [k] = await q(`SELECT id FROM cases WHERE id = $1 AND status IN ('open', 'complete')`, [req.params.id]);
      if (!k) return false;
      const [l] = await q(
        `INSERT INTO upload_links (firm_id, case_id, token_hash, expires_at)
         VALUES ($1, $2, $3, now() + make_interval(days => $4)) RETURNING id`,
        [req.user.firm_id, req.params.id, sha256(token), cfg.linkDays]
      );
      await audit(q, { ...actor(req), action: 'upload_link.created', entityType: 'case', entityId: req.params.id, details: { link_id: l.id } });
      return true;
    });
    if (!ok) return res.status(404).render('error', { message: 'Case not found or closed.' });
    const data = await loadCase(req, req.params.id);
    // The full link is shown once here and never stored.
    res.render('case', { ...data, newLink: `${cfg.baseUrl}/u/${token}`, flash: null });
  });

  app.post('/cases/:id/links/:lid/revoke', requireUser, requireCsrf, checkId('id', 'lid'), async (req, res) => {
    await inFirm(req, async (q) => {
      const rows = await q(
        `UPDATE upload_links SET revoked_at = now() WHERE id = $1 AND case_id = $2 AND revoked_at IS NULL RETURNING id`,
        [req.params.lid, req.params.id]
      );
      if (rows.length) await audit(q, { ...actor(req), action: 'upload_link.revoked', entityType: 'case', entityId: req.params.id, details: { link_id: req.params.lid } });
    });
    res.redirect(`/cases/${req.params.id}`);
  });

  app.get('/documents/:id', requireUser, checkId('id'), async (req, res) => {
    const doc = await inFirm(req, async (q) => {
      const [d] = await q(
        `SELECT d.*, r.case_id FROM documents d JOIN document_requests r ON r.id = d.request_id
          WHERE d.id = $1 AND d.deleted_at IS NULL`,
        [req.params.id]
      );
      if (d) await audit(q, { ...actor(req), action: 'document.downloaded', entityType: 'document', entityId: d.id, details: { case_id: d.case_id } });
      return d;
    });
    if (!doc) return res.status(404).render('error', { message: 'Document not found.' });
    const body = await storage.get(doc.storage_key);
    res.set({
      'Content-Type': doc.mime_type,
      'Content-Disposition': `attachment; filename="${doc.original_filename.replace(/[^\w.\- ]/g, '_')}"`,
      'Cache-Control': 'private, no-store',
    });
    res.send(body);
  });

  // ------------------------------------------------- shared helpers (staff)
  const requireOwner = (req, res, next) =>
    req.user?.role === 'owner' ? next() : res.status(403).render('error', { message: 'Only the firm owner can do that.' });

  async function purgeFiles(keys) {
    for (const key of keys) {
      try { await storage.remove(key); } catch (err) { console.error('File purge failed', key, err.message); }
    }
  }

  // If chasing was on and a change left the case open with no reminder scheduled, schedule one.
  async function resumeChasingIfNeeded(q, caseId) {
    await q(
      `UPDATE cases SET next_reminder_at = now() + interval '1 day'
        WHERE id = $1 AND status = 'open' AND chasing_started_at IS NOT NULL AND NOT reminders_paused
          AND chasing_stopped IS NULL AND next_reminder_at IS NULL`,
      [caseId]
    );
  }

  function clientFields(body) {
    const v = {
      first_name: clean(body.first_name, 100),
      last_name: clean(body.last_name, 100),
      email: clean(body.email, 200).toLowerCase() || null,
      phone: clean(body.phone, 40) || null,
    };
    let error = null;
    if (!v.first_name || !v.last_name) error = 'First and last name are needed.';
    else if (!v.email && !v.phone) error = 'Add an email or phone number so reminders can reach them.';
    else if (v.email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v.email)) error = 'That email address doesn\'t look right.';
    return { v, error };
  }

  // ------------------------------------------------------------ client page
  async function loadClient(req, id) {
    return inFirm(req, async (q) => {
      const [client] = await q('SELECT * FROM clients WHERE id = $1', [id]);
      if (!client) return null;
      const cases = await q(
        `SELECT c.id, c.title, c.lender, c.status, c.created_at, p.required_total::int, p.required_done::int
           FROM cases c JOIN case_progress p ON p.case_id = c.id WHERE c.client_id = $1 ORDER BY c.created_at DESC`,
        [id]
      );
      return { client, cases };
    });
  }

  app.get('/clients/:id', requireUser, checkId('id'), async (req, res) => {
    const data = await loadClient(req, req.params.id);
    if (!data) return res.status(404).render('error', { message: 'Client not found.' });
    const flash = req.query.saved ? { ok: true, text: 'Client details saved.' } : null;
    res.render('client', { ...data, values: data.client, error: null, flash });
  });

  app.post('/clients/:id', requireUser, requireCsrf, checkId('id'), async (req, res) => {
    const { v, error } = clientFields(req.body);
    if (error) {
      const data = await loadClient(req, req.params.id);
      if (!data) return res.status(404).render('error', { message: 'Client not found.' });
      return res.status(400).render('client', { ...data, values: { ...data.client, ...v }, error, flash: null });
    }
    const ok = await inFirm(req, async (q) => {
      const rows = await q(
        `UPDATE clients SET first_name = $2, last_name = $3, email = $4, phone = $5 WHERE id = $1 RETURNING id`,
        [req.params.id, v.first_name, v.last_name, v.email, v.phone]
      );
      if (!rows.length) return false;
      // A new email address means chasing can start again where it had stopped for want of one.
      if (v.email) {
        await q(
          `UPDATE cases SET chasing_stopped = NULL, next_reminder_at = coalesce(next_reminder_at, now() + interval '1 hour')
            WHERE client_id = $1 AND chasing_stopped = 'no_email' AND status = 'open'`,
          [req.params.id]
        );
      }
      await audit(q, { ...actor(req), action: 'client.updated', entityType: 'client', entityId: req.params.id });
      return true;
    });
    if (!ok) return res.status(404).render('error', { message: 'Client not found.' });
    res.redirect(303, `/clients/${req.params.id}?saved=1`);
  });

  app.post('/clients/:id/:action', requireUser, requireCsrf, checkId('id'), async (req, res, next) => {
    if (!['archive', 'unarchive'].includes(req.params.action)) return next();
    const archive = req.params.action === 'archive';
    const ok = await inFirm(req, async (q) => {
      const rows = await q(`UPDATE clients SET archived_at = ${archive ? 'now()' : 'NULL'} WHERE id = $1 RETURNING id`, [req.params.id]);
      if (rows.length) await audit(q, { ...actor(req), action: `client.${archive ? 'archived' : 'unarchived'}`, entityType: 'client', entityId: req.params.id });
      return rows.length > 0;
    });
    if (!ok) return res.status(404).render('error', { message: 'Client not found.' });
    res.redirect(303, archive ? '/clients?archived=1' : `/clients/${req.params.id}`);
  });

  app.post('/clients/:id/delete', requireUser, requireCsrf, requireOwner, checkId('id'), async (req, res) => {
    if (req.body.confirm !== 'yes') return res.status(400).render('error', { message: 'Tick the box to confirm you want to delete this client and all their documents.' });
    const keys = await inFirm(req, async (q) => {
      const docs = await q(
        `SELECT d.storage_key FROM documents d JOIN document_requests r ON r.id = d.request_id
           JOIN cases c ON c.id = r.case_id WHERE c.client_id = $1`,
        [req.params.id]
      );
      const rows = await q('DELETE FROM clients WHERE id = $1 RETURNING id', [req.params.id]);
      if (!rows.length) return null;
      await audit(q, { ...actor(req), action: 'client.deleted', entityType: 'client', entityId: req.params.id, details: { files: docs.length } });
      return docs.map((d) => d.storage_key);
    });
    if (!keys) return res.status(404).render('error', { message: 'Client not found.' });
    await purgeFiles(keys);
    res.redirect(303, '/clients?deleted=1');
  });

  // ------------------------------------------------------------ case status
  app.post('/cases/:id/status', requireUser, requireCsrf, checkId('id'), async (req, res) => {
    const action = req.body.action;
    if (!['close', 'hold', 'reopen'].includes(action)) return res.status(400).render('error', { message: 'Unknown action.' });
    const ok = await inFirm(req, async (q) => {
      let rows;
      if (action === 'close') {
        rows = await q(`UPDATE cases SET status = 'closed', closed_at = now(), next_reminder_at = NULL WHERE id = $1 AND status <> 'closed' RETURNING id`, [req.params.id]);
      } else if (action === 'hold') {
        rows = await q(`UPDATE cases SET status = 'on_hold', next_reminder_at = NULL WHERE id = $1 AND status IN ('open', 'complete') RETURNING id`, [req.params.id]);
      } else {
        rows = await q(
          `UPDATE cases c SET closed_at = NULL,
                  status = CASE WHEN p.required_total > 0 AND p.required_done = p.required_total THEN 'complete'::case_status ELSE 'open'::case_status END
             FROM case_progress p
            WHERE c.id = $1 AND p.case_id = c.id AND c.status IN ('closed', 'on_hold') RETURNING c.id`,
          [req.params.id]
        );
        if (rows.length) await resumeChasingIfNeeded(q, req.params.id);
      }
      if (rows.length) await audit(q, { ...actor(req), action: `case.${{ close: 'closed', hold: 'put_on_hold', reopen: 'reopened' }[action]}`, entityType: 'case', entityId: req.params.id });
      return rows.length > 0;
    });
    if (!ok) return res.status(409).render('error', { message: 'That case can\'t be changed that way right now. Reload it and try again.' });
    res.redirect(303, `/cases/${req.params.id}`);
  });

  app.post('/cases/:id/delete', requireUser, requireCsrf, requireOwner, checkId('id'), async (req, res) => {
    if (req.body.confirm !== 'yes') return res.status(400).render('error', { message: 'Tick the box to confirm you want to delete this case and its documents.' });
    const result = await inFirm(req, async (q) => {
      const [k] = await q('SELECT client_id FROM cases WHERE id = $1', [req.params.id]);
      if (!k) return null;
      const docs = await q(
        `SELECT d.storage_key FROM documents d JOIN document_requests r ON r.id = d.request_id WHERE r.case_id = $1`,
        [req.params.id]
      );
      await q('DELETE FROM cases WHERE id = $1', [req.params.id]);
      await audit(q, { ...actor(req), action: 'case.deleted', entityType: 'case', entityId: req.params.id, details: { files: docs.length } });
      return { clientId: k.client_id, keys: docs.map((d) => d.storage_key) };
    });
    if (!result) return res.status(404).render('error', { message: 'Case not found.' });
    await purgeFiles(result.keys);
    res.redirect(303, `/clients/${result.clientId}`);
  });

  // ------------------------------------------- remove a file / a checklist item
  app.post('/documents/:id/remove', requireUser, requireCsrf, checkId('id'), async (req, res) => {
    const result = await inFirm(req, async (q) => {
      const [d] = await q(
        `UPDATE documents d SET deleted_at = now() FROM document_requests r
          WHERE d.id = $1 AND r.id = d.request_id AND d.deleted_at IS NULL
          RETURNING d.storage_key, d.request_id, r.case_id`,
        [req.params.id]
      );
      if (!d) return null;
      // No files left on that item: it goes back to being requested from the client.
      await q(
        `UPDATE document_requests SET status = 'requested', rejected_reason = NULL
          WHERE id = $1 AND status IN ('received', 'accepted', 'rejected')
            AND NOT EXISTS (SELECT 1 FROM documents WHERE request_id = $1 AND deleted_at IS NULL)`,
        [d.request_id]
      );
      await resumeChasingIfNeeded(q, d.case_id);
      await audit(q, { ...actor(req), action: 'document.removed', entityType: 'document', entityId: req.params.id, details: { case_id: d.case_id } });
      return d;
    });
    if (!result) return res.status(404).render('error', { message: 'File not found.' });
    await purgeFiles([result.storage_key]);
    res.redirect(303, `/cases/${result.case_id}`);
  });

  app.post('/cases/:id/requests/:rid/delete', requireUser, requireCsrf, checkId('id', 'rid'), async (req, res) => {
    const keys = await inFirm(req, async (q) => {
      const docs = await q('SELECT storage_key FROM documents WHERE request_id = $1', [req.params.rid]);
      const rows = await q('DELETE FROM document_requests WHERE id = $1 AND case_id = $2 RETURNING label', [req.params.rid, req.params.id]);
      if (!rows.length) return null;
      await audit(q, { ...actor(req), action: 'request.removed', entityType: 'case', entityId: req.params.id, details: { label: rows[0].label } });
      return docs.map((d) => d.storage_key);
    });
    if (!keys) return res.status(404).render('error', { message: 'Checklist item not found.' });
    await purgeFiles(keys);
    res.redirect(303, `/cases/${req.params.id}`);
  });

  // ------------------------------------------------------ forgot password
  app.get('/forgot', (req, res) => res.render('forgot', { sent: false, error: null }));

  app.post('/forgot', async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase().slice(0, 200);
    const key = `forgot|${req.ip}`;
    if (limiter.blocked(key)) return res.status(429).render('forgot', { sent: false, error: 'Too many requests. Wait 15 minutes and try again.' });
    limiter.fail(key);
    const token = randomToken();
    const [u] = await db.asApp((q) => q('SELECT * FROM reset_create($1, $2, $3)', [email, sha256(token), 60]));
    if (u) {
      const msg = accountEmail({ purpose: 'reset', name: u.full_name, firmName: u.firm_name, link: `${cfg.baseUrl}/reset/${token}` });
      mailer.send({ to: u.email, toName: u.full_name, fromName: 'Fileready', ...msg }).catch((err) => console.error('Reset email failed:', err.message));
    }
    // Same answer whether or not the account exists.
    res.render('forgot', { sent: true, error: null });
  });

  const tokenOk = (t) => /^[A-Za-z0-9_-]{43}$/.test(t);

  app.get('/reset/:token', async (req, res) => {
    res.set('Referrer-Policy', 'no-referrer');
    const [r] = tokenOk(req.params.token) ? await db.asApp((q) => q('SELECT * FROM reset_check($1)', [sha256(req.params.token)])) : [];
    if (!r) return res.status(404).render('reset', { valid: false, error: null, who: null, token: null });
    res.render('reset', { valid: true, error: null, who: r, token: req.params.token });
  });

  app.post('/reset/:token', async (req, res) => {
    res.set('Referrer-Policy', 'no-referrer');
    const t = req.params.token;
    const [r] = tokenOk(t) ? await db.asApp((q) => q('SELECT * FROM reset_check($1)', [sha256(t)])) : [];
    if (!r) return res.status(404).render('reset', { valid: false, error: null, who: null, token: null });
    const next = String(req.body.new_password || '').slice(0, 200);
    const confirm = String(req.body.confirm || '').slice(0, 200);
    const fail = (error) => res.status(400).render('reset', { valid: true, error, who: r, token: t });
    if (next.length < MIN_PASSWORD_LENGTH) return fail(`Your password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
    if (next !== confirm) return fail('The two passwords don\'t match.');
    const [done] = await db.asApp(async (q) => q('SELECT * FROM reset_consume($1, $2)', [sha256(t), await hashPassword(next)]));
    if (!done) return res.status(404).render('reset', { valid: false, error: null, who: null, token: null });
    res.redirect(303, '/login?reset=1');
  });

  // ----------------------------------------------------------------- team
  async function loadTeam(req) {
    return inFirm(req, (q) =>
      q(`SELECT id, full_name, email, role, disabled_at, last_login_at, password_hash IS NOT NULL AS has_password
           FROM users ORDER BY disabled_at NULLS FIRST, role, full_name`)
    );
  }

  async function sendInvite(req, userId) {
    const token = randomToken();
    const target = await inFirm(req, async (q) => {
      const [ok] = await q('SELECT invite_create($1, $2, $3) AS ok', [userId, sha256(token), 10080]);
      if (!ok.ok) return null;
      const [u] = await q('SELECT full_name, email FROM users WHERE id = $1', [userId]);
      await audit(q, { ...actor(req), action: 'user.invited', entityType: 'user', entityId: userId });
      return u;
    });
    if (!target) return false;
    const msg = accountEmail({ purpose: 'invite', name: target.full_name, firmName: req.user.firm_name, inviter: req.user.full_name, link: `${cfg.baseUrl}/reset/${token}` });
    try {
      await mailer.send({ to: target.email, toName: target.full_name, fromName: 'Fileready', replyTo: req.user.email, ...msg });
      return true;
    } catch (err) {
      console.error('Invite email failed:', err.message);
      return 'email_failed';
    }
  }

  app.get('/team', requireUser, requireOwner, async (req, res) => {
    const flash = { invited: { ok: true, text: 'Invitation sent. The link works for 7 days.' }, failed: { ok: false, text: 'The person was added, but the invitation email couldn\'t be sent. Try "Resend invitation".' } }[req.query.f] || null;
    res.render('team', { team: await loadTeam(req), error: null, values: {}, flash });
  });

  app.post('/team', requireUser, requireCsrf, requireOwner, async (req, res) => {
    const v = { full_name: clean(req.body.full_name, 100), email: clean(req.body.email, 200).toLowerCase(), role: req.body.role === 'admin_staff' ? 'admin_staff' : 'adviser' };
    const fail = async (error) => res.status(400).render('team', { team: await loadTeam(req), error, values: v, flash: null });
    if (!v.full_name) return fail('Add their name.');
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v.email)) return fail('That email address doesn\'t look right.');
    let id;
    try {
      id = await inFirm(req, async (q) => {
        const [u] = await q(`INSERT INTO users (firm_id, email, full_name, role) VALUES ($1, $2, $3, $4) RETURNING id`, [req.user.firm_id, v.email, v.full_name, v.role]);
        await audit(q, { ...actor(req), action: 'user.added', entityType: 'user', entityId: u.id, details: { role: v.role } });
        return u.id;
      });
    } catch (err) {
      if (/users_email_key|duplicate key/.test(err.message)) return fail('That email address already has a Fileready login.');
      throw err;
    }
    const sent = await sendInvite(req, id);
    res.redirect(303, `/team?f=${sent === true ? 'invited' : 'failed'}`);
  });

  app.post('/team/:uid/:action', requireUser, requireCsrf, requireOwner, checkId('uid'), async (req, res, next) => {
    const { uid, action } = req.params;
    if (!['resend', 'disable', 'enable'].includes(action)) return next();
    if (uid === req.user.user_id) return res.status(400).render('error', { message: 'You can\'t change your own access here.' });
    if (action === 'resend') {
      const sent = await sendInvite(req, uid);
      if (!sent) return res.status(404).render('error', { message: 'That person isn\'t active in your firm.' });
      return res.redirect(303, `/team?f=${sent === true ? 'invited' : 'failed'}`);
    }
    const ok = await inFirm(req, async (q) => {
      const rows = await q(`UPDATE users SET disabled_at = ${action === 'disable' ? 'now()' : 'NULL'} WHERE id = $1 RETURNING id`, [uid]);
      if (!rows.length) return false;
      if (action === 'disable') await q('SELECT sessions_revoke_user($1)', [uid]);
      await audit(q, { ...actor(req), action: `user.${action}d`, entityType: 'user', entityId: uid });
      return true;
    });
    if (!ok) return res.status(404).render('error', { message: 'Person not found.' });
    res.redirect(303, '/team');
  });

  // ------------------------------------------------------------- settings
  app.get('/settings', requireUser, requireOwner, async (req, res) => {
    const [firm] = await inFirm(req, (q) => q('SELECT name, reminder_every_days, max_reminders FROM firms'));
    res.render('settings', { values: firm, error: null, flash: req.query.saved ? { ok: true, text: 'Settings saved.' } : null });
  });

  app.post('/settings', requireUser, requireCsrf, requireOwner, async (req, res) => {
    const v = { name: clean(req.body.name, 120), reminder_every_days: Number(req.body.reminder_every_days), max_reminders: Number(req.body.max_reminders) };
    let error = null;
    if (!v.name) error = 'Add your firm\'s name.';
    else if (!Number.isInteger(v.reminder_every_days) || v.reminder_every_days < 1 || v.reminder_every_days > 30) error = 'Days between reminders must be a whole number from 1 to 30.';
    else if (!Number.isInteger(v.max_reminders) || v.max_reminders < 1 || v.max_reminders > 20) error = 'Most emails per case must be a whole number from 1 to 20.';
    if (error) return res.status(400).render('settings', { values: v, error, flash: null });
    await inFirm(req, async (q) => {
      await q('UPDATE firms SET name = $1, reminder_every_days = $2, max_reminders = $3', [v.name, v.reminder_every_days, v.max_reminders]);
      await audit(q, { ...actor(req), action: 'firm.settings_updated', entityType: 'firm', entityId: req.user.firm_id, details: { reminder_every_days: v.reminder_every_days, max_reminders: v.max_reminders } });
    });
    res.redirect(303, '/settings?saved=1');
  });

  // ------------------------------------------- client upload page (no login)
  async function resolveLink(token) {
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
    const [link] = await db.asApp((q) => q('SELECT * FROM upload_link_resolve($1)', [sha256(token)]));
    return link || null;
  }

  async function loadUploadPage(link) {
    return db.asFirm(link.firm_id, async (q) => {
      const [info] = await q(
        `SELECT f.name AS firm_name, cl.first_name, c.title
           FROM cases c JOIN clients cl ON cl.firm_id = c.firm_id AND cl.id = c.client_id
           JOIN firms f ON f.id = c.firm_id WHERE c.id = $1`,
        [link.case_id]
      );
      const requests = await q(
        `SELECT r.id, r.label, r.help_text, r.required, r.status, r.rejected_reason,
                (SELECT count(*)::int FROM documents d WHERE d.request_id = r.id AND d.deleted_at IS NULL) AS file_count
           FROM document_requests r WHERE r.case_id = $1 ORDER BY r.sort_order, r.created_at`,
        [link.case_id]
      );
      return { info, requests };
    });
  }

  // Tell the case's adviser that the client uploaded, at most once every 30 minutes per case.
  async function notifyAdviser(link) {
    const row = await db.asFirm(link.firm_id, async (q) => {
      const [r] = await q(
        `UPDATE cases c SET last_upload_alert_at = now()
           FROM clients cl, users u
          WHERE c.id = $1 AND cl.id = c.client_id AND cl.firm_id = c.firm_id AND u.id = c.adviser_id AND u.firm_id = c.firm_id
            AND u.disabled_at IS NULL AND (c.last_upload_alert_at IS NULL OR c.last_upload_alert_at < now() - interval '30 minutes')
          RETURNING u.email, u.full_name, cl.first_name, cl.last_name`,
        [link.case_id]
      );
      if (!r) return null;
      const items = await q(`SELECT label FROM document_requests WHERE case_id = $1 AND status = 'received' ORDER BY sort_order`, [link.case_id]);
      return { ...r, items: items.map((i) => i.label) };
    });
    if (!row) return;
    const msg = uploadAlertEmail({
      adviserName: row.full_name, clientName: `${row.first_name} ${row.last_name}`, items: row.items,
      link: `${cfg.baseUrl}/cases/${link.case_id}`,
    });
    await mailer.send({ to: row.email, toName: row.full_name, fromName: 'Fileready', ...msg });
  }

  app.get('/u/:token', async (req, res) => {
    res.set('Cache-Control', 'no-store');
    const link = await resolveLink(req.params.token);
    if (!link) return res.status(404).render('upload_invalid');
    res.render('upload', { ...(await loadUploadPage(link)), token: req.params.token, message: req.query.done ? 'Thanks, your file was received.' : null, error: null });
  });

  app.post('/u/:token/:rid', (req, res, next) => {
    upload.single('file')(req, res, (err) => {
      if (err) req.uploadError = err.code === 'LIMIT_FILE_SIZE' ? 'That file is over 25 MB. Try a smaller scan or photo.' : 'Upload failed. Please try again.';
      next();
    });
  }, async (req, res) => {
    res.set('Cache-Control', 'no-store');
    const link = await resolveLink(req.params.token);
    if (!link) return res.status(404).render('upload_invalid');
    const showError = async (error) =>
      res.status(400).render('upload', { ...(await loadUploadPage(link)), token: req.params.token, message: null, error });

    if (!UUID.test(req.params.rid)) return showError('Choose which document you are uploading.');
    if (req.uploadError) return showError(req.uploadError);
    if (!req.file || !req.file.size) return showError('Choose a file first.');
    const type = detectFileType(req.file.buffer);
    if (!type) return showError('Please upload a PDF or a photo (JPG, PNG or HEIC).');

    const docId = crypto.randomUUID();
    const storageKey = `${link.firm_id}/${docId}`;
    const saved = await db.asFirm(link.firm_id, async (q) => {
      const [r] = await q(
        `SELECT id, status FROM document_requests WHERE id = $1 AND case_id = $2`,
        [req.params.rid, link.case_id]
      );
      if (!r || ['accepted', 'waived'].includes(r.status)) return false;
      // Write the file first; if the database insert then fails, the
      // transaction rolls back and the orphan file is harmless.
      await storage.put(storageKey, req.file.buffer, type.mime);
      const filename = (req.file.originalname || `upload.${type.ext}`).replace(/[\u0000-\u001f]/g, '').slice(0, 200);
      await q(
        `INSERT INTO documents (id, firm_id, request_id, original_filename, mime_type, size_bytes, sha256, storage_key)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [docId, link.firm_id, r.id, filename, type.mime, req.file.size, sha256(req.file.buffer), storageKey]
      );
      await q(`UPDATE document_requests SET status = 'received', rejected_reason = NULL WHERE id = $1 AND status IN ('requested', 'rejected')`, [r.id]);
      await audit(q, {
        firmId: link.firm_id, actorType: 'client', action: 'document.uploaded', entityType: 'document', entityId: docId,
        details: { case_id: link.case_id, request_id: r.id, size_bytes: req.file.size, link_id: link.link_id }, ip: req.ip,
      });
      return true;
    });
    if (!saved) return showError('That item no longer needs a file.');
    notifyAdviser(link).catch((err) => console.error('Upload alert failed:', err.message));
    res.redirect(303, `/u/${req.params.token}?done=1`);
  });

  // -------------------------------------------------------------- errors
  app.use((req, res) => res.status(404).render('error', { message: 'Page not found.' }));
  app.use((err, req, res, _next) => {
    console.error(err);
    res.status(500).render('error', { message: 'Something went wrong. Please try again.' });
  });

  return app;
}

function clean(value, max) {
  return String(value ?? '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, max);
}
