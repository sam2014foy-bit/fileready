import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { audit } from './db.js';
import { sendCaseReminder, runReminders } from './reminders.js';
import { accountEmail, uploadAlertEmail, formatDue, dateOnly } from './emails.js';
import { runDaily } from './daily.js';
import QRCode from 'qrcode';
import { ZipArchive } from 'archiver';
import {
  verifyPassword, burnPasswordCheck, hashPassword, MIN_PASSWORD_LENGTH, randomToken, sha256,
  csrfTokenFor, safeEqual, createLoginLimiter, detectFileType, newTotpSecret, verifyTotp, totpUri,
  encryptSecret, decryptSecret, newRecoveryCodes, normaliseRecovery, normalisePhone,
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
export function createApp({ db, storage, mailer, sms = null, stripe = null, config }) {
  const cfg = {
    sessionHours: 12, linkDays: 14, secureCookies: false, remindersSecret: null, devOutbox: false,
    appSecret: null, allowSignup: false, contactEmail: null, legalName: null, legalAddress: null, privacyEmail: null, trialDays: 30, stripePriceId: null, stripeWebhookSecret: null, ...config,
  };
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
  // Animation libraries, served from our own origin so the CSP stays 'self'.
  app.use('/static/vendor/gsap', express.static(path.join(ROOT, 'node_modules/gsap/dist'), { maxAge: '7d' }));
  app.use('/static/vendor/lenis', express.static(path.join(ROOT, 'node_modules/lenis/dist'), { maxAge: '7d' }));
  app.get('/healthz', (req, res) => res.type('text').send('ok'));

  // Called by the scheduler (Supabase pg_cron) to send due reminders.
  app.post('/internal/reminders/run', async (req, res) => {
    const auth = req.get('authorization') || '';
    if (!cfg.remindersSecret || !safeEqual(auth, `Bearer ${cfg.remindersSecret}`)) return res.status(401).json({ error: 'unauthorised' });
    res.json(await runReminders({ db, mailer, sms, baseUrl: cfg.baseUrl }));
  });

  // Called once a day by the scheduler: morning summaries and retention clean-up.
  app.post('/internal/daily/run', async (req, res) => {
    const auth = req.get('authorization') || '';
    if (!cfg.remindersSecret || !safeEqual(auth, `Bearer ${cfg.remindersSecret}`)) return res.status(401).json({ error: 'unauthorised' });
    res.json(await runDaily({ db, mailer, storage, baseUrl: cfg.baseUrl }));
  });

  // Stripe tells us about payments here. Needs the raw body to check Stripe's signature.
  app.post('/stripe/webhook', express.raw({ type: 'application/json', limit: '1mb' }), async (req, res) => {
    if (!stripe || !cfg.stripeWebhookSecret) return res.status(404).end();
    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, req.get('stripe-signature') || '', cfg.stripeWebhookSecret);
    } catch {
      return res.status(400).send('bad signature');
    }
    const map = { active: 'active', trialing: 'active', past_due: 'past_due', unpaid: 'past_due', incomplete: 'past_due', canceled: 'cancelled', incomplete_expired: 'cancelled' };
    const o = event.data.object;
    if (event.type === 'checkout.session.completed' && o.mode === 'subscription') {
      const firmId = UUID.test(o.client_reference_id || '') ? o.client_reference_id : null;
      if (firmId) await db.asApp((q) => q('SELECT billing_update($1, $2, $3, $4)', [firmId, o.customer, o.subscription, 'active']));
    } else if (event.type.startsWith('customer.subscription.') && map[o.status]) {
      const firmId = UUID.test(o.metadata?.firm_id || '') ? o.metadata.firm_id : null;
      await db.asApp((q) => q('SELECT billing_update($1, $2, $3, $4)', [firmId, o.customer, o.id, map[o.status]]));
    }
    res.json({ received: true });
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
    res.locals.allowSignup = cfg.allowSignup; res.locals.dateOnly = dateOnly; res.locals.formatDue = formatDue;
    res.locals.billingBanner = null;
    const token = req.cookies[SESSION_COOKIE];
    if (token && token.length < 100) {
      const [row] = await db.asApp((q) => q('SELECT * FROM session_resolve($1)', [sha256(token)]));
      if (row && row.mfa_pending) {
        // Password checked, second step still to do: only /login/2fa is open to this session.
        req.pendingMfa = row;
        req.sessionToken = token;
      } else if (row) {
        req.user = row;
        req.sessionToken = token;
        res.locals.user = row;
        res.locals.csrf = csrfTokenFor(token);
        const trialOver = row.billing_status === 'trial' && row.trial_ends_at && new Date(row.trial_ends_at) < new Date();
        res.locals.billingBanner = row.role === 'owner' && stripe && (trialOver || row.billing_status === 'past_due')
          ? (row.billing_status === 'past_due' ? 'Your last payment didn\'t go through.' : 'Your free trial has ended.') : null;
      }
    }
    next();
  });

  const requireUser = (req, res, next) => (req.user ? next() : res.redirect('/login'));
  const requireCsrf = (req, res, next) =>
    req.user && safeEqual(req.body?._csrf ?? '', csrfTokenFor(req.sessionToken)) ? next() : res.status(403).send('Forbidden');
  const checkId = (...names) => (req, res, next) =>
    names.every((n) => UUID.test(req.params[n])) ? next() : res.status(404).render('error', { message: 'Not found.' });
  const inFirm = (req, fn) => db.asFirm(req.user.firm_id, fn, {
    userId: req.user.user_id,
    restrict: req.user.role === 'adviser' && req.user.advisers_see_all === false,
  });
  const setSessionCookie = (res, token) => res.cookie(SESSION_COOKIE, token, {
    httpOnly: true, sameSite: 'strict', secure: cfg.secureCookies, maxAge: cfg.sessionHours * 3600 * 1000, path: '/',
  });
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
    const [{ two_step: twoStep }] = await db.asFirm(found.firm_id, (q) =>
      q('SELECT totp_enabled_at IS NOT NULL AS two_step FROM users WHERE id = $1', [found.user_id]));
    await db.asApp((q) => q('SELECT session_create_v2($1, $2, $3, $4)', [sha256(token), found.user_id, cfg.sessionHours, twoStep]));
    if (!twoStep) {
      await db.asFirm(found.firm_id, (q) =>
        audit(q, { firmId: found.firm_id, actorType: 'user', userId: found.user_id, action: 'user.login', entityType: 'user', entityId: found.user_id, ip: req.ip })
      );
    }
    setSessionCookie(res, token);
    res.redirect(twoStep ? '/login/2fa' : '/');
  });

  app.post('/logout', requireUser, requireCsrf, async (req, res) => {
    await db.asApp((q) => q('SELECT session_revoke($1)', [sha256(req.sessionToken)]));
    res.clearCookie(SESSION_COOKIE, { path: '/' });
    res.redirect('/login');
  });

  app.get('/account/password', requireUser, (req, res) => res.render('password', { error: null, done: false }));

  app.get('/account', requireUser, async (req, res) => {
    const [me] = await inFirm(req, (q) => q('SELECT daily_summary, totp_enabled_at, totp_recovery FROM users WHERE id = $1', [req.user.user_id]));
    const flash = { summary: 'Morning summary setting saved.', on: 'Two-step login is on.', off: 'Two-step login is off.' }[req.query.f];
    res.render('account', { me, flash: flash ? { ok: true, text: flash } : null, twoStepAvailable: !!cfg.appSecret });
  });

  app.post('/account/summary', requireUser, requireCsrf, async (req, res) => {
    await inFirm(req, (q) => q('UPDATE users SET daily_summary = $2 WHERE id = $1', [req.user.user_id, req.body.daily_summary === 'on']));
    res.redirect(303, '/account?f=summary');
  });

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
  // ---------------------------------------------------------- legal pages
  const legal = { name: cfg.legalName || 'Fileready', address: cfg.legalAddress, email: cfg.privacyEmail || cfg.contactEmail };
  for (const [doc, title] of [['privacy', 'Privacy policy'], ['terms', 'Terms of service'], ['dpa', 'Data processing agreement']]) {
    app.get(`/${doc}`, (req, res) => res.render('legal', { doc, title, legal }));
  }

  // ---------------------------------------------------------- demo requests
  // A public form that emails the request to CONTACT_EMAIL, with Reply-To set
  // to the visitor so a reply goes straight to them.
  const demoLimiter = createLoginLimiter({ max: 5, windowMs: 60 * 60 * 1000 });
  const esc = (v) => String(v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  app.get('/demo', (req, res, next) => {
    if (!cfg.contactEmail) return next();
    res.render('demo', { sent: false, error: null, values: {} });
  });
  app.post('/demo', async (req, res, next) => {
    if (!cfg.contactEmail) return next();
    const v = {};
    for (const [k, max] of [['name', 120], ['firm', 160], ['email', 254], ['phone', 40], ['message', 2000]]) v[k] = String(req.body[k] || '').trim().slice(0, max);
    const again = (status, error) => res.status(status).render('demo', { sent: false, error, values: v });
    if (req.body.website) return res.render('demo', { sent: true, error: null, values: { ...v, name: v.name || 'there' } }); // bot
    if (!v.name || !v.firm) return again(400, 'Please add your name and firm.');
    if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(v.email)) return again(400, 'Please check your email address.');
    const key = `demo:${req.ip}`;
    if (demoLimiter.blocked(key)) return again(429, 'Too many requests from this connection. Try again in an hour.');
    demoLimiter.fail(key);
    const lines = [`Name: ${v.name}`, `Firm: ${v.firm}`, `Email: ${v.email}`, `Phone: ${v.phone || '-'}`, '', v.message || '(no message)'];
    try {
      await mailer.send({
        to: cfg.contactEmail, replyTo: v.email, fromName: 'Fileready website',
        subject: `Demo request: ${v.firm.replace(/[\r\n]+/g, ' ')}`,
        text: lines.join('\n') + '\n\nReply to this email to answer them directly.',
        html: `<p>${lines.map(esc).join('<br>')}</p><p>Reply to this email to answer them directly.</p>`,
      });
    } catch (err) {
      console.error('demo request email failed:', err.message);
      return again(502, "Your request couldn't be sent just now. Please try again in a few minutes.");
    }
    res.render('demo', { sent: true, error: null, values: v });
  });

  // Logged-out visitors get the marketing page; staff go straight to their cases.
  app.get('/', (req, res, next) => {
    if (req.user || req.pendingMfa) return next();
    res.render('home', { allowSignup: cfg.allowSignup, contactEmail: cfg.contactEmail });
  });
  app.get('/', requireUser, async (req, res) => {
    const filters = ['open', 'complete', 'all', 'review', 'stuck', 'due'];
    const filter = filters.includes(req.query.show) ? req.query.show : 'open';
    const data = await inFirm(req, async (q) => {
      const cases = await q(
        `SELECT c.id, c.title, c.lender, c.status, c.created_at, c.completed_at, c.due_date,
                c.chasing_started_at, c.next_reminder_at, c.reminders_paused, c.chasing_stopped, c.reminders_sent,
                cl.first_name, cl.last_name,
                p.required_total::int, p.required_done::int, p.awaiting_review::int, p.rejected::int
           FROM cases c
           JOIN clients cl ON cl.firm_id = c.firm_id AND cl.id = c.client_id
           JOIN case_progress p ON p.case_id = c.id
          WHERE CASE $1
                  WHEN 'all' THEN true
                  WHEN 'review' THEN c.status = 'open' AND p.awaiting_review > 0
                  WHEN 'stuck' THEN c.status = 'open' AND c.chasing_stopped IS NOT NULL
                  WHEN 'due' THEN c.status = 'open' AND c.due_date IS NOT NULL AND c.due_date <= current_date + 7
                  ELSE c.status::text = $1 END
          ORDER BY CASE WHEN $1 = 'due' THEN c.due_date END, p.awaiting_review DESC, c.created_at DESC
          LIMIT 300`,
        [filter]
      );
      const [counts] = await q(
        `SELECT count(*) FILTER (WHERE c.status = 'open')::int AS open,
                count(*) FILTER (WHERE c.status = 'complete')::int AS complete,
                count(*)::int AS all,
                count(*) FILTER (WHERE c.status = 'open' AND p.awaiting_review > 0)::int AS review,
                coalesce(sum(p.awaiting_review) FILTER (WHERE c.status = 'open'), 0)::int AS docs_to_review,
                count(*) FILTER (WHERE c.status = 'open' AND c.chasing_stopped IS NOT NULL)::int AS stuck,
                count(*) FILTER (WHERE c.status = 'open' AND c.due_date IS NOT NULL AND c.due_date <= current_date + 7)::int AS due,
                count(*) FILTER (WHERE c.status = 'open' AND c.due_date < current_date)::int AS overdue
           FROM cases c JOIN case_progress p ON p.case_id = c.id`
      );
      return { cases, counts };
    });
    const today = dateOnly(new Date());
    res.render('dashboard', { ...data, filter, today, formatDue });
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
        `SELECT kind, channel, status, recipient, outstanding, sent_at, created_at, error FROM reminders
          WHERE case_id = $1 ORDER BY created_at DESC LIMIT 20`,
        [caseId]
      );
      const [firm] = await q('SELECT reminder_every_days, max_reminders, sms_enabled FROM firms');
      const notes = await q(
        `SELECT n.body, n.created_at, u.full_name FROM case_notes n LEFT JOIN users u ON u.id = n.user_id
          WHERE n.case_id = $1 ORDER BY n.created_at DESC LIMIT 100`, [caseId]);
      for (const r of requests) r.documents = documents.filter((d) => d.request_id === r.id);
      return { kase, requests, links, history, reminders, firm, notes };
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
    const result = await sendCaseReminder({ db, mailer, sms, baseUrl: cfg.baseUrl, firmId: req.user.firm_id, caseId: req.params.id, kind: 'first', force: true, userId: req.user.user_id, linkDays: cfg.linkDays });
    await chaseMessage(req, res, result);
  });

  app.post('/cases/:id/chase/now', requireUser, requireCsrf, checkId('id'), async (req, res) => {
    if (!(await caseExists(req))) return res.status(404).render('error', { message: 'Case not found.' });
    const result = await sendCaseReminder({ db, mailer, sms, baseUrl: cfg.baseUrl, firmId: req.user.firm_id, caseId: req.params.id, kind: 'manual', force: true, userId: req.user.user_id, linkDays: cfg.linkDays });
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
        `UPDATE clients SET first_name = $2, last_name = $3, email = $4, phone = $5, sms_opt_out = $6 WHERE id = $1 RETURNING id`,
        [req.params.id, v.first_name, v.last_name, v.email, v.phone, req.body.sms_opt_out === 'on']
      );
      if (!rows.length) return false;
      // A new email address (or mobile) means chasing can start again where it had stopped for want of one.
      if (v.email || v.phone) {
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
      q(`SELECT id, full_name, email, role, disabled_at, last_login_at, password_hash IS NOT NULL AS has_password, totp_enabled_at IS NOT NULL AS two_step
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
    const flash = { invited: { ok: true, text: 'Invitation sent. The link works for 7 days.' }, failed: { ok: false, text: 'The person was added, but the invitation email couldn\'t be sent. Try "Resend invitation".' }, reset2fa: { ok: true, text: 'Two-step login reset. They can log in with their password and set it up again.' } }[req.query.f] || null;
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
    const [firm] = await inFirm(req, (q) => q('SELECT name, reminder_every_days, max_reminders, advisers_see_all, sms_enabled, data_retention_days FROM firms'));
    res.render('settings', { values: firm, error: null, smsAvailable: !!sms, flash: req.query.saved ? { ok: true, text: 'Settings saved.' } : null });
  });

  app.post('/settings', requireUser, requireCsrf, requireOwner, async (req, res) => {
    const v = {
      name: clean(req.body.name, 120), reminder_every_days: Number(req.body.reminder_every_days), max_reminders: Number(req.body.max_reminders),
      advisers_see_all: req.body.advisers_see_all !== 'own', sms_enabled: req.body.sms_enabled === 'on',
      data_retention_days: Math.round(Number(req.body.retention_years) * 365) || null,
    };
    let error = null;
    if (!v.name) error = 'Add your firm\'s name.';
    else if (!Number.isInteger(v.reminder_every_days) || v.reminder_every_days < 1 || v.reminder_every_days > 30) error = 'Days between reminders must be a whole number from 1 to 30.';
    else if (!Number.isInteger(v.max_reminders) || v.max_reminders < 1 || v.max_reminders > 20) error = 'Most emails per case must be a whole number from 1 to 20.';
    else if (!v.data_retention_days || v.data_retention_days < 365 || v.data_retention_days > 3650) error = 'Keep closed cases for between 1 and 10 years.';
    if (error) return res.status(400).render('settings', { values: v, error, smsAvailable: !!sms, flash: null });
    await inFirm(req, async (q) => {
      await q('UPDATE firms SET name = $1, reminder_every_days = $2, max_reminders = $3, advisers_see_all = $4, sms_enabled = $5, data_retention_days = $6',
        [v.name, v.reminder_every_days, v.max_reminders, v.advisers_see_all, v.sms_enabled && !!sms, v.data_retention_days]);
      await audit(q, { ...actor(req), action: 'firm.settings_updated', entityType: 'firm', entityId: req.user.firm_id, details: { reminder_every_days: v.reminder_every_days, max_reminders: v.max_reminders, advisers_see_all: v.advisers_see_all, sms_enabled: v.sms_enabled, data_retention_days: v.data_retention_days } });
    });
    res.redirect(303, '/settings?saved=1');
  });

  // ------------------------------------------------------- two-step login
  app.get('/login/2fa', (req, res) => {
    if (!req.pendingMfa) return res.redirect('/login');
    res.render('login_2fa', { error: null });
  });

  app.post('/login/2fa', async (req, res) => {
    const p = req.pendingMfa;
    if (!p) return res.redirect('/login');
    const key = `2fa|${p.user_id}`;
    const fail = (status, error) => res.status(status).render('login_2fa', { error });
    if (limiter.blocked(key)) return fail(429, 'Too many attempts. Wait 15 minutes and try again.');
    const code = String(req.body.code || '').trim();
    const ok = await db.asFirm(p.firm_id, async (q) => {
      const [u] = await q('SELECT totp_secret_enc, totp_last_step, totp_recovery FROM users WHERE id = $1 FOR UPDATE', [p.user_id]);
      if (!u?.totp_secret_enc) return false;
      const step = verifyTotp(decryptSecret(u.totp_secret_enc, cfg.appSecret), code);
      if (step !== null && (u.totp_last_step === null || step > Number(u.totp_last_step))) {
        await q('UPDATE users SET totp_last_step = $2 WHERE id = $1', [p.user_id, step]);
        return 'code';
      }
      const rc = sha256(normaliseRecovery(code));
      if ((u.totp_recovery || []).includes(rc)) {
        await q('UPDATE users SET totp_recovery = array_remove(totp_recovery, $2) WHERE id = $1', [p.user_id, rc]);
        return 'recovery';
      }
      return false;
    });
    if (!ok) {
      limiter.fail(key);
      return fail(401, 'That code didn\'t work. Check the time on your phone and try the newest code.');
    }
    limiter.reset(key);
    await db.asApp((q) => q('SELECT session_mfa_complete($1, $2)', [sha256(req.sessionToken), cfg.sessionHours]));
    await db.asFirm(p.firm_id, (q) => audit(q, { firmId: p.firm_id, actorType: 'user', userId: p.user_id, action: ok === 'recovery' ? 'user.login_recovery_code' : 'user.login', entityType: 'user', entityId: p.user_id, ip: req.ip }));
    res.redirect(303, '/');
  });

  app.get('/account/2fa/setup', requireUser, async (req, res) => {
    if (!cfg.appSecret) return res.status(503).render('error', { message: 'Two-step login isn\'t available until APP_SECRET is set on the server.' });
    if (req.user.totp_enabled) return res.redirect('/account');
    const secret = newTotpSecret();
    await inFirm(req, (q) => q('UPDATE users SET totp_secret_enc = $2 WHERE id = $1 AND totp_enabled_at IS NULL', [req.user.user_id, encryptSecret(secret, cfg.appSecret)]));
    const qr = await QRCode.toString(totpUri({ secret, account: req.user.email }), { type: 'svg', margin: 1, color: { dark: '#14222B', light: '#FFFFFF' } });
    res.render('twostep_setup', { qr, secret: secret.replace(/(.{4})/g, '$1 ').trim(), error: null, codes: null });
  });

  app.post('/account/2fa/setup', requireUser, requireCsrf, async (req, res) => {
    if (!cfg.appSecret) return res.status(503).render('error', { message: 'Two-step login isn\'t available.' });
    const codes = newRecoveryCodes();
    const result = await inFirm(req, async (q) => {
      const [u] = await q('SELECT totp_secret_enc FROM users WHERE id = $1 AND totp_enabled_at IS NULL', [req.user.user_id]);
      if (!u?.totp_secret_enc) return 'missing';
      const secret = decryptSecret(u.totp_secret_enc, cfg.appSecret);
      const step = verifyTotp(secret, req.body.code);
      if (step === null) return { secret };
      await q(`UPDATE users SET totp_enabled_at = now(), totp_last_step = $2, totp_recovery = $3 WHERE id = $1`,
        [req.user.user_id, step, codes.map((c) => sha256(normaliseRecovery(c)))]);
      await audit(q, { ...actor(req), action: 'user.two_step_on', entityType: 'user', entityId: req.user.user_id });
      return 'ok';
    });
    if (result === 'missing') return res.redirect('/account/2fa/setup');
    if (result !== 'ok') {
      const qr = await QRCode.toString(totpUri({ secret: result.secret, account: req.user.email }), { type: 'svg', margin: 1, color: { dark: '#14222B', light: '#FFFFFF' } });
      return res.status(400).render('twostep_setup', { qr, secret: result.secret.replace(/(.{4})/g, '$1 ').trim(), error: 'That code didn\'t match. Enter the 6-digit code your app shows now.', codes: null });
    }
    res.render('twostep_setup', { qr: null, secret: null, error: null, codes });
  });

  app.post('/account/2fa/disable', requireUser, requireCsrf, async (req, res) => {
    const [found] = await db.asApp((q) => q('SELECT * FROM auth_find_user($1)', [req.user.email]));
    if (!found || !(await verifyPassword(String(req.body.password || ''), found.password_hash))) {
      return res.status(400).render('error', { message: 'Your password was wrong, so two-step login is still on.' });
    }
    await inFirm(req, async (q) => {
      await q('UPDATE users SET totp_enabled_at = NULL, totp_secret_enc = NULL, totp_recovery = NULL, totp_last_step = NULL WHERE id = $1', [req.user.user_id]);
      await audit(q, { ...actor(req), action: 'user.two_step_off', entityType: 'user', entityId: req.user.user_id });
    });
    res.redirect(303, '/account?f=off');
  });

  // Owner: someone lost their phone and their recovery codes.
  app.post('/team/:uid/reset-2fa', requireUser, requireCsrf, requireOwner, checkId('uid'), async (req, res) => {
    const ok = await inFirm(req, async (q) => {
      const rows = await q('UPDATE users SET totp_enabled_at = NULL, totp_secret_enc = NULL, totp_recovery = NULL, totp_last_step = NULL WHERE id = $1 AND id <> $2 RETURNING id', [req.params.uid, req.user.user_id]);
      if (!rows.length) return false;
      await q('SELECT sessions_revoke_user($1)', [req.params.uid]);
      await audit(q, { ...actor(req), action: 'user.two_step_reset', entityType: 'user', entityId: req.params.uid });
      return true;
    });
    if (!ok) return res.status(404).render('error', { message: 'Person not found.' });
    res.redirect(303, '/team?f=reset2fa');
  });

  app.post('/team/:uid/role', requireUser, requireCsrf, requireOwner, checkId('uid'), async (req, res) => {
    const role = ['owner', 'adviser', 'admin_staff'].includes(req.body.role) ? req.body.role : null;
    if (!role) return res.status(400).render('error', { message: 'Choose a role.' });
    if (req.params.uid === req.user.user_id) return res.status(400).render('error', { message: 'Ask another owner to change your own role.' });
    const ok = await inFirm(req, async (q) => {
      const rows = await q('UPDATE users SET role = $2 WHERE id = $1 RETURNING id', [req.params.uid, role]);
      if (!rows.length) return false;
      await audit(q, { ...actor(req), action: 'user.role_changed', entityType: 'user', entityId: req.params.uid, details: { role } });
      return true;
    });
    if (!ok) return res.status(404).render('error', { message: 'Person not found.' });
    res.redirect(303, '/team');
  });

  // ------------------------------------------------------- due dates & notes
  app.post('/cases/:id/due', requireUser, requireCsrf, checkId('id'), async (req, res) => {
    const raw = String(req.body.due_date || '').trim();
    if (raw && !/^\d{4}-\d{2}-\d{2}$/.test(raw)) return res.status(400).render('error', { message: 'Choose a valid date.' });
    const ok = await inFirm(req, async (q) => {
      const rows = await q('UPDATE cases SET due_date = $2 WHERE id = $1 RETURNING id', [req.params.id, raw || null]);
      if (rows.length) await audit(q, { ...actor(req), action: raw ? 'case.due_set' : 'case.due_cleared', entityType: 'case', entityId: req.params.id, details: raw ? { due_date: raw } : {} });
      return rows.length > 0;
    });
    if (!ok) return res.status(404).render('error', { message: 'Case not found.' });
    res.redirect(303, `/cases/${req.params.id}`);
  });

  app.post('/cases/:id/notes', requireUser, requireCsrf, checkId('id'), async (req, res) => {
    const body = String(req.body.body || '').replace(/\r\n/g, '\n').trim().slice(0, 2000);
    if (!body) return res.redirect(303, `/cases/${req.params.id}`);
    const ok = await inFirm(req, async (q) => {
      const [k] = await q('SELECT id FROM cases WHERE id = $1', [req.params.id]);
      if (!k) return false;
      await q('INSERT INTO case_notes (firm_id, case_id, user_id, body) VALUES ($1, $2, $3, $4)', [req.user.firm_id, req.params.id, req.user.user_id, body]);
      await audit(q, { ...actor(req), action: 'note.added', entityType: 'case', entityId: req.params.id });
      return true;
    });
    if (!ok) return res.status(404).render('error', { message: 'Case not found.' });
    res.redirect(303, `/cases/${req.params.id}#notes`);
  });

  // ------------------------------------------------------------------ search
  app.get('/search', requireUser, async (req, res) => {
    const term = clean(req.query.q, 100);
    let clients = [], cases = [];
    if (term.length >= 2) {
      const like = `%${term.replace(/[\\%_]/g, (m) => `\\${m}`)}%`;
      ({ clients, cases } = await inFirm(req, async (q) => ({
        clients: await q(
          `SELECT id, first_name, last_name, email, phone, archived_at FROM clients
            WHERE first_name || ' ' || last_name ILIKE $1 OR email ILIKE $1 OR replace(coalesce(phone, ''), ' ', '') ILIKE replace($1, ' ', '')
            ORDER BY archived_at NULLS FIRST, last_name LIMIT 50`, [like]),
        cases: await q(
          `SELECT c.id, c.title, c.lender, c.status, cl.first_name, cl.last_name FROM cases c JOIN clients cl ON cl.id = c.client_id
            WHERE c.title ILIKE $1 OR coalesce(c.lender, '') ILIKE $1 OR cl.first_name || ' ' || cl.last_name ILIKE $1
            ORDER BY c.created_at DESC LIMIT 50`, [like]),
      })));
    }
    res.render('search', { term, clients, cases });
  });

  // -------------------------------------------------------------- checklists
  function parseItems(text) {
    return String(text || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean).slice(0, 60).map((line, i) => {
      const optional = /^\(optional\)\s*/i.test(line);
      const [label, help] = line.replace(/^\(optional\)\s*/i, '').split('|').map((x) => x.trim());
      return { label: label.slice(0, 150), help_text: help ? help.slice(0, 300) : null, required: !optional, sort_order: i + 1 };
    }).filter((x) => x.label);
  }
  const itemsToText = (items) => items.map((i) => `${i.required ? '' : '(optional) '}${i.label}${i.help_text ? ` | ${i.help_text}` : ''}`).join('\n');

  app.get('/checklists', requireUser, async (req, res) => {
    const templates = await inFirm(req, (q) =>
      q(`SELECT t.id, t.name, t.firm_id IS NULL AS builtin, count(i.id)::int AS items
           FROM checklist_templates t LEFT JOIN checklist_template_items i ON i.template_id = t.id
          GROUP BY t.id ORDER BY t.firm_id NULLS FIRST, t.name`));
    res.render('checklists', { templates });
  });

  async function loadTemplate(req, id) {
    return inFirm(req, async (q) => {
      const [t] = await q('SELECT id, name, firm_id IS NULL AS builtin FROM checklist_templates WHERE id = $1', [id]);
      if (!t) return null;
      t.items = await q('SELECT label, help_text, required FROM checklist_template_items WHERE template_id = $1 ORDER BY sort_order', [id]);
      return t;
    });
  }

  app.get('/checklists/new', requireUser, async (req, res) => {
    const from = UUID.test(req.query.from || '') ? await loadTemplate(req, req.query.from) : null;
    res.render('checklist_edit', { t: null, values: { name: from ? `${from.name} (copy)` : '', items: from ? itemsToText(from.items) : '' }, error: null });
  });

  async function saveTemplate(req, res, id) {
    const name = clean(req.body.name, 100);
    const items = parseItems(req.body.items);
    const values = { name, items: req.body.items || '' };
    if (!name || !items.length) {
      return res.status(400).render('checklist_edit', { t: id ? { id } : null, values, error: !name ? 'Give the checklist a name.' : 'Add at least one document, one per line.' });
    }
    const savedId = await inFirm(req, async (q) => {
      let tid = id;
      if (tid) {
        const rows = await q('UPDATE checklist_templates SET name = $2 WHERE id = $1 AND firm_id IS NOT NULL RETURNING id', [tid, name]);
        if (!rows.length) return null;
        await q('DELETE FROM checklist_template_items WHERE template_id = $1', [tid]);
      } else {
        [{ id: tid }] = await q('INSERT INTO checklist_templates (firm_id, name) VALUES ($1, $2) RETURNING id', [req.user.firm_id, name]);
      }
      for (const it of items) {
        await q('INSERT INTO checklist_template_items (template_id, label, help_text, required, sort_order) VALUES ($1, $2, $3, $4, $5)',
          [tid, it.label, it.help_text, it.required, it.sort_order]);
      }
      await audit(q, { ...actor(req), action: id ? 'checklist.updated' : 'checklist.created', entityType: 'checklist', entityId: tid, details: { name } });
      return tid;
    });
    if (!savedId) return res.status(404).render('error', { message: 'Checklist not found, or it\'s a built-in one that can\'t be changed.' });
    res.redirect(303, '/checklists');
  }

  app.post('/checklists', requireUser, requireCsrf, (req, res) => saveTemplate(req, res, null));

  app.get('/checklists/:id', requireUser, checkId('id'), async (req, res) => {
    const t = await loadTemplate(req, req.params.id);
    if (!t) return res.status(404).render('error', { message: 'Checklist not found.' });
    if (t.builtin) return res.redirect(`/checklists/new?from=${t.id}`);
    res.render('checklist_edit', { t, values: { name: t.name, items: itemsToText(t.items) }, error: null });
  });

  app.post('/checklists/:id', requireUser, requireCsrf, checkId('id'), (req, res) => saveTemplate(req, res, req.params.id));

  app.post('/checklists/:id/delete', requireUser, requireCsrf, checkId('id'), async (req, res) => {
    const ok = await inFirm(req, async (q) => {
      const rows = await q('DELETE FROM checklist_templates WHERE id = $1 AND firm_id IS NOT NULL RETURNING name', [req.params.id]);
      if (rows.length) await audit(q, { ...actor(req), action: 'checklist.deleted', entityType: 'checklist', entityId: req.params.id, details: { name: rows[0].name } });
      return rows.length > 0;
    });
    if (!ok) return res.status(404).render('error', { message: 'Checklist not found.' });
    res.redirect(303, '/checklists');
  });

  // ----------------------------------------------------- download whole file
  app.get('/cases/:id/export', requireUser, checkId('id'), async (req, res) => {
    const data = await inFirm(req, async (q) => {
      const [k] = await q(`SELECT c.id, cl.first_name, cl.last_name FROM cases c JOIN clients cl ON cl.id = c.client_id WHERE c.id = $1`, [req.params.id]);
      if (!k) return null;
      const docs = await q(
        `SELECT d.storage_key, d.original_filename, d.mime_type, r.label, r.sort_order, r.status
           FROM documents d JOIN document_requests r ON r.id = d.request_id
          WHERE r.case_id = $1 AND d.deleted_at IS NULL AND r.status IN ('accepted', 'received')
          ORDER BY r.sort_order, d.uploaded_at`, [req.params.id]);
      await audit(q, { ...actor(req), action: 'case.exported', entityType: 'case', entityId: req.params.id, details: { files: docs.length } });
      return { k, docs };
    });
    if (!data) return res.status(404).render('error', { message: 'Case not found.' });
    if (!data.docs.length) return res.status(400).render('error', { message: 'There are no received or accepted documents to download yet.' });
    const safe = (x) => String(x).normalize('NFKD').replace(/[^\w.\- ]+/g, '').replace(/\s+/g, ' ').trim().slice(0, 80) || 'file';
    const zipName = `${safe(`${data.k.first_name} ${data.k.last_name}`)} - documents.zip`;
    res.set({ 'Content-Type': 'application/zip', 'Content-Disposition': `attachment; filename="${zipName}"`, 'Cache-Control': 'private, no-store' });
    const zip = new ZipArchive({ zlib: { level: 6 } });
    zip.on('error', (err) => { console.error('Zip failed:', err.message); res.destroy(err); });
    zip.pipe(res);
    const used = new Map();
    for (const d of data.docs) {
      const ext = (d.original_filename.match(/\.[A-Za-z0-9]{1,5}$/) || [''])[0] || { 'application/pdf': '.pdf', 'image/jpeg': '.jpg', 'image/png': '.png', 'image/heic': '.heic' }[d.mime_type] || '';
      const base = `${String(d.sort_order).padStart(2, '0')} ${safe(d.label)}${d.status === 'received' ? ' (not yet reviewed)' : ''}`;
      const n = (used.get(base) || 0) + 1;
      used.set(base, n);
      zip.append(await storage.get(d.storage_key), { name: `${base}${n > 1 ? ` ${n}` : ''}${ext.toLowerCase()}` });
    }
    await zip.finalize();
  });

  // ---------------------------------------------------------- security page
  app.get('/security', (req, res) => res.render('security', {}));

  // ----------------------------------------------------------------- billing
  app.get('/billing', requireUser, requireOwner, async (req, res) => {
    const [firm] = await inFirm(req, (q) => q('SELECT billing_status, trial_ends_at, stripe_customer_id FROM firms'));
    const flash = req.query.done ? { ok: true, text: 'Thanks. Your subscription is being set up and this page will show it shortly.' } : null;
    res.render('billing', { firm, available: !!(stripe && cfg.stripePriceId), flash });
  });

  app.post('/billing/checkout', requireUser, requireCsrf, requireOwner, async (req, res) => {
    if (!stripe || !cfg.stripePriceId) return res.status(503).render('error', { message: 'Billing isn\'t set up yet.' });
    const [firm] = await inFirm(req, (q) => q('SELECT stripe_customer_id FROM firms'));
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: cfg.stripePriceId, quantity: 1 }],
      client_reference_id: req.user.firm_id,
      ...(firm.stripe_customer_id ? { customer: firm.stripe_customer_id } : { customer_email: req.user.email }),
      subscription_data: { metadata: { firm_id: req.user.firm_id } },
      success_url: `${cfg.baseUrl}/billing?done=1`,
      cancel_url: `${cfg.baseUrl}/billing`,
    });
    res.redirect(303, session.url);
  });

  app.post('/billing/portal', requireUser, requireCsrf, requireOwner, async (req, res) => {
    const [firm] = await inFirm(req, (q) => q('SELECT stripe_customer_id FROM firms'));
    if (!stripe || !firm.stripe_customer_id) return res.status(400).render('error', { message: 'There\'s no subscription to manage yet.' });
    const portal = await stripe.billingPortal.sessions.create({ customer: firm.stripe_customer_id, return_url: `${cfg.baseUrl}/billing` });
    res.redirect(303, portal.url);
  });

  // ---------------------------------------------------------------- sign up
  app.get('/signup', (req, res) => {
    if (!cfg.allowSignup) return res.status(404).render('error', { message: 'Page not found.' });
    if (req.user) return res.redirect('/');
    res.render('signup', { error: null, values: {}, trialDays: cfg.trialDays });
  });

  app.post('/signup', async (req, res) => {
    if (!cfg.allowSignup) return res.status(404).render('error', { message: 'Page not found.' });
    const v = { firm: clean(req.body.firm, 120), full_name: clean(req.body.full_name, 100), email: clean(req.body.email, 200).toLowerCase() };
    const password = String(req.body.password || '').slice(0, 200);
    const fail = (status, error) => res.status(status).render('signup', { error, values: v, trialDays: cfg.trialDays });
    const key = `signup|${req.ip}`;
    if (limiter.blocked(key)) return fail(429, 'Too many sign-ups from here. Try again later.');
    if (!v.firm || !v.full_name) return fail(400, 'Add your firm\'s name and your own name.');
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v.email)) return fail(400, 'That email address doesn\'t look right.');
    if (password.length < MIN_PASSWORD_LENGTH) return fail(400, `Your password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
    if (req.body.terms !== 'yes') return fail(400, 'Tick the box to accept the terms.');
    limiter.fail(key);
    let created;
    try {
      [created] = await db.asApp(async (q) => q('SELECT * FROM signup_create_firm($1, $2, $3, $4, $5)', [v.firm, v.full_name, v.email, await hashPassword(password), cfg.trialDays]));
    } catch (err) {
      if (/users_email_key|duplicate key/.test(err.message)) return fail(400, 'That email already has a Fileready login. Try logging in, or reset your password.');
      throw err;
    }
    const token = randomToken();
    await db.asApp((q) => q('SELECT session_create_v2($1, $2, $3, false)', [sha256(token), created.user_id, cfg.sessionHours]));
    setSessionCookie(res, token);
    res.redirect(303, '/?welcome=1');
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
    res.redirect(303, `/u/${req.params.token}?done=${req.params.rid}`);
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
