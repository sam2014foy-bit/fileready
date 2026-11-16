import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { audit } from './db.js';
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
export function createApp({ db, storage, config }) {
  const cfg = { sessionHours: 12, linkDays: 14, secureCookies: false, ...config };
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
  app.get('/login', (req, res) => (req.user ? res.redirect('/') : res.render('login', { error: null, email: '' })));

  app.post('/login', async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase().slice(0, 200);
    const password = String(req.body.password || '').slice(0, 200);
    const key = `${req.ip}|${email}`;
    const fail = (status = 401, error = 'Email or password is wrong.') => res.status(status).render('login', { error, email });

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
    res.render('password', { error: null, done: true });
  });

  // ----------------------------------------------------------- dashboard
  app.get('/', requireUser, async (req, res) => {
    const filter = ['open', 'complete', 'all'].includes(req.query.show) ? req.query.show : 'open';
    const cases = await inFirm(req, (q) =>
      q(
        `SELECT c.id, c.title, c.lender, c.status, c.created_at, c.completed_at,
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
    res.render('dashboard', { cases, filter });
  });

  // ------------------------------------------------------------- clients
  app.get('/clients', requireUser, async (req, res) => {
    const clients = await inFirm(req, (q) =>
      q(`SELECT c.*, (SELECT count(*)::int FROM cases k WHERE k.client_id = c.id) AS case_count
           FROM clients c WHERE archived_at IS NULL ORDER BY last_name, first_name LIMIT 500`)
    );
    res.render('clients', { clients });
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
      for (const r of requests) r.documents = documents.filter((d) => d.request_id === r.id);
      return { kase, requests, links, history };
    });
  }

  app.get('/cases/:id', requireUser, checkId('id'), async (req, res) => {
    const data = await loadCase(req, req.params.id);
    if (!data) return res.status(404).render('error', { message: 'Case not found.' });
    res.render('case', { ...data, newLink: null });
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
      await audit(q, { ...actor(req), action: 'request.added', entityType: 'document_request', entityId: r.id, details: { label } });
      return true;
    });
    if (!ok) return res.status(404).render('error', { message: 'Case not found.' });
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
    res.render('case', { ...data, newLink: `${cfg.baseUrl}/u/${token}` });
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
