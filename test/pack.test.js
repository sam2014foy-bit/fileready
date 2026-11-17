// Tests for the feature pack: Today panel, due dates, notes, search, checklists,
// daily summary, retention, roles, advisers-own-cases, two-step login, zip export,
// text reminders, security page, billing and sign-up.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readdir } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import request from 'supertest';
import { PGlite } from '@electric-sql/pglite';
import { migrate } from '../db/migrate.js';
import { createDb, pgliteDriver } from '../src/db.js';
import { createApp } from '../src/app.js';
import { localDiskStorage } from '../src/storage.js';
import { hashPassword, totpCode } from '../src/security.js';
import { memoryMailer, memorySms } from '../src/mailer.js';
import { runReminders } from '../src/reminders.js';
import { sendSummaries, runRetention } from '../src/daily.js';

const BASE = 'http://fileready.test';
const PDF = Buffer.from('%PDF-1.4\n%%EOF\n');
const PW = 'correct-horse-battery';
const APP_SECRET = 'test-app-secret-that-is-long-enough-123';
let pglite, db, app, mailer, sms, storageDir, stripeCalls;
const s = {};
const q1 = async (sql, p) => (await pglite.query(sql, p)).rows[0];
const lastEmail = () => mailer.outbox[mailer.outbox.length - 1];
const MONDAY_9AM = new Date('2026-11-16T09:00:00Z');
const csrfOf = (html) => html.match(/name="_csrf" value="([0-9a-f]{64})"/)[1];
const formT = async (appInstance, url) => (await request(appInstance).get(url)).text.match(/name="_t" value="([^"]+)"/)[1];

const fakeStripe = {
  webhooks: { constructEvent(body, sig) { if (sig !== 'good-signature') throw new Error('bad'); return JSON.parse(body.toString()); } },
  checkout: { sessions: { create: async (o) => { stripeCalls.push(o); return { url: 'https://checkout.stripe.test/s/1' }; } } },
  billingPortal: { sessions: { create: async () => ({ url: 'https://billing.stripe.test/p/1' }) } },
};

async function login(email, password = PW, appInstance = app) {
  const agent = request.agent(appInstance);
  const res = await agent.post('/login').type('form').send({ email, password });
  assert.equal(res.status, 302, `login ${email}`);
  if (res.headers.location === '/login/2fa') return { agent, pending: true };
  const csrf = csrfOf((await agent.get('/')).text);
  return { agent, csrf, post: (url, body = {}) => agent.post(url).type('form').send({ _csrf: csrf, ...body }) };
}

before(async () => {
  pglite = new PGlite();
  await migrate(pglite, () => {});
  db = createDb(pgliteDriver(pglite));
  mailer = memoryMailer();
  sms = memorySms();
  stripeCalls = [];
  storageDir = await mkdtemp(path.join(os.tmpdir(), 'fr-pack-'));
  app = createApp({
    db, storage: localDiskStorage(storageDir), mailer, sms, stripe: fakeStripe,
    config: { baseUrl: BASE, appSecret: APP_SECRET, allowSignup: true, stripePriceId: 'price_123', stripeWebhookSecret: 'whsec_test', remindersSecret: 'rs', formMinMs: 0, adminEmails: ['owner@cork.test'] },
  });
  const firm = async (name) => (await q1('INSERT INTO firms (name) VALUES ($1) RETURNING id', [name])).id;
  s.firmA = await firm('Cork Brokers');
  s.firmB = await firm('Other Brokers');
  const user = async (firmId, email, name, role) => (await q1(
    `INSERT INTO users (firm_id, email, full_name, role, password_hash) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
    [firmId, email, name, role, await hashPassword(PW)])).id;
  s.ownerId = await user(s.firmA, 'owner@cork.test', 'Aoife Owner', 'owner');
  s.advId = await user(s.firmA, 'adv@cork.test', 'Ciarán Adviser', 'adviser');
  await user(s.firmB, 'owner@other.test', 'Bríd Other', 'owner');
  s.owner = await login('owner@cork.test');
  s.adv = await login('adv@cork.test');
  s.other = await login('owner@other.test');

  const mk = async (who, first, email, phone = '') => {
    const c = await who.post('/clients', { first_name: first, last_name: 'Byrne', email, phone });
    const clientId = c.headers.location.split('client=')[1];
    const tpl = (await q1('SELECT id FROM checklist_templates WHERE firm_id IS NULL')).id;
    const k = await who.post('/cases', { client_id: clientId, title: 'Mortgage application', lender: 'Demo Bank', template_id: tpl });
    return { clientId, caseId: k.headers.location.split('/cases/')[1] };
  };
  s.ownerCase = await mk(s.owner, 'Niamh', 'niamh@example.com', '087 111 2222');
  s.advCase = await mk(s.adv, 'Seán', 'sean@example.com');
});
after(() => rm(storageDir, { recursive: true, force: true }));

// ------------------------------------------------------------- Today panel
test('Today panel counts documents to review, clients not responding and due dates, and filters by each', async () => {
  const link = await s.owner.post(`/cases/${s.ownerCase.caseId}/links`);
  s.token = link.text.match(/\/u\/([A-Za-z0-9_-]{43})/)[1];
  const reqs = (await pglite.query('SELECT id FROM document_requests WHERE case_id = $1 ORDER BY sort_order', [s.ownerCase.caseId])).rows;
  s.reqs = reqs;
  await request(app).post(`/u/${s.token}/${reqs[0].id}`).attach('file', PDF, 'passport.pdf');
  await request(app).post(`/u/${s.token}/${reqs[1].id}`).attach('file', PDF, 'bill.pdf');
  await pglite.query(`UPDATE cases SET chasing_started_at = now(), chasing_stopped = 'limit_reached' WHERE id = $1`, [s.advCase.caseId]);
  const page = await s.owner.agent.get('/');
  assert.match(page.text, /<b class="num">2<\/b><span>documents to review/);
  assert.match(page.text, /<b class="num">1<\/b><span>client not responding/);
  const review = await s.owner.agent.get('/?show=review');
  assert.ok(review.text.includes('Niamh Byrne') && !review.text.includes('Seán Byrne'));
  const stuck = await s.owner.agent.get('/?show=stuck');
  assert.ok(stuck.text.includes('Seán Byrne') && !stuck.text.includes('Niamh Byrne'));
});

// ------------------------------------------------------------- due dates
test('a due date shows on the case and dashboard, flags overdue, and appears in reminder emails', async () => {
  const future = new Date(Date.now() + 3 * 86400000).toISOString().slice(0, 10);
  assert.equal((await s.owner.post(`/cases/${s.ownerCase.caseId}/due`, { due_date: 'nonsense' })).status, 400);
  await s.owner.post(`/cases/${s.ownerCase.caseId}/due`, { due_date: future });
  assert.match((await s.owner.agent.get('/?show=due')).text, /Niamh Byrne/);
  await s.owner.post(`/cases/${s.ownerCase.caseId}/chase/start`);
  assert.match(lastEmail().text, /Please send them by \w+day, \d+ \w+\./);
  await s.owner.post(`/cases/${s.ownerCase.caseId}/due`, { due_date: '2026-01-05' });
  const page = await s.owner.agent.get(`/cases/${s.ownerCase.caseId}`);
  assert.match(page.text, /chip bad">Overdue/);
  assert.match((await s.owner.agent.get('/')).text, /overdue/);
  await s.owner.post(`/cases/${s.ownerCase.caseId}/due`, { due_date: '' });
  assert.equal((await q1('SELECT due_date FROM cases WHERE id = $1', [s.ownerCase.caseId])).due_date, null);
});

// ------------------------------------------------------------- notes
test('notes are added to a case, shown to the team, and never on the client page', async () => {
  await s.owner.post(`/cases/${s.ownerCase.caseId}/notes`, { body: 'Rang Niamh, payslips coming Monday <b>soon</b>' });
  const page = await s.owner.agent.get(`/cases/${s.ownerCase.caseId}`);
  assert.match(page.text, /Rang Niamh, payslips coming Monday &lt;b&gt;soon&lt;\/b&gt;/);
  assert.ok(!(await request(app).get(`/u/${s.token}`)).text.includes('Rang Niamh'), 'client never sees notes');
  assert.equal((await s.other.post(`/cases/${s.ownerCase.caseId}/notes`, { body: 'x' })).status, 404);
});

// ------------------------------------------------------------- search
test('search finds clients by name, email or phone and cases by lender, only in your own firm', async () => {
  for (const term of ['niamh', 'NIAMH@EXAMPLE', '0871112222', 'Demo Bank']) {
    assert.match((await s.owner.agent.get(`/search?q=${encodeURIComponent(term)}`)).text, /Niamh Byrne/, term);
  }
  assert.ok(!(await s.other.agent.get('/search?q=niamh')).text.includes('Niamh Byrne'));
  assert.match((await s.owner.agent.get('/search?q=n')).text, /at least two letters/);
});

// ------------------------------------------------------------- checklists
test('a firm creates its own checklist with optional items and hints, and starts a case with it', async () => {
  const res = await s.owner.post('/checklists', { name: 'Self-employed', items: "Photo ID | Passport or licence\nLast 2 years' accounts\n(optional) Gift letter" });
  assert.equal(res.status, 303);
  const t = await q1(`SELECT id FROM checklist_templates WHERE name = 'Self-employed'`);
  const items = (await pglite.query('SELECT label, help_text, required FROM checklist_template_items WHERE template_id = $1 ORDER BY sort_order', [t.id])).rows;
  assert.deepEqual(items.map((i) => ({ ...i })), [
    { label: 'Photo ID', help_text: 'Passport or licence', required: true },
    { label: "Last 2 years' accounts", help_text: null, required: true },
    { label: 'Gift letter', help_text: null, required: false },
  ]);
  const k = await s.owner.post('/cases', { client_id: s.ownerCase.clientId, title: 'Second property', template_id: t.id });
  const caseId = k.headers.location.split('/cases/')[1];
  assert.equal((await q1('SELECT count(*)::int AS n FROM document_requests WHERE case_id = $1', [caseId])).n, 3);
  assert.ok(!(await s.other.agent.get('/checklists')).text.includes('Self-employed'), 'other firm doesn\'t see it');
  assert.equal((await s.other.post(`/checklists/${t.id}/delete`)).status, 404);
  await s.owner.post(`/checklists/${t.id}`, { name: 'Self-employed (sole trader)', items: 'Photo ID' });
  assert.equal((await q1('SELECT count(*)::int AS n FROM checklist_template_items WHERE template_id = $1', [t.id])).n, 1);
  const builtin = await q1('SELECT id FROM checklist_templates WHERE firm_id IS NULL');
  assert.equal((await s.owner.post(`/checklists/${builtin.id}/delete`)).status, 404, 'built-in can\'t be deleted');
  const edit = await s.owner.agent.get(`/checklists/${builtin.id}`);
  assert.equal(edit.status, 302, 'built-in opens as a copy');
  await s.owner.post(`/checklists/${t.id}/delete`);
  assert.equal((await q1('SELECT count(*)::int AS n FROM checklist_templates WHERE id = $1', [t.id])).n, 0);
});

// ------------------------------------------------------------- zip export
test('download all gives a zip of received and accepted files with tidy names', async () => {
  const res = await s.owner.agent.get(`/cases/${s.ownerCase.caseId}/export`).buffer(true).parse((r, cb) => {
    const chunks = []; r.on('data', (c) => chunks.push(c)); r.on('end', () => cb(null, Buffer.concat(chunks)));
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers['content-type'], 'application/zip');
  assert.equal(res.body.subarray(0, 2).toString(), 'PK');
  assert.ok(res.body.includes(Buffer.from('01 Photo ID (not yet reviewed).pdf')));
  assert.equal((await s.other.agent.get(`/cases/${s.ownerCase.caseId}/export`)).status, 404);
});

// ------------------------------------------------------------- text reminders
test('text reminders go to clients with a mobile when the firm turns them on', async () => {
  await s.owner.post('/settings', { name: 'Cork Brokers', reminder_every_days: 3, max_reminders: 6, retention_years: 6, sms_enabled: 'on', advisers_see_all: 'all' });
  assert.equal((await q1('SELECT sms_enabled FROM firms WHERE id = $1', [s.firmA])).sms_enabled, true);
  const before = sms.outbox.length;
  await s.owner.post(`/cases/${s.ownerCase.caseId}/chase/now`);
  assert.equal(sms.outbox.length, before + 1);
  const t = sms.outbox[sms.outbox.length - 1];
  assert.equal(t.to, '+353871112222');
  assert.match(t.content, /^Hi Niamh, Cork Brokers still needs \d+ documents? for your application\. Upload securely: http:\/\/fileready\.test\/u\/[A-Za-z0-9_-]{43}$/);
  assert.match((await s.owner.agent.get(`/cases/${s.ownerCase.caseId}`)).text, /by text to \+353871112222/);
});

test('a client with only a mobile number is chased by text; opting out stops texts', async () => {
  const c = await s.owner.post('/clients', { first_name: 'Úna', last_name: 'Walsh', email: '', phone: '0861234567' });
  const clientId = c.headers.location.split('client=')[1];
  const tpl = (await q1('SELECT id FROM checklist_templates WHERE firm_id IS NULL')).id;
  const k = await s.owner.post('/cases', { client_id: clientId, title: 'Mortgage application', template_id: tpl });
  const caseId = k.headers.location.split('/cases/')[1];
  assert.match((await s.owner.agent.get(`/cases/${caseId}`)).text, /Reminders go by text/);
  const emails = mailer.outbox.length, texts = sms.outbox.length;
  assert.equal((await s.owner.post(`/cases/${caseId}/chase/start`)).status, 303);
  assert.equal(mailer.outbox.length, emails, 'no email');
  assert.equal(sms.outbox.length, texts + 1, 'one text');
  await s.owner.post(`/clients/${clientId}`, { first_name: 'Úna', last_name: 'Walsh', email: '', phone: '0861234567', sms_opt_out: 'on' });
  await pglite.query(`UPDATE cases SET next_reminder_at = now() - interval '1 minute' WHERE id = $1`, [caseId]);
  await runReminders({ db, mailer, sms, baseUrl: BASE, ignoreHours: true });
  assert.equal(sms.outbox.length, texts + 1, 'opted out: no more texts');
  assert.equal((await q1('SELECT chasing_stopped FROM cases WHERE id = $1', [caseId])).chasing_stopped, 'no_email');
});

// ------------------------------------------------------------- daily summary
test('morning summary: owner gets the firm view, adviser gets only their own cases, once a day, weekdays', async () => {
  const before = mailer.outbox.length;
  const sat = await sendSummaries({ db, mailer, baseUrl: BASE, now: new Date('2026-11-21T09:00:00Z') });
  assert.match(sat.skipped, /weekday/);
  const r = await sendSummaries({ db, mailer, baseUrl: BASE, now: MONDAY_9AM });
  assert.ok(r.sent >= 2);
  const sent = mailer.outbox.slice(before);
  const own = sent.find((e) => e.to === 'owner@cork.test');
  const adv = sent.find((e) => e.to === 'adv@cork.test');
  assert.match(own.text, /To review\n• Niamh Byrne: 2 documents/);
  assert.match(own.text, /Not responding\n• Seán Byrne/);
  assert.ok(!adv.text.includes('Niamh'), 'adviser only sees own cases');
  assert.match(adv.text, /Seán Byrne/);
  const again = await sendSummaries({ db, mailer, baseUrl: BASE, now: MONDAY_9AM });
  assert.equal(again.sent, 0, 'not twice in one day');
});

test('turning the summary off on the Account page stops it', async () => {
  await s.adv.post('/account/summary', {});
  assert.equal((await q1('SELECT daily_summary FROM users WHERE id = $1', [s.advId])).daily_summary, false);
  await pglite.query('UPDATE users SET last_summary_on = NULL');
  const before = mailer.outbox.length;
  await sendSummaries({ db, mailer, baseUrl: BASE, now: new Date('2026-11-17T09:00:00Z') });
  assert.ok(!mailer.outbox.slice(before).some((e) => e.to === 'adv@cork.test'));
});

// ------------------------------------------------------------- retention
test('retention deletes closed cases past the firm\'s period, with their files, and keeps recent ones', async () => {
  const c = await s.owner.post('/clients', { first_name: 'Old', last_name: 'Case', email: 'old@example.com' });
  const clientId = c.headers.location.split('client=')[1];
  const tpl = (await q1('SELECT id FROM checklist_templates WHERE firm_id IS NULL')).id;
  const k = await s.owner.post('/cases', { client_id: clientId, title: 'Old mortgage', template_id: tpl });
  const oldCase = k.headers.location.split('/cases/')[1];
  const link = await s.owner.post(`/cases/${oldCase}/links`);
  const tok = link.text.match(/\/u\/([A-Za-z0-9_-]{43})/)[1];
  const r = await q1('SELECT id FROM document_requests WHERE case_id = $1 ORDER BY sort_order LIMIT 1', [oldCase]);
  await request(app).post(`/u/${tok}/${r.id}`).attach('file', PDF, 'old.pdf');
  const key = (await q1('SELECT storage_key FROM documents WHERE request_id = $1', [r.id])).storage_key;
  await pglite.query(`UPDATE cases SET status = 'closed', closed_at = now() - interval '7 years' WHERE id = $1`, [oldCase]);
  await s.owner.post(`/cases/${s.advCase.caseId}/status`, { action: 'close' });
  const res = await runRetention({ db, storage: localDiskStorage(storageDir) });
  assert.equal(res.deleted, 1);
  assert.equal((await q1('SELECT count(*)::int AS n FROM cases WHERE id = $1', [oldCase])).n, 0);
  assert.equal((await q1('SELECT count(*)::int AS n FROM cases WHERE id = $1', [s.advCase.caseId])).n, 1, 'recently closed kept');
  const [firmDir, file] = key.split('/');
  assert.ok(!(await readdir(path.join(storageDir, firmDir))).includes(file), 'file deleted');
  assert.equal((await q1(`SELECT count(*)::int AS n FROM audit_log WHERE action = 'case.retention_deleted'`)).n, 1);
  await s.owner.post(`/cases/${s.advCase.caseId}/status`, { action: 'reopen' });
});

test('the daily job endpoint needs the secret', async () => {
  assert.equal((await request(app).post('/internal/daily/run')).status, 401);
  const ok = await request(app).post('/internal/daily/run').set('Authorization', 'Bearer rs');
  assert.equal(ok.status, 200);
  assert.ok('summaries' in ok.body && 'retention' in ok.body);
});

// ------------------------------------------------------------- advisers see own cases
test('with "advisers see only their own cases", an adviser can\'t see or touch colleagues\' cases', async () => {
  await s.owner.post('/settings', { name: 'Cork Brokers', reminder_every_days: 3, max_reminders: 6, retention_years: 6, sms_enabled: 'on', advisers_see_all: 'own' });
  const adv = await login('adv@cork.test');
  const dash = await adv.agent.get('/?show=all');
  assert.ok(dash.text.includes('Seán Byrne'));
  assert.ok(!dash.text.includes('Niamh Byrne'), 'colleague\'s case hidden');
  assert.equal((await adv.agent.get(`/cases/${s.ownerCase.caseId}`)).status, 404);
  const doc = await q1('SELECT id FROM documents WHERE request_id = $1', [s.reqs[0].id]);
  assert.equal((await adv.agent.get(`/documents/${doc.id}`)).status, 404);
  assert.equal((await adv.agent.get(`/cases/${s.ownerCase.caseId}/export`)).status, 404);
  assert.equal((await adv.post(`/cases/${s.ownerCase.caseId}/requests/${s.reqs[0].id}`, { action: 'accept' })).status, 409);
  assert.ok((await s.owner.agent.get('/?show=all')).text.includes('Niamh Byrne'), 'owner still sees all');
  const fresh = await s.owner.post(`/cases/${s.ownerCase.caseId}/links`);
  s.token = fresh.text.match(/\/u\/([A-Za-z0-9_-]{43})/)[1];
  const up = await request(app).post(`/u/${s.token}/${s.reqs[2].id}`).attach('file', PDF, 'x.pdf');
  assert.equal(up.status, 303, 'client links unaffected');
  await s.owner.post('/settings', { name: 'Cork Brokers', reminder_every_days: 3, max_reminders: 6, retention_years: 6, sms_enabled: 'on', advisers_see_all: 'all' });
  assert.equal((await adv.agent.get(`/cases/${s.ownerCase.caseId}`)).status, 200);
});

// ------------------------------------------------------------- roles
test('the owner can make someone else an owner but can\'t change their own role', async () => {
  assert.equal((await s.owner.post(`/team/${s.ownerId}/role`, { role: 'adviser' })).status, 400);
  await s.owner.post(`/team/${s.advId}/role`, { role: 'owner' });
  const adv = await login('adv@cork.test');
  assert.equal((await adv.agent.get('/team')).status, 200);
  await s.owner.post(`/team/${s.advId}/role`, { role: 'adviser' });
  assert.equal((await adv.agent.get('/team')).status, 403);
  assert.equal((await s.other.post(`/team/${s.advId}/role`, { role: 'owner' })).status, 404, 'other firm cannot');
});

// ------------------------------------------------------------- two-step login
test('two-step login: set up with an authenticator code, get recovery codes, then every login needs a code', async () => {
  const setup = await s.adv.agent.get('/account/2fa/setup');
  assert.equal(setup.status, 200);
  assert.match(setup.text, /<svg/);
  const secret = setup.text.match(/Key: <span[^>]*>([A-Z2-7 ]+)<\/span>/)[1].replace(/ /g, '');
  const stored = await q1('SELECT totp_secret_enc FROM users WHERE id = $1', [s.advId]);
  assert.ok(stored.totp_secret_enc.startsWith('v1.') && !stored.totp_secret_enc.includes(secret), 'secret stored encrypted');
  assert.equal((await s.adv.post('/account/2fa/setup', { code: '000000' })).status, 400);
  const on = await s.adv.post('/account/2fa/setup', { code: totpCode(secret) });
  const codes = [...on.text.matchAll(/<li>([a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4})<\/li>/g)].map((m) => m[1]);
  assert.equal(codes.length, 8);
  s.secret = secret; s.codes = codes;

  const pending = await login('adv@cork.test');
  assert.equal(pending.pending, true);
  assert.equal((await pending.agent.get('/clients')).status, 302, 'no access before the code');
  assert.equal((await pending.agent.post('/login/2fa').type('form').send({ code: '123456' })).status, 401);
  const next = totpCode(secret, Date.now() + 30000);
  assert.equal((await pending.agent.post('/login/2fa').type('form').send({ code: next })).status, 303);
  assert.equal((await pending.agent.get('/')).status, 200);

  const replay = await login('adv@cork.test');
  assert.equal((await replay.agent.post('/login/2fa').type('form').send({ code: next })).status, 401, 'a code works only once');
  assert.equal((await replay.agent.post('/login/2fa').type('form').send({ code: codes[0].toUpperCase() })).status, 303, 'recovery code works');
  const again = await login('adv@cork.test');
  assert.equal((await again.agent.post('/login/2fa').type('form').send({ code: codes[0] })).status, 401, 'recovery code works once');
});

test('the owner can reset a colleague\'s two-step login; turning it off needs your password', async () => {
  await s.owner.post(`/team/${s.advId}/reset-2fa`);
  const plain = await login('adv@cork.test');
  assert.ok(!plain.pending, 'password alone works after reset');
  assert.equal((await plain.post('/account/2fa/disable', { password: 'wrong' })).status, 400);
});

// ------------------------------------------------------------- security page
test('the security page is public', async () => {
  const res = await request(app).get('/security');
  assert.equal(res.status, 200);
  assert.match(res.text, /Ireland/);
  assert.match(res.text, /audit trail/);
});

// ------------------------------------------------------------- billing
test('billing: the owner starts a Stripe subscription; webhooks update the status', async () => {
  const adv = await login('adv@cork.test');
  assert.equal((await adv.agent.get('/billing')).status, 403);
  const res = await s.owner.post('/billing/checkout');
  assert.equal(res.status, 303);
  assert.equal(res.headers.location, 'https://checkout.stripe.test/s/1');
  assert.equal(stripeCalls[0].client_reference_id, s.firmA);
  assert.equal(stripeCalls[0].line_items[0].price, 'price_123');
  const event = { type: 'checkout.session.completed', data: { object: { mode: 'subscription', client_reference_id: s.firmA, customer: 'cus_1', subscription: 'sub_1' } } };
  assert.equal((await request(app).post('/stripe/webhook').set('stripe-signature', 'forged').set('content-type', 'application/json').send(JSON.stringify(event))).status, 400);
  assert.equal((await request(app).post('/stripe/webhook').set('stripe-signature', 'good-signature').set('content-type', 'application/json').send(JSON.stringify(event))).status, 200);
  let f = await q1('SELECT billing_status, stripe_customer_id FROM firms WHERE id = $1', [s.firmA]);
  assert.deepEqual({ ...f }, { billing_status: 'active', stripe_customer_id: 'cus_1' });
  const lapsed = { type: 'customer.subscription.updated', data: { object: { id: 'sub_1', customer: 'cus_1', status: 'past_due', metadata: { firm_id: s.firmA } } } };
  await request(app).post('/stripe/webhook').set('stripe-signature', 'good-signature').set('content-type', 'application/json').send(JSON.stringify(lapsed));
  f = await q1('SELECT billing_status FROM firms WHERE id = $1', [s.firmA]);
  assert.equal(f.billing_status, 'past_due');
  assert.match((await s.owner.agent.get('/')).text, /last payment didn&#39;t go through/);
  assert.equal((await q1('SELECT billing_status FROM firms WHERE id = $1', [s.firmB])).billing_status, 'none', 'other firm untouched');
  const portal = await s.owner.post('/billing/portal');
  assert.equal(portal.headers.location, 'https://billing.stripe.test/p/1');
});

// ------------------------------------------------------------- sign up
test('self sign-up creates a firm on a free trial and logs the owner in; duplicates are refused', async () => {
  const res = await request.agent(app).post('/signup').type('form').send({ _t: await formT(app, '/signup'), firm: 'Kerry Mortgages', full_name: 'Tadhg Ryan', email: 'tadhg@kerry.test', password: 'tadhgs-long-passphrase', terms: 'yes' });
  assert.equal(res.status, 303);
  const f = await q1(`SELECT billing_status, trial_ends_at > now() + interval '29 days' AS ok FROM firms WHERE name = 'Kerry Mortgages'`);
  assert.equal(f.billing_status, 'trial');
  assert.ok(f.ok);
  const dup = await request(app).post('/signup').type('form').send({ _t: await formT(app, '/signup'), firm: 'X', full_name: 'Y', email: 'owner@cork.test', password: 'another-long-passphrase', terms: 'yes' });
  assert.equal(dup.status, 400);
  assert.match(dup.text, /already has a Fileready login/);
  const closed = createApp({ db, storage: localDiskStorage(storageDir), mailer, config: { baseUrl: BASE } });
  assert.equal((await request(closed).get('/signup')).status, 404, 'off unless switched on');
});

test('the trial-ended banner shows to the owner once the trial is over', async () => {
  const kerry = await login('tadhg@kerry.test', 'tadhgs-long-passphrase');
  assert.ok(!(await kerry.agent.get('/')).text.includes('free trial has ended'));
  await pglite.query(`UPDATE firms SET trial_ends_at = now() - interval '1 day' WHERE name = 'Kerry Mortgages'`);
  assert.match((await kerry.agent.get('/')).text, /free trial has ended/);
});

// ------------------------------------------------------------- demo requests
test('the demo form emails the request to the contact address, with reply-to set to the visitor', async () => {
  const site = createApp({ db, storage: localDiskStorage(storageDir), mailer, config: { baseUrl: BASE, contactEmail: 'hello@fileready.test', formMinMs: 0 } });
  const home = await request(site).get('/');
  const t = await formT(site, '/demo');
  assert.match(home.text, /href="\/demo\?from=header"><span class="lg">Book a 15-minute demo/);
  for (const w of ['hero', 'story', 'footer']) assert.ok(home.text.includes(`href="/demo?from=${w}"`), w);
  assert.ok(!home.text.includes('mailto:'), 'no mail-app link');
  assert.equal((await request(site).get('/demo')).status, 200);
  assert.equal((await request(site).post('/demo').type('form').send({ _t: t, name: 'Máire', firm: 'West Cork', email: 'not-an-email' })).status, 400);
  const before = mailer.outbox.length;
  const ok = await request(site).post('/demo').type('form').send({ _t: t, name: 'Máire Ní Bhriain', firm: 'West Cork Mortgages', email: 'maire@westcork.test', phone: '021 555 0101', message: '3 advisers <b>busy</b>' });
  assert.equal(ok.status, 200);
  assert.match(ok.text, /Thanks, Máire/);
  const e = mailer.outbox[mailer.outbox.length - 1];
  assert.equal(mailer.outbox.length, before + 1);
  assert.equal(e.to, 'hello@fileready.test');
  assert.equal(e.replyTo, 'maire@westcork.test');
  assert.equal(e.subject, 'Demo request: West Cork Mortgages');
  assert.match(e.html, /3 advisers &lt;b&gt;busy&lt;\/b&gt;/);
  const bot = await request(site).post('/demo').type('form').send({ _t: t, name: 'x', firm: 'y', email: 'a@b.co', website: 'spam.example' });
  assert.equal(bot.status, 200);
  assert.equal(mailer.outbox.length, before + 1, 'bots are ignored quietly');
  assert.equal((await request(app).get('/demo')).status, 404, 'off without CONTACT_EMAIL');
});

// ------------------------------------------------------------- legal pages
test('privacy, terms and DPA pages are public, use the configured business details, and are linked', async () => {
  const site = createApp({ db, storage: localDiskStorage(storageDir), mailer, config: { baseUrl: BASE, legalName: 'Test Trading Ltd', legalAddress: '1 Main Street, Cork', privacyEmail: 'privacy@fileready.test' } });
  for (const [url, title] of [['/privacy', 'Privacy policy'], ['/terms', 'Terms of service'], ['/dpa', 'Data processing agreement']]) {
    const res = await request(site).get(url);
    assert.equal(res.status, 200, url);
    assert.match(res.text, new RegExp(`<h1>${title}</h1>`));
    assert.match(res.text, /Test Trading Ltd<\/strong>, 1 Main Street, Cork/);
    assert.match(res.text, /mailto:privacy@fileready\.test/);
  }
  const plain = await request(app).get('/privacy');
  assert.match(plain.text, /run by <strong>Fileready<\/strong>\./, 'falls back to the product name');
  assert.match((await request(app).get('/dpa')).text, /within 48 hours/);
  const home = await request(app).get('/');
  for (const l of ['/privacy', '/terms', '/dpa']) assert.ok(home.text.includes(`href="${l}"`), `home links ${l}`);
  assert.match((await request(app).get('/signup')).text, /href="\/dpa"/);
});

// ------------------------------------------------------------- SEO, social and icons
test('public pages have titles, descriptions, canonical and social tags; private pages stay out of search', async () => {
  const site = createApp({ db, storage: localDiskStorage(storageDir), mailer, config: { baseUrl: 'https://fileready.example', contactEmail: 'hello@fileready.test' } });
  const home = (await request(site).get('/')).text;
  assert.match(home, /<title>Fileready – Every document in. Without the chasing.<\/title>/);
  assert.match(home, /<meta name="description" content="Fileready sends your mortgage clients/);
  assert.match(home, /<meta name="robots" content="index, follow">/);
  assert.match(home, /<link rel="canonical" href="https:\/\/fileready\.example\/">/);
  assert.match(home, /<meta property="og:image" content="https:\/\/fileready\.example\/static\/og-image\.png">/);
  assert.match(home, /twitter:card" content="summary_large_image"/);
  assert.equal((home.match(/<title>/g) || []).length, 1);
  for (const [url, title] of [['/security', 'Security and privacy'], ['/privacy', 'Privacy policy'], ['/demo', 'Book a demo']]) {
    const t = (await request(site).get(url)).text;
    assert.match(t, new RegExp(`<title>${title} – Fileready</title>`), url);
    assert.match(t, /<meta name="robots" content="index, follow">/, url);
    assert.match(t, new RegExp(`canonical" href="https://fileready.example${url}"`), url);
    const d = t.match(/<meta name="description" content="([^"]+)"/)[1];
    assert.ok(d.length > 50 && d.length <= 170, `${url} description length ${d.length}`);
  }
  assert.match((await request(site).get('/forgot')).text, /<meta name="robots" content="noindex, nofollow">/);
  assert.match((await request(site).get('/login')).text, /<main class="auth-form">/);
  assert.match((await s.owner.agent.get('/')).text, /noindex, nofollow/);
  assert.match((await request(app).get(`/u/${s.token}`)).text, /noindex, nofollow/);
});

test('robots.txt, sitemap.xml, icons, manifest and the social image are served', async () => {
  const site = createApp({ db, storage: localDiskStorage(storageDir), mailer, config: { baseUrl: 'https://fileready.example', contactEmail: 'hello@fileready.test' } });
  const robots = await request(site).get('/robots.txt');
  assert.equal(robots.status, 200);
  assert.match(robots.text, /Disallow: \/u\//);
  assert.match(robots.text, /Sitemap: https:\/\/fileready\.example\/sitemap\.xml/);
  const map = await request(site).get('/sitemap.xml');
  assert.match(map.headers['content-type'], /xml/);
  for (const p of ['/', '/security', '/privacy', '/terms', '/dpa', '/demo']) assert.ok(map.text.includes(`<loc>https://fileready.example${p}</loc>`), p);
  assert.ok(!map.text.includes('/signup'), 'sign-up left out while it is off');
  for (const f of ['/favicon.ico', '/apple-touch-icon.png', '/static/favicon.svg', '/static/og-image.png', '/static/icon-512.png']) {
    assert.equal((await request(site).get(f)).status, 200, f);
  }
  const mf = await request(site).get('/site.webmanifest');
  assert.equal(JSON.parse(mf.text).icons.length, 2);
});

test('unknown addresses get the custom 404 page with status 404', async () => {
  const anon = await request(app).get('/this-does-not-exist');
  assert.equal(anon.status, 404);
  assert.match(anon.text, /This page isn't here/);
  assert.match(anon.text, /noindex/);
  assert.match(anon.text, /href="\/login"/);
  const staff = await s.owner.agent.get('/nope');
  assert.equal(staff.status, 404);
  assert.match(staff.text, /action="\/search"/);
  assert.match(staff.text, /Back to cases/);
});

test('responses are gzip-compressed and CSS is versioned for long caching', async () => {
  const res = await request(app).get('/privacy').set('Accept-Encoding', 'gzip');
  assert.equal(res.headers['content-encoding'], 'gzip');
  assert.match(res.text, /\/static\/app\.css\?v=[a-z0-9]+"/);
  const css = await request(app).get('/static/app.css');
  assert.match(css.headers['cache-control'], /max-age=2592000/);
});

// ------------------------------------------------------------- spam protection
test('spam guard: honeypot and too-fast submissions are dropped; stale or forged tokens get the form again', async () => {
  const { createSpamGuard } = await import('../src/spam.js');
  let now = 1_000_000;
  const g = createSpamGuard({ secret: 'x', now: () => now });
  const tok = g.token();
  assert.equal(g.check({ _t: tok }), 'bot', 'instant submit');
  now += 5000;
  assert.equal(g.check({ _t: tok }), 'ok');
  assert.equal(g.check({ _t: tok, website: 'http://spam' }), 'bot', 'honeypot');
  assert.equal(g.check({ _t: tok.replace(/.$/, (c) => (c === 'a' ? 'b' : 'a')) }), 'stale', 'forged');
  assert.equal(g.check({}), 'stale', 'missing');
  now += 25 * 3600 * 1000;
  assert.equal(g.check({ _t: tok }), 'stale', 'a day old');
  assert.equal(g.tooManyLinks('see http://a.example and http://b.example', 'www.c.example'), true);
  assert.equal(g.tooManyLinks('call me on 087 123 4567'), false);
});

test('demo form: link spam and bots send no email; a stale form is shown again with the details kept', async () => {
  const site = createApp({ db, storage: localDiskStorage(storageDir), mailer, config: { baseUrl: BASE, contactEmail: 'hello@fileready.test', formMinMs: 0 } });
  const t = await formT(site, '/demo');
  const before = mailer.outbox.length;
  const spammy = await request(site).post('/demo').type('form').send({ _t: t, name: 'Buy', firm: 'SEO', email: 'a@b.co', message: 'http://x.example http://y.example http://z.example' });
  assert.equal(spammy.status, 200);
  const stale = await request(site).post('/demo').type('form').send({ _t: '123.abc', name: 'Real Person', firm: 'Real Firm', email: 'real@firm.ie' });
  assert.equal(stale.status, 400);
  assert.match(stale.text, /open for a long time/);
  assert.match(stale.text, /value="Real Firm"/);
  assert.equal(mailer.outbox.length, before);
  const slow = createApp({ db, storage: localDiskStorage(storageDir), mailer, config: { baseUrl: BASE, contactEmail: 'hello@fileready.test' } });
  const fast = await request(slow).post('/demo').type('form').send({ _t: await formT(slow, '/demo'), name: 'Bot', firm: 'Bot', email: 'bot@bot.co' });
  assert.equal(fast.status, 200, 'looks accepted to the bot');
  assert.equal(mailer.outbox.length, before, 'but nothing is sent');
});

// ------------------------------------------------------------- analytics
test('website stats count people on public pages (not bots, not staff) without cookies, and only admins see them', async () => {
  const UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Mobile/15E148 Safari/604.1';
  const wait = () => new Promise((r) => setTimeout(r, 150));
  const home = await request(app).get('/?ref=LinkedIn').set('User-Agent', UA).set('Referer', 'https://www.linkedin.com/feed/');
  assert.equal(home.headers['set-cookie'], undefined, 'no cookies');
  await request(app).get('/security').set('User-Agent', UA);
  await request(app).get('/signup?from=hero').set('User-Agent', UA);
  await request(app).get('/').set('User-Agent', 'Googlebot/2.1 (+http://www.google.com/bot.html)');
  await request(app).get('/u/abc').set('User-Agent', UA);
  await s.owner.agent.get('/security').set('User-Agent', UA);
  await wait();
  const rows = (await pglite.query(`SELECT path, referrer, source, cta, device, views, visitors FROM site_stats ORDER BY path`)).rows.map((r) => ({ ...r }));
  const homeRow = rows.find((r) => r.path === '/');
  assert.deepEqual(homeRow, { path: '/', referrer: 'linkedin.com', source: 'linkedin', cta: '', device: 'mobile', views: 1, visitors: 1 });
  assert.equal(rows.filter((r) => r.path === '/').reduce((n, r) => n + r.views, 0), 1, 'bot not counted');
  assert.equal(rows.find((r) => r.path === '/security').visitors, 0, 'same visitor, same day');
  assert.equal(rows.find((r) => r.path === '/security').views, 1, 'staff visit not counted');
  assert.equal(rows.find((r) => r.path === '/signup').cta, 'hero');
  assert.ok(!rows.some((r) => r.path.startsWith('/u/')), 'client upload pages never tracked');
  const cols = (await pglite.query(`SELECT column_name FROM information_schema.columns WHERE table_name = 'site_stats'`)).rows.map((r) => r.column_name);
  assert.ok(!cols.some((c) => /ip|agent|hash/.test(c)), 'no IP or identifier column');

  const page = await s.owner.agent.get('/admin/stats?days=7');
  assert.equal(page.status, 200);
  assert.match(page.text, /Website stats/);
  assert.match(page.text, /linkedin\.com/);
  assert.match(page.text, /Top of page/);
  const adv = await login('adv@cork.test');
  assert.equal((await adv.agent.get('/admin/stats')).status, 404, 'non-admins get not found');
  assert.ok(!(await adv.agent.get('/')).text.includes('/admin/stats'), 'no nav link for non-admins');
});

// ------------------------------------------------------------- security review fixes
test('the real visitor address comes from the edge header when configured, and fake values are ignored', async () => {
  const site = createApp({ db, storage: localDiskStorage(storageDir), mailer, config: { baseUrl: BASE, clientIpHeader: 'true-client-ip', contactEmail: 'h@x.ie', formMinMs: 0 } });
  // Five demo requests from one address hit the limit, but a different real address is unaffected.
  for (let i = 0; i < 5; i++) {
    await request(site).post('/demo').set('True-Client-IP', '203.0.113.7').type('form').send({ _t: await formT(site, '/demo'), name: 'A', firm: 'B', email: `a${i}@b.ie` });
  }
  const blocked = await request(site).post('/demo').set('True-Client-IP', '203.0.113.7').type('form').send({ _t: await formT(site, '/demo'), name: 'A', firm: 'B', email: 'z@b.ie' });
  assert.equal(blocked.status, 429);
  const other = await request(site).post('/demo').set('True-Client-IP', '198.51.100.9').type('form').send({ _t: await formT(site, '/demo'), name: 'C', firm: 'D', email: 'c@d.ie' });
  assert.equal(other.status, 200, 'a different visitor is not blocked by someone else');
  const junk = await request(site).post('/demo').set('True-Client-IP', 'not-an-ip, 1.2.3.4').type('form').send({ _t: await formT(site, '/demo'), name: 'E', firm: 'F', email: 'e@f.ie' });
  assert.equal(junk.status, 200, 'invalid header falls back to the connection address');
});

test('login: password spraying from one address is stopped even across different emails', async () => {
  const site = createApp({ db, storage: localDiskStorage(storageDir), mailer, config: { baseUrl: BASE, clientIpHeader: 'true-client-ip' } });
  for (let i = 0; i < 30; i++) {
    await request(site).post('/login').set('True-Client-IP', '203.0.113.50').type('form').send({ email: `nobody${i}@spray.test`, password: 'Winter2026!!' });
  }
  const res = await request(site).post('/login').set('True-Client-IP', '203.0.113.50').type('form').send({ email: 'owner@cork.test', password: PW });
  assert.equal(res.status, 429, 'that address is paused, even with the right password');
  const elsewhere = await request(site).post('/login').set('True-Client-IP', '198.51.100.20').type('form').send({ email: 'owner@cork.test', password: PW });
  assert.equal(elsewhere.status, 302, 'the real owner, from their own address, still gets in');
});

test('security headers: no framing, and form posts may only go to us or Stripe', async () => {
  const res = await request(app).get('/login');
  const csp = res.headers['content-security-policy'];
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /form-action 'self' https:\/\/checkout\.stripe\.com https:\/\/billing\.stripe\.com/);
  assert.match(csp, /script-src 'self'/);
  assert.equal(res.headers['x-frame-options'], 'DENY');
  assert.match(res.headers['strict-transport-security'], /max-age=/);
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
});

test('uploads: a bad link is refused before the file is read, and each document has a file limit', async () => {
  const big = Buffer.alloc(2 * 1024 * 1024, 1);
  const bad = await request(app).post(`/u/${'x'.repeat(43)}/${s.reqs[0].id}`).attach('file', big, 'x.pdf');
  assert.equal(bad.status, 404);
  const fresh = await s.owner.post(`/cases/${s.ownerCase.caseId}/links`);
  const tok = fresh.text.match(/\/u\/([A-Za-z0-9_-]{43})/)[1];
  const rid = (await q1(`SELECT id FROM document_requests WHERE case_id = $1 AND status IN ('requested', 'received', 'rejected') ORDER BY sort_order DESC LIMIT 1`, [s.ownerCase.caseId])).id;
  const have = (await q1('SELECT count(*)::int AS n FROM documents WHERE request_id = $1', [rid])).n;
  let last;
  for (let i = have; i < 16; i++) last = await request(app).post(`/u/${tok}/${rid}`).attach('file', PDF, `p${i}.pdf`);
  assert.equal(last.status, 400);
  assert.match(last.text, /most files Fileready can take/);
  assert.equal((await q1('SELECT count(*)::int AS n FROM documents WHERE request_id = $1', [rid])).n, 15);
});

test('uploads: only a few run at once; extra ones are asked to retry', async () => {
  const site = createApp({ db, storage: localDiskStorage(storageDir), mailer, config: { baseUrl: BASE, maxConcurrentUploads: 0 } });
  const fresh = await s.owner.post(`/cases/${s.ownerCase.caseId}/links`);
  const tok = fresh.text.match(/\/u\/([A-Za-z0-9_-]{43})/)[1];
  const res = await request(site).post(`/u/${tok}/${s.reqs[1].id}`).attach('file', PDF, 'a.pdf');
  assert.equal(res.status, 503);
  assert.equal(res.headers['retry-after'], '10');
  assert.match(res.text, /busy for a moment/);
});

test('helper database functions are not callable by public roles', async () => {
  const rows = (await pglite.query(`SELECT p.proname, has_function_privilege('public', p.oid, 'EXECUTE') AS pub
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'
    AND p.proname IN ('current_firm_id', 'set_updated_at', 'audit_log_block_changes', 'refresh_case_completion', 'current_app_user', 'app_restricted')`)).rows;
  assert.ok(rows.length >= 6);
  assert.ok(rows.every((r) => !r.pub), JSON.stringify(rows));
});
