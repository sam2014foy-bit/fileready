// Tests for client management, case actions, file removal, password reset,
// team invites, firm settings and upload alerts.
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
import { hashPassword } from '../src/security.js';
import { memoryMailer } from '../src/mailer.js';
import { runReminders } from '../src/reminders.js';

const BASE = 'http://fileready.test';
const PDF = Buffer.from('%PDF-1.4\n%%EOF\n');
const PW = 'correct-horse-battery';
let pglite, db, app, mailer, storageDir;
const s = {};
const q1 = async (sql, p) => (await pglite.query(sql, p)).rows[0];
const lastEmail = () => mailer.outbox[mailer.outbox.length - 1];
const fileCount = async () => {
  let n = 0;
  for (const d of await readdir(storageDir).catch(() => [])) n += (await readdir(path.join(storageDir, d))).length;
  return n;
};

async function login(email, password = PW) {
  const agent = request.agent(app);
  const res = await agent.post('/login').type('form').send({ email, password });
  assert.equal(res.status, 302, `login for ${email}`);
  const csrf = (await agent.get('/')).text.match(/name="_csrf" value="([0-9a-f]{64})"/)[1];
  return { agent, csrf, post: (url, body = {}) => agent.post(url).type('form').send({ _csrf: csrf, ...body }) };
}

before(async () => {
  pglite = new PGlite();
  await migrate(pglite, () => {});
  db = createDb(pgliteDriver(pglite));
  mailer = memoryMailer();
  storageDir = await mkdtemp(path.join(os.tmpdir(), 'fr-feat-'));
  app = createApp({ db, storage: localDiskStorage(storageDir), mailer, config: { baseUrl: BASE } });
  for (const [firm, email, role] of [['Cork Brokers', 'owner@cork.test', 'owner'], ['Other Brokers', 'owner@other.test', 'owner']]) {
    const f = await q1('INSERT INTO firms (name) VALUES ($1) RETURNING id', [firm]);
    await pglite.query(`INSERT INTO users (firm_id, email, full_name, role, password_hash) VALUES ($1, $2, 'Aoife Owner', $3, $4)`, [f.id, email, role, await hashPassword(PW)]);
    s[email] = f.id;
  }
  await pglite.query(`INSERT INTO users (firm_id, email, full_name, role, password_hash) VALUES ($1, 'adviser@cork.test', 'Ciarán Adviser', 'adviser', $2)`, [s['owner@cork.test'], await hashPassword(PW)]);
  s.owner = await login('owner@cork.test');
  s.adviser = await login('adviser@cork.test');
  s.other = await login('owner@other.test');

  const mk = async (who, first, email) => {
    const c = await who.post('/clients', { first_name: first, last_name: 'Byrne', email, phone: email ? '' : '+353870000000' });
    const clientId = c.headers.location.split('client=')[1];
    const tpl = (await q1('SELECT id FROM checklist_templates WHERE firm_id IS NULL')).id;
    const k = await who.post('/cases', { client_id: clientId, title: 'Mortgage application', template_id: tpl });
    return { clientId, caseId: k.headers.location.split('/cases/')[1] };
  };
  Object.assign(s, { a: await mk(s.owner, 'Niamh', 'niamh@example.com'), b: await mk(s.owner, 'Dónal', '') });
  s.reqs = (await pglite.query('SELECT id, label FROM document_requests WHERE case_id = $1 ORDER BY sort_order', [s.a.caseId])).rows;
  const link = await s.owner.post(`/cases/${s.a.caseId}/links`);
  s.token = link.text.match(/\/u\/([A-Za-z0-9_-]{43})/)[1];
});
after(() => rm(storageDir, { recursive: true, force: true }));

// ------------------------------------------------------------------ clients
test('client names in the list open the client page', async () => {
  const list = await s.owner.agent.get('/clients');
  assert.ok(list.text.includes(`href="/clients/${s.a.clientId}"`));
  const page = await s.owner.agent.get(`/clients/${s.a.clientId}`);
  assert.equal(page.status, 200);
  assert.match(page.text, /Niamh Byrne/);
  assert.match(page.text, /Mortgage application/);
});

test('editing a client fixes their details and validates the email', async () => {
  const bad = await s.owner.post(`/clients/${s.a.clientId}`, { first_name: 'Niamh', last_name: 'Byrne', email: 'not-an-email' });
  assert.equal(bad.status, 400);
  const ok = await s.owner.post(`/clients/${s.a.clientId}`, { first_name: 'Niamh', last_name: 'Ó Briain', email: 'Niamh.New@Example.com' });
  assert.equal(ok.status, 303);
  const c = await q1('SELECT last_name, email FROM clients WHERE id = $1', [s.a.clientId]);
  assert.deepEqual({ ...c }, { last_name: 'Ó Briain', email: 'niamh.new@example.com' });
  assert.match((await s.owner.agent.get(ok.headers.location)).text, /Client details saved/);
});

test('adding an email to a client restarts chasing that had stopped for want of one', async () => {
  await pglite.query(`UPDATE cases SET chasing_started_at = now(), chasing_stopped = 'no_email', next_reminder_at = NULL WHERE id = $1`, [s.b.caseId]);
  await s.owner.post(`/clients/${s.b.clientId}`, { first_name: 'Dónal', last_name: 'Byrne', email: 'donal@example.com', phone: '' });
  const k = await q1('SELECT chasing_stopped, next_reminder_at FROM cases WHERE id = $1', [s.b.caseId]);
  assert.equal(k.chasing_stopped, null);
  assert.ok(k.next_reminder_at);
});

test('archive hides a client from the list; restore brings them back', async () => {
  await s.owner.post(`/clients/${s.b.clientId}/archive`);
  assert.ok(!(await s.owner.agent.get('/clients')).text.includes('Dónal'));
  assert.ok((await s.owner.agent.get('/clients?show=archived')).text.includes('Dónal'));
  await s.owner.post(`/clients/${s.b.clientId}/unarchive`);
  assert.ok((await s.owner.agent.get('/clients')).text.includes('Dónal'));
});

test('another firm cannot see, edit, archive or delete this firm\'s client', async () => {
  assert.equal((await s.other.agent.get(`/clients/${s.a.clientId}`)).status, 404);
  assert.equal((await s.other.post(`/clients/${s.a.clientId}`, { first_name: 'X', last_name: 'Y', email: 'x@y.ie' })).status, 404);
  assert.equal((await s.other.post(`/clients/${s.a.clientId}/archive`)).status, 404);
  assert.equal((await s.other.post(`/clients/${s.a.clientId}/delete`, { confirm: 'yes' })).status, 404);
  assert.equal((await q1('SELECT count(*)::int AS n FROM clients WHERE id = $1', [s.a.clientId])).n, 1);
});

// ------------------------------------------------------------- uploads & alerts
test('a client upload emails the adviser once, not for every file within 30 minutes', async () => {
  const before = mailer.outbox.length;
  await request(app).post(`/u/${s.token}/${s.reqs[0].id}`).attach('file', PDF, 'passport.pdf');
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(mailer.outbox.length, before + 1);
  const e = lastEmail();
  assert.equal(e.to, 'owner@cork.test', 'the case adviser (who created it)');
  assert.match(e.subject, /Niamh Ó Briain uploaded Photo ID/);
  assert.ok(e.text.includes(`${BASE}/cases/${s.a.caseId}`));
  await request(app).post(`/u/${s.token}/${s.reqs[1].id}`).attach('file', PDF, 'bill.pdf');
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(mailer.outbox.length, before + 1, 'second upload within 30 minutes: no new alert');
});

test('removing a wrong file deletes it and asks the client for that item again', async () => {
  const doc = await q1('SELECT id FROM documents WHERE request_id = $1', [s.reqs[1].id]);
  const filesBefore = await fileCount();
  assert.equal((await s.other.post(`/documents/${doc.id}/remove`)).status, 404, 'other firm cannot remove it');
  const res = await s.owner.post(`/documents/${doc.id}/remove`);
  assert.equal(res.status, 303);
  assert.equal(await fileCount(), filesBefore - 1, 'file deleted from storage');
  assert.equal((await q1('SELECT status FROM document_requests WHERE id = $1', [s.reqs[1].id])).status, 'requested');
  assert.ok(!(await s.owner.agent.get(`/cases/${s.a.caseId}`)).text.includes('bill.pdf'));
  assert.equal((await s.owner.agent.get(`/documents/${doc.id}`)).status, 404);
});

test('removing a checklist item takes it off the list and deletes its files', async () => {
  const extra = await s.owner.post(`/cases/${s.a.caseId}/requests`, { label: 'P60 for 2025', required: 'on' });
  assert.equal(extra.status, 302);
  const r = await q1(`SELECT id FROM document_requests WHERE case_id = $1 AND label = 'P60 for 2025'`, [s.a.caseId]);
  await request(app).post(`/u/${s.token}/${r.id}`).attach('file', PDF, 'p60.pdf');
  const filesBefore = await fileCount();
  assert.equal((await s.other.post(`/cases/${s.a.caseId}/requests/${r.id}/delete`)).status, 404);
  assert.equal((await s.owner.post(`/cases/${s.a.caseId}/requests/${r.id}/delete`)).status, 303);
  assert.equal((await q1('SELECT count(*)::int AS n FROM document_requests WHERE id = $1', [r.id])).n, 0);
  assert.equal(await fileCount(), filesBefore - 1);
});

// ------------------------------------------------------------------ case status
test('bug fix: reopening a document on a finished case restarts chasing', async () => {
  await pglite.query(`UPDATE document_requests SET status = 'waived' WHERE case_id = $1 AND required`, [s.a.caseId]);
  assert.equal((await q1('SELECT status FROM cases WHERE id = $1', [s.a.caseId])).status, 'complete');
  await pglite.query(`UPDATE cases SET chasing_started_at = now(), next_reminder_at = NULL WHERE id = $1`, [s.a.caseId]);
  await s.owner.post(`/cases/${s.a.caseId}/requests/${s.reqs[2].id}`, { action: 'reopen' });
  const k = await q1('SELECT status, next_reminder_at FROM cases WHERE id = $1', [s.a.caseId]);
  assert.equal(k.status, 'open');
  assert.ok(k.next_reminder_at, 'a reminder is scheduled again');
});

test('put on hold stops reminders; reopen resumes them', async () => {
  await s.owner.post(`/cases/${s.a.caseId}/status`, { action: 'hold' });
  let k = await q1('SELECT status, next_reminder_at FROM cases WHERE id = $1', [s.a.caseId]);
  assert.equal(k.status, 'on_hold');
  assert.equal(k.next_reminder_at, null);
  const page = await s.owner.agent.get(`/cases/${s.a.caseId}`);
  assert.match(page.text, /On hold\. No reminders go out/);
  assert.ok(!page.text.includes('on_hold.'), 'no raw status names');
  assert.equal((await runReminders({ db, mailer, baseUrl: BASE, ignoreHours: true })).sent, 0);
  await s.owner.post(`/cases/${s.a.caseId}/status`, { action: 'reopen' });
  k = await q1('SELECT status, next_reminder_at FROM cases WHERE id = $1', [s.a.caseId]);
  assert.equal(k.status, 'open');
  assert.ok(k.next_reminder_at);
});

test('reopening a case whose required documents are all done makes it complete, not open', async () => {
  await s.owner.post(`/cases/${s.a.caseId}/status`, { action: 'close' });
  await pglite.query(`UPDATE document_requests SET status = 'waived' WHERE case_id = $1 AND required`, [s.a.caseId]);
  assert.equal((await q1('SELECT status FROM cases WHERE id = $1', [s.a.caseId])).status, 'closed', 'closed stays closed');
  await s.owner.post(`/cases/${s.a.caseId}/status`, { action: 'reopen' });
  assert.equal((await q1('SELECT status FROM cases WHERE id = $1', [s.a.caseId])).status, 'complete');
});

test('another firm cannot change or delete this firm\'s case', async () => {
  assert.equal((await s.other.post(`/cases/${s.a.caseId}/status`, { action: 'close' })).status, 409);
  assert.equal((await s.other.post(`/cases/${s.a.caseId}/delete`, { confirm: 'yes' })).status, 404);
});

test('only the owner can delete; deleting needs the confirm tick', async () => {
  assert.equal((await s.adviser.post(`/cases/${s.b.caseId}/delete`, { confirm: 'yes' })).status, 403);
  assert.equal((await s.owner.post(`/cases/${s.b.caseId}/delete`)).status, 400);
  const res = await s.owner.post(`/cases/${s.b.caseId}/delete`, { confirm: 'yes' });
  assert.equal(res.status, 303);
  assert.equal(res.headers.location, `/clients/${s.b.clientId}`);
  assert.equal((await q1('SELECT count(*)::int AS n FROM cases WHERE id = $1', [s.b.caseId])).n, 0);
});

test('deleting a client removes their cases and every file', async () => {
  assert.equal((await s.adviser.post(`/clients/${s.a.clientId}/delete`, { confirm: 'yes' })).status, 403);
  assert.ok(await fileCount() > 0);
  const res = await s.owner.post(`/clients/${s.a.clientId}/delete`, { confirm: 'yes' });
  assert.equal(res.status, 303);
  assert.equal(await fileCount(), 0);
  assert.equal((await q1('SELECT count(*)::int AS n FROM cases WHERE client_id = $1', [s.a.clientId])).n, 0);
  assert.equal((await q1(`SELECT count(*)::int AS n FROM audit_log WHERE action = 'client.deleted'`)).n, 1, 'the deletion itself is logged');
  assert.match((await s.owner.agent.get(res.headers.location)).text, /deleted/);
});

// ------------------------------------------------------------- password reset
test('forgot password: same answer for unknown emails, and no email sent', async () => {
  const before = mailer.outbox.length;
  const res = await request(app).post('/forgot').type('form').send({ email: 'nobody@nowhere.test' });
  assert.equal(res.status, 200);
  assert.match(res.text, /Check your email/);
  assert.equal(mailer.outbox.length, before);
});

test('forgot password: a reset link sets a new password, signs out old sessions, and works once', async () => {
  const oldSession = await login('adviser@cork.test');
  await request(app).post('/forgot').type('form').send({ email: 'Adviser@Cork.test' });
  const e = lastEmail();
  assert.equal(e.to, 'adviser@cork.test');
  assert.match(e.subject, /Reset your Fileready password/);
  const token = e.text.match(/\/reset\/([A-Za-z0-9_-]{43})/)[1];
  assert.match((await request(app).get(`/reset/${token}`)).text, /Set a new password/);
  assert.equal((await request(app).post(`/reset/${token}`).type('form').send({ new_password: 'short', confirm: 'short' })).status, 400);
  const done = await request(app).post(`/reset/${token}`).type('form').send({ new_password: 'a-whole-new-passphrase', confirm: 'a-whole-new-passphrase' });
  assert.equal(done.status, 303);
  assert.equal(done.headers.location, '/login?reset=1');
  assert.equal((await oldSession.agent.get('/')).status, 302, 'old session signed out');
  assert.equal((await request(app).get(`/reset/${token}`)).status, 404, 'link used up');
  await login('adviser@cork.test', 'a-whole-new-passphrase');
  assert.match((await request(app).get('/login?reset=1')).text, /Your password is set/);
});

test('changing your password signs out your other sessions but keeps this one', async () => {
  const other = await login('adviser@cork.test', 'a-whole-new-passphrase');
  const me = await login('adviser@cork.test', 'a-whole-new-passphrase');
  const res = await me.post('/account/password', { current: 'a-whole-new-passphrase', new_password: 'yet-another-passphrase', confirm: 'yet-another-passphrase' });
  assert.equal(res.status, 200);
  assert.equal((await me.agent.get('/')).status, 200, 'this session still works');
  assert.equal((await other.agent.get('/')).status, 302, 'other session signed out');
  s.adviser = me;
});

// ------------------------------------------------------------------ team
test('only the owner sees Team and Settings', async () => {
  assert.equal((await s.adviser.agent.get('/team')).status, 403);
  assert.equal((await s.adviser.agent.get('/settings')).status, 403);
  assert.ok(!(await s.adviser.agent.get('/')).text.includes('href="/team"'));
  assert.ok((await s.owner.agent.get('/')).text.includes('href="/team"'));
});

test('the owner invites a colleague, who sets a password and logs in', async () => {
  const res = await s.owner.post('/team', { full_name: 'Gráinne Staff', email: 'grainne@cork.test', role: 'admin_staff' });
  assert.equal(res.status, 303);
  assert.equal(res.headers.location, '/team?f=invited');
  const e = lastEmail();
  assert.equal(e.to, 'grainne@cork.test');
  assert.equal(e.replyTo, 'owner@cork.test');
  assert.match(e.subject, /invited to Cork Brokers/);
  assert.match((await s.owner.agent.get('/team')).text, /Invited/);
  const token = e.text.match(/\/reset\/([A-Za-z0-9_-]{43})/)[1];
  assert.match((await request(app).get(`/reset/${token}`)).text, /Set up your login/);
  await request(app).post(`/reset/${token}`).type('form').send({ new_password: 'grainnes-own-passphrase', confirm: 'grainnes-own-passphrase' });
  s.grainne = await login('grainne@cork.test', 'grainnes-own-passphrase');
  assert.match((await s.owner.agent.get('/team')).text, /Active/);
});

test('an email that already has a login cannot be invited again', async () => {
  const res = await s.owner.post('/team', { full_name: 'Someone', email: 'owner@other.test', role: 'adviser' });
  assert.equal(res.status, 400);
  assert.match(res.text, /already has a Fileready login/);
});

test('removing access signs the person out and blocks login; giving access restores it', async () => {
  const uid = (await q1(`SELECT id FROM users WHERE email = 'grainne@cork.test'`)).id;
  assert.equal((await s.other.post(`/team/${uid}/disable`)).status, 404, 'other firm cannot');
  await s.owner.post(`/team/${uid}/disable`);
  assert.equal((await s.grainne.agent.get('/')).status, 302, 'signed out');
  assert.equal((await request(app).post('/login').type('form').send({ email: 'grainne@cork.test', password: 'grainnes-own-passphrase' })).status, 401);
  await s.owner.post(`/team/${uid}/enable`);
  await login('grainne@cork.test', 'grainnes-own-passphrase');
});

test('the owner cannot remove their own access', async () => {
  const me = (await q1(`SELECT id FROM users WHERE email = 'owner@cork.test'`)).id;
  assert.equal((await s.owner.post(`/team/${me}/disable`)).status, 400);
});

// ------------------------------------------------------------------ settings
test('settings: the owner changes the firm name and reminder rules, with checks', async () => {
  assert.equal((await s.owner.post('/settings', { name: 'Cork Brokers', reminder_every_days: 0, max_reminders: 6 })).status, 400);
  assert.equal((await s.owner.post('/settings', { name: '', reminder_every_days: 3, max_reminders: 6 })).status, 400);
  const ok = await s.owner.post('/settings', { name: 'Cork Mortgage Brokers', reminder_every_days: 5, max_reminders: 8 });
  assert.equal(ok.status, 303);
  const f = await q1('SELECT name, reminder_every_days, max_reminders FROM firms WHERE id = $1', [s['owner@cork.test']]);
  assert.deepEqual({ ...f }, { name: 'Cork Mortgage Brokers', reminder_every_days: 5, max_reminders: 8 });
  assert.equal((await q1('SELECT name FROM firms WHERE id = $1', [s['owner@other.test']])).name, 'Other Brokers', 'other firm untouched');
});
