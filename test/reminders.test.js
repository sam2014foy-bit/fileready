// Tests for automatic chasing.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
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
import { runReminders, withinSendingHours } from '../src/reminders.js';
import { reminderEmail } from '../src/emails.js';

const BASE = 'http://fileready.test';
const SECRET = 'test-reminders-secret-value';
const PDF = Buffer.from('%PDF-1.4\n%%EOF\n');
let pglite, db, app, mailer, storageDir, agent, csrf, firmId;
const ctx = {};

const q1 = async (sql, params) => (await pglite.query(sql, params)).rows[0];
const run = () => runReminders({ db, mailer, baseUrl: BASE, ignoreHours: true });
const makeDue = (caseId) => pglite.query(`UPDATE cases SET next_reminder_at = now() - interval '1 minute' WHERE id = $1`, [caseId]);
const lastEmail = () => mailer.outbox[mailer.outbox.length - 1];
const tokenFrom = (email) => email.text.match(/\/u\/([A-Za-z0-9_-]{43})/)[1];

before(async () => {
  pglite = new PGlite();
  await migrate(pglite, () => {});
  db = createDb(pgliteDriver(pglite));
  mailer = memoryMailer();
  storageDir = await mkdtemp(path.join(os.tmpdir(), 'fr-rem-'));
  app = createApp({ db, storage: localDiskStorage(storageDir), mailer, config: { baseUrl: BASE, remindersSecret: SECRET } });

  for (const [name, email] of [['Cork Brokers', 'owner@cork.test'], ['Other Brokers', 'owner@other.test']]) {
    const f = await q1(`INSERT INTO firms (name) VALUES ($1) RETURNING id`, [name]);
    await pglite.query(
      `INSERT INTO users (firm_id, email, full_name, role, password_hash) VALUES ($1, $2, 'Aoife Murphy', 'owner', $3)`,
      [f.id, email, await hashPassword('correct-horse-battery')]
    );
    if (!firmId) firmId = f.id;
  }
  agent = request.agent(app);
  await agent.post('/login').type('form').send({ email: 'owner@cork.test', password: 'correct-horse-battery' });
  csrf = (await agent.get('/')).text.match(/name="_csrf" value="([0-9a-f]{64})"/)[1];

  const newCase = async (first, email) => {
    const c = await agent.post('/clients').type('form').send({ _csrf: csrf, first_name: first, last_name: 'Byrne', email, phone: email ? '' : '+353870000000' });
    const clientId = c.headers.location.split('client=')[1];
    const tpl = (await q1(`SELECT id FROM checklist_templates WHERE firm_id IS NULL`)).id;
    const k = await agent.post('/cases').type('form').send({ _csrf: csrf, client_id: clientId, title: 'Mortgage application', template_id: tpl });
    return k.headers.location.split('/cases/')[1];
  };
  ctx.caseId = await newCase('Ciara', 'ciara@example.com');
  ctx.noEmailCase = await newCase('Dónal', '');
  ctx.requests = (await pglite.query(`SELECT id, label FROM document_requests WHERE case_id = $1 ORDER BY sort_order`, [ctx.caseId])).rows;
});
after(() => rm(storageDir, { recursive: true, force: true }));

test('sending hours: Mon–Sat 9am–7pm Irish time, summer time included', () => {
  assert.equal(withinSendingHours(new Date('2026-11-16T10:00:00Z')), true, 'Monday 10:00');
  assert.equal(withinSendingHours(new Date('2026-11-15T12:00:00Z')), false, 'Sunday');
  assert.equal(withinSendingHours(new Date('2026-11-16T08:30:00Z')), false, 'before 9');
  assert.equal(withinSendingHours(new Date('2026-11-16T19:00:00Z')), false, '7pm');
  assert.equal(withinSendingHours(new Date('2026-07-06T08:30:00Z')), true, 'summer: 08:30 UTC is 09:30 in Dublin');
});

test('outside sending hours the scheduler sends nothing', async () => {
  const r = await runReminders({ db, mailer, baseUrl: BASE, now: new Date('2026-11-15T12:00:00Z') });
  assert.equal(r.ran, false);
});

test('nothing is sent before the broker starts chasing', async () => {
  const r = await run();
  assert.equal(r.sent, 0);
  assert.equal(mailer.outbox.length, 0);
});

test('"Email client & start chasing" sends the first request with a working link and schedules reminders', async () => {
  const manual = await agent.post(`/cases/${ctx.caseId}/links`).type('form').send({ _csrf: csrf });
  ctx.manualToken = manual.text.match(/\/u\/([A-Za-z0-9_-]{43})/)[1];

  const sent = await agent.post(`/cases/${ctx.caseId}/chase/start`).type('form').send({ _csrf: csrf });
  assert.equal(sent.status, 303, 'redirects so a page refresh cannot resend');
  const res = await agent.get(sent.headers.location);
  assert.match(res.text, /Email sent to your client/);
  const e = lastEmail();
  assert.equal(e.to, 'ciara@example.com');
  assert.equal(e.replyTo, 'owner@cork.test', 'replies go to the adviser');
  assert.equal(e.fromName, 'Cork Brokers via Fileready');
  assert.match(e.subject, /Documents needed for your mortgage application – Cork Brokers/);
  assert.match(e.text, /Photo ID/);
  assert.match(e.text, /Aoife Murphy/);
  assert.match(e.text, /Gift letter.*if it applies/, 'optional items are marked as such');

  const c = await q1(`SELECT reminders_sent, chasing_started_at, round(extract(epoch FROM next_reminder_at - now()) / 86400)::int AS days FROM cases WHERE id = $1`, [ctx.caseId]);
  assert.equal(c.reminders_sent, 1);
  assert.ok(c.chasing_started_at);
  assert.equal(c.days, 3, 'next reminder 3 days out');

  ctx.token = tokenFrom(e);
  assert.equal((await request(app).get(`/u/${ctx.token}`)).status, 200, 'link in the email works');
  assert.equal((await request(app).get(`/u/${ctx.manualToken}`)).status, 404, 'older link turned off');
  assert.match(res.text, /First request/);
});

test('the scheduler ignores cases that are not due yet', async () => {
  const before = mailer.outbox.length;
  assert.equal((await run()).sent, 0);
  assert.equal(mailer.outbox.length, before);
});

test('when due, the scheduler sends a reminder listing only what is still missing', async () => {
  const up = await request(app).post(`/u/${ctx.token}/${ctx.requests[0].id}`).attach('file', PDF, 'id.pdf');
  assert.equal(up.status, 303, up.text.match(/class="error"[^>]*>([^<]*)/)?.[1]);
  await makeDue(ctx.caseId);
  const r = await run();
  assert.equal(r.sent, 1);
  const e = lastEmail();
  assert.match(e.subject, /^Reminder: 6 documents still needed – Cork Brokers/);
  assert.ok(!e.text.includes('Photo ID'), 'uploaded item is not chased');
  assert.match(e.text, /Proof of address/);
  const fresh = tokenFrom(e);
  assert.equal((await request(app).get(`/u/${fresh}`)).status, 200);
  assert.equal((await request(app).get(`/u/${ctx.token}`)).status, 404, 'previous email link turned off');
  ctx.token = fresh;
  const rem = await q1(`SELECT kind, status, outstanding FROM reminders WHERE case_id = $1 ORDER BY created_at DESC LIMIT 1`, [ctx.caseId]);
  assert.deepEqual({ ...rem }, { kind: 'reminder', status: 'sent', outstanding: 6 });
});

test('running the scheduler twice does not double-send', async () => {
  const before = mailer.outbox.length;
  await run();
  await run();
  assert.equal(mailer.outbox.length, before);
});

test('rejecting a document brings the next reminder forward and explains what to fix', async () => {
  await agent.post(`/cases/${ctx.caseId}/requests/${ctx.requests[0].id}`).type('form').send({ _csrf: csrf, action: 'reject', reason: 'Passport has expired' });
  const c = await q1(`SELECT extract(epoch FROM next_reminder_at - now())::int AS secs FROM cases WHERE id = $1`, [ctx.caseId]);
  assert.ok(c.secs > 0 && c.secs <= 600, `next reminder within 10 minutes (was ${c.secs}s)`);
  await makeDue(ctx.caseId);
  await run();
  const e = lastEmail();
  assert.match(e.subject, /^Please re-upload a document – Cork Brokers/);
  assert.match(e.text, /Photo ID – please upload again: Passport has expired/);
  ctx.token = tokenFrom(e);
});

test('a send failure is recorded, not counted, and retried in 2 hours', async () => {
  const before = await q1(`SELECT reminders_sent FROM cases WHERE id = $1`, [ctx.caseId]);
  await makeDue(ctx.caseId);
  mailer.failNext = true;
  const r = await run();
  assert.equal(r.failed, 1);
  const c = await q1(`SELECT reminders_sent, extract(epoch FROM next_reminder_at - now())::int AS secs FROM cases WHERE id = $1`, [ctx.caseId]);
  assert.equal(c.reminders_sent, before.reminders_sent);
  assert.ok(c.secs > 7000 && c.secs <= 7200);
  const rem = await q1(`SELECT status, error FROM reminders WHERE case_id = $1 ORDER BY created_at DESC LIMIT 1`, [ctx.caseId]);
  assert.equal(rem.status, 'failed');
});

test('pause stops reminders; resume brings them back', async () => {
  await agent.post(`/cases/${ctx.caseId}/chase/pause`).type('form').send({ _csrf: csrf });
  await makeDue(ctx.caseId);
  const before = mailer.outbox.length;
  await run();
  assert.equal(mailer.outbox.length, before, 'paused: nothing sent');
  const page = await agent.get(`/cases/${ctx.caseId}`);
  assert.match(page.text, /Paused\./);
  await agent.post(`/cases/${ctx.caseId}/chase/resume`).type('form').send({ _csrf: csrf });
  await makeDue(ctx.caseId);
  await run();
  assert.equal(mailer.outbox.length, before + 1, 'resumed: reminder sent');
});

test('after the firm\'s limit, chasing stops and the broker is told', async () => {
  await pglite.query(`UPDATE firms SET max_reminders = 4 WHERE id = $1`, [firmId]);
  const sent = (await q1(`SELECT reminders_sent FROM cases WHERE id = $1`, [ctx.caseId])).reminders_sent;
  assert.ok(sent >= 4);
  await makeDue(ctx.caseId);
  const before = mailer.outbox.length;
  await run();
  assert.equal(mailer.outbox.length, before);
  const c = await q1(`SELECT chasing_stopped, next_reminder_at FROM cases WHERE id = $1`, [ctx.caseId]);
  assert.equal(c.chasing_stopped, 'limit_reached');
  assert.equal(c.next_reminder_at, null);
  assert.match((await agent.get('/')).text, /No reply after/);
  assert.match((await agent.get(`/cases/${ctx.caseId}`)).text, /No response after/);
  await pglite.query(`UPDATE firms SET max_reminders = 6 WHERE id = $1`, [firmId]);
});

test('"Send reminder now" works even after the limit, and resume restarts chasing', async () => {
  const res = await agent.post(`/cases/${ctx.caseId}/chase/now`).type('form').send({ _csrf: csrf });
  assert.equal(res.status, 303);
  assert.match(lastEmail().subject, /Cork Brokers/);
  await agent.post(`/cases/${ctx.caseId}/chase/resume`).type('form').send({ _csrf: csrf });
  const c = await q1(`SELECT chasing_stopped, next_reminder_at FROM cases WHERE id = $1`, [ctx.caseId]);
  assert.equal(c.chasing_stopped, null);
  assert.ok(c.next_reminder_at);
});

test('a complete case is never chased', async () => {
  for (const r of ctx.requests) {
    await pglite.query(`UPDATE document_requests SET status = 'waived', rejected_reason = NULL WHERE id = $1`, [r.id]);
  }
  assert.equal((await q1(`SELECT status FROM cases WHERE id = $1`, [ctx.caseId])).status, 'complete');
  await makeDue(ctx.caseId);
  const before = mailer.outbox.length;
  await run();
  assert.equal(mailer.outbox.length, before);
  assert.match((await agent.get(`/cases/${ctx.caseId}`)).text, /Finished\./);
});

test('a client with no email cannot be chased, and the broker is told why', async () => {
  const page = await agent.get(`/cases/${ctx.noEmailCase}`);
  assert.ok(!page.text.includes('/chase/start'), 'no start button');
  assert.match(page.text, /no email address/);
  const res = await agent.post(`/cases/${ctx.noEmailCase}/chase/start`).type('form').send({ _csrf: csrf });
  assert.equal(res.status, 400);
  assert.match(res.text, /no email address/);
});

test('another firm cannot trigger emails to this firm\'s clients', async () => {
  const other = request.agent(app);
  await other.post('/login').type('form').send({ email: 'owner@other.test', password: 'correct-horse-battery' });
  const otherCsrf = (await other.get('/')).text.match(/name="_csrf" value="([0-9a-f]{64})"/)[1];
  const before = mailer.outbox.length;
  for (const a of ['start', 'now', 'pause', 'resume']) {
    const res = await other.post(`/cases/${ctx.caseId}/chase/${a}`).type('form').send({ _csrf: otherCsrf });
    assert.ok([404, 409].includes(res.status), `${a} → ${res.status}`);
  }
  assert.equal(mailer.outbox.length, before);
});

test('the scheduler endpoint needs the secret', async () => {
  assert.equal((await request(app).post('/internal/reminders/run')).status, 401);
  assert.equal((await request(app).post('/internal/reminders/run').set('Authorization', 'Bearer wrong')).status, 401);
  const ok = await request(app).post('/internal/reminders/run').set('Authorization', `Bearer ${SECRET}`);
  assert.equal(ok.status, 200);
  assert.equal(typeof ok.body.ran, 'boolean');
});

test('reminder emails escape names in HTML', () => {
  const e = reminderEmail({
    kind: 'first', firstName: '<b>Seán</b>', firmName: 'O\'Brien & Co', caseTitle: 'Mortgage application', adviserName: null,
    link: 'https://x/u/abc', linkDays: 14, items: [{ label: '<script>x</script>', status: 'requested', required: true }],
  });
  assert.ok(!e.html.includes('<script>'));
  assert.ok(!e.html.includes('<b>Seán</b>'));
  assert.match(e.html, /O&#39;Brien &amp; Co/);
});
