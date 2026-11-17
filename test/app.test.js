// End-to-end tests of the web app against in-memory Postgres.
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

const BASE = 'http://fileready.test';
const PDF = Buffer.from('%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n');
let pglite, app, storageDir;
const firms = {};

async function addFirm(key, email) {
  const firm = (await pglite.query(`INSERT INTO firms (name) VALUES ($1) RETURNING id`, [`${key} Brokers`])).rows[0].id;
  await pglite.query(
    `INSERT INTO users (firm_id, email, full_name, role, password_hash) VALUES ($1, $2, $3, 'owner', $4)`,
    [firm, email, `${key} Owner`, await hashPassword('correct-horse-battery')]
  );
  firms[key] = { id: firm, email };
}

before(async () => {
  pglite = new PGlite();
  await migrate(pglite, () => {});
  await addFirm('A', 'a@brokers.test');
  await addFirm('B', 'b@brokers.test');
  storageDir = await mkdtemp(path.join(os.tmpdir(), 'fr-'));
  app = createApp({ db: createDb(pgliteDriver(pglite)), storage: localDiskStorage(storageDir), mailer: memoryMailer(), config: { baseUrl: BASE } });
});
after(async () => {
  await rm(storageDir, { recursive: true, force: true });
});

async function login(email, password = 'correct-horse-battery') {
  const agent = request.agent(app);
  const res = await agent.post('/login').type('form').send({ email, password });
  assert.equal(res.status, 302, `login failed for ${email}`);
  const page = await agent.get('/');
  const csrf = page.text.match(/name="_csrf" value="([0-9a-f]{64})"/)[1];
  return { agent, csrf };
}

const status = async (rid) => (await pglite.query('SELECT status FROM document_requests WHERE id = $1', [rid])).rows[0].status;

// Shared state across the flow below (tests run in order).
const s = {};

test('pages need a login; logged-out visitors to / get the public home page', async () => {
  const res = await request(app).get('/clients');
  assert.equal(res.status, 302);
  assert.equal(res.headers.location, '/login');
  const home = await request(app).get('/');
  assert.equal(home.status, 200);
  assert.match(home.text, /Every document in\. <em>Without the chasing\.<\/em>/);
  assert.ok(!home.text.includes('noindex'), 'home page can be found by search engines');
  const gsap = await request(app).get('/static/vendor/gsap/gsap.min.js');
  assert.equal(gsap.status, 200);
  assert.equal((await request(app).get('/static/vendor/lenis/lenis.min.js')).status, 200);
});

test('wrong password is refused, with the same message as an unknown email', async () => {
  const wrong = await request(app).post('/login').type('form').send({ email: 'a@brokers.test', password: 'nope-nope-nope' });
  const unknown = await request(app).post('/login').type('form').send({ email: 'ghost@brokers.test', password: 'nope-nope-nope' });
  assert.equal(wrong.status, 401);
  assert.equal(unknown.status, 401);
  assert.match(wrong.text, /Email or password is wrong/);
  assert.match(unknown.text, /Email or password is wrong/);
});

test('session cookie is httpOnly and SameSite=Strict', async () => {
  const res = await request(app).post('/login').type('form').send({ email: 'a@brokers.test', password: 'correct-horse-battery' });
  const cookie = res.headers['set-cookie'][0];
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
});

test('broker creates a client and a case with the mortgage checklist', async () => {
  Object.assign(s, await login('a@brokers.test'));
  const noCsrf = await s.agent.post('/clients').type('form').send({ first_name: 'Seán', last_name: "O'Brien", email: 'sean@example.com' });
  assert.equal(noCsrf.status, 403, 'form without CSRF token is refused');

  const c = await s.agent.post('/clients').type('form').send({ _csrf: s.csrf, first_name: 'Seán', last_name: "O'Brien", email: 'Sean@Example.com' });
  assert.equal(c.status, 302);
  s.clientId = c.headers.location.split('client=')[1];

  const form = await s.agent.get(`/cases/new?client=${s.clientId}`);
  const templateId = form.text.match(/<option value="([0-9a-f-]{36})">Mortgage application/)[1];
  const k = await s.agent.post('/cases').type('form').send({ _csrf: s.csrf, client_id: s.clientId, title: 'First-time buyer', lender: 'Demo Bank', template_id: templateId });
  assert.equal(k.status, 302);
  s.caseId = k.headers.location.split('/cases/')[1];

  const page = await s.agent.get(`/cases/${s.caseId}`);
  assert.equal(page.status, 200);
  assert.match(page.text, /Seán O&#39;Brien/, 'names are HTML-escaped');
  assert.equal((page.text.match(/class="item status-requested"/g) || []).length, 9);
  s.requests = (await pglite.query(`SELECT id, label FROM document_requests WHERE case_id = $1 ORDER BY sort_order`, [s.caseId])).rows;
});

test('client email is stored lower-case', async () => {
  const { rows } = await pglite.query('SELECT email FROM clients WHERE id = $1', [s.clientId]);
  assert.equal(rows[0].email, 'sean@example.com');
});

test('upload link is shown once and only its hash is stored', async () => {
  const res = await s.agent.post(`/cases/${s.caseId}/links`).type('form').send({ _csrf: s.csrf });
  assert.equal(res.status, 200);
  s.token = res.text.match(/\/u\/([A-Za-z0-9_-]{43})/)[1];
  const { rows } = await pglite.query('SELECT token_hash FROM upload_links WHERE case_id = $1', [s.caseId]);
  assert.equal(rows.length, 1);
  assert.notEqual(rows[0].token_hash, s.token);
  const again = await s.agent.get(`/cases/${s.caseId}`);
  assert.ok(!again.text.includes(s.token), 'link is not shown again');
});

test('client sees the checklist without logging in', async () => {
  const res = await request(app).get(`/u/${s.token}`);
  assert.equal(res.status, 200);
  assert.match(res.text, /Hi Seán/);
  assert.match(res.text, /Photo ID/);
  assert.equal(res.headers['cache-control'], 'no-store');
});

test('a made-up or malformed link shows "not active"', async () => {
  assert.equal((await request(app).get('/u/' + 'x'.repeat(43))).status, 404);
  assert.equal((await request(app).get('/u/short')).status, 404);
});

test('uploads that are not PDF or image are refused, whatever the file name says', async () => {
  const res = await request(app).post(`/u/${s.token}/${s.requests[0].id}`).attach('file', Buffer.from('MZ evil program'), 'payslip.pdf');
  assert.equal(res.status, 400);
  assert.match(res.text, /PDF or a photo/);
  assert.equal(await status(s.requests[0].id), 'requested');
});

test('client uploads a PDF: it is stored, the item shows received, and it is logged', async () => {
  const res = await request(app).post(`/u/${s.token}/${s.requests[0].id}`).attach('file', PDF, 'passport.pdf');
  assert.equal(res.status, 303);
  assert.equal(await status(s.requests[0].id), 'received');
  const { rows } = await pglite.query('SELECT * FROM documents WHERE request_id = $1', [s.requests[0].id]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].mime_type, 'application/pdf');
  s.docId = rows[0].id;
  const log = await pglite.query(`SELECT actor_type FROM audit_log WHERE action = 'document.uploaded' AND entity_id = $1`, [s.docId]);
  assert.equal(log.rows[0].actor_type, 'client');
});

test('broker downloads the file and it matches', async () => {
  const res = await s.agent.get(`/documents/${s.docId}`).buffer(true).parse((r, cb) => {
    const chunks = []; r.on('data', (c) => chunks.push(c)); r.on('end', () => cb(null, Buffer.concat(chunks)));
  });
  assert.equal(res.status, 200);
  assert.ok(Buffer.compare(res.body, PDF) === 0);
  assert.match(res.headers['content-disposition'], /attachment/);
});

test('another firm cannot see the case or the document', async () => {
  const other = await login('b@brokers.test');
  assert.equal((await other.agent.get(`/cases/${s.caseId}`)).status, 404);
  assert.equal((await other.agent.get(`/documents/${s.docId}`)).status, 404);
  const tryAccept = await other.agent.post(`/cases/${s.caseId}/requests/${s.requests[0].id}`).type('form').send({ _csrf: other.csrf, action: 'accept' });
  assert.equal(tryAccept.status, 409);
  assert.equal(await status(s.requests[0].id), 'received');
  const dash = await other.agent.get('/');
  assert.ok(!dash.text.includes("O&#39;Brien"));
});

test('rejecting needs a reason; the client then sees it', async () => {
  const noReason = await s.agent.post(`/cases/${s.caseId}/requests/${s.requests[0].id}`).type('form').send({ _csrf: s.csrf, action: 'reject' });
  assert.equal(noReason.status, 400);
  await s.agent.post(`/cases/${s.caseId}/requests/${s.requests[0].id}`).type('form').send({ _csrf: s.csrf, action: 'reject', reason: 'Photo is blurry' });
  assert.equal(await status(s.requests[0].id), 'rejected');
  const client = await request(app).get(`/u/${s.token}`);
  assert.match(client.text, /Please upload again: Photo is blurry/);
});

test('re-upload after rejection, accept, then waive the rest: case becomes "File complete"', async () => {
  await request(app).post(`/u/${s.token}/${s.requests[0].id}`).attach('file', PDF, 'passport2.pdf');
  assert.equal(await status(s.requests[0].id), 'received');
  await s.agent.post(`/cases/${s.caseId}/requests/${s.requests[0].id}`).type('form').send({ _csrf: s.csrf, action: 'accept' });
  assert.equal(await status(s.requests[0].id), 'accepted');

  for (const r of s.requests.slice(1)) {
    await s.agent.post(`/cases/${s.caseId}/requests/${r.id}`).type('form').send({ _csrf: s.csrf, action: 'waive' });
  }
  const { rows } = await pglite.query('SELECT status FROM cases WHERE id = $1', [s.caseId]);
  assert.equal(rows[0].status, 'complete');
  const dash = await s.agent.get('/?show=complete');
  assert.match(dash.text, /File complete/);
});

test('an accepted item cannot be uploaded to', async () => {
  const res = await request(app).post(`/u/${s.token}/${s.requests[0].id}`).attach('file', PDF, 'extra.pdf');
  assert.equal(res.status, 400);
});

test('turning off a link stops it working', async () => {
  const { rows } = await pglite.query('SELECT id FROM upload_links WHERE case_id = $1', [s.caseId]);
  await s.agent.post(`/cases/${s.caseId}/links/${rows[0].id}/revoke`).type('form').send({ _csrf: s.csrf });
  assert.equal((await request(app).get(`/u/${s.token}`)).status, 404);
});

test('cross-site form posts are refused', async () => {
  const res = await s.agent.post('/clients').set('Origin', 'https://evil.example').type('form').send({ _csrf: s.csrf, first_name: 'X', last_name: 'Y', email: 'x@y.z' });
  assert.equal(res.status, 403);
});

test('history records the actions', async () => {
  const page = await s.agent.get(`/cases/${s.caseId}`);
  for (const a of ['case created', 'upload link.created', 'document uploaded', 'request rejected', 'request accepted']) {
    assert.ok(page.text.includes(a.replace('.', ' ')) || page.text.includes(a), `history shows ${a}`);
  }
});

test('logging out ends the session', async () => {
  await s.agent.post('/logout').type('form').send({ _csrf: s.csrf });
  const res = await s.agent.get('/clients');
  assert.equal(res.status, 302);
});

test('10 failed logins lock that email for 15 minutes', async () => {
  for (let i = 0; i < 10; i++) {
    await request(app).post('/login').type('form').send({ email: 'b@brokers.test', password: 'wrong-wrong-wrong' });
  }
  const res = await request(app).post('/login').type('form').send({ email: 'b@brokers.test', password: 'correct-horse-battery' });
  assert.equal(res.status, 429);
});

test('pages use Referrer-Policy same-origin, so browsers send a real Origin on our own forms', async () => {
  for (const url of ['/login', `/u/${'x'.repeat(43)}`]) {
    const res = await request(app).get(url);
    assert.equal(res.headers['referrer-policy'], 'same-origin', url);
  }
});

test('changing password: checks the current one, then only the new one works', async () => {
  const { agent, csrf } = await login('a@brokers.test');
  const post = (body) => agent.post('/account/password').type('form').send({ _csrf: csrf, ...body });
  assert.equal((await post({ current: 'wrong-current-pw', new_password: 'a-brand-new-passphrase', confirm: 'a-brand-new-passphrase' })).status, 400);
  assert.equal((await post({ current: 'correct-horse-battery', new_password: 'a-brand-new-passphrase', confirm: 'something-else-entirely' })).status, 400);
  assert.equal((await post({ current: 'correct-horse-battery', new_password: 'short', confirm: 'short' })).status, 400);
  const ok = await post({ current: 'correct-horse-battery', new_password: 'a-brand-new-passphrase', confirm: 'a-brand-new-passphrase' });
  assert.equal(ok.status, 200);
  assert.match(ok.text, /Password changed/);
  const old = await request(app).post('/login').type('form').send({ email: 'a@brokers.test', password: 'correct-horse-battery' });
  assert.equal(old.status, 401);
  await login('a@brokers.test', 'a-brand-new-passphrase');
});

test('health check answers without a login', async () => {
  const res = await request(app).get('/healthz');
  assert.equal(res.status, 200);
  assert.equal(res.text, 'ok');
});
