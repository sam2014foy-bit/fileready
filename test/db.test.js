// Database tests. Run with: npm test
// Uses PGlite (real Postgres compiled to WebAssembly, in memory), so no
// database server is needed.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { PGlite } from '@electric-sql/pglite';
import { migrate } from '../db/migrate.js';
import { seed } from '../db/seed.js';

let db;
let demo;
const silent = () => {};

before(async () => {
  db = new PGlite();
  await migrate(db, silent);
  demo = await seed(db);
});

// Run fn as the app role with app.firm_id set, the way the web app will.
async function asFirm(firmId, fn) {
  await db.query('BEGIN');
  try {
    await db.query('SET LOCAL ROLE fileready_app');
    await db.query(`SELECT set_config('app.firm_id', $1, true)`, [firmId ?? '']);
    return await fn();
  } finally {
    await db.query('ROLLBACK');
  }
}

async function rejects(promise, pattern) {
  await assert.rejects(promise, (err) => {
    assert.match(err.message, pattern);
    return true;
  });
}

test('migrations are idempotent', async () => {
  await migrate(db, silent);
  const { rows } = await db.query('SELECT count(*)::int AS n FROM schema_migrations');
  assert.equal(rows[0].n, 3);
});

test('seed copies the 9-item built-in mortgage checklist onto the case', async () => {
  const { rows } = await db.query('SELECT * FROM case_progress WHERE case_id = $1', [demo.case]);
  assert.equal(Number(rows[0].required_total), 7);
  assert.equal(Number(rows[0].required_done), 0);
  assert.equal(rows[0].status, 'open');
});

test('case is marked complete when every required document is accepted or waived, and reopens if one is rejected', async () => {
  await db.query('BEGIN');
  try {
    await db.query(
      `UPDATE document_requests SET status = 'accepted' WHERE case_id = $1 AND required AND label <> 'Savings statements'`,
      [demo.case]
    );
    let c = (await db.query('SELECT status, completed_at FROM cases WHERE id = $1', [demo.case])).rows[0];
    assert.equal(c.status, 'open', 'still one outstanding');

    await db.query(`UPDATE document_requests SET status = 'waived' WHERE case_id = $1 AND label = 'Savings statements'`, [demo.case]);
    c = (await db.query('SELECT status, completed_at FROM cases WHERE id = $1', [demo.case])).rows[0];
    assert.equal(c.status, 'complete');
    assert.ok(c.completed_at);

    await db.query(
      `UPDATE document_requests SET status = 'rejected', rejected_reason = 'Blurry' WHERE case_id = $1 AND label = 'Photo ID'`,
      [demo.case]
    );
    c = (await db.query('SELECT status, completed_at FROM cases WHERE id = $1', [demo.case])).rows[0];
    assert.equal(c.status, 'open');
    assert.equal(c.completed_at, null);
  } finally {
    await db.query('ROLLBACK');
  }
});

test('a rejected document request must have a reason', async () => {
  await rejects(
    db.query(`UPDATE document_requests SET status = 'rejected' WHERE case_id = $1`, [demo.case]),
    /check constraint/
  );
});

test('composite foreign keys stop a case pointing at another firm\'s client', async () => {
  const other = (await db.query(`INSERT INTO firms (name) VALUES ('Other Firm') RETURNING id`)).rows[0].id;
  try {
    await rejects(
      db.query(`INSERT INTO cases (firm_id, client_id, title) VALUES ($1, $2, 'Sneaky')`, [other, demo.client]),
      /foreign key/
    );
  } finally {
    await db.query('DELETE FROM firms WHERE id = $1', [other]);
  }
});

test('audit log cannot be edited or deleted', async () => {
  await rejects(db.query(`UPDATE audit_log SET action = 'x'`), /append-only/);
  await rejects(db.query(`DELETE FROM audit_log`), /append-only/);
});

test('row level security: the app only sees its own firm', async () => {
  const other = (await db.query(`INSERT INTO firms (name) VALUES ('Rival Brokers') RETURNING id`)).rows[0].id;
  await db.query(
    `INSERT INTO clients (firm_id, first_name, last_name, email) VALUES ($1, 'Rival', 'Client', 'rival@example.com')`,
    [other]
  );
  try {
    await asFirm(demo.firm, async () => {
      const clients = (await db.query('SELECT first_name FROM clients ORDER BY first_name')).rows.map((r) => r.first_name);
      assert.deepEqual(clients, ['Niamh', 'Seán']);
      const firms = (await db.query('SELECT name FROM firms')).rows;
      assert.equal(firms.length, 1);
      // Built-in templates are visible to every firm.
      const t = (await db.query('SELECT count(*)::int AS n FROM checklist_template_items')).rows[0].n;
      assert.equal(t, 9);
    });

    await asFirm(other, async () => {
      const n = (await db.query('SELECT count(*)::int AS n FROM cases')).rows[0].n;
      assert.equal(n, 0, 'rival firm sees none of the demo cases');
    });

    await asFirm(null, async () => {
      const n = (await db.query('SELECT count(*)::int AS n FROM clients')).rows[0].n;
      assert.equal(n, 0, 'no firm set = no data');
    });
  } finally {
    await db.query('DELETE FROM firms WHERE id = $1', [other]);
  }
});

test('row level security: the app cannot write into another firm', async () => {
  const other = (await db.query(`INSERT INTO firms (name) VALUES ('Target Firm') RETURNING id`)).rows[0].id;
  try {
    await asFirm(demo.firm, () =>
      rejects(
        db.query(`INSERT INTO clients (firm_id, first_name, last_name, email) VALUES ($1, 'X', 'Y', 'x@example.com')`, [other]),
        /row-level security/
      )
    );
  } finally {
    await db.query('DELETE FROM firms WHERE id = $1', [other]);
  }
});

test('the app can add audit entries but not change them', async () => {
  await asFirm(demo.firm, async () => {
    await db.query(
      `INSERT INTO audit_log (firm_id, actor_type, action, entity_type) VALUES ($1, 'system', 'reminder.sent', 'case')`,
      [demo.firm]
    );
    await rejects(db.query(`DELETE FROM audit_log`), /permission denied|append-only/);
  });
});

test('upload links store only a 64-char token hash', async () => {
  await rejects(
    db.query(
      `INSERT INTO upload_links (firm_id, case_id, token_hash, expires_at) VALUES ($1, $2, 'raw-token', now() + interval '14 days')`,
      [demo.firm, demo.case]
    ),
    /check constraint/
  );
});

test('documents over 25 MB are rejected', async () => {
  const req = (await db.query('SELECT id FROM document_requests WHERE case_id = $1 LIMIT 1', [demo.case])).rows[0].id;
  await rejects(
    db.query(
      `INSERT INTO documents (firm_id, request_id, original_filename, mime_type, size_bytes, sha256, storage_key)
       VALUES ($1, $2, 'big.pdf', 'application/pdf', 30000000, repeat('a', 64), 'k1')`,
      [demo.firm, req]
    ),
    /check constraint/
  );
});
