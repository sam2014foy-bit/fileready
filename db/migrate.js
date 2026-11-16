// Applies every db/migrations/*.sql file that has not been applied yet,
// in filename order, each in its own transaction.
// Usage: DATABASE_URL=postgres://... npm run db:migrate
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const MIGRATIONS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'migrations');

export async function listMigrations() {
  const files = (await readdir(MIGRATIONS_DIR)).filter((f) => f.endsWith('.sql')).sort();
  return Promise.all(
    files.map(async (name) => ({ name, sql: await readFile(path.join(MIGRATIONS_DIR, name), 'utf8') }))
  );
}

// `db` needs one method: query(sql, params?) returning { rows }.
// Works with both node-postgres clients and PGlite.
export async function migrate(db, log = console.log) {
  await db.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
    name text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
  )`);
  const { rows } = await db.query('SELECT name FROM schema_migrations');
  const done = new Set(rows.map((r) => r.name));

  for (const { name, sql } of await listMigrations()) {
    if (done.has(name)) continue;
    log(`Applying ${name}`);
    await db.query('BEGIN');
    try {
      await (db.exec ? db.exec(sql) : db.query(sql));
      await db.query('INSERT INTO schema_migrations (name) VALUES ($1)', [name]);
      await db.query('COMMIT');
    } catch (err) {
      await db.query('ROLLBACK');
      throw new Error(`Migration ${name} failed: ${err.message}`);
    }
  }
  log('Database is up to date.');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error('Set DATABASE_URL first, e.g. postgres://user:pass@host:5432/fileready');
    process.exit(1);
  }
  const { default: pg } = await import('pg');
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    await migrate(client);
  } finally {
    await client.end();
  }
}
