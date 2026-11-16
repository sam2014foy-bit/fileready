// Run Fileready on your own computer with no database server:
//   npm run dev   then open http://localhost:3000
// Data is kept in ./.dev-db and uploaded files in ./.dev-storage (both git-ignored).
// Demo data only — never put real client documents in here.
import { PGlite } from '@electric-sql/pglite';
import { createApp } from './app.js';
import { createDb, pgliteDriver } from './db.js';
import { localDiskStorage } from './storage.js';
import { migrate } from '../db/migrate.js';
import { hashPassword } from './security.js';

const PORT = Number(process.env.PORT || 3000);
const DEMO_EMAIL = 'demo@fileready.test';
const DEMO_PASSWORD = 'demo-password-123';

const pglite = new PGlite('./.dev-db');
await migrate(pglite, () => {});

const { rows } = await pglite.query('SELECT count(*)::int AS n FROM firms');
if (rows[0].n === 0) {
  const firm = (await pglite.query(`INSERT INTO firms (name) VALUES ('Demo Mortgages Cork') RETURNING id`)).rows[0].id;
  await pglite.query(
    `INSERT INTO users (firm_id, email, full_name, role, password_hash) VALUES ($1, $2, 'Demo Owner', 'owner', $3)`,
    [firm, DEMO_EMAIL, await hashPassword(DEMO_PASSWORD)]
  );
}

const app = createApp({
  db: createDb(pgliteDriver(pglite)),
  storage: localDiskStorage('./.dev-storage'),
  config: { baseUrl: `http://localhost:${PORT}` },
});
app.listen(PORT, () => {
  console.log(`\nFileready running at http://localhost:${PORT}`);
  console.log(`Log in with ${DEMO_EMAIL} / ${DEMO_PASSWORD}\n`);
});
