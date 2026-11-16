// Onboard a new firm and its owner login. Run by you (the admin), not the app.
//   ADMIN_DATABASE_URL=postgres://postgres:...@... \
//   node scripts/create-firm.js "Firm name" owner@firm.ie "Owner Name"
// Prints a temporary password to give the owner securely (e.g. by phone).
import pg from 'pg';
import { hashPassword, randomToken } from '../src/security.js';

const [name, email, fullName] = process.argv.slice(2);
const url = process.env.ADMIN_DATABASE_URL;
if (!url || !name || !email || !fullName) {
  console.error('Usage: ADMIN_DATABASE_URL=... node scripts/create-firm.js "Firm name" owner@email "Full name"');
  process.exit(1);
}

const password = randomToken().slice(0, 20);
const client = new pg.Client({ connectionString: url, ssl: { rejectUnauthorized: false } });
await client.connect();
try {
  await client.query('BEGIN');
  const firm = (await client.query('INSERT INTO firms (name) VALUES ($1) RETURNING id', [name])).rows[0].id;
  const user = (await client.query(
    `INSERT INTO users (firm_id, email, full_name, role, password_hash) VALUES ($1, lower($2), $3, 'owner', $4) RETURNING id`,
    [firm, email.trim(), fullName, await hashPassword(password)]
  )).rows[0].id;
  await client.query(
    `INSERT INTO audit_log (firm_id, actor_type, action, entity_type, entity_id) VALUES ($1, 'system', 'firm.created', 'firm', $1)`,
    [firm]
  );
  await client.query('COMMIT');
  console.log(`Created firm ${name} (${firm}) with owner ${email} (${user}).`);
  console.log(`Temporary password: ${password}`);
} catch (err) {
  await client.query('ROLLBACK');
  console.error(err.message);
  process.exitCode = 1;
} finally {
  await client.end();
}
