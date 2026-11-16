// Loads made-up demo data (one firm, two staff, two clients, one case).
// NEVER run against a database holding real client data.
// Usage: DATABASE_URL=postgres://... npm run db:seed
import { fileURLToPath } from 'node:url';

export async function seed(db) {
  const firm = (await db.query(
    `INSERT INTO firms (name, cbi_reference) VALUES ('Demo Mortgages Cork', 'C00000') RETURNING id`
  )).rows[0].id;

  const owner = (await db.query(
    `INSERT INTO users (firm_id, email, full_name, role)
     VALUES ($1, 'owner@demo-mortgages.example', 'Aoife Murphy', 'owner') RETURNING id`, [firm]
  )).rows[0].id;
  await db.query(
    `INSERT INTO users (firm_id, email, full_name, role)
     VALUES ($1, 'staff@demo-mortgages.example', 'Ciarán Walsh', 'admin_staff')`, [firm]
  );

  const client = (await db.query(
    `INSERT INTO clients (firm_id, first_name, last_name, email)
     VALUES ($1, 'Seán', 'O''Brien', 'sean@example.com') RETURNING id`, [firm]
  )).rows[0].id;
  await db.query(
    `INSERT INTO clients (firm_id, first_name, last_name, phone)
     VALUES ($1, 'Niamh', 'Kelly', '+353870000000')`, [firm]
  );

  const kase = (await db.query(
    `INSERT INTO cases (firm_id, client_id, adviser_id, title, lender)
     VALUES ($1, $2, $3, 'First-time buyer mortgage', 'Demo Bank') RETURNING id`, [firm, client, owner]
  )).rows[0].id;

  // Copy the built-in checklist onto the case.
  await db.query(
    `INSERT INTO document_requests (firm_id, case_id, label, help_text, required, sort_order)
     SELECT $1, $2, i.label, i.help_text, i.required, i.sort_order
       FROM checklist_template_items i
       JOIN checklist_templates t ON t.id = i.template_id
      WHERE t.firm_id IS NULL AND t.name = 'Mortgage application (standard)'`, [firm, kase]
  );

  await db.query(
    `INSERT INTO audit_log (firm_id, actor_type, actor_user_id, action, entity_type, entity_id)
     VALUES ($1, 'user', $2, 'case.created', 'case', $3)`, [firm, owner, kase]
  );

  return { firm, owner, client, case: kase };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error('Set DATABASE_URL first.');
    process.exit(1);
  }
  const { default: pg } = await import('pg');
  const db = new pg.Client({ connectionString: url });
  await db.connect();
  try {
    console.log('Seeded demo data:', await seed(db));
  } finally {
    await db.end();
  }
}
