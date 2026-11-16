# Fileready

Chases mortgage-broker clients for documents: a checklist per case, a secure
upload link, automatic reminders, and a "file complete" status when everything
required is in. Built for small Irish brokerages.

## Status

- Done: database (live on Supabase), web app first slice: broker login,
  clients, cases with checklist, accept / reject / not needed, client upload
  page, file download, audit history.
- Hosting: Render (Frankfurt) via `render.yaml`; files in a private Supabase
  Storage bucket in Ireland; app connects as `fileready_web` through the
  Supabase session pooler.
- Chasing (`src/reminders.js`): broker clicks "Email client & start chasing";
  reminders every N days (firm setting, default 3), Mon–Sat 9am–7pm Irish time,
  only for items still missing; rejection triggers a reminder within 10 minutes;
  stops when complete, paused, or after the firm's limit (default 6). Each email
  carries a fresh upload link and turns off older ones. Email via Brevo (EU).
  Scheduled by Supabase pg_cron calling `POST /internal/reminders/run`.
- Next: password reset by email, staff management, firm settings page.

## Try it on your computer

Needs Node.js 20 or newer. No database server needed.

```bash
npm install
npm run dev
```

Open http://localhost:3000 and log in with `demo@fileready.test` /
`demo-password-123`. Data is stored in `.dev-db/` and files in `.dev-storage/`. Emails aren't sent locally: read them at http://localhost:3000/dev/outbox.
Demo data only.

## Web app (`src/`, `views/`)

- `src/app.js` routes and pages; `src/db.js` firm-scoped database access
  (every query runs as `fileready_app` with `app.firm_id` set);
  `src/security.js` passwords (scrypt), tokens, file-type checks;
  `src/storage.js` file storage.
- Security: httpOnly SameSite=Strict session cookie, CSRF tokens on every form,
  cross-site posts refused, login lockout after 10 failures, uploads checked by
  content (PDF, JPG, PNG, HEIC only, 25 MB max), upload links stored only as
  hashes and shown once, strict security headers.
- Onboard a firm: `ADMIN_DATABASE_URL=... npm run create-firm -- "Firm" owner@firm.ie "Owner Name"`.

## Database (`db/`)

PostgreSQL 15+. Host it in an EU region.

| Table | Holds |
|---|---|
| `firms` | Each brokerage (tenant), with reminder and retention settings |
| `users` | Broker staff logins (owner, adviser, admin staff) |
| `clients` | The broker's clients |
| `cases` | One application per client, e.g. a mortgage |
| `checklist_templates`, `checklist_template_items` | Reusable document lists. A standard Irish mortgage list is built in |
| `document_requests` | The checklist on a case: requested → received → accepted / rejected / waived |
| `documents` | Metadata for uploaded files. Files themselves go in object storage |
| `upload_links` | Client upload links. Only a hash of the token is stored |
| `reminders` | Scheduled and sent reminders |
| `audit_log` | Append-only record of who did what |

Safety built into the database:

- **Firm separation, twice.** Composite foreign keys stop any row pointing at
  another firm's data. Row Level Security limits the app role
  (`fileready_app`) to the firm in `app.firm_id`.
- **Audit log can't be edited or deleted.**
- **Case completes automatically** when every required document is accepted or
  waived, and reopens if one is later rejected.
- Rejections need a reason, files are capped at 25 MB, raw upload tokens are
  never stored.

## Commands

```bash
npm install
npm test                                   # 53 tests, in memory, no server needed
DATABASE_URL=postgres://... npm run db:migrate
DATABASE_URL=postgres://... npm run db:seed   # demo data only, never on a real database
```

The web app should connect as a login role granted `fileready_app`, and at the
start of each request run, inside a transaction:

```sql
SELECT set_config('app.firm_id', '<firm uuid>', true);
```

## Before any real client data

Follow the legal checklist in the SaaS Master Plan: data processing agreement,
privacy notice, insurance, EU hosting with backups, and an independent
security review.

## Live database

Hosted on Supabase, project `xrhzdbvtxrjjupdsgmxl`, region West EU (Ireland),
Postgres 17. Migrations 0001–0006 applied 16 Nov 2026. Currently on the free plan: upgrade to Pro (backups) before any real client data. Supabase's `anon` and
`authenticated` API roles have no access to Fileready tables (migration 0002);
the app must connect server-side as a role granted `fileready_app`.

## Deploying (Render)

1. Supabase SQL editor, once: `ALTER ROLE fileready_web WITH LOGIN PASSWORD '<long random password>';`
2. Supabase > Storage > S3: create an access key pair (storage only).
3. Supabase > Connect > Session pooler: copy the host (`aws-…-eu-west-1.pooler.supabase.com`).
4. Render > New > Blueprint > this repo. Fill in `DATABASE_HOST`, `DATABASE_PASSWORD`,
   `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`.
5. Before real client data: Supabase Pro, Render paid plan, set `DATABASE_CA`, security review.
