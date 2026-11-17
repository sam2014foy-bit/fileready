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
  Scheduled by Supabase pg_cron calling `POST /internal/reminders/run` (setup in `db/supabase-scheduler.sql`). Live app: https://fileready-kgk1.onrender.com
- Accounts: forgot-password email reset (1-hour link), staff invites from the
  Team page (7-day link), firm Settings (name, reminder gap, reminder limit).
  Changing or resetting a password signs out other sessions; removing a
  person's access signs them out at once.
- Records: client page (edit, archive, delete with all files), case close /
  hold / reopen / delete, remove a wrong upload, remove a checklist item.
  Permanent deletes are owner-only and need a confirm tick.
- Adviser gets an email when a client uploads (at most every 30 minutes per case).
- Feature pack (migration 0008):
  - Today panel on Cases: documents to review, clients not responding, due dates.
  - Case due dates (shown in reminder emails, overdue flags), team-only case notes, zip download of a case.
  - Search (clients and cases), firm's own checklists (one item per line, `(optional)` prefix, `label | hint`).
  - Two-step login with an authenticator app (keys encrypted with `APP_SECRET`, 8 one-time recovery codes);
    owners can reset a colleague's.
  - Roles: owners change anyone's role but their own; optional "advisers see only their own cases",
    enforced by restrictive database policies.
  - Morning summary email (weekdays, can be turned off on Account) and automatic deletion of closed
    cases after the firm's retention period: `POST /internal/daily/run`, scheduled 07:30 and 08:30 UTC.
  - Text reminders through Brevo SMS (off until the owner turns them on in Settings; clients can be excluded).
  - Public `/security` page, Stripe billing (`/billing`), self sign-up with a free trial (`ALLOW_SIGNUP=true`).

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
npm test                                   # 76 tests, in memory, no server needed
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
Postgres 17. Migrations 0001–0007 applied 16 Nov 2026. Currently on the free plan: upgrade to Pro (backups) before any real client data. Supabase's `anon` and
`authenticated` API roles have no access to Fileready tables (migration 0002);
the app must connect server-side as a role granted `fileready_app`.

## Deploying (Render)

1. Supabase SQL editor, once: `ALTER ROLE fileready_web WITH LOGIN PASSWORD '<long random password>';`
2. Supabase > Storage > S3: create an access key pair (storage only).
3. Supabase > Connect > Session pooler: copy the host (`aws-…-eu-west-1.pooler.supabase.com`).
4. Render > New > Blueprint > this repo. Fill in `DATABASE_HOST`, `DATABASE_PASSWORD`,
   `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`.
5. Optional settings in Render > Environment:
   - `APP_SECRET`: 32+ random characters, needed for two-step login. Never change it once people use it.
   - `BREVO_SMS_SENDER`: up to 11 letters (e.g. `Fileready`), after registering the sender ID and buying SMS credit in Brevo.
   - `STRIPE_SECRET_KEY`, `STRIPE_PRICE_ID`, `STRIPE_WEBHOOK_SECRET`: webhook endpoint `<app>/stripe/webhook`
     with events `checkout.session.completed` and `customer.subscription.*`.
   - `ALLOW_SIGNUP=true` to open self sign-up.
6. Before real client data: Supabase Pro, Render paid plan, set `DATABASE_CA`, security review.
