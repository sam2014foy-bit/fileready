# Fileready

Chases mortgage-broker clients for documents: a checklist per case, a secure
upload link, automatic reminders, and a "file complete" status when everything
required is in. Built for small Irish brokerages.

## Status

Step 1 of the build: the database. No web app yet.

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
npm test                                   # runs the database tests in memory, no server needed
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
