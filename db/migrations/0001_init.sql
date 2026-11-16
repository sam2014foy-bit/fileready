-- Fileready: initial schema
-- Product: chase mortgage-broker clients for documents (checklist per case,
-- client upload link, automatic reminders, "file complete" status).
--
-- Design rules
--  * Every row belongs to one firm (tenant). Child tables carry firm_id and
--    use composite foreign keys (firm_id, id) so a row can never point at
--    another firm's data, even if application code has a bug.
--  * Row Level Security restricts the app role to the firm set in
--    the session setting app.firm_id (defence in depth).
--  * Document files live in object storage (EU region). The database only
--    holds metadata: name, size, type, checksum, storage key.
--  * audit_log is append-only: updates and deletes are blocked.
--  * Hold as little personal data as possible (see the Master Plan's
--    legal checklist).

-- Requires PostgreSQL 15+ (gen_random_uuid is built in).

-- ---------------------------------------------------------------------------
-- Enums
-- ---------------------------------------------------------------------------
CREATE TYPE user_role       AS ENUM ('owner', 'adviser', 'admin_staff');
CREATE TYPE case_status     AS ENUM ('open', 'complete', 'on_hold', 'closed');
CREATE TYPE request_status  AS ENUM ('requested', 'received', 'accepted', 'rejected', 'waived');
CREATE TYPE reminder_channel AS ENUM ('email', 'sms');
CREATE TYPE reminder_status AS ENUM ('scheduled', 'sent', 'failed', 'cancelled');
CREATE TYPE actor_type      AS ENUM ('user', 'client', 'system');

-- Keep updated_at current on any table that has one.
CREATE FUNCTION set_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END $$;

-- ---------------------------------------------------------------------------
-- Firms (tenants) and staff
-- ---------------------------------------------------------------------------
CREATE TABLE firms (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name               text NOT NULL CHECK (length(trim(name)) > 0),
  cbi_reference      text,            -- Central Bank of Ireland register number
  reminder_every_days integer NOT NULL DEFAULT 3 CHECK (reminder_every_days BETWEEN 1 AND 30),
  data_retention_days integer NOT NULL DEFAULT 2190 CHECK (data_retention_days > 0), -- ~6 years
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  firm_id       uuid NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
  email         text NOT NULL CHECK (email = lower(email) AND email LIKE '%_@_%'),
  full_name     text NOT NULL,
  role          user_role NOT NULL DEFAULT 'adviser',
  password_hash text,                 -- null if login is handled by an auth provider
  last_login_at timestamptz,
  disabled_at   timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (firm_id, id)
);
-- One login per email across the whole service.
CREATE UNIQUE INDEX users_email_key ON users (email);

-- ---------------------------------------------------------------------------
-- Clients and cases
-- ---------------------------------------------------------------------------
CREATE TABLE clients (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  firm_id     uuid NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
  first_name  text NOT NULL,
  last_name   text NOT NULL,
  email       text CHECK (email IS NULL OR email = lower(email)),
  phone       text,
  archived_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (firm_id, id),
  CHECK (email IS NOT NULL OR phone IS NOT NULL)  -- must be reachable for reminders
);
CREATE INDEX clients_firm_name_idx ON clients (firm_id, last_name, first_name);

CREATE TABLE cases (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  firm_id          uuid NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
  client_id        uuid NOT NULL,
  adviser_id       uuid,
  title            text NOT NULL,     -- e.g. "First-time buyer mortgage"
  lender           text,
  status           case_status NOT NULL DEFAULT 'open',
  reminders_paused boolean NOT NULL DEFAULT false,
  completed_at     timestamptz,       -- set when every required document is accepted/waived
  closed_at        timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (firm_id, id),
  FOREIGN KEY (firm_id, client_id)  REFERENCES clients (firm_id, id) ON DELETE CASCADE,
  FOREIGN KEY (firm_id, adviser_id) REFERENCES users   (firm_id, id) ON DELETE SET NULL (adviser_id)
);
CREATE INDEX cases_firm_status_idx ON cases (firm_id, status);
CREATE INDEX cases_client_idx      ON cases (firm_id, client_id);

-- ---------------------------------------------------------------------------
-- Checklist templates (firm_id NULL = built-in template available to all)
-- ---------------------------------------------------------------------------
CREATE TABLE checklist_templates (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  firm_id    uuid REFERENCES firms(id) ON DELETE CASCADE,
  name       text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE checklist_template_items (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  template_id uuid NOT NULL REFERENCES checklist_templates(id) ON DELETE CASCADE,
  label       text NOT NULL,
  help_text   text,
  required    boolean NOT NULL DEFAULT true,
  sort_order  integer NOT NULL DEFAULT 0
);
CREATE INDEX checklist_template_items_template_idx ON checklist_template_items (template_id, sort_order);

-- ---------------------------------------------------------------------------
-- Document requests (the checklist on a case) and uploaded documents
-- ---------------------------------------------------------------------------
CREATE TABLE document_requests (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  firm_id         uuid NOT NULL,
  case_id         uuid NOT NULL,
  label           text NOT NULL,      -- e.g. "Last 3 payslips"
  help_text       text,
  required        boolean NOT NULL DEFAULT true,
  status          request_status NOT NULL DEFAULT 'requested',
  rejected_reason text,
  due_date        date,
  sort_order      integer NOT NULL DEFAULT 0,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (firm_id, id),
  FOREIGN KEY (firm_id, case_id) REFERENCES cases (firm_id, id) ON DELETE CASCADE,
  CHECK (status <> 'rejected' OR rejected_reason IS NOT NULL)
);
CREATE INDEX document_requests_case_idx ON document_requests (firm_id, case_id, sort_order);

CREATE TABLE documents (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  firm_id            uuid NOT NULL,
  request_id         uuid NOT NULL,
  original_filename  text NOT NULL,
  mime_type          text NOT NULL,
  size_bytes         bigint NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 26214400), -- 25 MB
  sha256             text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  storage_key        text NOT NULL UNIQUE,  -- path in object storage, never a public URL
  uploaded_by_user_id uuid,                 -- null = uploaded by the client via link
  uploaded_at        timestamptz NOT NULL DEFAULT now(),
  deleted_at         timestamptz,           -- soft delete; file purge is a separate job
  UNIQUE (firm_id, id),
  FOREIGN KEY (firm_id, request_id)          REFERENCES document_requests (firm_id, id) ON DELETE CASCADE,
  FOREIGN KEY (firm_id, uploaded_by_user_id) REFERENCES users (firm_id, id) ON DELETE SET NULL (uploaded_by_user_id)
);
CREATE INDEX documents_request_idx ON documents (firm_id, request_id) WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- Client upload links. Only a hash of the token is stored; the raw token
-- goes in the emailed link and is never saved.
-- ---------------------------------------------------------------------------
CREATE TABLE upload_links (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  firm_id      uuid NOT NULL,
  case_id      uuid NOT NULL,
  token_hash   text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  expires_at   timestamptz NOT NULL,
  revoked_at   timestamptz,
  last_used_at timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (firm_id, case_id) REFERENCES cases (firm_id, id) ON DELETE CASCADE,
  CHECK (expires_at > created_at)
);

-- ---------------------------------------------------------------------------
-- Reminders sent to clients
-- ---------------------------------------------------------------------------
CREATE TABLE reminders (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  firm_id       uuid NOT NULL,
  case_id       uuid NOT NULL,
  channel       reminder_channel NOT NULL DEFAULT 'email',
  scheduled_for timestamptz NOT NULL,
  status        reminder_status NOT NULL DEFAULT 'scheduled',
  sent_at       timestamptz,
  error         text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (firm_id, case_id) REFERENCES cases (firm_id, id) ON DELETE CASCADE,
  CHECK (status <> 'sent' OR sent_at IS NOT NULL)
);
-- The reminder worker scans this.
CREATE INDEX reminders_due_idx ON reminders (scheduled_for) WHERE status = 'scheduled';

-- ---------------------------------------------------------------------------
-- Audit trail (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
  id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  firm_id       uuid NOT NULL REFERENCES firms(id) ON DELETE RESTRICT,
  actor_type    actor_type NOT NULL,
  actor_user_id uuid,
  action        text NOT NULL,        -- e.g. 'document.uploaded', 'request.accepted'
  entity_type   text NOT NULL,
  entity_id     uuid,
  details       jsonb NOT NULL DEFAULT '{}'::jsonb,
  ip_address    inet,
  created_at    timestamptz NOT NULL DEFAULT now(),
  CHECK (actor_type <> 'user' OR actor_user_id IS NOT NULL)
);
CREATE INDEX audit_log_firm_time_idx   ON audit_log (firm_id, created_at DESC);
CREATE INDEX audit_log_entity_idx      ON audit_log (firm_id, entity_type, entity_id);

CREATE FUNCTION audit_log_block_changes() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END $$;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_block_changes();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION audit_log_block_changes();

-- ---------------------------------------------------------------------------
-- updated_at triggers
-- ---------------------------------------------------------------------------
CREATE TRIGGER firms_updated_at   BEFORE UPDATE ON firms   FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER users_updated_at   BEFORE UPDATE ON users   FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER clients_updated_at BEFORE UPDATE ON clients FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER cases_updated_at   BEFORE UPDATE ON cases   FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER document_requests_updated_at BEFORE UPDATE ON document_requests FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- "File complete": when every required request on an open case is accepted
-- or waived, mark the case complete. If a request is reopened, reopen it.
-- ---------------------------------------------------------------------------
CREATE FUNCTION refresh_case_completion() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  v_case uuid := COALESCE(NEW.case_id, OLD.case_id);
  v_firm uuid := COALESCE(NEW.firm_id, OLD.firm_id);
  v_outstanding integer;
  v_total integer;
BEGIN
  SELECT count(*) FILTER (WHERE required AND status NOT IN ('accepted', 'waived')),
         count(*) FILTER (WHERE required)
    INTO v_outstanding, v_total
    FROM document_requests
   WHERE firm_id = v_firm AND case_id = v_case;

  IF v_total > 0 AND v_outstanding = 0 THEN
    UPDATE cases SET status = 'complete', completed_at = now()
     WHERE firm_id = v_firm AND id = v_case AND status = 'open';
  ELSE
    UPDATE cases SET status = 'open', completed_at = NULL
     WHERE firm_id = v_firm AND id = v_case AND status = 'complete';
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER document_requests_completion
  AFTER INSERT OR UPDATE OF status, required OR DELETE ON document_requests
  FOR EACH ROW EXECUTE FUNCTION refresh_case_completion();

-- Progress per case, for the dashboard.
CREATE VIEW case_progress WITH (security_invoker = true) AS
SELECT c.firm_id,
       c.id AS case_id,
       c.status,
       count(r.id) FILTER (WHERE r.required)                                       AS required_total,
       count(r.id) FILTER (WHERE r.required AND r.status IN ('accepted','waived'))  AS required_done,
       count(r.id) FILTER (WHERE r.status = 'received')                            AS awaiting_review,
       count(r.id) FILTER (WHERE r.status = 'rejected')                            AS rejected
  FROM cases c
  LEFT JOIN document_requests r ON r.firm_id = c.firm_id AND r.case_id = c.id
 GROUP BY c.firm_id, c.id, c.status;

-- ---------------------------------------------------------------------------
-- Row Level Security. The web app connects as role fileready_app and runs
--   SET LOCAL app.firm_id = '<firm uuid>'
-- at the start of each request's transaction. Migrations run as the owner.
-- ---------------------------------------------------------------------------
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fileready_app') THEN
    CREATE ROLE fileready_app NOLOGIN;
  END IF;
END $$;

CREATE FUNCTION current_firm_id() RETURNS uuid LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.firm_id', true), '')::uuid
$$;

ALTER TABLE firms             ENABLE ROW LEVEL SECURITY;
ALTER TABLE users             ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients           ENABLE ROW LEVEL SECURITY;
ALTER TABLE cases             ENABLE ROW LEVEL SECURITY;
ALTER TABLE checklist_templates      ENABLE ROW LEVEL SECURITY;
ALTER TABLE checklist_template_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents         ENABLE ROW LEVEL SECURITY;
ALTER TABLE upload_links      ENABLE ROW LEVEL SECURITY;
ALTER TABLE reminders         ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log         ENABLE ROW LEVEL SECURITY;

CREATE POLICY firm_isolation ON firms             TO fileready_app USING (id = current_firm_id()) WITH CHECK (id = current_firm_id());
CREATE POLICY firm_isolation ON users             TO fileready_app USING (firm_id = current_firm_id()) WITH CHECK (firm_id = current_firm_id());
CREATE POLICY firm_isolation ON clients           TO fileready_app USING (firm_id = current_firm_id()) WITH CHECK (firm_id = current_firm_id());
CREATE POLICY firm_isolation ON cases             TO fileready_app USING (firm_id = current_firm_id()) WITH CHECK (firm_id = current_firm_id());
CREATE POLICY firm_isolation ON document_requests TO fileready_app USING (firm_id = current_firm_id()) WITH CHECK (firm_id = current_firm_id());
CREATE POLICY firm_isolation ON documents         TO fileready_app USING (firm_id = current_firm_id()) WITH CHECK (firm_id = current_firm_id());
CREATE POLICY firm_isolation ON upload_links      TO fileready_app USING (firm_id = current_firm_id()) WITH CHECK (firm_id = current_firm_id());
CREATE POLICY firm_isolation ON reminders         TO fileready_app USING (firm_id = current_firm_id()) WITH CHECK (firm_id = current_firm_id());
-- Audit log: the app may read and add its own firm's entries (updates/deletes are blocked by trigger).
CREATE POLICY firm_read   ON audit_log FOR SELECT TO fileready_app USING (firm_id = current_firm_id());
CREATE POLICY firm_insert ON audit_log FOR INSERT TO fileready_app WITH CHECK (firm_id = current_firm_id());
-- Templates: built-in ones (firm_id NULL) are readable by all; firms manage their own.
CREATE POLICY read_templates  ON checklist_templates FOR SELECT TO fileready_app USING (firm_id IS NULL OR firm_id = current_firm_id());
CREATE POLICY write_templates ON checklist_templates FOR ALL TO fileready_app USING (firm_id = current_firm_id()) WITH CHECK (firm_id = current_firm_id());
CREATE POLICY read_template_items ON checklist_template_items FOR SELECT TO fileready_app
  USING (EXISTS (SELECT 1 FROM checklist_templates t WHERE t.id = template_id AND (t.firm_id IS NULL OR t.firm_id = current_firm_id())));
CREATE POLICY write_template_items ON checklist_template_items FOR ALL TO fileready_app
  USING      (EXISTS (SELECT 1 FROM checklist_templates t WHERE t.id = template_id AND t.firm_id = current_firm_id()))
  WITH CHECK (EXISTS (SELECT 1 FROM checklist_templates t WHERE t.id = template_id AND t.firm_id = current_firm_id()));

GRANT USAGE ON SCHEMA public TO fileready_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  firms, users, clients, cases, checklist_templates, checklist_template_items,
  document_requests, documents, upload_links, reminders
  TO fileready_app;
GRANT SELECT, INSERT ON audit_log TO fileready_app;
GRANT SELECT ON case_progress TO fileready_app;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO fileready_app;

-- ---------------------------------------------------------------------------
-- Built-in checklist: standard Irish mortgage application documents
-- ---------------------------------------------------------------------------
WITH t AS (
  INSERT INTO checklist_templates (firm_id, name)
  VALUES (NULL, 'Mortgage application (standard)')
  RETURNING id
)
INSERT INTO checklist_template_items (template_id, label, help_text, required, sort_order)
SELECT t.id, v.label, v.help_text, v.required, v.sort_order
  FROM t, (VALUES
    ('Photo ID',                         'Passport or driving licence, in date',                 true,  1),
    ('Proof of address',                 'Utility bill or bank statement from the last 3 months', true,  2),
    ('Last 3 payslips',                  NULL,                                                    true,  3),
    ('Employment Detail Summary',        'From Revenue myAccount, for the last 2 years',          true,  4),
    ('Salary certificate',               'Completed and stamped by your employer',                true,  5),
    ('Current account statements',       'Last 6 months, all accounts',                           true,  6),
    ('Savings statements',               'Last 6 months',                                         true,  7),
    ('Loan and credit card statements',  'Last 6 months, if you have any',                        false, 8),
    ('Gift letter',                      'If family are helping with the deposit',                false, 9)
  ) AS v(label, help_text, required, sort_order);
