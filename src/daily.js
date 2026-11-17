// Once-a-day jobs, triggered by the scheduler (POST /internal/daily/run):
//  1. Morning summary email for each person (Mon–Fri), if anything needs them.
//  2. Retention clean-up: closed cases older than the firm's retention period
//     are deleted with their files.
import { audit } from './db.js';
import { dailySummaryEmail } from './emails.js';

function dublinToday(now) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Dublin', year: 'numeric', month: '2-digit', day: '2-digit', weekday: 'short', hour: 'numeric', hourCycle: 'h23',
  }).formatToParts(now).map((p) => [p.type, p.value]));
  return { date: `${parts.year}-${parts.month}-${parts.day}`, weekday: parts.weekday, hour: Number(parts.hour) };
}

export async function sendSummaries({ db, mailer, baseUrl, now = new Date(), force = false }) {
  const today = dublinToday(now);
  if (!force && (['Sat', 'Sun'].includes(today.weekday) || today.hour < 7)) return { sent: 0, skipped: 'not a weekday morning' };
  const due = await db.asApp((q) => q('SELECT * FROM summary_due($1)', [today.date]));
  let sent = 0;
  for (const { firm_id, user_id } of due) {
    const data = await db.asFirm(firm_id, async (q) => {
      const [u] = await q('SELECT full_name, email, role FROM users WHERE id = $1', [user_id]);
      const [f] = await q('SELECT name FROM firms');
      const mine = u.role === 'adviser';
      const cases = await q(
        `SELECT c.id, c.status, c.chasing_stopped, c.due_date, cl.first_name, cl.last_name, p.awaiting_review::int
           FROM cases c JOIN clients cl ON cl.id = c.client_id JOIN case_progress p ON p.case_id = c.id
          WHERE c.status = 'open' AND ($1::uuid IS NULL OR c.adviser_id = $1)`,
        [mine ? user_id : null]
      );
      const [{ n }] = await q(
        `SELECT count(*)::int AS n FROM documents d JOIN document_requests r ON r.id = d.request_id JOIN cases c ON c.id = r.case_id
          WHERE d.uploaded_at > now() - interval '24 hours' AND d.deleted_at IS NULL AND ($1::uuid IS NULL OR c.adviser_id = $1)`,
        [mine ? user_id : null]
      );
      await q('UPDATE users SET last_summary_on = $2 WHERE id = $1', [user_id, today.date]);
      const name = (c) => `${c.first_name} ${c.last_name}`;
      return {
        user: u, firmName: f.name, received: n,
        toReview: cases.filter((c) => c.awaiting_review > 0).map((c) => `${name(c)}: ${c.awaiting_review} document${c.awaiting_review === 1 ? '' : 's'}`),
        notResponding: cases.filter((c) => c.chasing_stopped === 'limit_reached').map(name),
        overdue: cases.filter((c) => c.due_date && String(c.due_date instanceof Date ? c.due_date.toISOString() : c.due_date).slice(0, 10) < today.date).map(name),
      };
    });
    if (!data.received && !data.toReview.length && !data.notResponding.length && !data.overdue.length) continue;
    const msg = dailySummaryEmail({
      name: data.user.full_name.split(' ')[0], firmName: data.firmName, toReview: data.toReview,
      notResponding: data.notResponding, overdue: data.overdue, received: data.received, link: `${baseUrl}/`,
    });
    try {
      await mailer.send({ to: data.user.email, toName: data.user.full_name, fromName: 'Fileready', ...msg });
      sent += 1;
    } catch (err) {
      console.error('Summary email failed:', err.message);
    }
  }
  return { sent };
}

export async function runRetention({ db, storage }) {
  const due = await db.asApp((q) => q('SELECT * FROM retention_due($1)', [200]));
  let deleted = 0;
  for (const { firm_id, case_id } of due) {
    const keys = await db.asFirm(firm_id, async (q) => {
      const docs = await q(
        `SELECT d.storage_key FROM documents d JOIN document_requests r ON r.id = d.request_id WHERE r.case_id = $1`, [case_id]
      );
      const gone = await q('DELETE FROM cases WHERE id = $1 RETURNING id', [case_id]);
      if (!gone.length) return [];
      await audit(q, { firmId: firm_id, actorType: 'system', action: 'case.retention_deleted', entityType: 'case', entityId: case_id, details: { files: docs.length } });
      return docs.map((d) => d.storage_key);
    });
    for (const key of keys) {
      try { await storage.remove(key); } catch (err) { console.error('Retention file purge failed', key, err.message); }
    }
    deleted += 1;
  }
  return { deleted };
}

export async function runDaily(ctx) {
  const summaries = await sendSummaries(ctx);
  const retention = await runRetention(ctx);
  return { summaries, retention };
}
