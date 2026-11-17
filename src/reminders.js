// The chasing engine.
//
// sendCaseReminder() sends one email for one case in three steps:
//   1. In a transaction: lock the case, decide whether to send, create a fresh
//      upload link (turning off older ones), record the reminder as scheduled
//      and move next_reminder_at forward. This "claims" the send so two
//      workers can't email the same client twice.
//   2. Send the email (outside the transaction, so a slow email service never
//      holds a database lock).
//   3. Record the result. On failure, retry in 2 hours.
//
// runReminders() is called on a schedule and sends whatever is due, within
// sending hours (Mon–Sat, 09:00–19:00 Irish time).
import { audit } from './db.js';
import { randomToken, sha256, normalisePhone } from './security.js';
import { reminderEmail, reminderSms } from './emails.js';

export const SEND_DAYS = [1, 2, 3, 4, 5, 6]; // Mon–Sat
export const SEND_FROM_HOUR = 9;
export const SEND_UNTIL_HOUR = 19;

export function withinSendingHours(date = new Date()) {
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat('en-IE', { timeZone: 'Europe/Dublin', weekday: 'short', hour: 'numeric', hourCycle: 'h23' })
      .formatToParts(date).map((p) => [p.type, p.value])
  );
  const day = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(parts.weekday);
  const hour = Number(parts.hour);
  return SEND_DAYS.includes(day) && hour >= SEND_FROM_HOUR && hour < SEND_UNTIL_HOUR;
}

/**
 * Sends one reminder for one case, by email and (when the firm has text
 * reminders on and the client has a mobile number) by text.
 * @returns {Promise<{status: 'sent'|'failed'|'skipped', reason?: string}>}
 */
export async function sendCaseReminder({ db, mailer, sms = null, baseUrl, firmId, caseId, kind = 'reminder', force = false, userId = null, linkDays = 14 }) {
  const actorType = userId ? 'user' : 'system';
  const token = randomToken();

  // ---- 1. claim
  const claim = await db.asFirm(firmId, async (q) => {
    const [c] = await q(
      `SELECT c.id, c.title, c.status, c.reminders_paused, c.next_reminder_at, c.reminders_sent, c.chasing_started_at, c.due_date,
              cl.first_name, cl.last_name, cl.email AS client_email, cl.phone AS client_phone, cl.sms_opt_out,
              f.name AS firm_name, f.reminder_every_days, f.max_reminders, f.sms_enabled,
              u.full_name AS adviser_name, u.email AS adviser_email
         FROM cases c
         JOIN clients cl ON cl.firm_id = c.firm_id AND cl.id = c.client_id
         JOIN firms f ON f.id = c.firm_id
         LEFT JOIN users u ON u.firm_id = c.firm_id AND u.id = c.adviser_id
        WHERE c.id = $1
        FOR UPDATE OF c SKIP LOCKED`,
      [caseId]
    );
    if (!c) return { skip: 'busy or not found' };
    if (c.status !== 'open') {
      await q('UPDATE cases SET next_reminder_at = NULL WHERE id = $1', [caseId]);
      return { skip: 'case not open' };
    }
    if (!force && (c.reminders_paused || !c.next_reminder_at || new Date(c.next_reminder_at) > new Date())) {
      return { skip: 'not due' };
    }
    const smsTo = sms && c.sms_enabled && !c.sms_opt_out ? normalisePhone(c.client_phone) : null;
    if (!c.client_email && !smsTo) {
      await q(`UPDATE cases SET next_reminder_at = NULL, chasing_stopped = 'no_email' WHERE id = $1`, [caseId]);
      await audit(q, { firmId, actorType, userId, action: 'reminder.no_email', entityType: 'case', entityId: caseId });
      return { skip: 'client has no email' };
    }
    const items = await q(
      `SELECT label, help_text, status, rejected_reason, required
         FROM document_requests WHERE case_id = $1 AND status IN ('requested', 'rejected')
        ORDER BY status DESC, required DESC, sort_order`,
      [caseId]
    );
    if (!items.some((i) => i.required) && !force) {
      await q(`UPDATE cases SET next_reminder_at = now() + interval '1 day' WHERE id = $1`, [caseId]);
      return { skip: 'nothing outstanding from the client' };
    }
    if (!items.length) return { skip: 'nothing outstanding from the client' };
    if (kind === 'reminder' && c.reminders_sent >= c.max_reminders) {
      await q(`UPDATE cases SET next_reminder_at = NULL, chasing_stopped = 'limit_reached' WHERE id = $1`, [caseId]);
      await audit(q, { firmId, actorType: 'system', action: 'reminder.limit_reached', entityType: 'case', entityId: caseId, details: { sent: c.reminders_sent } });
      return { skip: 'reminder limit reached' };
    }

    // Fresh link for this reminder; older links stop working so only the latest one is live.
    await q(`UPDATE upload_links SET revoked_at = now() WHERE case_id = $1 AND revoked_at IS NULL`, [caseId]);
    const [link] = await q(
      `INSERT INTO upload_links (firm_id, case_id, token_hash, expires_at)
       VALUES ($1, $2, $3, now() + make_interval(days => $4)) RETURNING id`,
      [firmId, caseId, sha256(token), linkDays]
    );
    const url = `${baseUrl}/u/${token}`;
    const email = reminderEmail({
      kind, firstName: c.first_name, firmName: c.firm_name, caseTitle: c.title, adviserName: c.adviser_name,
      link: url, linkDays, items, dueDate: c.due_date,
    });
    const sends = [];
    if (c.client_email) {
      const [r] = await q(
        `INSERT INTO reminders (firm_id, case_id, channel, scheduled_for, status, kind, recipient, outstanding)
         VALUES ($1, $2, 'email', now(), 'scheduled', $3, $4, $5) RETURNING id`,
        [firmId, caseId, kind, c.client_email, email.outstanding]
      );
      sends.push({ id: r.id, channel: 'email' });
    }
    if (smsTo) {
      const [r] = await q(
        `INSERT INTO reminders (firm_id, case_id, channel, scheduled_for, status, kind, recipient, outstanding)
         VALUES ($1, $2, 'sms', now(), 'scheduled', $3, $4, $5) RETURNING id`,
        [firmId, caseId, kind, smsTo, email.outstanding]
      );
      sends.push({ id: r.id, channel: 'sms' });
    }
    await q(
      `UPDATE cases SET reminders_sent = reminders_sent + 1, chasing_stopped = NULL,
              chasing_started_at = coalesce(chasing_started_at, now()),
              reminders_paused = CASE WHEN $2 THEN false ELSE reminders_paused END,
              next_reminder_at = now() + make_interval(days => $3)
        WHERE id = $1`,
      [caseId, kind === 'first', c.reminder_every_days]
    );
    return {
      sends, linkId: link.id, email,
      smsTo, smsText: reminderSms({ firstName: c.first_name, firmName: c.firm_name, outstanding: email.outstanding, link: url, rejected: items.some((i) => i.status === 'rejected') }),
      to: c.client_email, toName: `${c.first_name} ${c.last_name}`,
      replyTo: c.adviser_email, fromName: `${c.firm_name} via Fileready`,
    };
  });
  if (claim.skip) return { status: 'skipped', reason: claim.skip };

  // ---- 2. send (outside the transaction)
  for (const sd of claim.sends) {
    try {
      if (sd.channel === 'email') {
        await mailer.send({ to: claim.to, toName: claim.toName, replyTo: claim.replyTo, fromName: claim.fromName,
          subject: claim.email.subject, text: claim.email.text, html: claim.email.html });
      } else {
        await sms.send({ to: claim.smsTo, content: claim.smsText });
      }
      sd.ok = true;
    } catch (err) {
      sd.error = String(err.message || err).slice(0, 500);
    }
  }
  const anyOk = claim.sends.some((sd) => sd.ok);

  // ---- 3. record
  await db.asFirm(firmId, async (q) => {
    for (const sd of claim.sends) {
      if (sd.ok) await q(`UPDATE reminders SET status = 'sent', sent_at = now() WHERE id = $1`, [sd.id]);
      else await q(`UPDATE reminders SET status = 'failed', error = $2 WHERE id = $1`, [sd.id, sd.error]);
    }
    if (!anyOk) {
      await q(
        `UPDATE cases SET reminders_sent = greatest(reminders_sent - 1, 0), next_reminder_at = now() + interval '2 hours' WHERE id = $1`,
        [caseId]
      );
      await audit(q, { firmId, actorType, userId, action: 'reminder.failed', entityType: 'case', entityId: caseId, details: { kind, error: claim.sends.map((x) => x.error).join(' / ') } });
    } else {
      await audit(q, {
        firmId, actorType, userId, action: 'reminder.sent', entityType: 'case', entityId: caseId,
        details: { kind, outstanding: claim.email.outstanding, link_id: claim.linkId, channels: claim.sends.filter((x) => x.ok).map((x) => x.channel) },
      });
    }
  });
  return anyOk ? { status: 'sent' } : { status: 'failed', reason: claim.sends.map((x) => x.error).join(' / ') };
}

export async function runReminders({ db, mailer, sms = null, baseUrl, now = new Date(), ignoreHours = false, limit = 50 }) {
  if (!ignoreHours && !withinSendingHours(now)) return { ran: false, reason: 'outside sending hours', sent: 0, failed: 0, skipped: 0 };
  const due = await db.asApp((q) => q('SELECT * FROM reminders_due($1)', [limit]));
  const summary = { ran: true, sent: 0, failed: 0, skipped: 0 };
  for (const { firm_id, case_id } of due) {
    try {
      const r = await sendCaseReminder({ db, mailer, sms, baseUrl, firmId: firm_id, caseId: case_id });
      summary[r.status] += 1;
    } catch (err) {
      console.error(`Reminder for case ${case_id} failed:`, err.message);
      summary.failed += 1;
    }
  }
  return summary;
}
