// Reminder email wording. Plain, friendly, and specific about what's missing.

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/**
 * @param {object} p
 * @param {'first'|'reminder'|'manual'} p.kind
 * @param {string} p.firstName
 * @param {string} p.firmName
 * @param {string} p.caseTitle
 * @param {string|null} p.adviserName
 * @param {string} p.link
 * @param {number} p.linkDays
 * @param {{label:string, help_text?:string, status:string, rejected_reason?:string, required:boolean}[]} p.items
 */
// Postgres DATE values arrive as a Date at local midnight (node-postgres, PGlite) or as 'YYYY-MM-DD'.
export const dateOnly = (d) => {
  if (!d) return null;
  if (d instanceof Date) return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  return String(d).slice(0, 10);
};
export const formatDue = (d) => d ? new Date(`${dateOnly(d)}T12:00:00Z`).toLocaleDateString('en-IE', { weekday: 'long', day: 'numeric', month: 'long', timeZone: 'Europe/Dublin' }) : null;

export function reminderEmail({ kind, firstName, firmName, caseTitle, adviserName, link, linkDays, items, dueDate = null }) {
  const due = formatDue(dueDate);
  const rejected = items.filter((i) => i.status === 'rejected');
  const missing = items.filter((i) => i.status === 'requested');
  // Count what's required in subject lines; optional items are listed but marked "if it applies".
  const n = items.filter((i) => i.required).length || items.length;
  const what = caseTitle.toLowerCase().includes('mortgage') ? 'your mortgage application' : caseTitle;

  let subject;
  let intro;
  if (kind === 'first') {
    subject = `Documents needed for ${what} – ${firmName}`;
    intro = `${firmName} needs a few documents from you for ${what}. You can upload them all from your phone or computer using the secure link below.`;
  } else if (rejected.length) {
    subject = `Please re-upload ${rejected.length === 1 ? 'a document' : `${rejected.length} documents`} – ${firmName}`;
    intro = `Thanks for what you've sent so far. ${rejected.length === 1 ? 'One document needs' : 'Some documents need'} another look before ${firmName} can go ahead.`;
  } else {
    subject = `Reminder: ${n} document${n === 1 ? '' : 's'} still needed – ${firmName}`;
    intro = `Just a reminder that ${firmName} is still waiting on ${n === 1 ? 'one document' : `${n} documents`} for ${what}.`;
  }

  const line = (i) =>
    i.status === 'rejected'
      ? `• ${i.label} – please upload again: ${i.rejected_reason}`
      : `• ${i.label}${i.help_text ? ` (${i.help_text})` : ''}${i.required ? '' : ' – if it applies'}`;
  const signoff = adviserName ? `${adviserName}\n${firmName}` : firmName;
  const replyLine = adviserName ? `Questions? Just reply to this email to reach ${adviserName}.` : 'Questions? Just reply to this email.';

  const text = [
    `Hi ${firstName},`,
    '',
    intro,
    '',
    ...rejected.map(line),
    ...missing.map(line),
    ...(due ? ['', `Please send them by ${due}.`] : []),
    '',
    `Upload here: ${link}`,
    '',
    `This link is private to you and works for ${linkDays} days. ${replyLine}`,
    '',
    'Thanks,',
    signoff,
  ].join('\n');

  const li = (i) =>
    i.status === 'rejected'
      ? `<li><strong>${esc(i.label)}</strong> – <span style="color:#9B1E2B">please upload again: ${esc(i.rejected_reason)}</span></li>`
      : `<li><strong>${esc(i.label)}</strong>${i.help_text ? ` <span style="color:#56685F">(${esc(i.help_text)})</span>` : ''}${i.required ? '' : ' <span style="color:#56685F">– if it applies</span>'}</li>`;
  const html = `<!doctype html><html><body style="margin:0;background:#F3F6F4;padding:24px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#FFFFFF;border:1px solid #DAE2DD;border-radius:14px">
<tr><td style="padding:22px 28px;border-bottom:1px solid #DAE2DD;font:700 18px -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;letter-spacing:-0.01em;color:#13201C">${esc(firmName)}</td></tr>
<tr><td style="padding:28px;font:15px/1.6 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#13201C">
<p style="margin:0 0 14px">Hi ${esc(firstName)},</p>
<p style="margin:0 0 18px">${esc(intro)}</p>
<ul style="margin:0 0 24px;padding-left:20px">${[...rejected, ...missing].map(li).join('')}</ul>
${due ? `<p style="margin:0 0 18px"><strong>Please send them by ${esc(due)}.</strong></p>` : ''}
<p style="margin:0 0 24px"><a href="${esc(link)}" style="background:#0E6A51;color:#FFFFFF;padding:13px 22px;border-radius:999px;text-decoration:none;font-weight:600;display:inline-block">Upload documents</a></p>
<p style="margin:0 0 18px;color:#56685F;font-size:14px">This link is private to you and works for ${linkDays} days. ${esc(replyLine)}</p>
<p style="margin:0">Thanks,<br>${esc(adviserName ? `${adviserName}` : firmName)}${adviserName ? `<br><span style="color:#56685F">${esc(firmName)}</span>` : ''}</p>
</td></tr>
<tr><td style="padding:16px 28px;border-top:1px solid #DAE2DD;font:12px/1.5 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#56685F">Files you upload are sent securely to ${esc(firmName)} and stored in Ireland.</td></tr>
</table></td></tr></table>
</body></html>`;

  return { subject, text, html, outstanding: n };
}


// Shared frame for Fileready's own emails to staff.
function frame(heading, bodyHtml, footer) {
  return `<!doctype html><html><body style="margin:0;background:#F3F6F4;padding:24px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#FFFFFF;border:1px solid #DAE2DD;border-radius:14px">
<tr><td style="padding:22px 28px;border-bottom:1px solid #DAE2DD;font:700 18px -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;letter-spacing:-0.01em;color:#0E6A51">fileready</td></tr>
<tr><td style="padding:28px;font:15px/1.6 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#13201C">
<h1 style="margin:0 0 16px;font:700 24px/1.25 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;letter-spacing:-0.015em">${esc(heading)}</h1>${bodyHtml}</td></tr>
<tr><td style="padding:16px 28px;border-top:1px solid #DAE2DD;font:12px/1.5 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#56685F">${esc(footer)}</td></tr>
</table></td></tr></table></body></html>`;
}
const button = (link, label) => `<p style="margin:24px 0"><a href="${esc(link)}" style="background:#0E6A51;color:#FFFFFF;padding:13px 22px;border-radius:999px;text-decoration:none;font-weight:600;display:inline-block">${esc(label)}</a></p>`;

export function accountEmail({ purpose, name, firmName, inviter, link }) {
  if (purpose === 'invite') {
    const intro = `${inviter} has added you to ${firmName} on Fileready, where you'll track clients' mortgage documents.`;
    return {
      subject: `You're invited to ${firmName} on Fileready`,
      text: `Hi ${name},\n\n${intro}\n\nSet your password here: ${link}\n\nThis link works for 7 days.`,
      html: frame('Set up your login', `<p style="margin:0 0 12px">Hi ${esc(name)},</p><p style="margin:0">${esc(intro)}</p>${button(link, 'Set your password')}<p style="margin:0;color:#56685F;font-size:14px">This link works for 7 days.</p>`, 'If you weren\'t expecting this, you can ignore it.'),
    };
  }
  return {
    subject: 'Reset your Fileready password',
    text: `Hi ${name},\n\nSomeone asked to reset the password for your ${firmName} login on Fileready. If it was you, set a new one here: ${link}\n\nThis link works for 1 hour. If it wasn't you, ignore this email and your password stays the same.`,
    html: frame('Reset your password', `<p style="margin:0 0 12px">Hi ${esc(name)},</p><p style="margin:0">Someone asked to reset the password for your ${esc(firmName)} login. If it was you, set a new one below.</p>${button(link, 'Set a new password')}<p style="margin:0;color:#56685F;font-size:14px">This link works for 1 hour.</p>`, 'If you didn\'t ask for this, ignore this email and your password stays the same.'),
  };
}

export function uploadAlertEmail({ adviserName, clientName, items, link }) {
  const list = items.length ? items : ['A document'];
  const subject = `${clientName} uploaded ${list.length === 1 ? list[0] : `${list.length} documents`}`;
  return {
    subject,
    text: `Hi ${adviserName},\n\n${clientName} has uploaded documents waiting for your review:\n${list.map((l) => `• ${l}`).join('\n')}\n\nReview them: ${link}`,
    html: frame('Documents to review', `<p style="margin:0 0 12px">Hi ${esc(adviserName)},</p><p style="margin:0 0 12px">${esc(clientName)} has uploaded documents waiting for your review:</p><ul style="margin:0;padding-left:20px">${list.map((l) => `<li>${esc(l)}</li>`).join('')}</ul>${button(link, 'Review documents')}`, 'You get at most one of these every 30 minutes per case.'),
  };
}


export function reminderSms({ firstName, firmName, outstanding, link, rejected }) {
  const what = rejected ? 'needs you to re-upload a document' : `still needs ${outstanding} document${outstanding === 1 ? '' : 's'}`;
  return `Hi ${firstName}, ${firmName} ${what} for your application. Upload securely: ${link}`;
}

export function dailySummaryEmail({ name, firmName, toReview, notResponding, overdue, received, link }) {
  const n = toReview.length + notResponding.length + overdue.length;
  const subject = n ? `Fileready: ${toReview.length} to review, ${notResponding.length + overdue.length} need attention` : 'Fileready: nothing needs you today';
  const section = (title, rows) => rows.length
    ? `<h2 style="margin:20px 0 8px;font:600 15px -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif">${esc(title)}</h2><ul style="margin:0;padding-left:20px">${rows.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>` : '';
  const textSection = (title, rows) => rows.length ? `\n${title}\n${rows.map((r) => `• ${r}`).join('\n')}\n` : '';
  const rec = received ? `${received} document${received === 1 ? '' : 's'} came in since yesterday.` : 'No new documents came in since yesterday.';
  return {
    subject,
    text: `Good morning ${name},\n\n${rec}\n${textSection('To review', toReview)}${textSection('Not responding', notResponding)}${textSection('Overdue', overdue)}\nOpen Fileready: ${link}`,
    html: frame(`Good morning ${name}`, `<p style="margin:0">${esc(rec)}</p>${section('To review', toReview)}${section('Not responding to reminders', notResponding)}${section('Past their due date', overdue)}${button(link, 'Open Fileready')}`,
      `${firmName}. You can turn this email off on your Account page.`),
  };
}
