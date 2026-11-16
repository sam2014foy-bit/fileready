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
export function reminderEmail({ kind, firstName, firmName, caseTitle, adviserName, link, linkDays, items }) {
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
      ? `<li><strong>${esc(i.label)}</strong> – <span style="color:#b3261e">please upload again: ${esc(i.rejected_reason)}</span></li>`
      : `<li><strong>${esc(i.label)}</strong>${i.help_text ? ` <span style="color:#66707c">(${esc(i.help_text)})</span>` : ''}${i.required ? '' : ' <span style="color:#66707c">– if it applies</span>'}</li>`;
  const html = `<!doctype html><html><body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#1c2430;line-height:1.5;max-width:560px;margin:0 auto;padding:16px">
<p>Hi ${esc(firstName)},</p>
<p>${esc(intro)}</p>
<ul style="padding-left:20px">${[...rejected, ...missing].map(li).join('')}</ul>
<p style="margin:24px 0"><a href="${esc(link)}" style="background:#1f5f8b;color:#fff;padding:12px 20px;border-radius:6px;text-decoration:none;font-weight:600;display:inline-block">Upload documents</a></p>
<p style="color:#66707c;font-size:14px">This link is private to you and works for ${linkDays} days. ${esc(replyLine)}</p>
<p>Thanks,<br>${esc(adviserName ? `${adviserName}` : firmName)}${adviserName ? `<br>${esc(firmName)}` : ''}</p>
</body></html>`;

  return { subject, text, html, outstanding: n };
}
