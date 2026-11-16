// Sending email. The app only calls mailer.send({ to, toName, subject, text, html, replyTo, fromName }).
// - brevoMailer: production (Brevo, EU-hosted, transactional API).
// - memoryMailer: tests and local development; keeps sent emails in a list.

export function brevoMailer({ apiKey, senderEmail, fetchImpl = fetch }) {
  if (!apiKey || !senderEmail) throw new Error('brevoMailer needs apiKey and senderEmail');
  return {
    async send({ to, toName, subject, text, html, replyTo, fromName }) {
      const res = await fetchImpl('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: { 'api-key': apiKey, 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({
          sender: { email: senderEmail, name: (fromName || 'Fileready').slice(0, 70) },
          to: [{ email: to, ...(toName ? { name: toName } : {}) }],
          ...(replyTo ? { replyTo: { email: replyTo } } : {}),
          subject,
          textContent: text,
          htmlContent: html,
          tags: ['fileready-reminder'],
        }),
        signal: AbortSignal.timeout(15000),
      });
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error(`Brevo ${res.status}: ${body.slice(0, 200)}`);
      }
      const data = await res.json().catch(() => ({}));
      return { id: data.messageId || null };
    },
  };
}

export function memoryMailer({ log = false } = {}) {
  const outbox = [];
  return {
    outbox,
    failNext: false,
    async send(message) {
      if (this.failNext) {
        this.failNext = false;
        throw new Error('simulated send failure');
      }
      outbox.push({ ...message, sentAt: new Date() });
      if (log) console.log(`\n[email] to ${message.to}: ${message.subject}\n${message.text}\n`);
      return { id: `mem-${outbox.length}` };
    },
  };
}
