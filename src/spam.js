// Spam protection for public forms, without third-party CAPTCHAs or cookies.
//  - Honeypot: a hidden "website" field people never see; bots fill it in.
//  - Time trap: each form carries a signed timestamp. Submissions faster than
//    a person could type are bots; very old or tampered tokens get a fresh form.
//  - Link check: messages stuffed with links are dropped.
import crypto from 'node:crypto';

export function createSpamGuard({ secret, minMs = 3000, maxMs = 24 * 3600 * 1000, now = () => Date.now() }) {
  const key = crypto.createHash('sha256').update(`fileready-forms|${secret || crypto.randomBytes(32).toString('hex')}`).digest();
  const sign = (t) => crypto.createHmac('sha256', key).update(String(t)).digest('base64url').slice(0, 22);
  return {
    token() { const t = now(); return `${t}.${sign(t)}`; },
    /** Returns 'ok', 'bot' (drop quietly) or 'stale' (show the form again). */
    check(body = {}) {
      if (body.website) return 'bot';
      const [t, sig] = String(body._t || '').split('.');
      const ts = Number(t);
      if (!ts || !sig || sig.length !== 22 || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(sign(ts)))) return 'stale';
      const age = now() - ts;
      if (age < minMs) return 'bot';
      if (age > maxMs) return 'stale';
      return 'ok';
    },
    tooManyLinks(...texts) { return texts.join(' ').match(/https?:\/\/|www\./gi)?.length > 2; },
  };
}
