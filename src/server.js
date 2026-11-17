// Production entry point (Render). Settings come from environment variables:
//
// Database (Supabase session pooler, IPv4):
//   SUPABASE_PROJECT_REF   e.g. xrhzdbvtxrjjupdsgmxl
//   DATABASE_HOST          the Session pooler host, e.g. aws-0-eu-west-1.pooler.supabase.com
//   DATABASE_PASSWORD      password of the fileready_web role
//   DATABASE_CA            optional: Supabase's SSL certificate (PEM) to verify the server
//   (or DATABASE_URL instead of the three above)
// Files (Supabase Storage, S3-compatible, storage-only keys):
//   S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY, S3_BUCKET (documents), S3_REGION (eu-west-1)
//   S3_ENDPOINT            optional, defaults to https://<ref>.storage.supabase.co/storage/v1/s3
// Email (Brevo, EU-hosted):
//   BREVO_API_KEY, SENDER_EMAIL (a sender verified in Brevo)
// Reminders:
//   REMINDERS_SECRET       shared with the scheduler that calls /internal/reminders/run
// Text messages (optional, Brevo SMS credit and a registered sender ID):
//   BREVO_SMS_SENDER       up to 11 letters/numbers, e.g. Fileready
// Two-step login:
//   APP_SECRET             32+ random characters, used to encrypt authenticator keys. Never change it once set.
// Billing (optional, Stripe):
//   STRIPE_SECRET_KEY, STRIPE_PRICE_ID, STRIPE_WEBHOOK_SECRET
// Sign-up:
//   ALLOW_SIGNUP           'true' to let new firms sign up for a free trial (off by default)
//   TRIAL_DAYS             default 30
//   CONTACT_EMAIL          optional: shown as "Book a demo" on the home page when sign-up is off
// Web:
//   BASE_URL               optional on Render (RENDER_EXTERNAL_URL is used)
import pg from 'pg';
import { createApp } from './app.js';
import { createDb, pgDriver } from './db.js';
import { localDiskStorage, s3Storage } from './storage.js';
import { brevoMailer, memoryMailer, brevoSms } from './mailer.js';

const env = process.env;
const baseUrl = env.BASE_URL || env.RENDER_EXTERNAL_URL;
const ref = env.SUPABASE_PROJECT_REF;

function fail(msg) {
  console.error(`Configuration error: ${msg}`);
  process.exit(1);
}
if (!baseUrl) fail('set BASE_URL');

const ssl = env.DATABASE_CA ? { ca: env.DATABASE_CA.replace(/\\n/g, '\n') } : { rejectUnauthorized: false };
if (!env.DATABASE_CA) console.warn('DATABASE_CA not set: the database certificate is not verified. Set it before real client data.');

let poolConfig;
if (env.DATABASE_URL) {
  poolConfig = { connectionString: env.DATABASE_URL };
} else {
  if (!ref || !env.DATABASE_HOST || !env.DATABASE_PASSWORD) fail('set SUPABASE_PROJECT_REF, DATABASE_HOST and DATABASE_PASSWORD (or DATABASE_URL)');
  poolConfig = {
    host: env.DATABASE_HOST.trim(),
    port: Number(env.DATABASE_PORT || 5432),
    database: 'postgres',
    user: `fileready_web.${ref}`, // Supavisor needs <role>.<project ref>
    password: env.DATABASE_PASSWORD.trim(), // ignore stray spaces from copy-paste
  };
}
const pool = new pg.Pool({ ...poolConfig, ssl, max: 5, idleTimeoutMillis: 30000 });
pool.on('error', (err) => console.error('Database pool error:', err.message));

let storage;
if (env.S3_ACCESS_KEY_ID && env.S3_SECRET_ACCESS_KEY) {
  storage = await s3Storage({
    bucket: env.S3_BUCKET || 'documents',
    config: {
      endpoint: env.S3_ENDPOINT || `https://${ref}.storage.supabase.co/storage/v1/s3`,
      region: env.S3_REGION || 'eu-west-1',
      accessKeyId: env.S3_ACCESS_KEY_ID,
      secretAccessKey: env.S3_SECRET_ACCESS_KEY,
    },
  });
} else {
  console.warn('S3 keys not set: files are saved on this server\'s disk and will be lost on restart.');
  storage = localDiskStorage(env.STORAGE_DIR || './storage');
}

let mailer;
if (env.BREVO_API_KEY && env.SENDER_EMAIL) {
  mailer = brevoMailer({ apiKey: env.BREVO_API_KEY.trim(), senderEmail: env.SENDER_EMAIL.trim() });
} else {
  console.warn('BREVO_API_KEY / SENDER_EMAIL not set: emails are only written to the log, not sent.');
  mailer = memoryMailer({ log: true });
}
let sms = null;
if (env.BREVO_API_KEY && env.BREVO_SMS_SENDER) sms = brevoSms({ apiKey: env.BREVO_API_KEY.trim(), sender: env.BREVO_SMS_SENDER.trim() });
else console.warn('BREVO_SMS_SENDER not set: text-message reminders are unavailable.');

let stripe = null;
if (env.STRIPE_SECRET_KEY) {
  const { default: Stripe } = await import('stripe');
  stripe = new Stripe(env.STRIPE_SECRET_KEY.trim());
  if (!env.STRIPE_PRICE_ID || !env.STRIPE_WEBHOOK_SECRET) console.warn('STRIPE_PRICE_ID / STRIPE_WEBHOOK_SECRET not set: billing is incomplete.');
} else console.warn('STRIPE_SECRET_KEY not set: billing is switched off.');

const appSecret = env.APP_SECRET?.trim() || null;
if (!appSecret || appSecret.length < 32) console.warn('APP_SECRET missing or under 32 characters: two-step login is unavailable.');

if (!env.REMINDERS_SECRET) console.warn('REMINDERS_SECRET not set: scheduled reminders are switched off.');

// Fail fast if the database login is wrong.
try {
  const db = createDb(pgDriver(pool));
  await db.asApp((q) => q('SELECT 1'));
  const app = createApp({
    db, storage, mailer, sms, stripe,
    config: {
      baseUrl, secureCookies: baseUrl.startsWith('https://'), remindersSecret: env.REMINDERS_SECRET?.trim() || null,
      appSecret: appSecret && appSecret.length >= 32 ? appSecret : null,
      allowSignup: env.ALLOW_SIGNUP === 'true', contactEmail: env.CONTACT_EMAIL?.trim() || null, trialDays: Number(env.TRIAL_DAYS || 30),
      stripePriceId: env.STRIPE_PRICE_ID?.trim() || null, stripeWebhookSecret: env.STRIPE_WEBHOOK_SECRET?.trim() || null,
    },
  });
  const port = Number(env.PORT || 3000);
  app.listen(port, () => console.log(`Fileready listening on ${port} as ${baseUrl}`));
} catch (err) {
  fail(`could not connect to the database: ${err.message}`);
}
