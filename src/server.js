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
// Web:
//   BASE_URL               optional on Render (RENDER_EXTERNAL_URL is used)
import pg from 'pg';
import { createApp } from './app.js';
import { createDb, pgDriver } from './db.js';
import { localDiskStorage, s3Storage } from './storage.js';
import { brevoMailer, memoryMailer } from './mailer.js';

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
if (!env.REMINDERS_SECRET) console.warn('REMINDERS_SECRET not set: scheduled reminders are switched off.');

// Fail fast if the database login is wrong.
try {
  const db = createDb(pgDriver(pool));
  await db.asApp((q) => q('SELECT 1'));
  const app = createApp({
    db, storage, mailer,
    config: { baseUrl, secureCookies: baseUrl.startsWith('https://'), remindersSecret: env.REMINDERS_SECRET?.trim() || null },
  });
  const port = Number(env.PORT || 3000);
  app.listen(port, () => console.log(`Fileready listening on ${port} as ${baseUrl}`));
} catch (err) {
  fail(`could not connect to the database: ${err.message}`);
}
