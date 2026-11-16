// Production entry point.
// Env: DATABASE_URL (a login role granted fileready_app, NOT the postgres owner),
//      BASE_URL (e.g. https://app.fileready.ie), PORT, STORAGE_DIR.
import pg from 'pg';
import { createApp } from './app.js';
import { createDb, pgDriver } from './db.js';
import { localDiskStorage } from './storage.js';

const { DATABASE_URL, BASE_URL, PORT = 3000, STORAGE_DIR = './storage' } = process.env;
if (!DATABASE_URL || !BASE_URL) {
  console.error('Set DATABASE_URL and BASE_URL.');
  process.exit(1);
}

// Verify the database's TLS certificate when its CA is provided (Supabase:
// Project Settings > Database > SSL certificate). Set DATABASE_CA before live use.
const ssl = process.env.DATABASE_CA ? { ca: process.env.DATABASE_CA } : { rejectUnauthorized: false };
if (!process.env.DATABASE_CA) console.warn('DATABASE_CA not set: database certificate is not being verified.');
const pool = new pg.Pool({ connectionString: DATABASE_URL, max: 5, ssl });
const db = createDb(pgDriver(pool));
// TODO before real client data: swap for the Supabase Storage adapter (private EU bucket).
const storage = localDiskStorage(STORAGE_DIR);

const app = createApp({ db, storage, config: { baseUrl: BASE_URL, secureCookies: BASE_URL.startsWith('https://') } });
app.listen(PORT, () => console.log(`Fileready listening on ${PORT}`));
