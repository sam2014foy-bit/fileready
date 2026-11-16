// File storage. The app only calls put(key, buffer) and get(key).
// - localDiskStorage: development and tests.
// - s3Storage: production, pointed at a private Supabase Storage bucket (EU)
//   through its S3-compatible endpoint, using storage-only access keys.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const SAFE_KEY = /^[0-9a-f-]{36}\/[0-9a-f-]{36}$/;
const checkKey = (key) => {
  if (!SAFE_KEY.test(key)) throw new Error('invalid storage key');
  return key;
};

export function localDiskStorage(rootDir) {
  return {
    async put(key, buffer) {
      const file = path.join(rootDir, checkKey(key));
      await mkdir(path.dirname(file), { recursive: true });
      await writeFile(file, buffer, { flag: 'wx', mode: 0o600 });
    },
    async get(key) {
      return readFile(path.join(rootDir, checkKey(key)));
    },
  };
}

/**
 * @param {object} opts
 * @param {string} opts.bucket
 * @param {object} [opts.client]  an S3Client (injected in tests)
 * @param {object} [opts.config]  endpoint, region, accessKeyId, secretAccessKey
 */
export async function s3Storage({ bucket, client, config }) {
  const { S3Client, PutObjectCommand, GetObjectCommand } = await import('@aws-sdk/client-s3');
  const s3 = client ?? new S3Client({
    forcePathStyle: true,
    region: config.region,
    endpoint: config.endpoint,
    credentials: { accessKeyId: config.accessKeyId, secretAccessKey: config.secretAccessKey },
  });
  return {
    async put(key, buffer, contentType = 'application/octet-stream') {
      await s3.send(new PutObjectCommand({
        // Keys are random UUIDs, so an existing file is never overwritten.
        Bucket: bucket, Key: checkKey(key), Body: buffer, ContentType: contentType,
      }));
    },
    async get(key) {
      const res = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: checkKey(key) }));
      return Buffer.from(await res.Body.transformToByteArray());
    },
  };
}
