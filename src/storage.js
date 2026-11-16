// File storage. The app only calls put(key, buffer) and get(key).
// localDiskStorage is for development and tests. Production will use a
// Supabase Storage adapter with the same two methods (private bucket, EU).
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const SAFE_KEY = /^[0-9a-f-]{36}\/[0-9a-f-]{36}$/;

export function localDiskStorage(rootDir) {
  const resolve = (key) => {
    if (!SAFE_KEY.test(key)) throw new Error('invalid storage key');
    return path.join(rootDir, key);
  };
  return {
    async put(key, buffer) {
      const file = resolve(key);
      await mkdir(path.dirname(file), { recursive: true });
      await writeFile(file, buffer, { flag: 'wx', mode: 0o600 });
    },
    async get(key) {
      return readFile(resolve(key));
    },
  };
}
