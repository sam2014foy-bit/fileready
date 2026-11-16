import { test } from 'node:test';
import assert from 'node:assert/strict';
import { s3Storage } from '../src/storage.js';

const KEY = '11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222';

function fakeClient() {
  const sent = [];
  const objects = new Map();
  return {
    sent,
    async send(cmd) {
      sent.push({ name: cmd.constructor.name, input: cmd.input });
      if (cmd.constructor.name === 'PutObjectCommand') objects.set(cmd.input.Key, cmd.input.Body);
      if (cmd.constructor.name === 'GetObjectCommand') {
        const body = objects.get(cmd.input.Key);
        return { Body: { transformToByteArray: async () => new Uint8Array(body) } };
      }
      return {};
    },
  };
}

test('s3 storage puts into the private bucket and reads back', async () => {
  const client = fakeClient();
  const store = await s3Storage({ bucket: 'documents', client });
  await store.put(KEY, Buffer.from('hello'), 'application/pdf');
  const put = client.sent[0];
  assert.equal(put.name, 'PutObjectCommand');
  assert.equal(put.input.Bucket, 'documents');
  assert.equal(put.input.ContentType, 'application/pdf');
  assert.equal((await store.get(KEY)).toString(), 'hello');
});

test('storage refuses keys that are not firm-id/document-id', async () => {
  const store = await s3Storage({ bucket: 'documents', client: fakeClient() });
  await assert.rejects(store.put('../../etc/passwd', Buffer.from('x')), /invalid storage key/);
  await assert.rejects(store.get('someone-else/file'), /invalid storage key/);
});
