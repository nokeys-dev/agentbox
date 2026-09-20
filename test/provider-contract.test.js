import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { GitHub } from '../src/github.js';
import { assertProvider, providerCapabilities, runProviderContract } from '../src/providers/index.js';

const pem = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' });

test('GitHub satisfies the provider contract', async () => {
  await runProviderContract((fetchImpl) => new GitHub({ appId: '1', privateKey: pem, fetchImpl }));
  const github = new GitHub({ appId: '1', privateKey: pem });
  assert.doesNotThrow(() => assertProvider(github, { capabilities: ['git', 'api', 'lfs', 'logs'] }));
  assert.deepEqual(providerCapabilities(github), { git: true, pullRequests: true, actionsRead: true, lfs: true });
  assert.throws(() => assertProvider({ forward() {} }, { capabilities: ['git', 'api'] }), /api, apiRaw/);
  assert.deepEqual(providerCapabilities({ forward() {} }), { git: true, pullRequests: false, actionsRead: false, lfs: false });
});
