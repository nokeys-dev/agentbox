import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, verify } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { commandSigner, localSigner, signerFromEnv } from '../src/signer.js';
import { GitHub } from '../src/github.js';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const signScript = "const c=require('node:crypto');const fs=require('node:fs');process.stdout.write(c.sign('RSA-SHA256',fs.readFileSync(0),fs.readFileSync(process.argv[1])))";

test('local signer produces verifiable RS256 signatures and rejects non-RSA keys', async () => {
  const signature = await localSigner(pem).sign(Buffer.from('payload'));
  assert(verify('RSA-SHA256', Buffer.from('payload'), publicKey, signature));
  const { privateKey: ec } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  assert.throws(() => localSigner(ec.export({ type: 'pkcs8', format: 'pem' })), /must be RSA/);
});

test('command signer pipes data to an external signer and fails closed', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-signer-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const keyPath = join(directory, 'key.pem');
  writeFileSync(keyPath, pem, { mode: 0o600 });
  const signer = commandSigner([process.execPath, '-e', signScript, keyPath]);
  assert.equal(signer.kind, 'command');
  assert(verify('RSA-SHA256', Buffer.from('jwt'), publicKey, await signer.sign(Buffer.from('jwt'))));
  await assert.rejects(commandSigner([process.execPath, '-e', 'process.exit(3)']).sign(Buffer.from('x')), { code: 'SIGNER_FAILED' });
  await assert.rejects(commandSigner([process.execPath, '-e', "process.stdout.write('short')"]).sign(Buffer.from('x')), { code: 'SIGNER_FAILED' });
  await assert.rejects(commandSigner(['/nonexistent/signer']).sign(Buffer.from('x')), { code: 'SIGNER_FAILED' });
  await assert.rejects(commandSigner([process.execPath, '-e', 'setTimeout(()=>{},5000)'], { timeoutMs: 100 }).sign(Buffer.from('x')), { code: 'SIGNER_FAILED' });
  assert.throws(() => commandSigner([]), /nonempty JSON array/);
});

test('signerFromEnv prefers the command signer and requires one source', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-signer-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const keyPath = join(directory, 'key.pem');
  writeFileSync(keyPath, pem, { mode: 0o600 });
  assert.equal(signerFromEnv({ AGENTGATE_SIGN_COMMAND: JSON.stringify(['signer']), GITHUB_PRIVATE_KEY_PATH: keyPath }).kind, 'command');
  assert.equal(signerFromEnv({ GITHUB_PRIVATE_KEY_PATH: keyPath }).kind, 'local');
  assert.throws(() => signerFromEnv({}), /AGENTGATE_SIGN_COMMAND, AGENTGATE_KMS_KEY_ID, or GITHUB_PRIVATE_KEY_PATH/);
  assert.throws(() => signerFromEnv({ AGENTGATE_SIGN_COMMAND: 'not json' }), /JSON array/);
});

test('GitHub uses an injected signer for the App JWT', async () => {
  const calls = [];
  const signer = { kind: 'command', sign: async (data) => { calls.push(data.toString()); return localSigner(pem).sign(data); } };
  const github = new GitHub({ appId: '123', signer, fetchImpl: async () => Response.json({ token: 't', expires_at: new Date(Date.now() + 3600_000).toISOString() }) });
  assert.equal(await github.token({ id: 1, installationId: 2 }, 'read'), 't');
  assert.equal(calls.length, 1);
  assert.throws(() => new GitHub({ appId: '123' }), /signer or privateKey/);
});
