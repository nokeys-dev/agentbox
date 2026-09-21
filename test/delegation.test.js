import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { issueAssertion } from '../src/assertion.js';
import { validateConfig } from '../src/config.js';
import { exampleConfig, fixture } from '../scripts/support/fixture.js';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const clientToken = 'delegation-client-token-0123456789abcdef';
const pem = publicKey.export({ type: 'spki', format: 'pem' });

function config(directoryPath, delegation) {
  const base = exampleConfig();
  delete base.runtime;
  base.identity = { mode: 'assertion', audience: 'agentgate:acme', issuers: [{ kid: 'k1', publicKeyPem: pem }], delegation };
  base.entitlements = { static: { path: directoryPath } };
  return base;
}

async function scenario(t, delegation) {
  // The static source re-reads its file on every uncached resolve, so the directory can be written
  // after the fixture starts; each assertion has a fresh jti and therefore a fresh envelope cache key.
  const directory = join(await mkdtemp(join(tmpdir(), 'agentgate-delegation-')), 'directory.json');
  await writeFile(directory, JSON.stringify({ humans: { 'dev@example.com': { teams: ['payments'], groups: ['eng'], owns: [] } } }));
  const live = await fixture({ clientToken, config: config(directory, delegation) });
  t.after(() => live.close());
  const call = async (team) => {
    const assertion = issueAssertion({ iss: 'issuer', aud: 'agentgate:acme', sub: `rt-${team}-${Math.random().toString(16).slice(2)}`, human: 'dev@example.com', agent: 'cursor', team, mode: 'build' }, { privateKey, kid: 'k1', ttlSeconds: 600, clientToken });
    const response = await fetch(`${live.remote}/info/refs?service=git-upload-pack`, { headers: { ...live.authHeaders, 'x-agentgate-runtime': assertion } });
    let body;
    try { body = await response.clone().json(); } catch { body = undefined; }
    return { status: response.status, code: body?.code };
  };
  const audit = async () => (await readFile(join(live.directory, 'state', 'audit.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  return { live, directory, call, audit };
}

test('delegation "enforce" refuses a team the developer does not hold and fails closed when the directory is unreadable', async (t) => {
  const { directory, call, audit } = await scenario(t, 'enforce');
  assert.equal((await call('payments')).status, 200);
  assert.equal((await call('eng')).status, 200, 'a directory group counts as a held team');
  assert.deepEqual(await call('platform'), { status: 403, code: 'DELEGATION_MISMATCH' });
  const refused = (await audit()).filter((event) => event.decision === 'delegation-refused');
  assert.equal(refused.length, 1);
  assert.equal(refused[0].code, 'DELEGATION_MISMATCH');
  assert.equal(refused[0].claimedTeam, 'platform');
  assert.equal(refused[0].runtime.human, 'dev@example.com');
  await writeFile(directory, '{broken');
  assert.deepEqual(await call('payments'), { status: 503, code: 'DELEGATION_UNKNOWN' });
});

test('delegation "audit" lets the request through but records the mismatch', async (t) => {
  const { call, audit } = await scenario(t, 'audit');
  assert.equal((await call('platform')).status, 200);
  const warned = (await audit()).filter((event) => event.decision === 'delegation-warning');
  assert.equal(warned.length, 1);
  assert.equal(warned[0].code, 'DELEGATION_MISMATCH');
});

test('delegation config requires assertion mode and a membership source', () => {
  assert.doesNotThrow(() => validateConfig(config('/etc/agentgate/directory.json', 'enforce')));
  assert.doesNotThrow(() => validateConfig(config('/etc/agentgate/directory.json', undefined)));
  const noSource = config('/etc/agentgate/directory.json', 'enforce');
  delete noSource.entitlements;
  assert.throws(() => validateConfig(noSource), /membership entitlement source/);
  assert.throws(() => validateConfig(config('/etc/agentgate/directory.json', 'strict')), /delegation/);
  const staticMode = exampleConfig();
  staticMode.identity = { mode: 'static', delegation: 'enforce' };
  assert.throws(() => validateConfig(staticMode), /identity/);
});
