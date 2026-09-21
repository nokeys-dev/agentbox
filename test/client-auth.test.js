import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { readFile, rm } from 'node:fs/promises';
import { createClientAuth, loadClientToken } from '../src/client-auth.js';
import { clientAuthHeader } from '../src/workspace-config.js';
import { fixture } from '../scripts/support/fixture.js';

const token = 'a'.repeat(64);

test('token file must be long and owner-only', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-auth-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'token');
  writeFileSync(path, `${token}\n`, { mode: 0o600 });
  assert.equal(loadClientToken(path), token);
  chmodSync(path, 0o644);
  assert.throws(() => loadClientToken(path), /owner-only/);
  writeFileSync(path, 'short', { mode: 0o600 });
  chmodSync(path, 0o600);
  assert.throws(() => loadClientToken(path), /at least 32/);
});

test('bearer check is exact and disabled only without a token', () => {
  const check = createClientAuth(token);
  assert.doesNotThrow(() => check({ headers: { authorization: `Bearer ${token}` } }));
  for (const authorization of [undefined, `Bearer ${'b'.repeat(64)}`, `Basic ${token}`, `Bearer ${token}x`, 'Bearer ']) {
    assert.throws(() => check({ headers: { authorization } }), { code: 'UNAUTHENTICATED', status: 401 });
  }
  assert.doesNotThrow(() => createClientAuth(undefined)({ headers: {} }));
});

test('createClientAuth rejects an empty-string token at construction instead of building an unusable checker', () => {
  assert.throws(() => createClientAuth(''), /non-empty token/);
});

test('fixture normalizes an empty-string clientToken the same as undefined: auth disabled', async (t) => {
  for (const disabled of ['', undefined]) {
    const f = await fixture({ clientToken: disabled });
    t.after(() => f.close());
    assert.equal(f.clientToken, undefined);
    assert.deepEqual(f.authHeaders, {});
    const response = await fetch(`${f.remote}/info/refs?service=git-upload-pack`);
    assert.equal(response.status, 200);
    await response.arrayBuffer();
  }
});

test('broker rejects unauthenticated Git and API requests but serves healthz', async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const denied = await fetch(`${f.remote}/info/refs?service=git-upload-pack`);
  assert.equal(denied.status, 401);
  assert.equal(denied.headers.get('www-authenticate'), 'Bearer realm="agentgate"');
  assert.equal((await denied.json()).code, 'UNAUTHENTICATED');
  assert.equal((await fetch(`${f.gate.url}/api/repos/acme/demo/pulls`)).status, 401);
  assert.equal((await fetch(`${f.gate.url}/healthz`)).status, 200);
  const allowed = await fetch(`${f.remote}/info/refs?service=git-upload-pack`, { headers: f.authHeaders });
  assert.equal(allowed.status, 200);
  await allowed.arrayBuffer();
  await f.git(f.directory, 'clone', f.remote, join(f.directory, 'authed'));
});

test('unauthenticated floods are summarized at most once per 60s window, never audited per request', async (t) => {
  let now = 1_000_000;
  const f = await fixture({ now: () => now });
  let closed = false;
  t.after(async () => { if (!closed) await f.close(); });
  for (let i = 0; i < 3; i++) {
    const response = await fetch(`${f.remote}/info/refs?service=git-upload-pack`);
    assert.equal(response.status, 401);
    await response.arrayBuffer();
  }
  now += 60_000; // roll into the next 60s window
  const rolled = await fetch(`${f.remote}/info/refs?service=git-upload-pack`);
  assert.equal(rolled.status, 401);
  await rolled.arrayBuffer();
  // gate.close() flushes the trailing (still-open) window's summary.
  await f.gate.close();
  closed = true;
  const audit = (await readFile(join(f.directory, 'state', 'audit.jsonl'), 'utf8')).trim().split('\n').filter(Boolean).map((line) => JSON.parse(line));
  await rm(f.directory, { recursive: true, force: true });
  const summaries = audit.filter((event) => event.type === 'rejections' && event.code === 'UNAUTHENTICATED');
  assert.equal(summaries.length, 2);
  assert.equal(summaries[0].count, 3);
  assert.equal(summaries[1].count, 1);
  assert.equal(audit.filter((event) => event.type === 'error' && event.code === 'UNAUTHENTICATED').length, 0);
});

test('workspace tools read the client token file', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-auth-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'token');
  writeFileSync(path, `${token}\n`, { mode: 0o600 });
  assert.deepEqual(clientAuthHeader({ AGENTGATE_CLIENT_TOKEN_FILE: path }), { authorization: `Bearer ${token}` });
  assert.deepEqual(clientAuthHeader({}), {});
});
