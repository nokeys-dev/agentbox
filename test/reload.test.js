import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { adminRequest } from '../src/admin-client.js';
import { reloadConfig } from '../src/reload.js';
import { exampleConfig, fixture, pushBody } from './support/fixture.js';

test('reload swaps validated policy, rejects invalid config, and invalidates prior approvals', async (t) => {
  let forwarded = 0;
  const provider = { forward: async () => { forwarded++; return new Response('0000', { headers: { 'content-type': 'application/x-git-receive-pack-result' } }); } };
  const f = await fixture({ provider });
  t.after(() => f.close());
  const push = () => fetch(`${f.remote}/git-receive-pack`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/x-git-receive-pack-request' }, body: pushBody() });
  const blocked = await push();
  const { requestId } = await blocked.json();
  await adminRequest(f.gate.adminSocket, 'POST', `/approvals/${requestId}/approve`, { reviewer: 'local:reviewer' });

  const next = exampleConfig();
  next.rules.push({ id: 'note', action: 'git.push', repository: 'acme/demo', ref: 'refs/heads/notes', effect: 'allow' });
  const { policyHash } = f.gate.reload(next);
  assert.match(policyHash, /^[0-9a-f]{64}$/);
  const afterReload = await push();
  assert.equal(afterReload.status, 403);
  assert.equal((await afterReload.json()).code, 'REQUIRE_APPROVAL');
  assert.equal(forwarded, 0);

  const invalid = exampleConfig();
  invalid.rules.push({ id: 'bad', action: 'git.nope', repository: 'acme/demo', effect: 'allow' });
  assert.throws(() => f.gate.reload(invalid), /Invalid action/);
  const denied = exampleConfig();
  denied.rules = denied.rules.filter((rule) => rule.id !== 'read');
  f.gate.reload(denied);
  const read = await fetch(`${f.remote}/info/refs?service=git-upload-pack`, { headers: f.authHeaders });
  assert.equal(read.status, 403);
  await read.arrayBuffer();
  const audit = await readFile(join(f.directory, 'state', 'audit.jsonl'), 'utf8');
  const reloads = audit.trim().split('\n').map(JSON.parse).filter((event) => event.type === 'config.reload');
  assert.deepEqual(reloads.map((event) => event.result), ['applied', 'rejected', 'applied']);
});

test('a SIGHUP reload is not applied when a stop signal arrived during the ruleset check', async () => {
  const logs = [];
  const logger = { info() {}, warn: (msg, fields) => logs.push({ msg, ...fields }), error: (msg, fields) => logs.push({ msg, ...fields }) };
  let stopping = false;
  let reloads = 0;
  const gate = { reload: () => { reloads++; } };
  let release;
  const verify = () => new Promise((resolve) => { release = () => resolve([]); });
  const attempt = reloadConfig({ gate, logger, load: () => exampleConfig(), isStopping: () => stopping, verify });
  await new Promise((resolve) => setImmediate(resolve));
  stopping = true;
  release();
  assert.equal(await attempt, 'stopping');
  assert.equal(reloads, 0);
  assert.equal(logs.at(-1).msg, 'config.reload_skipped');
  assert.equal(await reloadConfig({ gate, logger, load: () => exampleConfig(), verify: async () => [] }), 'applied');
  assert.equal(reloads, 1);
});
