import test from 'node:test';
import assert from 'node:assert/strict';
import { REQUIRED_RULES, verifyProtectedBranches } from '../src/rulesets.js';

const config = { repositories: [
  { name: 'acme/demo', id: 1, installationId: 2, protectedBranches: ['main', 'release/v1'] },
  { name: 'acme/other', id: 3, installationId: 2 }
] };

test('reports missing rules per protected branch using a metadata-read token', async () => {
  const calls = [];
  const provider = { api: async ({ repository, operation }) => {
    calls.push({ repository: repository.name, operation });
    const rules = operation.path.endsWith('/main') ? REQUIRED_RULES.map((type) => ({ type })) : [{ type: 'deletion' }];
    return Response.json(rules);
  } };
  const failures = await verifyProtectedBranches(config, provider);
  assert.deepEqual(failures, [{ repository: 'acme/demo', branch: 'release/v1', missing: ['non_fast_forward', 'pull_request'] }]);
  assert.deepEqual(calls.map((call) => call.operation.path), ['rules/branches/main', 'rules/branches/release%2Fv1']);
  assert.deepEqual(calls[0].operation.permissions, { metadata: 'read' });
  assert.equal(calls[0].operation.method, 'GET');
});

test('fails closed when GitHub cannot be queried', async () => {
  const provider = { api: async () => new Response('nope', { status: 403 }) };
  await assert.rejects(verifyProtectedBranches(config, provider), { code: 'RULESET_CHECK_FAILED' });
  const invalid = { api: async () => Response.json({ not: 'an array' }) };
  await assert.rejects(verifyProtectedBranches(config, invalid), { code: 'RULESET_CHECK_FAILED' });
});

test('an overall deadline bounds the whole check, not only each request', async () => {
  const many = { repositories: [{ name: 'acme/demo', id: 1, installationId: 2, protectedBranches: ['a', 'b', 'c', 'd', 'e'] }] };
  let calls = 0;
  // Each request is well under the per-request timeout, but together they exceed the deadline.
  const provider = { api: async ({ signal }) => {
    calls += 1;
    await new Promise((resolve, reject) => {
      const timer = setTimeout(resolve, 40);
      signal.addEventListener('abort', () => { clearTimeout(timer); reject(signal.reason); }, { once: true });
    });
    return Response.json(REQUIRED_RULES.map((type) => ({ type })));
  } };
  const started = Date.now();
  await assert.rejects(verifyProtectedBranches(many, provider, { timeoutMs: 60, requestTimeoutMs: 1000 }), { code: 'RULESET_CHECK_FAILED' });
  assert.ok(Date.now() - started < 500);
  assert.ok(calls < 5);
});
