import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { adminRequest } from '../src/admin-client.js';
import { fixture, packet, pushBody } from '../scripts/support/fixture.js';

test('real Git clone, fetch, branch push, main approval and tag denial', async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const clone = join(f.directory, 'workspace');
  await f.git(f.directory, 'clone', f.remote, clone);
  assert.equal(await readFile(join(clone, 'README.md'), 'utf8'), '# Demo repository\n');
  await f.git(clone, 'config', 'user.name', 'Test Agent');
  await f.git(clone, 'config', 'user.email', 'agent@example.com');
  await f.git(clone, 'checkout', '-b', 'agent/demo');
  await writeFile(join(clone, 'work.txt'), 'Authorized agent work\n');
  await f.git(clone, 'add', 'work.txt');
  await f.git(clone, 'commit', '-m', 'Agent work');
  await f.git(clone, 'push', 'origin', 'HEAD:refs/heads/agent/demo');
  const head = await f.git(clone, 'rev-parse', 'HEAD');
  assert.equal(await f.git(f.bare, 'rev-parse', 'refs/heads/agent/demo'), head);
  await f.git(clone, 'fetch', 'origin');
  await assert.rejects(f.git(clone, 'push', 'origin', 'HEAD:refs/heads/main'));
  assert.notEqual(await f.git(f.bare, 'rev-parse', 'refs/heads/main'), head);
  const pending = await adminRequest(f.gate.adminSocket, 'GET', '/approvals');
  assert.equal(pending.length, 1);
  assert.equal(pending[0].context.changes[0].ref, 'refs/heads/main');
  assert(!Object.keys(pending[0]).includes('created'), 'created must never leak into the admin approvals JSON');
  await adminRequest(f.gate.adminSocket, 'POST', `/approvals/${pending[0].id}/approve`, { reviewer: 'local:reviewer' });
  await f.git(clone, 'push', 'origin', 'HEAD:refs/heads/main');
  assert.equal(await f.git(f.bare, 'rev-parse', 'refs/heads/main'), head);
  assert.equal(f.gate.state.list()[0].status, 'consumed');
  await assert.rejects(f.git(clone, 'push', 'origin', 'HEAD:refs/tags/v1'));
  await assert.rejects(f.git(clone, 'push', 'origin', '--delete', 'agent/demo'));
  assert.equal(await f.git(f.bare, 'rev-parse', 'refs/heads/agent/demo'), head);
  const audit = (await readFile(join(f.directory, 'state', 'audit.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert(audit.some((event) => event.decision === 'deny'));
  assert(audit.some((event) => event.type === 'approval.review'));
  assert(audit.every((event) => event.timestamp));
});

test('concurrent retries consume one grant, changed ref targets cannot use it, and replay requires approval', async (t) => {
  let calls = 0;
  const provider = { forward: async () => { calls++; return new Response('0000', { headers: { 'content-type': 'application/x-git-receive-pack-result' } }); } };
  const f = await fixture({ provider });
  t.after(() => f.close());
  const push = (body = pushBody()) => fetch(`${f.remote}/git-receive-pack`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/x-git-receive-pack-request' }, body });
  const blocked = await push();
  assert.equal(blocked.status, 403);
  const approval = await blocked.json();
  assert.equal(approval.code, 'REQUIRE_APPROVAL');
  await adminRequest(f.gate.adminSocket, 'POST', `/approvals/${approval.requestId}/approve`, { reviewer: 'local:reviewer' });
  const changed = await push(pushBody('refs/heads/main', '1'.repeat(40), '3'.repeat(40)));
  assert.equal(changed.status, 403);
  await changed.arrayBuffer();
  assert.equal(calls, 0);
  const retries = await Promise.all([push(), push()]);
  assert.deepEqual(retries.map((response) => response.status).sort(), [200, 403]);
  await Promise.all(retries.map((response) => response.arrayBuffer()));
  assert.equal(calls, 1);
  const replay = await push();
  assert.equal(replay.status, 403);
  await replay.arrayBuffer();
});

test('rejects malformed, oversized, cross-origin and unknown requests before upstream access', async (t) => {
  const f = await fixture({ maxBodyBytes: 128 });
  t.after(() => f.close());
  const attempts = [
    [`${f.gate.url}/acme/unknown.git/info/refs?service=git-upload-pack`, {}, 403],
    [`${f.remote}/info/refs?service=git-upload-pack&extra=x`, {}, 404],
    [`${f.remote}/info/refs?service=git-upload-pack`, { headers: { origin: 'https://example.com' } }, 403],
    [`${f.gate.url}/approvals`, {}, 404],
    [`${f.remote}/git-receive-pack`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: 'bad' }, 415],
    [`${f.remote}/git-receive-pack`, { method: 'POST', headers: { 'content-type': 'application/x-git-receive-pack-request' }, body: 'bad' }, 400],
    [`${f.remote}/git-receive-pack`, { method: 'POST', headers: { 'content-type': 'application/x-git-receive-pack-request' }, body: Buffer.alloc(129) }, 413],
    [`${f.remote}/git-receive-pack`, { method: 'POST', headers: { 'content-type': 'application/x-git-receive-pack-request', 'content-encoding': 'gzip' }, body: 'bad' }, 415]
  ];
  for (const [url, options, status] of attempts) {
    const response = await fetch(url, { ...options, headers: { ...f.authHeaders, ...options.headers } });
    assert.equal(response.status, status, url);
    await response.arrayBuffer();
  }
  assert.equal(f.calls.length, 0);
});

test('a denied ref blocks the entire push even alongside an approved ref', async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const push = (body) => fetch(`${f.remote}/git-receive-pack`, {
    method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/x-git-receive-pack-request' }, body
  });
  const pending = await (await push(pushBody())).json();
  await adminRequest(f.gate.adminSocket, 'POST', `/approvals/${pending.requestId}/approve`, { reviewer: 'local:reviewer' });
  const body = Buffer.concat([
    packet(`${'1'.repeat(40)} ${'2'.repeat(40)} refs/heads/main\0report-status`),
    packet(`${'0'.repeat(40)} ${'2'.repeat(40)} refs/tags/forbidden`), Buffer.from('0000')
  ]);
  const response = await push(body);
  assert.equal(response.status, 403);
  assert.equal((await response.json()).code, 'DENIED');
  assert.equal(f.calls.length, 0);
  assert.equal(f.gate.state.list()[0].status, 'approved');
});

test('admin approvals reject a missing reviewer and the delegating human reviewing their own request', async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const push = () => fetch(`${f.remote}/git-receive-pack`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/x-git-receive-pack-request' }, body: pushBody() });
  const { requestId } = await (await push()).json();
  // A request with no JSON body at all must fail closed with 400 REVIEWER_REQUIRED, not 500.
  await assert.rejects(adminRequest(f.gate.adminSocket, 'POST', `/approvals/${requestId}/approve`), { code: 'REVIEWER_REQUIRED' });
  // A JSON body that parses but isn't a plain object (null, an array) must fail closed with 400
  // INVALID_JSON rather than a 500 TypeError from reading `.reviewer` off it.
  await assert.rejects(adminRequest(f.gate.adminSocket, 'POST', `/approvals/${requestId}/approve`, null), { code: 'INVALID_JSON' });
  await assert.rejects(adminRequest(f.gate.adminSocket, 'POST', `/approvals/${requestId}/approve`, []), { code: 'INVALID_JSON' });
  // The example fixture's runtime.human is test@example.com; reviewing as that identity (with or
  // without a local:/oidc: prefix) is a self-approval and must be rejected.
  await assert.rejects(adminRequest(f.gate.adminSocket, 'POST', `/approvals/${requestId}/approve`, { reviewer: 'local:test@example.com' }), { code: 'SELF_APPROVAL' });
  const approved = await adminRequest(f.gate.adminSocket, 'POST', `/approvals/${requestId}/approve`, { reviewer: 'local:reviewer' });
  assert.equal(approved.status, 'approved');
});

test('audit failure prevents even a policy-allowed request from reaching the provider', async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  f.gate.state.audit = () => { throw new Error('Simulated full audit disk'); };
  const response = await fetch(`${f.remote}/info/refs?service=git-upload-pack`, { headers: f.authHeaders });
  assert.equal(response.status, 500);
  assert.equal((await response.json()).code, 'INTERNAL_ERROR');
  assert.equal(f.calls.length, 0);
});

test('push options are allowlisted per repository and shallow clones can push', async (t) => {
  const { exampleConfig } = await import('../scripts/support/fixture.js');
  const config = exampleConfig();
  config.repositories[0].allowedPushOptions = ['ci.skip', 'merge_request.*'];
  const f = await fixture({ config });
  t.after(() => f.close());
  const shallow = join(f.directory, 'shallow');
  await f.git(f.directory, 'clone', '--depth', '1', f.remote, shallow);
  await f.git(shallow, 'config', 'user.name', 'T');
  await f.git(shallow, 'config', 'user.email', 't@example.com');
  await f.git(f.bare, 'config', 'receive.advertisePushOptions', 'true');
  await f.git(shallow, 'switch', '-c', 'agent/opts');
  await writeFile(join(shallow, 'o.txt'), 'o\n');
  await f.git(shallow, 'add', '.');
  await f.git(shallow, 'commit', '-m', 'opts');
  await f.git(shallow, 'push', '-o', 'ci.skip', 'origin', 'HEAD:refs/heads/agent/opts');
  await assert.rejects(f.git(shallow, 'push', '-o', 'deploy=prod', 'origin', 'HEAD:refs/heads/agent/opts2'), /PUSH_OPTION_DENIED|403/);
  const audit = (await readFile(join(f.directory, 'state', 'audit.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert(audit.some((event) => event.code === 'PUSH_OPTION_DENIED' || event.rule === 'push-option-not-allowed'));
});

test('an allowlisted push option requiring approval never has its value stored in audit, approvals.json, or admin GET /approvals', async (t) => {
  const { exampleConfig } = await import('../scripts/support/fixture.js');
  const config = exampleConfig();
  config.repositories[0].allowedPushOptions = ['ci.skip', 'merge_request.*'];
  const f = await fixture({ config });
  t.after(() => f.close());
  const clone = join(f.directory, 'workspace');
  await f.git(f.directory, 'clone', f.remote, clone);
  await f.git(clone, 'config', 'user.name', 'Test Agent');
  await f.git(clone, 'config', 'user.email', 'agent@example.com');
  await f.git(f.bare, 'config', 'receive.advertisePushOptions', 'true');
  await writeFile(join(clone, 'work.txt'), 'Agent work\n');
  await f.git(clone, 'add', 'work.txt');
  await f.git(clone, 'commit', '-m', 'Agent work');
  // refs/heads/main requires approval in the example policy; -o ci.skip is allowlisted.
  await assert.rejects(f.git(clone, 'push', '-o', 'ci.skip', 'origin', 'HEAD:refs/heads/main'));

  const pending = await adminRequest(f.gate.adminSocket, 'GET', '/approvals');
  assert.equal(pending.length, 1);
  const item = pending[0];
  assert.equal(item.context.pushOptionsCount, 1);
  assert.match(item.context.pushOptionsDigest, /^[0-9a-f]{64}$/);
  assert(!('pushOptions' in item.context), 'raw push option values must never be stored in the approval context');

  await adminRequest(f.gate.adminSocket, 'POST', `/approvals/${item.id}/approve`, { reviewer: 'local:reviewer' });

  const auditText = await readFile(join(f.directory, 'state', 'audit.jsonl'), 'utf8');
  const approvalsText = await readFile(join(f.directory, 'state', 'approvals.json'), 'utf8');
  const adminText = JSON.stringify(await adminRequest(f.gate.adminSocket, 'GET', '/approvals'));
  for (const haystack of [auditText, approvalsText, adminText]) assert(!haystack.includes('ci.skip'), 'push option value leaked');
  // The approval.review audit record does carry the context (by design, for traceability); make
  // sure that context is still the redacted count/digest form, not the raw value.
  const audit = auditText.trim().split('\n').map(JSON.parse);
  const review = audit.find((event) => event.type === 'approval.review');
  assert.equal(review.context.pushOptionsCount, 1);
  assert.match(review.context.pushOptionsDigest, /^[0-9a-f]{64}$/);
});

test('approving a push binds the exact push options requested; a different (or missing) option set needs a new approval', async (t) => {
  const { exampleConfig } = await import('../scripts/support/fixture.js');
  const config = exampleConfig();
  config.repositories[0].allowedPushOptions = ['ci.skip', 'merge_request.*'];
  const f = await fixture({ config });
  t.after(() => f.close());
  const clone = join(f.directory, 'workspace');
  await f.git(f.directory, 'clone', f.remote, clone);
  await f.git(clone, 'config', 'user.name', 'Test Agent');
  await f.git(clone, 'config', 'user.email', 'agent@example.com');
  await f.git(f.bare, 'config', 'receive.advertisePushOptions', 'true');
  await writeFile(join(clone, 'work.txt'), 'Agent work\n');
  await f.git(clone, 'add', 'work.txt');
  await f.git(clone, 'commit', '-m', 'Agent work');
  const head = await f.git(clone, 'rev-parse', 'HEAD');

  const knownIds = new Set();
  const newlyCreatedId = async () => {
    const items = await adminRequest(f.gate.adminSocket, 'GET', '/approvals');
    const fresh = items.map((entry) => entry.id).filter((id) => !knownIds.has(id));
    assert.equal(fresh.length, 1, `expected exactly one new approval request, saw ${JSON.stringify(fresh)}`);
    knownIds.add(fresh[0]);
    return fresh[0];
  };

  await assert.rejects(f.git(clone, 'push', '-o', 'ci.skip', 'origin', 'HEAD:refs/heads/main'));
  const first = await newlyCreatedId();
  await adminRequest(f.gate.adminSocket, 'POST', `/approvals/${first}/approve`, { reviewer: 'local:reviewer' });

  // A different allowlisted option is a different request: the ci.skip approval must not cover it.
  await assert.rejects(f.git(clone, 'push', '-o', 'merge_request.x', 'origin', 'HEAD:refs/heads/main'));
  const second = await newlyCreatedId();
  assert.notEqual(second, first);

  // No options at all is likewise distinct from both.
  await assert.rejects(f.git(clone, 'push', 'origin', 'HEAD:refs/heads/main'));
  const third = await newlyCreatedId();
  assert.notEqual(third, first);
  assert.notEqual(third, second);

  // Retrying with exactly the approved option set succeeds and consumes that approval.
  await f.git(clone, 'push', '-o', 'ci.skip', 'origin', 'HEAD:refs/heads/main');
  assert.equal(await f.git(f.bare, 'rev-parse', 'refs/heads/main'), head);
  const finalItems = await adminRequest(f.gate.adminSocket, 'GET', '/approvals');
  assert.equal(new Set(finalItems.map((entry) => entry.id)).size, 3, 'no extra approval should have been created for the matching retry');
  assert.equal(finalItems.find((entry) => entry.id === first).status, 'consumed');
});

test('a real git push of an NFC Unicode branch name is opt-in per repository', async (t) => {
  const { exampleConfig } = await import('../scripts/support/fixture.js');
  // U+00E9 (precomposed 'é'), already NFC-normalized -- matches "refs/heads/agent/*" and only
  // needs Unicode support, not any other policy change, to be pushable.
  const branch = 'agent/café';
  const commitBranch = async (f, clone) => {
    await f.git(f.directory, 'clone', f.remote, clone);
    await f.git(clone, 'config', 'user.name', 'Test Agent');
    await f.git(clone, 'config', 'user.email', 'agent@example.com');
    await f.git(clone, 'checkout', '-b', branch);
    await writeFile(join(clone, 'work.txt'), 'Unicode branch work\n');
    await f.git(clone, 'add', 'work.txt');
    await f.git(clone, 'commit', '-m', 'Unicode branch work');
    return f.git(clone, 'rev-parse', 'HEAD');
  };

  const allowedConfig = exampleConfig();
  allowedConfig.repositories[0].allowUnicodeRefs = true;
  const allowed = await fixture({ config: allowedConfig });
  t.after(() => allowed.close());
  const allowedClone = join(allowed.directory, 'workspace-unicode-allowed');
  const allowedHead = await commitBranch(allowed, allowedClone);
  await allowed.git(allowedClone, 'push', 'origin', `HEAD:refs/heads/${branch}`);
  assert.equal(await allowed.git(allowed.bare, 'rev-parse', `refs/heads/${branch}`), allowedHead);

  const denied = await fixture({ config: exampleConfig() });
  t.after(() => denied.close());
  const deniedClone = join(denied.directory, 'workspace-unicode-denied');
  await commitBranch(denied, deniedClone);
  await assert.rejects(denied.git(deniedClone, 'push', 'origin', `HEAD:refs/heads/${branch}`));
  // The ref was never created on the upstream bare repo: rev-parse on a ref that was never
  // written errors (unlike an existing-but-different ref, which would just resolve to it).
  await assert.rejects(denied.git(denied.bare, 'rev-parse', `refs/heads/${branch}`));
});
