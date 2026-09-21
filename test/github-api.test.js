import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { resolve, join } from 'node:path';
import { access, readFile, writeFile } from 'node:fs/promises';
import { fixture, exampleConfig } from '../scripts/support/fixture.js';
import { adminRequest } from '../src/admin-client.js';
import { routeApi, projectApiResponse, commentPayload, reviewPayload, pullRequestPayload, mergePayload, LOG_HOST_PATTERN } from '../src/github-api.js';
import { validateConfig } from '../src/config.js';
import { decide } from '../src/policy.js';

const execute = promisify(execFile);
const draft = { title: 'Implement feature', head: 'agent/feature', base: 'main', body: 'Description', draft: true };
const pull = { number: 7, title: draft.title, html_url: 'https://github.com/acme/demo/pull/7', head: { ref: draft.head, sha: '1'.repeat(40), repo: { temp_clone_token: 'never-expose-this' } }, base: { ref: 'main' }, token: 'never-expose-this' };
const comment = { id: 9, body: 'A review comment', html_url: 'https://github.com/acme/demo/issues/7#issuecomment-9', created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-01T00:00:00Z', user: { login: 'agent' }, token: 'never-expose-this' };
const review = { id: 11, state: 'COMMENTED', body: 'Looks fine', html_url: 'https://github.com/acme/demo/pull/7#pullrequestreview-11', submitted_at: '2024-01-01T00:00:00Z', token: 'never-expose-this' };

function apiConfig(effect = 'approval') {
  const config = exampleConfig();
  config.rules.push(
    { id: 'pr-read', action: 'github.pr.read', repository: 'acme/demo', effect: 'allow' },
    { id: 'pr-create', action: 'github.pr.create', repository: 'acme/demo', ref: 'refs/heads/agent/*', effect },
    { id: 'pr-comment', action: 'github.pr.comment', repository: 'acme/demo', effect: 'allow' },
    { id: 'ci-read', action: 'github.actions.read', repository: 'acme/demo', effect: 'allow' }
  );
  return config;
}

function provider(calls) {
  return { api: async (request) => {
    calls.push(request);
    const resource = request.operation.resource;
    const create = request.operation.create;
    if (resource === 'pulls') return Response.json(create ? pull : [pull], { status: create ? 201 : 200 });
    if (/^issues\/\d+$/.test(resource)) return Response.json({ number: Number(resource.split('/')[1]), pull_request: {} }, { status: 200 });
    if (/^issues\/\d+\/comments$/.test(resource)) return Response.json(create ? comment : [comment], { status: create ? 201 : 200 });
    if (/^pulls\/\d+\/comments$/.test(resource)) return Response.json([comment], { status: 200 });
    if (/^pulls\/\d+\/reviews$/.test(resource)) return Response.json(review, { status: 200 });
    if (resource.startsWith('pulls/')) return Response.json(pull, { status: 200 });
    if (resource.endsWith('/jobs')) return Response.json({ total_count: 1, jobs: [{ id: 10, name: 'test', status: 'completed', conclusion: 'failure', steps: [{ number: 1, name: 'npm test', conclusion: 'failure' }] }] }, { status: 200 });
    if (resource === 'actions/runs') return Response.json({ total_count: 1, workflow_runs: [{ id: 3, status: 'completed', conclusion: 'failure' }] }, { status: 200 });
    return Response.json({ id: 3, status: 'completed', conclusion: 'failure' }, { status: 200 });
  } };
}

function create(f, payload = draft) {
  return fetch(`${f.gate.url}/api/repos/acme/demo/pulls`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/json' }, body: JSON.stringify(payload) });
}

test('GitHub routes reject arbitrary APIs, ambiguous parameters, and unsupported mutations', () => {
  for (const [method, url] of [
    ['GET', '/api/repos/acme/demo/../../installation/token'],
    ['GET', '/api/repos/acme/demo/pulls?state=open&state=closed'],
    ['GET', '/api/repos/acme/demo/pulls?url=https://evil.invalid'],
    ['GET', '/api/repos/acme/demo/pulls?per_page=101'],
    ['GET', '/api/repos/acme/demo/actions/runs?branch=../bad'],
    ['GET', '/api/repos/acme/demo/pulls/1?state=open'],
    ['POST', '/api/repos/acme/demo/pulls/1'],
    ['POST', '/api/repos/acme/demo/pulls/1/merge'],
    ['PUT', '/api/repos/acme/demo/pulls/1/merge?sha=x'],
    ['PUT', '/api/repos/acme/demo/pulls/1'],
    ['POST', '/api/repos/acme/demo/actions/runs/3'],
    ['POST', '/api/repos/acme/demo/pulls?state=open']
  ]) assert.throws(() => routeApi({ method, url }), `${method} ${url}`);
});

test('PR comment and review routes map to comment action with least privilege', () => {
  const r = (method, url) => routeApi({ method, url });
  assert.deepEqual(pickRoute(r('POST', '/api/repos/acme/demo/issues/5/comments')), { action: 'github.pr.comment', permissions: { pull_requests: 'write' }, path: 'issues/5/comments' });
  assert.deepEqual(pickRoute(r('POST', '/api/repos/acme/demo/pulls/5/reviews')), { action: 'github.pr.comment', permissions: { pull_requests: 'write' }, path: 'pulls/5/reviews' });
  assert.deepEqual(pickRoute(r('GET', '/api/repos/acme/demo/pulls/5/comments')), { action: 'github.pr.read', permissions: { pull_requests: 'read' }, path: 'pulls/5/comments?page=1&per_page=30' });
  assert.throws(() => r('DELETE', '/api/repos/acme/demo/issues/5/comments'), { code: 'METHOD_NOT_ALLOWED' });
  assert.throws(() => r('POST', '/api/repos/acme/demo/issues/5/labels'), { code: 'NOT_FOUND' });
  assert.deepEqual(commentPayload(Buffer.from('{"body":"hi"}')), { body: 'hi' });
  assert.throws(() => commentPayload(Buffer.from('{"body":""}')), { code: 'INVALID_API_REQUEST' });
  assert.deepEqual(reviewPayload(Buffer.from('{"body":"lgtm?","event":"COMMENT"}')), { body: 'lgtm?', event: 'COMMENT' });
  assert.throws(() => reviewPayload(Buffer.from('{"body":"ship","event":"APPROVE"}')), { code: 'REVIEW_EVENT_DENIED' });
});

function pickRoute(operation) {
  return { action: operation.action, permissions: operation.permissions, path: operation.path };
}

test('posting a PR comment checks the target is a pull request, then posts least-privilege', async (t) => {
  const calls = [];
  const f = await fixture({ config: apiConfig('allow'), provider: provider(calls) });
  t.after(f.close);
  const response = await fetch(`${f.gate.url}/api/repos/acme/demo/issues/5/comments`, {
    method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/json' }, body: JSON.stringify({ body: 'hi' })
  });
  assert.equal(response.status, 201);
  const body = await response.json();
  assert.equal(body.id, comment.id);
  assert.equal(body.body, comment.body);
  assert(!JSON.stringify(body).includes('never-expose-this'));
  assert.deepEqual(calls.map((call) => `${call.operation.method} ${call.operation.resource}`), ['GET issues/5', 'POST issues/5/comments']);
  assert.deepEqual(calls[0].operation.permissions, { pull_requests: 'read' });
  assert.equal(calls[0].payload, undefined);
  assert.deepEqual(calls[1].payload, { body: 'hi' });
});

test('a plain issue is rejected as a comment target and never receives a POST', async (t) => {
  const calls = [];
  const f = await fixture({
    config: apiConfig('allow'),
    provider: { api: async (request) => { calls.push(request); return Response.json({ number: 5 }, { status: 200 }); } }
  });
  t.after(f.close);
  const response = await fetch(`${f.gate.url}/api/repos/acme/demo/issues/5/comments`, {
    method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/json' }, body: JSON.stringify({ body: 'hi' })
  });
  assert.equal(response.status, 404);
  assert.equal((await response.json()).code, 'NOT_A_PULL_REQUEST');
  assert.equal(calls.length, 1);
});

test('PR comments and reviews are default-deny without an explicit rule', async (t) => {
  const calls = [];
  const f = await fixture({ config: exampleConfig(), provider: provider(calls) });
  t.after(f.close);
  for (const [path, body] of [
    ['issues/5/comments', { body: 'hi' }],
    ['pulls/5/reviews', { body: 'hi', event: 'COMMENT' }]
  ]) {
    const response = await fetch(`${f.gate.url}/api/repos/acme/demo/${path}`, {
      method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/json' }, body: JSON.stringify(body)
    });
    assert.equal(response.status, 403);
    await response.arrayBuffer();
  }
  assert.equal(calls.length, 0);
});

test('reviews always post as COMMENT and are projected without upstream credentials', async (t) => {
  const calls = [];
  const f = await fixture({ config: apiConfig('allow'), provider: provider(calls) });
  t.after(f.close);
  const response = await fetch(`${f.gate.url}/api/repos/acme/demo/pulls/7/reviews`, {
    method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/json' }, body: JSON.stringify({ body: 'Looks fine', event: 'COMMENT' })
  });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.id, review.id);
  assert(!JSON.stringify(body).includes('never-expose-this'));
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].payload, { body: 'Looks fine', event: 'COMMENT' });
  const denied = await fetch(`${f.gate.url}/api/repos/acme/demo/pulls/7/reviews`, {
    method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/json' }, body: JSON.stringify({ body: 'ship it', event: 'APPROVE' })
  });
  assert.equal(denied.status, 403);
  assert.equal((await denied.json()).code, 'REVIEW_EVENT_DENIED');
  assert.equal(calls.length, 1);
});

test('API access is default-deny even when Git repository access is allowed', async (t) => {
  const calls = [];
  const f = await fixture({ provider: provider(calls) });
  t.after(f.close);
  for (const path of ['pulls', 'actions/runs']) {
    const response = await fetch(`${f.gate.url}/api/repos/acme/demo/${path}`, { headers: f.authHeaders });
    assert.equal(response.status, 403);
    await response.arrayBuffer();
  }
  const response = await create(f);
  assert.equal(response.status, 403);
  await response.arrayBuffer();
  assert.equal(calls.length, 0);
});

test('PR approvals bind exact normalized parameters and can only be consumed once', async (t) => {
  const calls = [];
  const f = await fixture({ config: apiConfig(), provider: provider(calls) });
  t.after(f.close);
  const first = await create(f);
  assert.equal(first.status, 403);
  const pending = await first.json();
  assert.equal(pending.code, 'REQUIRE_APPROVAL');
  await adminRequest(f.gate.adminSocket, 'POST', `/approvals/${pending.requestId}/approve`, { reviewer: 'local:reviewer' });
  for (const payload of [{ ...draft, base: 'release' }, { ...draft, body: 'Different text' }, { ...draft, draft: false }]) {
    const response = await create(f, payload);
    assert.equal(response.status, 403);
    await response.arrayBuffer();
  }
  const attempts = await Promise.all([create(f), create(f)]);
  assert.deepEqual(attempts.map((response) => response.status).sort(), [201, 403]);
  const data = await Promise.all(attempts.map((response) => response.json()));
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].payload, draft);
  assert(!JSON.stringify(data).includes('never-expose-this'));
  const replay = await create(f);
  assert.equal(replay.status, 403);
  await replay.arrayBuffer();
  const badHead = await create(f, { ...draft, head: 'someone-elses-branch' });
  assert.equal((await badHead.json()).code, 'DENIED');
});

test('malformed PR fields, fork heads, and oversized bodies never reach the provider', async (t) => {
  const calls = [];
  const f = await fixture({ config: apiConfig('allow'), provider: provider(calls) });
  t.after(f.close);
  for (const payload of [
    { ...draft, head: 'other:branch' }, { ...draft, base: '../main' },
    { ...draft, head: draft.base }, { ...draft, title: '' },
    { ...draft, draft: 'false' }, { ...draft, maintainer_can_modify: true },
    { ...draft, body: 'x'.repeat(65537) }
  ]) {
    const response = await create(f, payload);
    assert([400, 413].includes(response.status));
    await response.arrayBuffer();
  }
  assert.equal(calls.length, 0);
});

test('workspace CLI reads PRs and CI, infers origin, and submits draft PRs from a body file', async (t) => {
  const calls = [];
  const f = await fixture({ config: apiConfig('allow'), provider: provider(calls) });
  t.after(f.close);
  await f.git(f.seed, 'remote', 'add', 'origin', 'git@github.com:acme/demo.git');
  await f.git(f.seed, 'switch', '-c', 'agent/feature');
  const bodyFile = join(f.directory, 'body.md');
  await writeFile(bodyFile, 'Body with `code`, $(literal), and\nnewlines.\n');
  const tokenFile = join(f.directory, 'client-token');
  await writeFile(tokenFile, f.clientToken, { mode: 0o600 });
  const cli = async (...args) => JSON.parse((await execute(process.execPath, [resolve('src/workspace-cli.js'), ...args], {
    cwd: f.seed, env: { PATH: process.env.PATH, HOME: f.directory, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', AGENTGATE_URL: f.gate.url, AGENTGATE_CLIENT_TOKEN_FILE: tokenFile }
  })).stdout);
  assert.equal((await cli('pr', 'list', '--state', 'all', '--page', '2', '--per-page', '10'))[0].number, 7);
  assert.equal(calls[0].operation.path, 'pulls?page=2&per_page=10&state=all');
  assert.equal((await cli('pr', 'view', '7')).number, 7);
  assert.equal((await cli('ci', 'list', '--branch', 'agent/feature')).workflow_runs[0].id, 3);
  assert.equal((await cli('ci', 'view', '3')).conclusion, 'failure');
  assert.equal((await cli('ci', 'jobs', '3')).jobs[0].steps[0].conclusion, 'failure');
  await cli('pr', 'create', '--title', draft.title, '--base', 'main', '--body-file', bodyFile);
  assert.equal(calls.at(-1).payload.draft, true);
  assert.equal(calls.at(-1).payload.head, 'agent/feature');
  assert.equal(calls.at(-1).payload.body, await readFile(bodyFile, 'utf8'));
  await cli('pr', 'comment', '7', '--body-file', bodyFile);
  assert.deepEqual(calls.slice(-2).map((call) => call.operation.resource), ['issues/7', 'issues/7/comments']);
  assert.equal(calls.at(-1).payload.body, await readFile(bodyFile, 'utf8'));
  await cli('pr', 'review', '7', '--body-file', bodyFile);
  assert.equal(calls.at(-1).operation.resource, 'pulls/7/reviews');
  assert.deepEqual(calls.at(-1).payload, { body: await readFile(bodyFile, 'utf8'), event: 'COMMENT' });
  await assert.rejects(cli('pr', 'list', '--repo', 'acme/not-configured'));
  await assert.rejects(cli('pr', 'create', '--title', 'Missing base'));
  await assert.rejects(cli('pr', 'comment', '7'));
});

test('workspace CLI creates a fork PR against --upstream using the origin owner as the head owner', async (t) => {
  const calls = [];
  const f = await fixture({ config: forkConfig('allow'), provider: provider(calls) });
  t.after(f.close);
  await f.git(f.seed, 'remote', 'add', 'origin', 'git@github.com:agent-bot/demo.git');
  await f.git(f.seed, 'switch', '-c', 'agent/feature');
  const tokenFile = join(f.directory, 'client-token');
  await writeFile(tokenFile, f.clientToken, { mode: 0o600 });
  const cli = (...args) => execute(process.execPath, [resolve('src/workspace-cli.js'), ...args], {
    cwd: f.seed, env: { PATH: process.env.PATH, HOME: f.directory, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', AGENTGATE_URL: f.gate.url, AGENTGATE_CLIENT_TOKEN_FILE: tokenFile }
  });
  await cli('pr', 'create', '--title', draft.title, '--base', 'main', '--upstream', 'acme/demo');
  assert.equal(calls.at(-1).repository.name, 'acme/demo');
  assert.equal(calls.at(-1).payload.head, 'agent-bot:agent/feature');
  const records = (await readFile(join(f.directory, 'state', 'audit.jsonl'), 'utf8')).trim().split('\n').map((line) => JSON.parse(line)).filter((record) => record.action === 'github.pr.create');
  assert(records.some((record) => record.type === 'decision') && records.some((record) => record.type === 'execution'));
  for (const record of records) assert.equal(record.headRepository, 'agent-bot/demo', JSON.stringify(record));
  await assert.rejects(cli('pr', 'create', '--title', 't', '--base', 'main', '--upstream', 'acme/demo', '--head', 'x:y'));
});

test('API failures hide upstream bodies and approval stays consumed after provider rejection', async (t) => {
  const f = await fixture({ config: apiConfig(), provider: { api: async () => new Response('secret upstream token', { status: 403 }) } });
  t.after(f.close);
  const pending = await (await create(f)).json();
  await adminRequest(f.gate.adminSocket, 'POST', `/approvals/${pending.requestId}/approve`, { reviewer: 'local:reviewer' });
  const response = await create(f);
  assert.equal(response.status, 502);
  assert(!(await response.text()).includes('secret upstream token'));
  assert.equal(f.gate.state.list()[0].status, 'consumed');
});

test('API audit failure prevents forwarding and response projection removes nested credentials', async (t) => {
  assert(!JSON.stringify(projectApiResponse({ resource: 'pulls/7' }, pull)).includes('never-expose-this'));
  const calls = [];
  const f = await fixture({ config: apiConfig('allow'), provider: provider(calls) });
  t.after(f.close);
  f.gate.state.audit = () => { throw new Error('Full disk'); };
  const response = await create(f);
  assert.equal(response.status, 500);
  await response.arrayBuffer();
  assert.equal(calls.length, 0);
});

// Redirect host observed live on 2026-09-17 against actions/checkout and actions/setup-node:
// productionresultssa7.blob.core.windows.net, status 302 in both cases -- matches LOG_HOST_PATTERN
// without adjustment (see task-7-report.md Step 1 for the full record).
test('job logs follow only allowlisted redirect hosts, without credentials, under a cap', async (t) => {
  const fetched = [];
  const provider = {
    apiRaw: async () => new Response(null, { status: 302, headers: { location: 'https://productionresultssa1.blob.core.windows.net/logs/1?sig=abc' } }),
    fetchLog: async (url, options) => { fetched.push({ url, options }); return new Response('line 1\nline 2\n', { status: 200 }); }
  };
  const config = apiConfig('allow');
  const f = await fixture({ provider, config });
  t.after(() => f.close());
  const response = await fetch(`${f.gate.url}/api/repos/acme/demo/actions/jobs/9/logs`, { headers: f.authHeaders });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('content-type'), 'text/plain; charset=utf-8');
  assert.equal(await response.text(), 'line 1\nline 2\n');
  assert.equal(fetched[0].options.headers?.authorization, undefined);
  assert.equal(fetched[0].options.redirect, 'error');
  assert(LOG_HOST_PATTERN.test('productionresultssa1.blob.core.windows.net'));
  assert(!LOG_HOST_PATTERN.test('evil.blob.core.windows.net.attacker.com'));
  provider.apiRaw = async () => new Response(null, { status: 302, headers: { location: 'https://attacker.example/x' } });
  assert.equal((await fetch(`${f.gate.url}/api/repos/acme/demo/actions/jobs/9/logs`, { headers: f.authHeaders })).status, 502);
});

test('job log downloads are default-deny, deny mismatched methods, and never send GitHub credentials', async (t) => {
  const calls = [];
  const f = await fixture({ provider: { apiRaw: async (request) => { calls.push(request); return new Response(null, { status: 302, headers: { location: 'https://productionresultssa1.blob.core.windows.net/logs/1' } }); } } });
  t.after(f.close);
  const response = await fetch(`${f.gate.url}/api/repos/acme/demo/actions/jobs/9/logs`, { headers: f.authHeaders });
  assert.equal(response.status, 403);
  await response.arrayBuffer();
  assert.equal(calls.length, 0);
  const wrongMethod = await fetch(`${f.gate.url}/api/repos/acme/demo/actions/jobs/9/logs`, { method: 'POST', headers: f.authHeaders });
  assert.equal(wrongMethod.status, 405);
  await wrongMethod.arrayBuffer();
});

test('job log downloads reject non-https and non-redirect upstream responses', async (t) => {
  for (const upstream of [
    async () => new Response(null, { status: 200 }),
    async () => new Response(null, { status: 302, headers: { location: 'http://productionresultssa1.blob.core.windows.net/logs/1' } }),
    async () => new Response(null, { status: 302 })
  ]) {
    const f = await fixture({ config: apiConfig('allow'), provider: { apiRaw: upstream, fetchLog: async () => new Response('should not be reached', { status: 200 }) } });
    t.after(f.close);
    const response = await fetch(`${f.gate.url}/api/repos/acme/demo/actions/jobs/9/logs`, { headers: f.authHeaders });
    assert.equal(response.status, 502);
    await response.arrayBuffer();
  }
});

test('job log downloads reject untrusted storage hosts: suffix attacks, userinfo, ports, trailing dots, and dropped host families', async (t) => {
  for (const location of [
    'https://productionresultssa1.blob.core.windows.net.evil.com/x',
    'https://evil.productionresultssa1.blob.core.windows.net/x',
    'https://user@productionresultssa1.blob.core.windows.net/x',
    'https://user:pass@productionresultssa1.blob.core.windows.net/x',
    'https://productionresultssa1.blob.core.windows.net:8443/x',
    'https://productionresultssa1.blob.core.windows.net./x',
    'https://pipelines.actions.githubusercontent.com/x',
    'https://results-receiver.actions.githubusercontent.com/x',
    'https://productionresultssa1.actions.githubusercontent.com/x'
  ]) {
    const fetched = [];
    const f = await fixture({ config: apiConfig('allow'), provider: {
      apiRaw: async () => new Response(null, { status: 302, headers: { location } }),
      fetchLog: async (url, options) => { fetched.push({ url, options }); return new Response('should not be reached', { status: 200 }); }
    } });
    t.after(f.close);
    const response = await fetch(`${f.gate.url}/api/repos/acme/demo/actions/jobs/9/logs`, { headers: f.authHeaders });
    assert.equal(response.status, 502, `expected 502 for ${location}`);
    await response.arrayBuffer();
    assert.equal(fetched.length, 0, `fetchLog must never be called for ${location}`);
  }
});

test('job log downloads at the 64 MiB cap destroy the connection instead of ending cleanly, and audit the truncation', async (t) => {
  const chunk = Buffer.alloc(8 * 1024 * 1024, 'a');
  const provider = {
    apiRaw: async () => new Response(null, { status: 302, headers: { location: 'https://productionresultssa1.blob.core.windows.net/logs/1' } }),
    fetchLog: async () => new Response(new ReadableStream({
      async pull(controller) {
        for (let i = 0; i < 10; i++) controller.enqueue(chunk);
        controller.close();
      }
    }), { status: 200 })
  };
  const f = await fixture({ config: apiConfig('allow'), provider });
  t.after(f.close);
  const response = await fetch(`${f.gate.url}/api/repos/acme/demo/actions/jobs/9/logs`, { headers: f.authHeaders });
  // Headers are already committed (200) before the cap is known -- a truncated log must never
  // read back as a complete, successful body, so the connection is destroyed mid-stream instead
  // of ending cleanly: reading the body must fail rather than quietly return a short-but-valid one.
  assert.equal(response.status, 200);
  await assert.rejects(response.text(), 'a capped log must not read as a complete, successful body');
  const audit = (await readFile(join(f.directory, 'state', 'audit.jsonl'), 'utf8')).trim().split('\n').map((line) => JSON.parse(line));
  const record = audit.find((entry) => entry.result === 'log-truncated');
  assert(record, 'expected a log-truncated audit record');
  assert.equal(record.truncated, true);
  assert.equal(record.bytes, 64 * 1024 * 1024);
  assert(!JSON.stringify(record).includes('blob.core.windows.net'), 'audit record must never include the storage host/URL');
});

test('a client that disconnects mid-download while backpressured does not hang the handler', async (t) => {
  let cancelled = false;
  let push;
  const bodyStream = new ReadableStream({
    start(controller) { push = (chunk) => controller.enqueue(chunk); },
    cancel() { cancelled = true; }
  });
  const f = await fixture({ config: apiConfig('allow'), provider: {
    apiRaw: async () => new Response(null, { status: 302, headers: { location: 'https://productionresultssa1.blob.core.windows.net/logs/1' } }),
    fetchLog: async () => new Response(bodyStream, { status: 200 })
  } });
  t.after(f.close);
  const unhandled = [];
  const onUnhandledRejection = (reason) => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandledRejection);
  try {
    // Node only flushes response headers together with the first body write, not on writeHead()
    // alone -- so a first, tiny chunk is queued before the request even starts, letting the
    // client's fetch() resolve promptly instead of waiting on data that is deliberately withheld.
    push(Buffer.from('start\n'));
    const controller = new AbortController();
    const response = await fetch(`${f.gate.url}/api/repos/acme/demo/actions/jobs/9/logs`, { headers: f.authHeaders, signal: controller.signal });
    assert.equal(response.status, 200);
    // Push enough data to exceed Node's default write buffer, so the server's response.write
    // returns false and streaming is backpressured -- exactly the state in which the old manual
    // write/drain loop never settled after a disconnect (a destroyed response never emits 'drain').
    push(Buffer.alloc(4 * 1024 * 1024, 'a'));
    controller.abort();
    await assert.rejects(response.text());
    // If the handler hung on 'drain', pipeline would never destroy the source and this stream's
    // cancel() would never fire; poll for it with a short, explicit bound so a regression fails
    // fast and clearly instead of relying on the overall test timeout.
    const settled = await Promise.race([
      (async () => { while (!cancelled) await new Promise((resolve) => setTimeout(resolve, 20)); return true; })(),
      new Promise((resolve) => setTimeout(() => resolve(false), 5000))
    ]);
    assert(settled, 'server never released the upstream log body after the client disconnected (handler hung)');
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(unhandled, [], 'no unhandled rejection should fire on client disconnect');
  } finally {
    process.off('unhandledRejection', onUnhandledRejection);
  }
});

test('workspace CLI downloads a job log to a file with restrictive permissions and refuses to overwrite', async (t) => {
  const f = await fixture({ config: apiConfig('allow'), provider: { apiRaw: async () => new Response(null, { status: 302, headers: { location: 'https://productionresultssa1.blob.core.windows.net/logs/1' } }), fetchLog: async () => new Response('line 1\nline 2\n', { status: 200 }) } });
  t.after(f.close);
  await f.git(f.seed, 'remote', 'add', 'origin', 'git@github.com:acme/demo.git');
  const tokenFile = join(f.directory, 'client-token');
  await writeFile(tokenFile, f.clientToken, { mode: 0o600 });
  const outFile = join(f.directory, 'job-9.log');
  const cliEnv = { PATH: process.env.PATH, HOME: f.directory, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', AGENTGATE_URL: f.gate.url, AGENTGATE_CLIENT_TOKEN_FILE: tokenFile };
  await execute(process.execPath, [resolve('src/workspace-cli.js'), 'ci', 'logs', '9', '--output', outFile], { cwd: f.seed, env: cliEnv });
  assert.equal(await readFile(outFile, 'utf8'), 'line 1\nline 2\n');
  const { mode } = await (await import('node:fs/promises')).stat(outFile);
  assert.equal(mode & 0o777, 0o600);
  await assert.rejects(execute(process.execPath, [resolve('src/workspace-cli.js'), 'ci', 'logs', '9', '--output', outFile], { cwd: f.seed, env: cliEnv }));
  await execute(process.execPath, [resolve('src/workspace-cli.js'), 'ci', 'logs', '9', '--output', outFile, '--force'], { cwd: f.seed, env: cliEnv });
});

test('workspace CLI detects an incomplete (truncated) log download, exits non-zero with a clear message, and leaves no output file behind', async (t) => {
  const chunk = Buffer.alloc(8 * 1024 * 1024, 'a');
  const provider = {
    apiRaw: async () => new Response(null, { status: 302, headers: { location: 'https://productionresultssa1.blob.core.windows.net/logs/1' } }),
    fetchLog: async () => new Response(new ReadableStream({
      async pull(controller) {
        for (let i = 0; i < 10; i++) controller.enqueue(chunk);
        controller.close();
      }
    }), { status: 200 })
  };
  const f = await fixture({ config: apiConfig('allow'), provider });
  t.after(f.close);
  await f.git(f.seed, 'remote', 'add', 'origin', 'git@github.com:acme/demo.git');
  const tokenFile = join(f.directory, 'client-token');
  await writeFile(tokenFile, f.clientToken, { mode: 0o600 });
  const outFile = join(f.directory, 'incomplete-job-9.log');
  const cliEnv = { PATH: process.env.PATH, HOME: f.directory, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', AGENTGATE_URL: f.gate.url, AGENTGATE_CLIENT_TOKEN_FILE: tokenFile };
  await assert.rejects(
    execute(process.execPath, [resolve('src/workspace-cli.js'), 'ci', 'logs', '9', '--output', outFile], { cwd: f.seed, env: cliEnv }),
    (error) => {
      assert.notEqual(error.code, 0);
      assert.match(error.stderr, /interrupted/i);
      return true;
    }
  );
  await assert.rejects(access(outFile), 'no output file should exist after an interrupted download');
});

test('fork heads require a configured fork and a matching headRepository rule', () => {
  const forks = [{ owner: 'agent-bot', name: 'agent-bot/demo' }];
  const payload = (head) => Buffer.from(JSON.stringify({ title: 't', head, base: 'main' }));
  assert.equal(pullRequestPayload(payload('agent-bot:agent/x'), { forks }).head, 'agent-bot:agent/x');
  assert.throws(() => pullRequestPayload(payload('someone:agent/x'), { forks }), { code: 'INVALID_API_REQUEST' });
  assert.throws(() => pullRequestPayload(payload('agent-bot:agent/x'), { forks: [] }), { code: 'INVALID_API_REQUEST' });
  const config = validateConfig({
    runtime: { human: 'h', agent: 'a', runtimeId: 'r', task: 't' },
    repositories: [{ name: 'acme/demo', id: 1, installationId: 2 }, { name: 'agent-bot/demo', id: 9, installationId: 3, forkOf: 'acme/demo' }],
    rules: [
      { id: 'same', action: 'github.pr.create', repository: 'acme/demo', ref: 'refs/heads/agent/*', effect: 'allow' },
      { id: 'fork', action: 'github.pr.create', repository: 'acme/demo', ref: 'refs/heads/agent/*', headRepository: 'agent-bot/demo', effect: 'approval' }
    ]
  });
  assert.equal(decide(config, 'github.pr.create', 'acme/demo', { ref: 'refs/heads/agent/x' }).effect, 'allow');
  assert.equal(decide(config, 'github.pr.create', 'acme/demo', { ref: 'refs/heads/agent/x', headRepository: 'agent-bot/demo' }).effect, 'approval');
  assert.equal(decide(config, 'github.pr.create', 'acme/demo', { ref: 'refs/heads/agent/x', headRepository: 'other/demo' }).effect, 'deny');
});

test('fork head syntax: one colon, GitHub owner syntax, valid branch, case-insensitive owner, ambiguous owners rejected', () => {
  const forks = [{ owner: 'agent-bot', name: 'agent-bot/demo' }];
  const payload = (head, base = 'main') => Buffer.from(JSON.stringify({ title: 't', head, base }));
  assert.equal(pullRequestPayload(payload('Agent-Bot:agent/x'), { forks }).head, 'Agent-Bot:agent/x');
  assert.equal(pullRequestPayload(payload('agent-bot:main'), { forks }).head, 'agent-bot:main');
  for (const head of ['agent-bot:a:b', ':agent/x', 'agent-bot:', 'agent-bot:../x', 'agent_bot:agent/x', `${'a'.repeat(40)}:x`, 'agent-bot:-x']) {
    assert.throws(() => pullRequestPayload(payload(head), { forks: [...forks, { owner: 'agent_bot', name: 'agent_bot/demo' }, { owner: 'a'.repeat(40), name: `${'a'.repeat(40)}/demo` }] }), { code: 'INVALID_API_REQUEST' }, head);
  }
  assert.throws(() => pullRequestPayload(payload('agent-bot:agent/x'), { forks: [...forks, { owner: 'agent-bot', name: 'agent-bot/demo2' }] }), { code: 'INVALID_API_REQUEST' });
  assert.throws(() => pullRequestPayload(payload('agent-bot:agent/x')), { code: 'INVALID_API_REQUEST' });
  const config = validateConfig({
    runtime: { human: 'h', agent: 'a', runtimeId: 'r', task: 't' },
    repositories: [{ name: 'acme/demo', id: 1, installationId: 2 }, { name: 'agent-bot/demo', id: 9, installationId: 3, forkOf: 'acme/demo' },
      { name: 'acme/other', id: 5, installationId: 2 }, { name: 'bot2/other', id: 6, installationId: 3, forkOf: 'acme/other' }],
    rules: [{ id: 'any', action: 'github.pr.create', repository: '*', ref: '*', headRepository: '*', effect: 'allow' }]
  });
  assert.equal(decide(config, 'github.pr.create', 'acme/demo', { ref: 'refs/heads/x', headRepository: 'agent-bot/demo' }).effect, 'allow');
  // '*' only covers configured forks of the target, and never same-repository heads.
  assert.equal(decide(config, 'github.pr.create', 'acme/demo', { ref: 'refs/heads/x', headRepository: 'bot2/other' }).effect, 'deny');
  assert.equal(decide(config, 'github.pr.create', 'acme/demo', { ref: 'refs/heads/x' }).effect, 'deny');
});

function forkConfig(effect, headRepository = 'agent-bot/demo') {
  const config = exampleConfig();
  config.repositories.push({ name: 'agent-bot/demo', id: 9, installationId: 3, forkOf: 'acme/demo' }, { name: 'unread/demo', id: 10, installationId: 3, forkOf: 'acme/demo' });
  config.rules.push(
    { id: 'fork-read', action: 'git.read', repository: 'agent-bot/demo', effect: 'allow' },
    { id: 'pr-same', action: 'github.pr.create', repository: 'acme/demo', ref: 'refs/heads/agent/*', effect: 'allow' },
    { id: 'pr-fork', action: 'github.pr.create', repository: 'acme/demo', ref: 'refs/heads/agent/*', headRepository, effect }
  );
  return config;
}

test('fork PR creation through the broker: allowed by headRepository rule, rejected for unconfigured or unreadable forks', async (t) => {
  const calls = [];
  const f = await fixture({ config: forkConfig('allow'), provider: provider(calls) });
  t.after(f.close);
  const ok = await create(f, { ...draft, head: 'agent-bot:agent/feature' });
  assert.equal(ok.status, 201);
  await ok.arrayBuffer();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].repository.name, 'acme/demo');
  assert.equal(calls[0].payload.head, 'agent-bot:agent/feature');
  assert.deepEqual(calls[0].operation.permissions, { pull_requests: 'write' });
  for (const head of ['someone:agent/feature', 'unread:agent/feature', 'agent-bot:agent/x:y']) {
    const response = await create(f, { ...draft, head });
    assert.equal(response.status, 400, head);
    assert.equal((await response.json()).code, 'INVALID_API_REQUEST');
  }
  const outside = await create(f, { ...draft, head: 'agent-bot:feature' });
  assert.equal((await outside.json()).code, 'DENIED');
  assert.equal(calls.length, 1);
});

test('fork PR creation is denied when only same-repository rules exist', async (t) => {
  const calls = [];
  const config = forkConfig('allow');
  config.rules = config.rules.filter((rule) => rule.id !== 'pr-fork');
  const f = await fixture({ config, provider: provider(calls) });
  t.after(f.close);
  const response = await create(f, { ...draft, head: 'agent-bot:agent/feature' });
  assert.equal((await response.json()).code, 'DENIED');
  assert.equal(calls.length, 0);
});

test('fork PR approvals bind headRepository', async (t) => {
  const calls = [];
  const notified = [];
  const f = await fixture({ config: forkConfig('approval', '*'), provider: provider(calls), notify: (item) => notified.push(item) });
  t.after(f.close);
  const first = await create(f, { ...draft, head: 'agent-bot:agent/feature' });
  const pending = await first.json();
  assert.equal(pending.code, 'REQUIRE_APPROVAL');
  assert.equal(notified[0].context.headRepository, 'agent-bot/demo');
  await adminRequest(f.gate.adminSocket, 'POST', `/approvals/${pending.requestId}/approve`, { reviewer: 'local:reviewer' });
  // The grant is keyed on the fork context: a same-branch same-repository PR (a different
  // decision path) must not consume it, and the fork retry consumes it exactly once.
  const same = await create(f, { ...draft, head: 'agent/feature' });
  assert.equal(same.status, 201);
  await same.arrayBuffer();
  const ok = await create(f, { ...draft, head: 'agent-bot:agent/feature' });
  assert.equal(ok.status, 201);
  await ok.arrayBuffer();
  assert.equal(calls.at(-1).payload.head, 'agent-bot:agent/feature');
  const replay = await create(f, { ...draft, head: 'agent-bot:agent/feature' });
  assert.equal((await replay.json()).code, 'REQUIRE_APPROVAL');
  const approvals = (await adminRequest(f.gate.adminSocket, 'GET', '/approvals'));
  assert(JSON.stringify(approvals).includes('agent-bot/demo'));
});

test('merges require approval, pin the head SHA, and refuse drafts or moved heads', async (t) => {
  const sha = 'a'.repeat(40);
  let head = sha;
  const calls = [];
  const provider = { api: async ({ operation, payload }) => {
    calls.push({ method: operation.method, path: operation.path, payload });
    if (operation.method === 'GET') return Response.json({ number: 5, state: 'open', draft: false, head: { ref: 'agent/x', sha: head, repo: { full_name: 'acme/demo' } }, base: { ref: 'main', sha: 'b'.repeat(40) } });
    return Response.json({ merged: true, sha: 'c'.repeat(40), message: 'Pull Request successfully merged' });
  } };
  const config = exampleConfig();
  config.rules.push({ id: 'merge-main', action: 'github.pr.merge', repository: 'acme/demo', ref: 'refs/heads/main', effect: 'approval', mergeMethods: ['squash'] });
  const f = await fixture({ provider, config });
  t.after(() => f.close());
  const merge = (body) => fetch(`${f.gate.url}/api/repos/acme/demo/pulls/5/merge`, { method: 'PUT', headers: { ...f.authHeaders, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  assert.equal((await merge({ sha, merge_method: 'rebase' })).status, 403);
  const pending = await merge({ sha, merge_method: 'squash' });
  assert.equal(pending.status, 403);
  const { requestId } = await pending.json();
  await adminRequest(f.gate.adminSocket, 'POST', `/approvals/${requestId}/approve`, { reviewer: 'local:reviewer' });
  head = 'd'.repeat(40);
  const moved = await merge({ sha, merge_method: 'squash' });
  assert.equal(moved.status, 409);
  assert.equal((await moved.json()).code, 'HEAD_MOVED');
  head = sha;
  const merged = await merge({ sha, merge_method: 'squash' });
  assert.equal(merged.status, 200);
  assert.deepEqual(await merged.json(), { merged: true, sha: 'c'.repeat(40) });
  assert.deepEqual(calls.filter((call) => call.method === 'PUT').map((call) => call.payload), [{ sha, merge_method: 'squash' }]);
  assert.throws(() => validateConfig({ ...config, rules: [{ id: 'm', action: 'github.pr.merge', repository: 'acme/demo', ref: 'refs/heads/main', effect: 'allow' }] }), /github.pr.merge/);
});

const mergeSha = 'a'.repeat(40);

function mergeProvider(state, calls) {
  return { api: async ({ repository, operation, payload }) => {
    calls.push({ repository: repository.name, method: operation.method, path: operation.path, permissions: operation.permissions, payload });
    if (operation.method === 'GET') {
      state.gets = (state.gets ?? 0) + 1;
      state.beforeGet?.(state.gets);
      if (state.getStatus) return new Response('UPSTREAM SECRET DETAIL', { status: state.getStatus });
      return Response.json({ number: 5, title: state.title ?? 'Ship it', state: state.state ?? 'open', draft: state.draft ?? false,
        head: { ref: 'agent/x', sha: state.head ?? mergeSha, repo: state.headRepo === undefined ? { full_name: 'acme/demo' } : state.headRepo },
        base: { ref: state.base ?? 'main', sha: 'b'.repeat(40) } });
    }
    if (state.putStatus) return Response.json({ message: 'UPSTREAM SECRET DETAIL', documentation_url: 'x' }, { status: state.putStatus });
    return Response.json({ merged: true, sha: 'c'.repeat(40), message: 'merged', token: 'never-expose-this' });
  } };
}

function mergeConfig(rules) {
  const config = exampleConfig();
  config.repositories.push({ name: 'agent-bot/demo', id: 9, installationId: 3, forkOf: 'acme/demo' }, { name: 'stranger/demo', id: 10, installationId: 3 });
  config.rules.push(...rules);
  return config;
}

async function mergeFixture(t, rules, state = {}, extra = {}) {
  const calls = [];
  const notified = [];
  const f = await fixture({ config: mergeConfig(rules), provider: mergeProvider(state, calls), notify: (item) => notified.push(item), ...extra });
  t.after(() => f.close());
  const merge = async (body = { sha: mergeSha, merge_method: 'squash' }, number = 5) => {
    const response = await fetch(`${f.gate.url}/api/repos/acme/demo/pulls/${number}/merge`, { method: 'PUT', headers: { ...f.authHeaders, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  };
  const approve = (id) => adminRequest(f.gate.adminSocket, 'POST', `/approvals/${id}/approve`, { reviewer: 'local:reviewer' });
  return { f, calls, notified, merge, approve };
}

const mainMerge = { id: 'merge-main', action: 'github.pr.merge', repository: 'acme/demo', ref: 'refs/heads/main', effect: 'approval' };

test('merge route, payload, and config validation are strict', () => {
  const operation = routeApi({ method: 'PUT', url: '/api/repos/Acme/demo/pulls/5/merge' });
  assert.deepEqual(pickRoute(operation), { action: 'github.pr.merge', permissions: { contents: 'write' }, path: 'pulls/5/merge' });
  assert.equal(operation.kind, 'merge');
  assert.deepEqual(mergePayload(Buffer.from(JSON.stringify({ sha: mergeSha, merge_method: 'rebase' }))), { sha: mergeSha, merge_method: 'rebase' });
  for (const input of [{ sha: mergeSha }, { sha: 'A'.repeat(40), merge_method: 'squash' }, { sha: 'a'.repeat(39), merge_method: 'squash' },
    { sha: mergeSha, merge_method: 'fast-forward' }, { sha: mergeSha, merge_method: 'squash', commit_title: 'x' }, [], null]) {
    assert.throws(() => mergePayload(Buffer.from(JSON.stringify(input))), { code: 'INVALID_API_REQUEST' }, JSON.stringify(input));
  }
  assert.throws(() => mergePayload(Buffer.from('{')), { code: 'INVALID_API_REQUEST' });
  const base = exampleConfig();
  const check = (rule) => validateConfig({ ...base, rules: [rule] });
  assert.doesNotThrow(() => check({ ...mainMerge, mergeMethods: ['squash', 'rebase'], approvals: 2, reviewerSources: ['oidc'] }));
  assert.doesNotThrow(() => check({ ...mainMerge, effect: 'deny' }));
  assert.throws(() => check({ ...mainMerge, effect: 'allow' }), /github.pr.merge/);
  assert.throws(() => check({ ...mainMerge, mergeMethods: [] }), /mergeMethods/);
  assert.throws(() => check({ ...mainMerge, mergeMethods: ['octopus'] }), /mergeMethods/);
  assert.throws(() => check({ ...mainMerge, mergeMethods: 'squash' }), /mergeMethods/);
  assert.throws(() => check({ ...mainMerge, operation: 'update' }), /operation/);
  assert.throws(() => check({ ...mainMerge, ref: undefined }), /ref/);
  assert.throws(() => check({ id: 'x', action: 'git.push', repository: 'acme/demo', ref: 'refs/heads/main', effect: 'allow', mergeMethods: ['squash'] }), /mergeMethods/);
});

test('merge denials (method, base, draft, closed, moved head) never consume an approval or reach the merge endpoint', async (t) => {
  const state = {};
  const { calls, merge, approve, f } = await mergeFixture(t, [mainMerge], state);
  const first = await merge();
  assert.equal(first.body.code, 'REQUIRE_APPROVAL');
  await approve(first.body.requestId);
  // Default mergeMethods is squash only; a denied method is not an approval request.
  assert.equal((await merge({ sha: mergeSha, merge_method: 'merge' })).body.code, 'DENIED');
  state.draft = true;
  assert.deepEqual([(await merge()).status, (await merge()).body.code], [409, 'PR_NOT_MERGEABLE']);
  state.draft = false;
  state.state = 'closed';
  assert.equal((await merge()).body.code, 'PR_NOT_MERGEABLE');
  state.state = 'open';
  state.base = 'develop';
  assert.equal((await merge()).body.code, 'DENIED');
  state.base = 'main';
  state.head = 'd'.repeat(40);
  assert.equal((await merge()).body.code, 'HEAD_MOVED');
  state.head = mergeSha;
  assert.equal(calls.filter((call) => call.method === 'PUT').length, 0);
  assert.equal((await adminRequest(f.gate.adminSocket, 'GET', '/approvals')).length, 1);
  // Title edits between retries do not change the approval key.
  state.title = 'Renamed while waiting';
  const ok = await merge();
  assert.equal(ok.status, 200);
  assert.deepEqual(ok.body, { merged: true, sha: 'c'.repeat(40) });
  const put = calls.filter((call) => call.method === 'PUT');
  assert.deepEqual(put.map((call) => [call.path, call.permissions, call.payload]), [['pulls/5/merge', { contents: 'write' }, { sha: mergeSha, merge_method: 'squash' }]]);
  assert.deepEqual(calls.filter((call) => call.method === 'GET').map((call) => call.permissions), Array(9).fill({ pull_requests: 'read' }));
  assert.equal((await merge()).body.code, 'REQUIRE_APPROVAL');
});

test('merge approvals bind number, sha, base, and method, and show the PR title', async (t) => {
  const { merge, approve, notified } = await mergeFixture(t, [{ ...mainMerge, mergeMethods: ['squash', 'rebase'] }]);
  const first = await merge();
  assert.equal(first.body.code, 'REQUIRE_APPROVAL');
  const context = notified[0].context;
  assert.deepEqual({ ...context, runtime: undefined, policyHash: undefined },
    { runtime: undefined, policyHash: undefined, repository: 'acme/demo', action: 'github.pr.merge', number: 5, sha: mergeSha, base: 'main', mergeMethod: 'squash', title: 'Ship it' });
  await approve(first.body.requestId);
  assert.equal((await merge({ sha: mergeSha, merge_method: 'rebase' })).body.code, 'REQUIRE_APPROVAL');
  assert.equal((await merge(undefined, 6)).body.code, 'REQUIRE_APPROVAL');
  assert.equal((await merge()).status, 200);
});

test('fork PR merges require a configured fork and a matching headRepository rule', async (t) => {
  const state = { headRepo: { full_name: 'Agent-Bot/demo' } };
  const { merge, approve, notified, calls } = await mergeFixture(t, [mainMerge], state);
  // Same-repository rules never cover a fork head.
  assert.equal((await merge()).body.code, 'DENIED');
  const withFork = await mergeFixture(t, [mainMerge, { ...mainMerge, id: 'merge-fork', headRepository: 'agent-bot/demo' }], state);
  const pending = await withFork.merge();
  assert.equal(pending.body.code, 'REQUIRE_APPROVAL');
  assert.equal(withFork.notified[0].context.headRepository, 'agent-bot/demo');
  await withFork.approve(pending.body.requestId);
  assert.equal((await withFork.merge()).status, 200);
  const forkAudit = (await readFile(join(withFork.f.directory, 'state', 'audit.jsonl'), 'utf8')).trim().split('\n').map((line) => JSON.parse(line)).filter((record) => record.action === 'github.pr.merge');
  assert.deepEqual([...new Set(forkAudit.map((record) => `${record.type}:${record.decision ?? record.result}`))].sort(), ['decision:allow', 'decision:approval', 'execution:upstream-response']);
  for (const record of forkAudit) assert.equal(record.headRepository, 'agent-bot/demo', JSON.stringify(record));
  for (const headRepo of [{ full_name: 'stranger/demo' }, { full_name: 'unknown/demo' }, null, {}]) {
    state.headRepo = headRepo;
    const star = await mergeFixture(t, [{ ...mainMerge, headRepository: '*' }], state);
    assert.equal((await star.merge()).body.code, 'DENIED', JSON.stringify(headRepo));
    assert.equal(star.calls.filter((call) => call.method === 'PUT').length, 0);
  }
  assert.equal(notified.length, 0);
  assert.equal(calls.filter((call) => call.method === 'PUT').length, 0);
  const policy = validateConfig(mergeConfig([{ ...mainMerge, headRepository: 'agent-bot/demo' }]));
  assert.equal(decide(policy, 'github.pr.merge', 'acme/demo', { ref: 'refs/heads/main', headRepository: 'agent-bot/demo' }).effect, 'approval');
  assert.equal(decide(policy, 'github.pr.merge', 'acme/demo', { ref: 'refs/heads/main', headRepository: 'stranger/demo' }).effect, 'deny');
});

test('the merge re-reads the PR right before the PUT and aborts if the base or head changed', async (t) => {
  for (const [change, code, result] of [[{ base: 'develop' }, 'BASE_CHANGED', 'base-changed'], [{ head: 'd'.repeat(40) }, 'HEAD_MOVED', 'head-moved']]) {
    const state = {};
    const { f, calls, merge, approve } = await mergeFixture(t, [mainMerge, { ...mainMerge, id: 'merge-develop', ref: 'refs/heads/develop' }], state);
    await approve((await merge()).body.requestId);
    // The pre-check (GET 2) still sees the approved PR; the base/head changes before the re-read (GET 3).
    state.beforeGet = (count) => { if (count === 3) Object.assign(state, change); };
    const aborted = await merge();
    assert.deepEqual([aborted.status, aborted.body.code], [409, code]);
    assert.equal(state.gets, 3);
    assert.equal(calls.filter((call) => call.method === 'PUT').length, 0);
    // The approval was consumed before the re-read, so the abort needs a new approval.
    assert.equal(f.gate.state.list()[0].status, 'consumed');
    const audit = await readFile(join(f.directory, 'state', 'audit.jsonl'), 'utf8');
    const record = audit.trim().split('\n').map((line) => JSON.parse(line)).find((item) => item.result === result && item.type === 'execution');
    assert.equal(record.approvalId, f.gate.state.list()[0].id);
  }
});

test('merge PR reads map 403/404 to 404 and GitHub 5xx to 502, before and after approval', async (t) => {
  for (const [getStatus, status] of [[404, 404], [403, 404], [500, 502], [503, 502]]) {
    const state = { getStatus };
    const { calls, merge, approve } = await mergeFixture(t, [mainMerge], state);
    const response = await merge();
    assert.deepEqual([response.status, response.body.code], [status, 'UPSTREAM_FAILED'], String(getStatus));
    assert(!JSON.stringify(response.body).includes('UPSTREAM SECRET DETAIL'));
    delete state.getStatus;
    await approve((await merge()).body.requestId);
    state.beforeGet = (count) => { if (count === 3) state.getStatus = getStatus; };
    const late = await merge();
    assert.deepEqual([late.status, late.body.code], [status, 'UPSTREAM_FAILED'], `re-read ${getStatus}`);
    assert.equal(calls.filter((call) => call.method === 'PUT').length, 0);
  }
});

test('merge upstream rejections map to clean 409/422 without upstream bodies', async (t) => {
  for (const [putStatus, status, code] of [[405, 409, 'PR_NOT_MERGEABLE'], [409, 409, 'HEAD_MOVED'], [422, 422, 'MERGE_REJECTED'], [403, 502, 'UPSTREAM_FAILED']]) {
    const state = { putStatus };
    const { merge, approve } = await mergeFixture(t, [mainMerge], state);
    await approve((await merge()).body.requestId);
    const response = await merge();
    assert.deepEqual([response.status, response.body.code], [status, code], String(putStatus));
    assert(!JSON.stringify(response.body).includes('UPSTREAM SECRET DETAIL'));
    // The approval is spent once the merge was attempted upstream.
    delete state.putStatus;
    assert.equal((await merge()).body.code, 'REQUIRE_APPROVAL');
  }
});

test('workspace CLI merges with a full sha and defaults to squash', async (t) => {
  const { f, calls, merge, approve } = await mergeFixture(t, [{ ...mainMerge, mergeMethods: ['squash', 'rebase'] }]);
  await f.git(f.seed, 'remote', 'add', 'origin', 'git@github.com:acme/demo.git');
  const tokenFile = join(f.directory, 'client-token');
  await writeFile(tokenFile, f.clientToken, { mode: 0o600 });
  const cli = (...args) => execute(process.execPath, [resolve('src/workspace-cli.js'), ...args], {
    cwd: f.seed, env: { PATH: process.env.PATH, HOME: f.directory, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', AGENTGATE_URL: f.gate.url, AGENTGATE_CLIENT_TOKEN_FILE: tokenFile }
  });
  await approve((await merge()).body.requestId);
  assert.deepEqual(JSON.parse((await cli('pr', 'merge', '5', '--sha', mergeSha)).stdout), { merged: true, sha: 'c'.repeat(40) });
  assert.deepEqual(calls.at(-1).payload, { sha: mergeSha, merge_method: 'squash' });
  await assert.rejects(cli('pr', 'merge', '5', '--sha', mergeSha, '--method', 'rebase'), /REQUIRE_APPROVAL/);
  await assert.rejects(cli('pr', 'merge', '5'), /--sha/);
  await assert.rejects(cli('pr', 'merge', '5', '--sha', 'abc1234'), /40/);
  await assert.rejects(cli('pr', 'merge', '5', '--sha', mergeSha, '--method', 'octopus'), /method/);
  assert.equal(calls.filter((call) => call.method === 'PUT').length, 1);
});
