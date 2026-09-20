import test from 'node:test';
import assert from 'node:assert/strict';
import { createNotifier } from '../src/notify.js';
import { fixture, pushBody, exampleConfig } from './support/fixture.js';

const silent = { info() {}, warn() {}, error() {} };

test('notifier posts a concise Slack-compatible message and swallows failures', async () => {
  const calls = [];
  const notify = createNotifier({ url: 'https://hooks.example/x', approvalUrl: 'https://approvals.example', logger: silent,
    fetchImpl: async (url, options) => { calls.push({ url, options }); return new Response(null, { status: 500 }); } });
  notify({ id: 'abcd1234-0000-0000-0000-000000000000', requiredApprovals: 2, expiresAt: 0,
    context: { repository: 'acme/demo', runtime: { agent: 'bot', human: 'dev@example.com', task: 'ship feature' }, changes: [{ ref: 'refs/heads/main', oldOid: '1'.repeat(40), newOid: '2'.repeat(40) }], payload: { body: 'SECRET BODY' } } });
  await new Promise((resolve) => setImmediate(resolve));
  const text = JSON.parse(calls[0].options.body).text;
  assert.match(text, /abcd1234/);
  assert.match(text, /acme\/demo/);
  assert.match(text, /Agent bot for dev@example\.com · task ship feature/);
  assert.match(text, /refs\/heads\/main 111111111111 → 222222222222/);
  assert.match(text, /0\/2 approvals/);
  assert.match(text, /https:\/\/approvals\.example/);
  assert(!text.includes('SECRET BODY'));
  assert.equal(calls[0].options.redirect, 'error');
  assert.doesNotThrow(() => createNotifier({ logger: silent })({}));
  assert.throws(() => createNotifier({ url: 'http://insecure', logger: silent }), /https/);
});

test('notifier neutralizes Slack mention/markup injection in agent-controlled fields', async () => {
  const calls = [];
  const notify = createNotifier({ url: 'https://hooks.example/x', logger: silent,
    fetchImpl: async (url, options) => { calls.push({ url, options }); return new Response(null, { status: 200 }); } });
  notify({ id: 'inj12345-0000-0000-0000-000000000000', requiredApprovals: 1, expiresAt: 0,
    context: {
      repository: 'acme/demo', action: 'github.pr.create',
      runtime: { agent: '<!channel> bot', human: '<@U123456>', task: 'notify <!channel> now' },
      payload: { head: '<@U123>-branch', base: 'main', title: 'line one\nline two <!channel>', body: 'SECRET BODY' }
    } });
  await new Promise((resolve) => setImmediate(resolve));
  const text = JSON.parse(calls[0].options.body).text;
  assert(!text.includes('<!channel>'));
  assert(!text.includes('<@U123456>'));
  assert(!text.includes('<@U123>'));
  assert(!text.includes('SECRET BODY'));
  // The hostile task value must be escaped, not just absent from the whole text: check the
  // specific line it appears on.
  const agentLine = text.split('\n').find((line) => line.startsWith('Agent '));
  assert.ok(agentLine);
  assert.match(agentLine, /task notify &lt;!channel&gt; now/);
  assert(!agentLine.includes('<!channel>'));
  // The title's embedded newline must not survive as a raw newline inside the PR bullet line.
  const prLine = text.split('\n').find((line) => line.includes('line one'));
  assert.ok(prLine);
  assert(!prLine.includes('\n'));
  assert.match(prLine, /line one line two/);
});

test('a non-ASCII ref is shown with its exact code points alongside the literal ref in the Slack message', async () => {
  const calls = [];
  const notify = createNotifier({ url: 'https://hooks.example/x', logger: silent,
    fetchImpl: async (url, options) => { calls.push({ url, options }); return new Response(null, { status: 200 }); } });
  notify({ id: 'uni12345-0000-0000-0000-000000000000', requiredApprovals: 1, expiresAt: 0,
    context: { repository: 'acme/demo', changes: [
      { ref: 'refs/heads/agent/café', oldOid: '1'.repeat(40), newOid: '2'.repeat(40) },
      { ref: 'refs/heads/main', oldOid: '1'.repeat(40), newOid: '2'.repeat(40) }
    ] } });
  await new Promise((resolve) => setImmediate(resolve));
  const text = JSON.parse(calls[0].options.body).text;
  assert.match(text, /refs\/heads\/agent\/café \(refs\/heads\/agent\/caf\\u00e9\) 111111111111 → 222222222222/);
  // The second, ASCII-only ref must render exactly as before -- no added "(\u....)" suffix.
  assert.match(text, /refs\/heads\/main 111111111111 → 222222222222/);
  assert.equal((text.match(/\\u/g) ?? []).length, 1);
});

test('broker notifies once per new approval request, not on retries', async (t) => {
  const seen = [];
  const f = await fixture({ notify: (item) => seen.push(item.id) });
  t.after(() => f.close());
  for (let i = 0; i < 2; i++) {
    const response = await fetch(`${f.remote}/git-receive-pack`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/x-git-receive-pack-request' }, body: pushBody() });
    await response.arrayBuffer();
  }
  assert.equal(seen.length, 1);
});

test('a synchronously throwing notifier does not break the approval response', async (t) => {
  const f = await fixture({ notify: () => { throw new Error('boom'); } });
  t.after(() => f.close());
  const response = await fetch(`${f.remote}/git-receive-pack`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/x-git-receive-pack-request' }, body: pushBody() });
  const body = await response.json();
  assert.equal(response.status, 403);
  assert.equal(body.code, 'REQUIRE_APPROVAL');
});

function prApprovalConfig() {
  const config = exampleConfig();
  config.rules.push({ id: 'pr-create', action: 'github.pr.create', repository: 'acme/demo', ref: 'refs/heads/agent/*', effect: 'approval' });
  return config;
}

const prDraft = { title: 'Implement feature', head: 'agent/feature', base: 'main', body: 'Description', draft: true };

function createPr(f, payload = prDraft) {
  return fetch(`${f.gate.url}/api/repos/acme/demo/pulls`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/json' }, body: JSON.stringify(payload) });
}

test('broker notifies once per new PR-create approval request, not on retries (github-api.js)', async (t) => {
  const seen = [];
  const provider = { api: async () => Response.json({ number: 1 }, { status: 201 }) };
  const f = await fixture({ config: prApprovalConfig(), provider, notify: (item) => seen.push(item.id) });
  t.after(() => f.close());
  for (let i = 0; i < 2; i++) {
    const response = await createPr(f);
    await response.arrayBuffer();
  }
  assert.equal(seen.length, 1);
});

test('a synchronously throwing notifier does not break the PR-create approval response (github-api.js)', async (t) => {
  const provider = { api: async () => Response.json({ number: 1 }, { status: 201 }) };
  const f = await fixture({ config: prApprovalConfig(), provider, notify: () => { throw new Error('boom'); } });
  t.after(() => f.close());
  const response = await createPr(f);
  const body = await response.json();
  assert.equal(response.status, 403);
  assert.equal(body.code, 'REQUIRE_APPROVAL');
});

test('a newly created approval is notified even when the approval decision audit then fails (push and PR paths)', async (t) => {
  const seen = [];
  const provider = { api: async () => Response.json({ number: 1 }, { status: 201 }) };
  const f = await fixture({ config: prApprovalConfig(), provider, notify: (item) => seen.push(item.id) });
  t.after(() => f.close());
  const audit = f.gate.state.audit.bind(f.gate.state);
  f.gate.state.audit = (event) => {
    if (event.type === 'decision' && event.decision === 'approval') throw new Error('Simulated audit failure');
    return audit(event);
  };
  const pushed = await fetch(`${f.remote}/git-receive-pack`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/x-git-receive-pack-request' }, body: pushBody() });
  assert.equal(pushed.status, 500);
  await pushed.arrayBuffer();
  const created = await createPr(f);
  assert.equal(created.status, 500);
  await created.arrayBuffer();
  const pending = f.gate.state.list().filter((item) => item.status === 'pending');
  assert.equal(pending.length, 2);
  assert.deepEqual(seen, pending.map((item) => item.id));
});

test('fork PR approvals show the escaped head repository in Slack', async () => {
  const calls = [];
  const notify = createNotifier({ url: 'https://hooks.example/x', logger: silent,
    fetchImpl: async (url, options) => { calls.push({ url, options }); return new Response(null, { status: 200 }); } });
  notify({ id: 'fork1234-0000-0000-0000-000000000000', requiredApprovals: 1, expiresAt: 0,
    context: { repository: 'acme/demo', action: 'github.pr.create', runtime: { agent: 'bot', human: 'dev' }, headRepository: 'agent-bot/<!here>',
      payload: { head: 'agent-bot:agent/x', base: 'main', title: 't' } } });
  await new Promise((resolve) => setImmediate(resolve));
  const text = JSON.parse(calls[0].options.body).text;
  assert.match(text, /head repository agent-bot\/&lt;!here&gt;/);
  assert(!text.includes('<!here>'));
});

test('merge approvals show number, base, method, escaped title, and head sha in Slack', async () => {
  const calls = [];
  const notify = createNotifier({ url: 'https://hooks.example/x', logger: silent,
    fetchImpl: async (url, options) => { calls.push({ url, options }); return new Response(null, { status: 200 }); } });
  notify({ id: 'merge123-0000-0000-0000-000000000000', requiredApprovals: 2, expiresAt: 0,
    context: { repository: 'acme/demo', action: 'github.pr.merge', runtime: { agent: 'bot', human: 'dev' }, number: 5, base: 'main', mergeMethod: 'squash',
      sha: 'ab'.repeat(20), headRepository: 'agent-bot/demo', title: 'Fix <!channel>\nline' } });
  await new Promise((resolve) => setImmediate(resolve));
  const text = JSON.parse(calls[0].options.body).text;
  assert(text.includes(`• Merge PR #5 into main (squash): Fix &lt;!channel&gt; line`));
  assert(text.includes(`• Head ${'ab'.repeat(6)} (${'ab'.repeat(20)})`));
  assert(text.includes('head repository agent-bot/demo'));
  assert(!text.includes('<!channel>'));
});
