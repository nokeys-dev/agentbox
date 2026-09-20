import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createEntitlements, githubTeamsSource, staticSource } from '../src/entitlements.js';
import { decide } from '../src/policy.js';
import { validateConfig } from '../src/config.js';

const runtime = { human: 'dev@example.com', runtimeId: 'rt', jti: 'j1', team: 'payments', mode: 'build', ghLogin: 'devgh', task: 'jira:PAY-12' };

test('rules with requires match only when the envelope satisfies them', () => {
  const config = validateConfig({
    runtime: { human: 'h', agent: 'a', runtimeId: 'r', task: 't' },
    repositories: [{ name: 'acme/demo', id: 1, installationId: 2 }],
    rules: [
      { id: 'team-write', action: 'git.push', repository: 'acme/demo', ref: 'refs/heads/agent/*', effect: 'allow', requires: { teams: ['payments'], modes: ['build'] } },
      { id: 'hotfix', action: 'git.push', repository: 'acme/demo', ref: 'refs/heads/main', effect: 'approval', requires: { elevation: 'jira' } }
    ]
  });
  const change = (ref) => ({ ref, operation: 'update' });
  const envelope = { teams: ['payments'], groups: [], owns: [], mode: 'build', errors: [] };
  assert.equal(decide(config, 'git.push', 'acme/demo', change('refs/heads/agent/x'), envelope).effect, 'allow');
  assert.equal(decide(config, 'git.push', 'acme/demo', change('refs/heads/agent/x'), { ...envelope, teams: [] }).effect, 'deny');
  assert.equal(decide(config, 'git.push', 'acme/demo', change('refs/heads/agent/x'), { ...envelope, mode: 'readonly' }).effect, 'deny');
  assert.equal(decide(config, 'git.push', 'acme/demo', change('refs/heads/main'), envelope).effect, 'deny');
  assert.equal(decide(config, 'git.push', 'acme/demo', change('refs/heads/main'), { ...envelope, elevation: { system: 'jira', id: 'X', status: 'active' } }).effect, 'approval');
  assert.equal(decide(config, 'git.push', 'acme/demo', change('refs/heads/agent/x')).effect, 'deny');
  assert.equal(decide(config, 'git.push', 'acme/demo', change('refs/heads/agent/x'), { ...envelope, teams: [], errors: ['static'], unknown: ['teams'] }).effect, 'deny', 'an allow rule never matches on unknown');
  assert.throws(() => validateConfig({ ...config, rules: [{ ...config.rules[0], requires: { teams: 'payments' } }] }), /requires/);
});

// ---- Validation, sources, and GitHub org tokens ----------------------------------------------

test('GitHub org tokens omit repository_ids, are cached apart from repository tokens, and never follow redirects', async () => {
  const { generateKeyPairSync } = await import('node:crypto');
  const { GitHub } = await import('../src/github.js');
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const calls = [];
  const github = new GitHub({ appId: '1', privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }), fetchImpl: async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/access_tokens')) return Response.json({ token: `tok-${calls.length}`, expires_at: new Date(Date.now() + 3600_000).toISOString() });
    return Response.json({ state: 'active' });
  } });
  const response = await github.apiOrg({ installationId: 2, path: 'orgs/acme/teams/payments/memberships/devgh', permissions: { members: 'read' } });
  assert.equal((await response.json()).state, 'active');
  await github.apiOrg({ installationId: 2, path: 'orgs/acme/teams/payments/memberships/devgh', permissions: { members: 'read' } });
  await github.token({ id: 5, installationId: 2 }, 'read');
  const tokenCalls = calls.filter((call) => call.url.endsWith('/access_tokens'));
  assert.equal(tokenCalls.length, 2, 'org token cached, repository token separate');
  assert.deepEqual(JSON.parse(tokenCalls[0].options.body), { permissions: { members: 'read' } });
  assert.deepEqual(JSON.parse(tokenCalls[1].options.body).repository_ids, [5]);
  const orgCall = calls.find((call) => call.url === 'https://api.github.com/orgs/acme/teams/payments/memberships/devgh');
  assert.equal(orgCall.options.redirect, 'error');
  assert.equal(orgCall.options.headers.authorization, 'Bearer tok-1');
  await assert.rejects(github.apiOrg({ installationId: 2, path: 'repos/acme/demo', permissions: { members: 'read' } }), /orgs/);
});

// ---- Through the broker ------------------------------------------------------------------------

const { exampleConfig, fixture, pushBody } = await import('./support/fixture.js');
const { adminRequest } = await import('../src/admin-client.js');
const { issueAssertion } = await import('../src/assertion.js');
const { generateKeyPairSync, createHash } = await import('node:crypto');
const { readFile, writeFile } = await import('node:fs/promises');
const issuer = generateKeyPairSync('ed25519');
const clientToken = 'test-client-token-0123456789abcdef';
const claims = { iss: 'host-launcher', aud: 'agentgate:acme', sub: 'rt-1', human: 'dev@example.com', agent: 'claude-code', team: 'payments', mode: 'build', task: { system: 'jira', id: 'PAY-12' }, ghLogin: 'devgh' };
const readAudit = async (f) => (await readFile(join(f.directory, 'state', 'audit.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
const okForward = () => new Response('0000', { headers: { 'content-type': 'application/x-git-receive-pack-result' } });

function teamsConfig() {
  const config = exampleConfig();
  delete config.runtime;
  config.identity = { mode: 'assertion', audience: 'agentgate:acme', issuers: [{ kid: 'k1', publicKeyPem: issuer.publicKey.export({ type: 'spki', format: 'pem' }) }] };
  config.entitlements = { githubTeams: { org: 'acme', installationId: 2, teams: ['payments'] } };
  config.rules = config.rules.map((rule) => rule.id === 'feature' ? { ...rule, requires: { teams: ['payments'], modes: ['build'] } } : rule);
  return config;
}

async function teamsBroker(t, membership) {
  const orgCalls = [];
  let forwards = 0;
  const provider = {
    forward: async () => { forwards++; return okForward(); },
    apiOrg: async (request) => { orgCalls.push(request); return membership(); }
  };
  const f = await fixture({ config: teamsConfig(), clientToken, provider, logger: { info() {}, warn() {}, error() {} } });
  t.after(() => f.close());
  const assertion = issueAssertion(claims, { privateKey: issuer.privateKey, kid: 'k1', ttlSeconds: 600, clientToken });
  const push = async (ref) => {
    const response = await fetch(`${f.remote}/git-receive-pack`, { method: 'POST', headers: { ...f.authHeaders, 'x-agentgate-runtime': assertion, 'content-type': 'application/x-git-receive-pack-request' }, body: pushBody(ref) });
    return { status: response.status, body: await response.text() };
  };
  return { f, push, orgCalls, forwards: () => forwards };
}

test('broker: a push is allowed only through requires.teams, resolved once per assertion', async (t) => {
  const { f, push, orgCalls, forwards } = await teamsBroker(t, () => Response.json({ state: 'active' }));
  assert.equal((await push('refs/heads/agent/x')).status, 200);
  assert.equal((await push('refs/heads/agent/y')).status, 200);
  assert.equal(forwards(), 2);
  assert.equal(orgCalls.length, 1, 'cached per jti');
  assert.deepEqual(orgCalls[0], { installationId: 2, path: 'orgs/acme/teams/payments/memberships/devgh', permissions: { members: 'read' } });
  const allow = (await readAudit(f)).find((event) => event.type === 'decision' && event.decision === 'allow');
  assert.deepEqual(allow.entitlements, { teams: ['payments'], groups: [], owns: [], mode: 'build', errors: [], unknown: [] });
  assert.equal(allow.changes[0].rule, 'feature');
});

test('broker: the same push is denied (and counted) when the teams source errors', async (t) => {
  const { f, push, forwards } = await teamsBroker(t, () => new Response('upstream secret body', { status: 502 }));
  const denied = await push('refs/heads/agent/x');
  assert.equal(denied.status, 403);
  assert.equal(JSON.parse(denied.body).code, 'DENIED');
  assert.equal(forwards(), 0);
  const audit = await readAudit(f);
  const deny = audit.find((event) => event.type === 'decision' && event.decision === 'deny');
  assert.deepEqual(deny.entitlements.errors, ['github-teams']);
  assert.equal(deny.changes[0].rule, 'default-deny');
  assert.ok(!JSON.stringify(audit).includes('upstream secret body'));
  assert.match(f.gate.registry.render(), /agentgate_entitlement_source_errors_total\{source="github-teams"\} 1/);
});


test('broker: LFS batch, LFS transfer, and PR routes all decide with the same envelope, and reload rebuilds sources', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-dir-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'directory.json');
  const member = JSON.stringify({ humans: { 'test@example.com': { teams: ['payments'], groups: ['lfs-writers'], owns: [] } } });
  writeFileSync(path, member);
  const config = exampleConfig();
  config.entitlements = { static: { path } };
  config.rules = [
    { id: 'read', action: 'git.read', repository: 'acme/demo', effect: 'allow', requires: { teams: ['payments'] } },
    { id: 'lfs-upload', action: 'git.lfs.upload', repository: 'acme/demo', effect: 'allow', requires: { groups: ['lfs-writers'] } },
    { id: 'pr-read', action: 'github.pr.read', repository: 'acme/demo', effect: 'allow', requires: { teams: ['payments'] } },
    { id: 'pr-create', action: 'github.pr.create', repository: 'acme/demo', ref: 'refs/heads/agent/*', effect: 'allow', requires: { teams: ['payments'] } }
  ];
  const content = Buffer.from('lfs!');
  const oid = createHash('sha256').update(content).digest('hex');
  const provider = {
    lfsBatch: async ({ operation }) => new Response(JSON.stringify({ objects: [{ oid, size: content.length, actions: { [operation]: { href: 'https://github-cloud.githubusercontent.com/o?sig=x', header: {} } } }] }), { headers: { 'content-type': 'application/vnd.git-lfs+json' } }),
    api: async ({ operation }) => operation.create
      ? Response.json({ number: 7, title: 'T', html_url: 'https://github.com/acme/demo/pull/7', head: { ref: 'agent/x', sha: '1'.repeat(40) }, base: { ref: 'main' } }, { status: 201 })
      : Response.json([], { status: 200 })
  };
  const f = await fixture({ config, provider, lfsFetch: async (href, options) => { for await (const chunk of options.body ?? []) void chunk; return new Response(null, { status: 200 }); } });
  t.after(() => f.close());
  const batch = (operation) => fetch(`${f.remote}/info/lfs/objects/batch`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/vnd.git-lfs+json' },
    body: JSON.stringify({ operation, transfers: ['basic'], objects: [{ oid, size: content.length }] }) });
  const prs = () => fetch(`${f.gate.url}/api/repos/acme/demo/pulls`, { headers: f.authHeaders });
  const createPr = () => fetch(`${f.gate.url}/api/repos/acme/demo/pulls`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/json' },
    body: JSON.stringify({ title: 'T', head: 'agent/x', base: 'main', body: 'B', draft: true }) });

  const upload = await batch('upload');
  assert.equal(upload.status, 200);
  const href = (await upload.json()).objects[0].actions.upload.href;
  // Membership is revoked in the directory, but the transfer re-check uses this runtime's cached
  // envelope (same as the batch), then a reload rebuilds the source and the new state applies.
  writeFileSync(path, JSON.stringify({ humans: {} }));
  const transfer = await fetch(href, { method: 'PUT', headers: { ...f.authHeaders, 'content-length': String(content.length) }, body: content });
  assert.equal(transfer.status, 200, await transfer.clone().text());
  await transfer.arrayBuffer();
  assert.equal((await prs()).status, 200);
  assert.equal((await createPr()).status, 201);

  f.gate.reload(structuredClone(config));
  const deniedBatch = await batch('download');
  assert.equal(deniedBatch.status, 403);
  await deniedBatch.arrayBuffer();
  const deniedList = await prs();
  assert.equal(deniedList.status, 403);
  await deniedList.arrayBuffer();
  const deniedCreate = await createPr();
  assert.equal(deniedCreate.status, 403);
  await deniedCreate.arrayBuffer();

  writeFileSync(path, JSON.stringify({ humans: { 'test@example.com': { teams: ['payments'], groups: [], owns: [] } } }));
  f.gate.reload(structuredClone(config));
  assert.equal((await batch('download')).status, 200);
  const noUpload = await batch('upload');
  assert.equal(noUpload.status, 403, 'git.lfs.upload requires the group');
  await noUpload.arrayBuffer();
  const decisions = (await readAudit(f)).filter((event) => event.type === 'decision');
  assert.ok(decisions.every((event) => event.entitlements), 'every decision record carries the envelope summary');
});

// ---- Three-valued requires (fail closed on unknown) ---------------------------------------------

function unknownConfig(rules) {
  return validateConfig({ runtime: { human: 'h', agent: 'a', runtimeId: 'r', task: 't' }, repositories: [{ name: 'acme/demo', id: 1, installationId: 2 }], rules });
}
const healthy = { teams: ['payments'], groups: ['eng'], owns: [], mode: 'readonly', errors: [], unknown: [] };
const outage = (fields, errors = ['jira']) => ({ teams: [], groups: [], owns: [], mode: 'readonly', errors, unknown: fields });
const push = (ref = 'refs/heads/main') => ({ ref, operation: 'update' });

test('requires: deny and approval rules stay in effect when their data is unknown; allow rules do not', async () => {
  const { evaluateRequires } = await import('../src/policy.js');
  const allowAll = { id: 'allow-all', action: 'git.push', repository: 'acme/demo', ref: '*', effect: 'allow' };
  const deny = unknownConfig([allowAll, { id: 'no-readonly-main', action: 'git.push', repository: 'acme/demo', ref: 'refs/heads/main', effect: 'deny', requires: { elevation: 'jira' } }]);
  assert.equal(decide(deny, 'git.push', 'acme/demo', push(), outage(['elevation:jira'])).rule, 'no-readonly-main', 'jira timeout cannot turn a deny into allow');
  assert.equal(decide(deny, 'git.push', 'acme/demo', push(), healthy).effect, 'allow', 'unsatisfied deny does not apply');
  assert.equal(decide(deny, 'git.push', 'acme/demo', push(), undefined).effect, 'deny', 'no envelope is unknown');

  const approval = unknownConfig([allowAll, { id: 'team-approval', action: 'git.push', repository: 'acme/demo', ref: 'refs/heads/main', effect: 'approval', requires: { teams: ['contractors'] } }]);
  assert.equal(decide(approval, 'git.push', 'acme/demo', push(), outage(['groups', 'owns', 'teams'], ['static'])).effect, 'approval');
  assert.equal(decide(approval, 'git.push', 'acme/demo', push(), healthy).effect, 'allow');

  const merges = unknownConfig([
    { id: 'base', action: 'github.pr.merge', repository: 'acme/demo', ref: 'refs/heads/main', effect: 'approval', mergeMethods: ['squash', 'merge'] },
    { id: 'strict', action: 'github.pr.merge', repository: 'acme/demo', ref: 'refs/heads/main', effect: 'approval', approvals: 3, reviewerSources: ['oidc'], mergeMethods: ['squash'], requires: { groups: ['contractors'] } }
  ]);
  const underOutage = decide(merges, 'github.pr.merge', 'acme/demo', { ref: 'refs/heads/main' }, outage(['groups', 'owns', 'teams'], ['github-teams']));
  assert.deepEqual([underOutage.requiredApprovals, underOutage.reviewerSources, underOutage.mergeMethods], [3, ['oidc'], ['squash']]);
  const normal = decide(merges, 'github.pr.merge', 'acme/demo', { ref: 'refs/heads/main' }, healthy);
  assert.deepEqual([normal.requiredApprovals, normal.reviewerSources, normal.mergeMethods], [1, undefined, ['merge', 'squash']]);

  // Positive evidence satisfies even while another source is down; an unsatisfied check wins over unknown.
  assert.equal(evaluateRequires({ teams: ['payments'] }, { ...outage(['teams']), teams: ['payments'] }), 'satisfied');
  assert.equal(evaluateRequires({ teams: ['x'], modes: ['build'] }, outage(['teams'])), 'unsatisfied');
  assert.equal(evaluateRequires({ modes: ['build'] }, { ...healthy, mode: undefined }), 'unknown', 'missing mode claim');
  assert.equal(evaluateRequires({ elevation: 'servicenow' }, outage(['elevation:jira'])), 'unsatisfied', 'a jira outage says nothing about servicenow');
  assert.equal(evaluateRequires(undefined, undefined), 'satisfied');
});

test('requires: a teams deny rule applies when the runtime has no ghLogin for the configured teams source', async () => {
  const source = githubTeamsSource({ provider: { apiOrg: async () => assert.fail('never called') }, org: 'acme', installationId: 2, teams: ['contractors'] });
  const envelope = await createEntitlements({ sources: [source] }).envelope({ ...runtime, ghLogin: undefined });
  assert.deepEqual(envelope.unknown, ['teams']);
  const config = unknownConfig([
    { id: 'allow-all', action: 'git.push', repository: 'acme/demo', ref: '*', effect: 'allow' },
    { id: 'no-contractors', action: 'git.push', repository: 'acme/demo', ref: '*', effect: 'deny', requires: { teams: ['contractors'] } }
  ]);
  assert.equal(decide(config, 'git.push', 'acme/demo', push(), envelope).rule, 'no-contractors');
  const known = await createEntitlements({ sources: [githubTeamsSource({ provider: { apiOrg: async () => Response.json({ state: 'active' }, { status: 200 }) }, org: 'acme', installationId: 2, teams: ['payments'] })] }).envelope(runtime);
  assert.equal(decide(config, 'git.push', 'acme/demo', push(), known).effect, 'allow');
});

test('entitlements: mode-tagged keys, no default mode, shared in-flight resolution, and bounded eviction', async () => {
  const { envelopeKey } = await import('../src/entitlements.js');
  assert.equal(envelopeKey({ jti: 'x', runtimeId: 'x' }), 'assertion:x');
  assert.equal(envelopeKey({ runtimeId: 'x' }), 'static:x');
  let calls = 0;
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const slow = { name: 'slow', provides: ['teams'], resolve: async () => { calls++; await gate; return { teams: ['t'] }; } };
  const entitlements = createEntitlements({ sources: [slow], maxEntries: 2 });
  const pending = [entitlements.envelope({ runtimeId: 'a' }), entitlements.envelope({ runtimeId: 'a' })];
  release();
  const [first, second] = await Promise.all(pending);
  assert.equal(calls, 1, 'concurrent resolves share one promise');
  assert.equal(first, second);
  assert.equal('mode' in first, false, 'no default mode');
  await entitlements.envelope({ runtimeId: 'b' });
  await entitlements.envelope({ runtimeId: 'c' });
  assert.equal(entitlements.size, 2);
  await entitlements.envelope({ runtimeId: 'c' });
  assert.equal(calls, 3, 'newest entry kept');
  await entitlements.envelope({ runtimeId: 'a' });
  assert.equal(calls, 4, 'oldest entry evicted');
});

test('broker: requests rejected before any decision never reach entitlement sources', async (t) => {
  let orgCalls = 0;
  const provider = { forward: async () => okForward(), apiOrg: async () => { orgCalls++; return Response.json({ state: 'active' }); } };
  const f = await fixture({ config: teamsConfig(), clientToken, provider, maxConcurrent: 1, logger: { info() {}, warn() {}, error() {} } });
  t.after(() => f.close());
  const assertion = issueAssertion(claims, { privateKey: issuer.privateKey, kid: 'k1', ttlSeconds: 600, clientToken });
  const headers = { ...f.authHeaders, 'x-agentgate-runtime': assertion };
  const unknownTransfer = await fetch(`${f.gate.url}/lfs-transfer/${'0'.repeat(64)}`, { headers });
  assert.equal(unknownTransfer.status, 404);
  await unknownTransfer.arrayBuffer();
  const badRoute = await fetch(`${f.remote}/info/refs?service=git-upload-pack&x=1`, { headers });
  assert.equal(badRoute.status, 404);
  await badRoute.arrayBuffer();
  assert.equal(orgCalls, 0);
});

