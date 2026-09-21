import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { createAssertionVerifier, issueAssertion, strictJson, verifyAssertion } from '../src/assertion.js';
import { adminRequest } from '../src/admin-client.js';
import { validateConfig } from '../src/config.js';
import { exampleConfig, fixture, pushBody } from '../scripts/support/fixture.js';

const execute = promisify(execFile);
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const other = generateKeyPairSync('ed25519');
const clientToken = 'test-client-token-0123456789abcdef';
const claims = { iss: 'host-launcher', aud: 'agentgate:acme', sub: 'rt-1', human: 'dev@example.com', agent: 'claude-code', team: 'payments', mode: 'build', task: { system: 'jira', id: 'PAY-12' } };
const pem = (key) => key.export({ type: 'spki', format: 'pem' });

function assertionConfig(issuers = [{ kid: 'k1', publicKeyPem: pem(publicKey) }]) {
  const config = exampleConfig();
  delete config.runtime;
  config.identity = { mode: 'assertion', audience: 'agentgate:acme', issuers };
  return config;
}

const readAudit = async (f) => (await readFile(`${f.directory}/state/audit.jsonl`, 'utf8')).trim().split('\n').map(JSON.parse);

test('assertions verify signature, audience, lifetime, token binding, and revocation', () => {
  let now = 1_800_000_000_000;
  const token = issueAssertion(claims, { privateKey, kid: 'k1', now: () => now, ttlSeconds: 3600, clientToken });
  const options = { keys: { k1: publicKey }, audience: 'agentgate:acme', clientToken, now: () => now };
  const verified = verifyAssertion(token, options);
  assert.equal(verified.sub, 'rt-1');
  assert.match(verified.jti, /^[0-9a-f]{32}$/);
  const fail = (value, override, message) => assert.throws(() => verifyAssertion(value, { ...options, ...override }), { code: 'ASSERTION_INVALID' }, message);
  fail(token, { keys: { k1: other.publicKey } }, 'wrong key');
  fail(token, { keys: {} }, 'unknown kid');
  fail(token, { audience: 'agentgate:other' }, 'audience');
  fail(token, { clientToken: 'another-client-token-0123456789abcdef' }, 'token binding');
  fail(token, { revoked: new Set([verified.jti]) }, 'revoked');
  fail(`${token.split('.').slice(0, 2).join('.')}.AAAA`, {}, 'bad signature');
  const [header, , signature] = token.split('.');
  fail(`${header}.${Buffer.from(JSON.stringify({ ...verified, mode: 'operate' })).toString('base64url')}.${signature}`, {}, 'tampered claims');
  fail(issueAssertion(claims, { privateKey, kid: 'k1', now: () => now, ttlSeconds: 2 * 86400, clientToken }), {}, 'ttl too long');
  now += 3601_000;
  fail(token, {}, 'expired');
  const none = `${Buffer.from('{"alg":"none","kid":"k1"}').toString('base64url')}.${token.split('.')[1]}.`;
  fail(none, {}, 'alg none');
});

test('assertion claims and headers are strictly validated', () => {
  const now = () => 1_800_000_000_000;
  const options = { keys: { k1: publicKey }, audience: 'agentgate:acme', clientToken, now };
  const issue = (override, kid = 'k1') => issueAssertion({ ...claims, ...override }, { privateKey, kid, now, ttlSeconds: 600, clientToken });
  const fail = (token, message) => assert.throws(() => verifyAssertion(token, options), { code: 'ASSERTION_INVALID' }, message);
  fail(issue({ sub: 'rt 1' }), 'sub charset');
  fail(issue({ sub: 'a'.repeat(129) }), 'sub length');
  fail(issue({ human: 'dev\n@example.com' }), 'control char in human');
  fail(issue({ human: 'a'.repeat(257) }), 'human length');
  fail(issue({ human: 'dév@example.com' }), 'non-ascii human');
  fail(issue({ team: 'x'.repeat(129) }), 'team length');
  fail(issue({ agent: '' }), 'empty agent');
  fail(issue({ mode: 'admin' }), 'mode');
  fail(issue({ task: { system: 'github', id: '1' } }), 'task system');
  fail(issue({ ghLogin: 'bad login!' }), 'ghLogin');
  fail(issue({}, 'k1/../x'), 'kid charset');
  const token = issue({});
  const [, body, signature] = token.split('.');
  const header = (value) => `${Buffer.from(JSON.stringify(value)).toString('base64url')}.${body}.${signature}`;
  fail(header({ alg: 'EdDSA', typ: 'JWT', kid: 'k1' }), 'typ');
  fail(header({ alg: 'ES256', typ: 'agentgate-runtime+jwt', kid: 'k1' }), 'alg');
  fail(header({ alg: 'EdDSA', typ: 'agentgate-runtime+jwt', kid: '__proto__' }), 'prototype kid');
  fail(undefined, 'missing');
  fail('a.b', 'malformed');
  assert.equal(verifyAssertion(issue({ ghLogin: 'octo-cat', application: 'payments-api' }), options).ghLogin, 'octo-cat');
});

test('verification cache skips repeated signature checks but still enforces revocation and expiry', () => {
  let now = 1_800_000_000_000;
  const revoked = new Set();
  const verifier = createAssertionVerifier({ keys: { k1: publicKey }, audience: 'agentgate:acme', clientToken, now: () => now, maxEntries: 2 });
  const token = issueAssertion(claims, { privateKey, kid: 'k1', now: () => now, ttlSeconds: 600, clientToken });
  const first = verifier.verify(token, revoked);
  assert.equal(verifier.verify(token, revoked).jti, first.jti);
  assert.equal(verifier.stats.signatureChecks, 1);
  revoked.add(first.jti);
  assert.throws(() => verifier.verify(token, revoked), { code: 'ASSERTION_INVALID' });
  revoked.clear();
  revoked.add('sub:rt-1');
  assert.throws(() => verifier.verify(token, revoked), { code: 'ASSERTION_INVALID' });
  revoked.clear();
  assert.equal(verifier.verify(token, revoked).jti, first.jti);
  for (let index = 0; index < 3; index++) verifier.verify(issueAssertion(claims, { privateKey, kid: 'k1', now: () => now, ttlSeconds: 600, clientToken }), revoked);
  assert.ok(verifier.stats.size <= 2, 'cache is bounded');
  now += 601_000;
  assert.throws(() => verifier.verify(token, revoked), { code: 'ASSERTION_INVALID' });
});

test('config validates the identity section', () => {
  assert.doesNotThrow(() => validateConfig(assertionConfig()));
  assert.doesNotThrow(() => validateConfig({ ...exampleConfig(), identity: { mode: 'static' } }));
  assert.throws(() => validateConfig({ ...assertionConfig(), runtime: exampleConfig().runtime }), /runtime/);
  const { runtime, ...noRuntime } = exampleConfig();
  assert.ok(runtime);
  assert.throws(() => validateConfig(noRuntime), /runtime/);
  assert.throws(() => validateConfig(assertionConfig([])), /issuers/);
  assert.throws(() => validateConfig(assertionConfig([{ kid: 'k1', publicKeyPem: pem(publicKey) }, { kid: 'k1', publicKeyPem: pem(other.publicKey) }])), /kid/);
  assert.throws(() => validateConfig(assertionConfig([{ kid: 'bad kid', publicKeyPem: pem(publicKey) }])), /kid/);
  const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 });
  assert.throws(() => validateConfig(assertionConfig([{ kid: 'k1', publicKeyPem: pem(rsa.publicKey) }])), /ed25519/);
  assert.throws(() => validateConfig(assertionConfig([{ kid: 'k1', publicKeyPem: 'nope' }])), /ed25519/);
  assert.throws(() => validateConfig({ ...assertionConfig(), identity: { ...assertionConfig().identity, audience: '' } }), /audience/);
  assert.throws(() => validateConfig({ ...assertionConfig(), identity: { mode: 'oidc' } }), /identity/);
});

test('broker in assertion mode requires a valid bound assertion and records verified identity', async (t) => {
  const config = assertionConfig();
  const f = await fixture({ config, clientToken });
  t.after(() => f.close());
  const url = `${f.remote}/info/refs?service=git-upload-pack`;
  assert.equal((await fetch(url, { headers: f.authHeaders })).status, 401);
  const assertion = issueAssertion(claims, { privateKey, kid: 'k1', ttlSeconds: 600, clientToken });
  const ok = await fetch(url, { headers: { ...f.authHeaders, 'x-agentgate-runtime': assertion } });
  assert.equal(ok.status, 200);
  await ok.arrayBuffer();
  const audit = await readAudit(f);
  const allowed = audit.find((event) => event.decision === 'allow');
  assert.deepEqual({ human: allowed.runtime.human, runtimeId: allowed.runtime.runtimeId, team: allowed.runtime.team }, { human: 'dev@example.com', runtimeId: 'rt-1', team: 'payments' });
  assert.match(allowed.runtime.jti, /^[0-9a-f]{32}$/);
  assert.ok(!JSON.stringify(audit).includes(assertion.split('.')[2]), 'raw assertion never audited');
  // An assertion bound to a different client token is useless with this workspace's token.
  const foreign = issueAssertion(claims, { privateKey, kid: 'k1', ttlSeconds: 600, clientToken: 'another-client-token-0123456789abcdef' });
  assert.equal((await fetch(url, { headers: { ...f.authHeaders, 'x-agentgate-runtime': foreign } })).status, 401);
  assert.equal((await fetch(`${f.gate.url}/healthz`)).status, 200);
});

test('broker revocations are checked on every request, including cached assertions', async (t) => {
  const revoked = new Set();
  const f = await fixture({ config: assertionConfig(), clientToken, revocations: () => revoked });
  t.after(() => f.close());
  const url = `${f.remote}/info/refs?service=git-upload-pack`;
  const assertion = issueAssertion(claims, { privateKey, kid: 'k1', ttlSeconds: 600, clientToken });
  const get = async () => { const response = await fetch(url, { headers: { ...f.authHeaders, 'x-agentgate-runtime': assertion } }); await response.arrayBuffer(); return response.status; };
  assert.equal(await get(), 200);
  const [, body] = assertion.split('.');
  revoked.add(JSON.parse(Buffer.from(body, 'base64url')).jti);
  assert.equal(await get(), 401);
  revoked.clear();
  assert.equal(await get(), 200);
});

test('startGate refuses assertion mode without a client token to bind to', async () => {
  await assert.rejects(fixture({ config: assertionConfig(), clientToken: '' }), /client token/);
});

test('reload applies identity issuer changes', async (t) => {
  const f = await fixture({ config: assertionConfig(), clientToken });
  t.after(() => f.close());
  const url = `${f.remote}/info/refs?service=git-upload-pack`;
  const get = async (assertion) => { const response = await fetch(url, { headers: { ...f.authHeaders, 'x-agentgate-runtime': assertion } }); await response.arrayBuffer(); return response.status; };
  const k1 = issueAssertion(claims, { privateKey, kid: 'k1', ttlSeconds: 600, clientToken });
  const k2 = issueAssertion(claims, { privateKey: other.privateKey, kid: 'k2', ttlSeconds: 600, clientToken });
  assert.equal(await get(k1), 200);
  assert.equal(await get(k2), 401);
  f.gate.reload(assertionConfig([{ kid: 'k2', publicKeyPem: pem(other.publicKey) }]));
  assert.equal(await get(k1), 401, 'cached verification from the previous issuer set is not reused');
  assert.equal(await get(k2), 200);
  f.gate.reload(exampleConfig());
  assert.equal(await get(k2), 200, 'static mode ignores the header');
});

test('assertion-mode approvals bind to the assertion and still block the delegating human', async (t) => {
  const f = await fixture({ config: assertionConfig(), clientToken });
  t.after(() => f.close());
  const assertion = issueAssertion(claims, { privateKey, kid: 'k1', ttlSeconds: 600, clientToken });
  const push = (value) => fetch(`${f.remote}/git-receive-pack`, { method: 'POST', headers: { ...f.authHeaders, 'x-agentgate-runtime': value, 'content-type': 'application/x-git-receive-pack-request' }, body: pushBody() });
  const blocked = await push(assertion);
  assert.equal(blocked.status, 403);
  const { requestId } = await blocked.json();
  const [item] = f.gate.state.list();
  assert.deepEqual(Object.keys(item.context.runtime).sort(), ['agent', 'human', 'jti', 'mode', 'runtimeId', 'task', 'team']);
  assert.equal(item.context.runtime.runtimeId, 'rt-1');
  assert.equal(item.context.runtime.task, 'jira:PAY-12');
  for (const reviewer of ['local:dev', 'local:dev@example.com']) {
    await assert.rejects(adminRequest(f.gate.adminSocket, 'POST', `/approvals/${requestId}/approve`, { reviewer }), { code: 'SELF_APPROVAL' }, reviewer);
  }
  await adminRequest(f.gate.adminSocket, 'POST', `/approvals/${requestId}/approve`, { reviewer: 'local:reviewer' });
  // A renewed assertion (new jti) does not inherit the approval granted to the previous one.
  const renewed = issueAssertion(claims, { privateKey, kid: 'k1', ttlSeconds: 600, clientToken });
  const again = await push(renewed);
  assert.equal(again.status, 403);
  assert.equal((await again.json()).code, 'REQUIRE_APPROVAL');
  assert.equal(f.calls.length, 0);
  const retried = await push(assertion);
  await retried.arrayBuffer();
  assert.equal(f.calls.length, 1, 'the original assertion reuses its approval');
});

test('workspace setup sends both the client token and the assertion with a real git clone, and renew refreshes it', async (t) => {
  const f = await fixture({ config: assertionConfig(), clientToken });
  t.after(() => f.close());
  const home = join(f.directory, 'developer-home');
  await mkdir(home);
  const tokenFile = join(f.directory, 'client-token');
  const assertionFile = join(f.directory, 'runtime-assertion');
  const keyFile = join(f.directory, 'issuer.pem');
  await writeFile(tokenFile, clientToken, { mode: 0o600 });
  await writeFile(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const issue = (runtimeId) => execute(process.execPath, [resolve('scripts/issue-runtime.js'), '--key', keyFile, '--kid', 'k1', '--client-token-file', tokenFile, '--out', assertionFile,
    '--audience', 'agentgate:acme', '--runtime-id', runtimeId, '--human', 'dev@example.com', '--agent', 'claude-code', '--team', 'payments', '--task', 'jira:PAY-12', '--ttl', '600']);
  await issue('rt-clone');
  const env = { PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0', AGENTGATE_URL: f.gate.url,
    AGENTGATE_CLIENT_TOKEN_FILE: tokenFile, AGENTGATE_RUNTIME_ASSERTION_FILE: assertionFile, AGENTGATE_GIT_NAME: 'Dev', AGENTGATE_GIT_EMAIL: 'dev@example.com' };
  const git = async (cwd, ...args) => (await execute('git', args, { cwd, env })).stdout.trim();
  const setup = () => execute(process.execPath, [resolve('src/workspace-setup.js')], { cwd: home, env });
  await setup();
  const headers = (await git(home, 'config', '--global', '--includes', '--get-all', `http.${f.gate.url}/.extraheader`)).split('\n');
  assert.equal(headers.length, 2);
  await git(home, 'clone', 'https://github.com/acme/demo', join(home, 'clone'));
  assert.equal(await git(join(home, 'clone'), 'show', 'HEAD:README.md'), '# Demo repository');
  let audit = await readAudit(f);
  assert.ok(audit.some((event) => event.decision === 'allow' && event.runtime?.runtimeId === 'rt-clone'));
  // Renewal: a new assertion takes effect once setup (agentgate renew) re-runs.
  await issue('rt-renewed');
  await execute(process.execPath, [resolve('src/workspace-cli.js'), 'renew'], { cwd: home, env });
  assert.equal((await git(home, 'config', '--global', '--includes', '--get-all', `http.${f.gate.url}/.extraheader`)).split('\n').length, 2);
  await git(join(home, 'clone'), 'fetch');
  audit = await readAudit(f);
  assert.ok(audit.some((event) => event.decision === 'allow' && event.runtime?.runtimeId === 'rt-renewed'));
  // Without the assertion the same token is rejected.
  delete env.AGENTGATE_RUNTIME_ASSERTION_FILE;
  await setup();
  await assert.rejects(git(home, 'clone', 'https://github.com/acme/demo', join(home, 'clone-2')));
});

test('JWS headers, nbf, and base64url encodings are strictly canonical', () => {
  const now = () => 1_800_000_000_000;
  const seconds = 1_800_000_000;
  const options = { keys: { k1: publicKey }, audience: 'agentgate:acme', clientToken, now };
  const fail = (token, message) => assert.throws(() => verifyAssertion(token, options), { code: 'ASSERTION_INVALID' }, message);
  const valid = issueAssertion(claims, { privateKey, kid: 'k1', now, ttlSeconds: 600, clientToken });
  const body = JSON.parse(Buffer.from(valid.split('.')[1], 'base64url'));
  const signSegments = (headerSegment, bodySegment) => `${headerSegment}.${bodySegment}.${sign(null, Buffer.from(`${headerSegment}.${bodySegment}`), privateKey).toString('base64url')}`;
  const segment = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const header = { alg: 'EdDSA', typ: 'agentgate-runtime+jwt', kid: 'k1' };
  assert.equal(verifyAssertion(signSegments(segment(header), segment(body)), options).jti, body.jti, 'helper builds valid tokens');
  fail(signSegments(segment({ ...header, jku: 'https://evil.example/keys' }), segment(body)), 'extra header key');
  fail(signSegments(segment({ ...header, crit: ['exp'] }), segment(body)), 'crit header');
  fail(signSegments(segment(header), segment({ ...body, nbf: seconds + 61 })), 'nbf in the future');
  fail(signSegments(segment(header), segment({ ...body, nbf: '0' })), 'nbf not an integer');
  fail(signSegments(segment(header), segment({ ...body, nbf: 1.5 })), 'nbf fractional');
  assert.equal(verifyAssertion(signSegments(segment(header), segment({ ...body, nbf: seconds + 30 })), options).jti, body.jti, 'nbf within skew');
  // Non-canonical signature: 64 bytes encode to 86 characters whose last one has 2 spare bits.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const [h, b, s] = valid.split('.');
  const spare = `${s.slice(0, -1)}${alphabet[alphabet.indexOf(s.at(-1)) ^ 1]}`;
  assert.deepEqual(Buffer.from(spare, 'base64url'), Buffer.from(s, 'base64url'), 'same signature bytes');
  fail(`${h}.${b}.${spare}`, 'non-canonical signature');
  // Non-canonical header and payload segments, correctly signed over their non-canonical text.
  const nonCanonical = (value) => {
    let json = JSON.stringify(value);
    while (Buffer.byteLength(json) % 3 === 0) json += ' ';
    const text = Buffer.from(json).toString('base64url');
    return `${text.slice(0, -1)}${alphabet[alphabet.indexOf(text.at(-1)) ^ 1]}`;
  };
  fail(signSegments(nonCanonical(header), segment(body)), 'non-canonical header');
  fail(signSegments(segment(header), nonCanonical(body)), 'non-canonical payload');
  fail(`${h}=.${b}.${s}`, 'padding');
});

test('git-lfs batch requests carry the managed gitconfig headers, and transfers are bound to the requesting assertion', async (t) => {
  const content = Buffer.from('lfs!');
  const lfsOid = createHash('sha256').update(content).digest('hex');
  const provider = { lfsBatch: async ({ operation }) => new Response(JSON.stringify({ objects: [{ oid: lfsOid, size: content.length, actions: { [operation]: { href: 'https://github-cloud.githubusercontent.com/o?sig=x', header: {} } } }] }),
    { headers: { 'content-type': 'application/vnd.git-lfs+json' } }) };
  const lfsFetch = async () => new Response(content, { status: 200 });
  const f = await fixture({ config: assertionConfig(), clientToken, provider, lfsFetch });
  t.after(() => f.close());
  const home = join(f.directory, 'lfs-home');
  await mkdir(home);
  const tokenFile = join(f.directory, 'lfs-token');
  const assertionFile = join(f.directory, 'lfs-assertion');
  await writeFile(tokenFile, clientToken, { mode: 0o600 });
  const assertion = issueAssertion(claims, { privateKey, kid: 'k1', ttlSeconds: 600, clientToken });
  await writeFile(assertionFile, `${assertion}\n`, { mode: 0o600 });
  const env = { PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1', AGENTGATE_URL: f.gate.url, AGENTGATE_CLIENT_TOKEN_FILE: tokenFile, AGENTGATE_RUNTIME_ASSERTION_FILE: assertionFile };
  await execute(process.execPath, [resolve('src/workspace-setup.js')], { cwd: home, env });
  // git-lfs sends every http.<url>.extraHeader value from Git's config on its batch and transfer
  // requests; build exactly those headers from the managed gitconfig (git-lfs is not installed on
  // every test host).
  const values = (await execute('git', ['config', '--global', '--includes', '--get-all', `http.${f.gate.url}/.extraheader`], { cwd: home, env })).stdout.trim().split('\n');
  const headers = Object.fromEntries(values.map((line) => [line.slice(0, line.indexOf(':')).trim().toLowerCase(), line.slice(line.indexOf(':') + 1).trim()]));
  assert.deepEqual(Object.keys(headers).sort(), ['authorization', 'x-agentgate-runtime']);
  const batchRequest = (sent) => fetch(`${f.remote}/info/lfs/objects/batch`, { method: 'POST', headers: { ...sent, 'content-type': 'application/vnd.git-lfs+json' },
    body: JSON.stringify({ operation: 'download', transfers: ['basic'], objects: [{ oid: lfsOid, size: content.length }] }) });
  const unauthenticated = await batchRequest({ authorization: headers.authorization });
  assert.equal(unauthenticated.status, 401);
  assert.equal((await unauthenticated.json()).code, 'ASSERTION_INVALID');
  const hrefOf = async (response) => { assert.equal(response.status, 200); return (await response.json()).objects[0].actions.download.href; };
  const href = await hrefOf(await batchRequest(headers));
  const other = issueAssertion(claims, { privateKey, kid: 'k1', ttlSeconds: 600, clientToken });
  const stolen = await fetch(href, { headers: { authorization: headers.authorization, 'x-agentgate-runtime': other } });
  assert.equal(stolen.status, 404, 'a different assertion cannot use the capability');
  await stolen.arrayBuffer();
  const consumed = await fetch(href, { headers });
  assert.equal(consumed.status, 404, 'the mismatched attempt consumed the claim');
  await consumed.arrayBuffer();
  const fresh = await fetch(await hrefOf(await batchRequest(headers)), { headers });
  assert.equal(fresh.status, 200);
  assert.deepEqual(Buffer.from(await fresh.arrayBuffer()), content);
});

test('static-mode LFS transfers are bound to the configured runtimeId', async (t) => {
  const content = Buffer.from('lfs!');
  const lfsOid = createHash('sha256').update(content).digest('hex');
  const provider = { lfsBatch: async () => new Response(JSON.stringify({ objects: [{ oid: lfsOid, size: content.length, actions: { download: { href: 'https://github-cloud.githubusercontent.com/o', header: {} } } }] }),
    { headers: { 'content-type': 'application/vnd.git-lfs+json' } }) };
  const f = await fixture({ provider, lfsFetch: async () => new Response(content, { status: 200 }) });
  t.after(() => f.close());
  const batchHref = async () => (await (await fetch(`${f.remote}/info/lfs/objects/batch`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/vnd.git-lfs+json' },
    body: JSON.stringify({ operation: 'download', objects: [{ oid: lfsOid, size: content.length }] }) })).json()).objects[0].actions.download.href;
  const href = await batchHref();
  const next = exampleConfig();
  next.runtime.runtimeId = 'another-runtime';
  f.gate.reload(next);
  const mismatched = await fetch(href, { headers: f.authHeaders });
  assert.equal(mismatched.status, 404);
  await mismatched.arrayBuffer();
  const ok = await fetch(await batchHref(), { headers: f.authHeaders });
  assert.equal(ok.status, 200);
  await ok.arrayBuffer();
});

test('LFS transfer owners never match across identity modes after a reload', async (t) => {
  const content = Buffer.from('lfs!');
  const lfsOid = createHash('sha256').update(content).digest('hex');
  const provider = { lfsBatch: async () => new Response(JSON.stringify({ objects: [{ oid: lfsOid, size: content.length, actions: { download: { href: 'https://github-cloud.githubusercontent.com/o', header: {} } } }] }),
    { headers: { 'content-type': 'application/vnd.git-lfs+json' } }) };
  const f = await fixture({ config: assertionConfig(), clientToken, provider, lfsFetch: async () => new Response(content, { status: 200 }) });
  t.after(() => f.close());
  const batchHref = async (headers) => {
    const response = await fetch(`${f.remote}/info/lfs/objects/batch`, { method: 'POST', headers: { ...f.authHeaders, ...headers, 'content-type': 'application/vnd.git-lfs+json' },
      body: JSON.stringify({ operation: 'download', objects: [{ oid: lfsOid, size: content.length }] }) });
    assert.equal(response.status, 200);
    return (await response.json()).objects[0].actions.download.href;
  };
  const transferStatus = async (href, headers = {}) => { const response = await fetch(href, { headers: { ...f.authHeaders, ...headers } }); await response.arrayBuffer(); return response.status; };
  // assertion -> static, where the static runtimeId equals the old jti.
  const assertion = issueAssertion(claims, { privateKey, kid: 'k1', ttlSeconds: 600, clientToken });
  const jti = JSON.parse(Buffer.from(assertion.split('.')[1], 'base64url')).jti;
  const fromAssertion = await batchHref({ 'x-agentgate-runtime': assertion });
  const staticConfig = exampleConfig();
  staticConfig.runtime.runtimeId = jti;
  f.gate.reload(staticConfig);
  assert.equal(await transferStatus(fromAssertion), 404);
  // static -> assertion, where the assertion's sub equals the old runtimeId.
  const fromStatic = await batchHref();
  f.gate.reload(assertionConfig());
  const matching = issueAssertion({ ...claims, sub: jti }, { privateKey, kid: 'k1', ttlSeconds: 600, clientToken });
  assert.equal(await transferStatus(fromStatic, { 'x-agentgate-runtime': matching }), 404);
  assert.equal(await transferStatus(await batchHref({ 'x-agentgate-runtime': matching }), { 'x-agentgate-runtime': matching }), 200);
});

test('an assertion can be issued from the client token digest alone, so the issuer never holds the token', async (t) => {
  const f = await fixture({ config: assertionConfig(), clientToken });
  t.after(() => f.close());
  const fingerprint = createHash('sha256').update(clientToken).digest('hex');
  const byDigest = issueAssertion(claims, { privateKey, kid: 'k1', ttlSeconds: 3600, clientTokenSha256: fingerprint });
  assert.equal(verifyAssertion(byDigest, { keys: { k1: publicKey }, audience: 'agentgate:acme', clientToken }).sub, claims.sub);
  assert.throws(() => issueAssertion(claims, { privateKey, kid: 'k1', clientTokenSha256: 'abc' }), /64 hex/);
  assert.throws(() => issueAssertion(claims, { privateKey, kid: 'k1', clientToken, clientTokenSha256: fingerprint }), /not both/);
  assert.throws(() => issueAssertion(claims, { privateKey, kid: 'k1' }), /client token/);
  // Script form: --client-token-sha256 replaces --client-token-file.
  const keyFile = join(f.directory, 'issuer.pem');
  const assertionFile = join(f.directory, 'runtime-assertion');
  await writeFile(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const base = [resolve('scripts/issue-runtime.js'), '--key', keyFile, '--kid', 'k1', '--out', assertionFile, '--audience', 'agentgate:acme',
    '--runtime-id', 'rt-digest', '--human', 'dev@example.com', '--agent', 'cursor', '--team', 'payments', '--ttl', '600'];
  await execute(process.execPath, [...base, '--client-token-sha256', fingerprint.toUpperCase()]);
  const token = (await readFile(assertionFile, 'utf8')).trim();
  assert.equal(verifyAssertion(token, { keys: { k1: publicKey }, audience: 'agentgate:acme', clientToken }).sub, 'rt-digest');
  await assert.rejects(execute(process.execPath, base), /client-token-file or --client-token-sha256/);
  await assert.rejects(execute(process.execPath, [...base, '--client-token-sha256', fingerprint, '--client-token-file', keyFile]), /not both/);
});

test('a verifier without a fixed client token binds each call to the presented token, cached or not', () => {
  const now = () => 1_800_000_000_000;
  const verifier = createAssertionVerifier({ keys: { k1: publicKey }, audience: 'agentgate:acme', now });
  const tokenA = 'workspace-a-token-0123456789abcdefXYZ';
  const tokenB = 'workspace-b-token-0123456789abcdefXYZ';
  const forA = issueAssertion(claims, { privateKey, kid: 'k1', now, ttlSeconds: 600, clientToken: tokenA });
  assert.equal(verifier.verify(forA, new Set(), tokenA).sub, 'rt-1');
  assert.equal(verifier.stats.signatureChecks, 1);
  // Cached claims must still be checked against the token presented on this call.
  assert.throws(() => verifier.verify(forA, new Set(), tokenB), { code: 'ASSERTION_INVALID' });
  assert.throws(() => verifier.verify(forA, new Set()), { code: 'ASSERTION_INVALID' }, 'a call without a token never passes');
  assert.equal(verifier.verify(forA, new Set(), tokenA).sub, 'rt-1');
  assert.equal(verifier.stats.signatureChecks, 1, 'the good path still served from cache');
  const fixed = createAssertionVerifier({ keys: { k1: publicKey }, audience: 'agentgate:acme', clientToken: tokenA, now });
  assert.throws(() => fixed.verify(forA, new Set(), tokenB), /fixed/, 'a fixed-token verifier refuses per-call tokens rather than silently ignoring them');
});

test('fleet mode: one broker serves many workspaces, each authenticated by its own assertion-bound token', async (t) => {
  const f = await fixture({ config: assertionConfig(), clientToken: '', clientAuth: 'assertion' });
  t.after(() => f.close());
  const url = `${f.remote}/info/refs?service=git-upload-pack`;
  const tokenA = 'fleet-workspace-a-token-0123456789abcdef';
  const tokenB = 'fleet-workspace-b-token-0123456789abcdef';
  const issue = (sub, token) => issueAssertion({ ...claims, sub }, { privateKey, kid: 'k1', ttlSeconds: 600, clientToken: token });
  const assertA = issue('rt-fleet-a', tokenA);
  const assertB = issue('rt-fleet-b', tokenB);
  const call = async (token, assertion) => (await fetch(url, { headers: {
    ...(token ? { authorization: `Bearer ${token}` } : {}), ...(assertion ? { 'x-agentgate-runtime': assertion } : {})
  } })).status;
  assert.equal(await call(tokenA, assertA), 200);
  assert.equal(await call(tokenB, assertB), 200);
  assert.equal(await call(tokenA, assertB), 401, 'token and assertion must belong together');
  assert.equal(await call(tokenB, assertA), 401);
  assert.equal(await call(tokenA, undefined), 401, 'no assertion');
  assert.equal(await call(undefined, assertA), 401, 'no token');
  assert.equal(await call('short', assertA), 401, 'malformed token');
  const audit = await readAudit(f);
  const served = new Set(audit.filter((event) => event.decision === 'allow').map((event) => event.runtime?.runtimeId));
  assert.deepEqual([...served].sort(), ['rt-fleet-a', 'rt-fleet-b']);
  assert.ok(!audit.some((event) => JSON.stringify(event).includes(tokenA)), 'tokens never reach the audit log');
});

test('fleet mode refuses to start without assertion identity, and static identity refuses fleet auth', async () => {
  await assert.rejects(fixture({ clientToken: '', clientAuth: 'assertion' }), /assertion/);
  await assert.rejects(fixture({ config: assertionConfig(), clientToken: '' }), /client token/);
});

test('fleet mode rate-limits each runtime separately from the shared address budget', async (t) => {
  const f = await fixture({ config: assertionConfig(), clientToken: '', clientAuth: 'assertion', rateLimit: { capacity: 100, refillPerSecond: 1 }, runtimeRateLimit: { capacity: 2, refillPerSecond: 0.001 } });
  t.after(() => f.close());
  const url = `${f.remote}/info/refs?service=git-upload-pack`;
  const tokenA = 'fleet-rate-a-token-0123456789abcdefghij';
  const tokenB = 'fleet-rate-b-token-0123456789abcdefghij';
  const issue = (sub, token) => issueAssertion({ ...claims, sub }, { privateKey, kid: 'k1', ttlSeconds: 600, clientToken: token });
  const assertA = issue('rt-rate-a', tokenA);
  const assertB = issue('rt-rate-b', tokenB);
  const call = async (token, assertion) => fetch(url, { headers: { authorization: `Bearer ${token}`, 'x-agentgate-runtime': assertion } });
  assert.equal((await call(tokenA, assertA)).status, 200);
  assert.equal((await call(tokenA, assertA)).status, 200);
  const limited = await call(tokenA, assertA);
  assert.equal(limited.status, 429);
  assert.equal((await limited.json()).code, 'RATE_LIMITED');
  assert.ok(Number(limited.headers.get('retry-after')) >= 1);
  assert.equal((await call(tokenB, assertB)).status, 200, 'the neighbour behind the same address is unaffected');
});

test('assertions with duplicate or case-variant JSON members are rejected, in the header and in the claims', () => {
  const now = () => 1_800_000_000_000;
  const options = { keys: { k1: publicKey }, audience: 'agentgate:acme', clientToken, now };
  const good = issueAssertion(claims, { privateKey, kid: 'k1', now, ttlSeconds: 600, clientToken });
  const [, payload] = good.split('.');
  const rawClaims = Buffer.from(payload, 'base64url').toString('utf8');
  const forge = (claimText, headerText = '{"alg":"EdDSA","typ":"agentgate-runtime+jwt","kid":"k1"}') => {
    const unsigned = `${Buffer.from(headerText).toString('base64url')}.${Buffer.from(claimText).toString('base64url')}`;
    return `${unsigned}.${sign(null, Buffer.from(unsigned), privateKey).toString('base64url')}`;
  };
  assert.equal(verifyAssertion(forge(rawClaims), options).sub, 'rt-1', 'the same claims re-signed still verify');
  const dup = rawClaims.replace(/}$/, `,"exp":${Math.floor(now() / 1000) + 999999}}`);
  assert.throws(() => verifyAssertion(forge(dup), options), /duplicate member/, 'a second exp is refused rather than silently winning');
  const variant = rawClaims.replace(/}$/, ',"Exp":1}');
  assert.throws(() => verifyAssertion(forge(variant), options), /duplicate member/, 'a case variant beside the real claim is a duplicate');
  const lone = rawClaims.replace('"exp":', '"Exp":');
  assert.throws(() => verifyAssertion(forge(lone), options), /case-variant member/, 'a known claim in the wrong case alone is refused, not treated as missing');
  const nested = rawClaims.replace('"cnf":{', '"cnf":{"tokenSha256":"00",');
  assert.throws(() => verifyAssertion(forge(nested), options), /duplicate member/, 'nested objects are checked too');
  assert.throws(() => verifyAssertion(forge(rawClaims, '{"alg":"EdDSA","alg":"none","typ":"agentgate-runtime+jwt","kid":"k1"}'), options), /duplicate member/);
  assert.deepEqual(strictJson('{"a":[{"x":1},{"x":2}],"b":"\\"quoted\\"}"}'), { a: [{ x: 1 }, { x: 2 }], b: '"quoted"}' }, 'strings with braces and escapes do not confuse the scanner');
  assert.throws(() => strictJson('{"a":1,"A":2}'), /duplicate member/, 'case-variant of any member is a duplicate');
});
