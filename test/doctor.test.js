import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { createServer } from 'node:net';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fixture } from '../scripts/support/fixture.js';
import { issueAssertion } from '../src/assertion.js';

const execute = promisify(execFile);
const cli = resolve('src/workspace-cli.js');
const { privateKey } = generateKeyPairSync('ed25519');

async function doctor(f, extra = {}) {
  const home = join(f.directory, `doctor-home-${Math.random().toString(16).slice(2)}`);
  await mkdir(home);
  const tokenFile = join(home, 'client-token');
  await writeFile(tokenFile, f.clientToken, { mode: 0o600 });
  await writeFile(join(home, '.gitconfig'), '[user]\n\tname = Dev\n\temail = dev@example.com\n');
  const env = { PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1', AGENTGATE_URL: f.gate.url, AGENTGATE_CLIENT_TOKEN_FILE: tokenFile, ...extra };
  let stdout;
  let code = 0;
  try { ({ stdout } = await execute(process.execPath, [cli, 'doctor'], { cwd: home, env })); }
  catch (error) { ({ stdout } = error); code = error.code; }
  const report = JSON.parse(stdout);
  const byName = Object.fromEntries(report.checks.map((check) => [check.check, check]));
  // git-lfs may be absent on the host running the tests; the exit code must track every check
  // AgentBox itself controls, so compare against the report rather than a fixed value.
  const agentgateChecks = report.checks.filter((check) => check.check !== 'git-lfs');
  assert.equal(code, report.checks.every((check) => check.ok) ? 0 : 1);
  return { report, byName, code, healthy: agentgateChecks.every((check) => check.ok) };
}

function assertion(claims, options) {
  return issueAssertion({ iss: 'issuer', aud: 'agentgate', sub: 'runtime-1', human: 'dev@example.com', agent: 'cursor', team: 'platform', mode: 'build', ...claims },
    { privateKey, kid: 'k1', ...options });
}

async function listener() {
  const server = createServer((socket) => socket.end());
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  return { port: server.address().port, close: () => new Promise((done) => server.close(done)) };
}

test('doctor reports a static identity, no gateway, and no proxy as informational, and exits 0 when the broker is up', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const { byName, healthy } = await doctor(f);
  assert.equal(byName.broker.ok, true);
  assert.equal(byName['runtime assertion'].ok, true);
  assert.equal(byName['runtime assertion'].present, false);
  assert.equal(byName['model gateway'].ok, true);
  assert.equal(byName['model gateway'].configured, false);
  assert.equal(byName['egress proxy'].ok, true);
  assert.equal(byName['egress proxy'].configured, false);
  assert.equal(byName['client token'].ok, true);
  assert.equal(healthy, true);
});

test('doctor decodes a valid runtime assertion and shows who the agent is and when it expires', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const file = join(f.directory, 'assertion');
  await writeFile(file, assertion({ task: { system: 'jira', id: 'PLAT-42' } }, { clientToken: f.clientToken, ttlSeconds: 7200 }));
  const { byName } = await doctor(f, { AGENTGATE_RUNTIME_ASSERTION_FILE: file });
  const check = byName['runtime assertion'];
  assert.equal(check.ok, true);
  assert.equal(check.present, true);
  assert.equal(check.runtime, 'runtime-1');
  assert.equal(check.human, 'dev@example.com');
  assert.equal(check.agent, 'cursor');
  assert.equal(check.mode, 'build');
  assert.equal(check.task, 'jira:PLAT-42');
  assert.equal(check.boundToClientToken, true);
  assert.ok(check.expiresInSeconds > 7100 && check.expiresInSeconds <= 7200);
  assert.match(check.expiresAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(check.message, undefined);
});

test('doctor fails an expired assertion, warns on one expiring within the hour, and flags a client-token mismatch', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const file = join(f.directory, 'assertion');
  await writeFile(file, assertion({}, { clientToken: f.clientToken, now: () => Date.now() - 7200_000, ttlSeconds: 3600 }));
  let result = await doctor(f, { AGENTGATE_RUNTIME_ASSERTION_FILE: file });
  assert.equal(result.byName['runtime assertion'].ok, false);
  assert.match(result.byName['runtime assertion'].message, /expired/);
  assert.equal(result.code, 1);

  await writeFile(file, assertion({}, { clientToken: f.clientToken, ttlSeconds: 600 }));
  result = await doctor(f, { AGENTGATE_RUNTIME_ASSERTION_FILE: file });
  assert.equal(result.byName['runtime assertion'].ok, true);
  assert.match(result.byName['runtime assertion'].message, /agentgate renew/);

  await writeFile(file, assertion({}, { clientToken: 'some-other-workspace-token-0123456789', ttlSeconds: 3600 }));
  result = await doctor(f, { AGENTGATE_RUNTIME_ASSERTION_FILE: file });
  assert.equal(result.byName['runtime assertion'].ok, false);
  assert.equal(result.byName['runtime assertion'].boundToClientToken, false);
  assert.match(result.byName['runtime assertion'].message, /client token/);
});

test('doctor reports an unreadable assertion file as a failure rather than crashing', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const file = join(f.directory, 'assertion');
  await writeFile(file, 'not.a.token!');
  const { byName, code } = await doctor(f, { AGENTGATE_RUNTIME_ASSERTION_FILE: file });
  assert.equal(byName['runtime assertion'].ok, false);
  assert.equal(byName.broker.ok, true, 'the broker check still runs');
  assert.equal(code, 1);
});

test('doctor probes the model gateway and egress proxy by TCP reachability and reports the token export', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const gateway = await listener();
  const proxy = await listener();
  t.after(() => Promise.all([gateway.close(), proxy.close()]));
  let { byName, healthy, code } = await doctor(f, {
    ANTHROPIC_BASE_URL: `http://127.0.0.1:${gateway.port}/anthropic`, ANTHROPIC_AUTH_TOKEN: 'gateway-client-token',
    HTTPS_PROXY: `http://127.0.0.1:${proxy.port}`
  });
  assert.equal(byName['model gateway'].ok, true);
  assert.equal(byName['model gateway'].configured, true);
  assert.equal(byName['model gateway'].url, `http://127.0.0.1:${gateway.port}/anthropic`);
  assert.equal(byName['model gateway'].tokenExported, true);
  assert.equal(byName['egress proxy'].ok, true);
  assert.equal(byName['egress proxy'].url, `http://127.0.0.1:${proxy.port}`);
  assert.equal(healthy, true);

  await Promise.all([gateway.close(), proxy.close()]);
  ({ byName, healthy, code } = await doctor(f, { ANTHROPIC_BASE_URL: `http://127.0.0.1:${gateway.port}/anthropic`, HTTPS_PROXY: `http://127.0.0.1:${proxy.port}` }));
  assert.equal(byName['model gateway'].ok, false);
  assert.equal(byName['model gateway'].tokenExported, false);
  assert.equal(byName['model gateway'].tokenFile, false);
  assert.match(byName['model gateway'].message, /ANTHROPIC_AUTH_TOKEN/);
  assert.equal(byName['egress proxy'].ok, false);
  assert.equal(healthy, false);
  assert.equal(code, 1);
});

test('doctor accepts a gateway token that is on disk but not exported, as in a docker exec session, with a hint', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const gateway = await listener();
  t.after(() => gateway.close());
  const tokenFile = join(f.directory, 'gateway-token');
  await writeFile(tokenFile, 'gateway-client-token-on-disk\n', { mode: 0o600 });
  const { byName } = await doctor(f, { ANTHROPIC_BASE_URL: `http://127.0.0.1:${gateway.port}/anthropic`, AGENTGATE_MODEL_GATEWAY_TOKEN_FILE: tokenFile });
  assert.equal(byName['model gateway'].ok, true);
  assert.equal(byName['model gateway'].tokenExported, false);
  assert.equal(byName['model gateway'].tokenFile, true);
  assert.match(byName['model gateway'].message, /bash -lc/);
  assert.ok(!JSON.stringify(byName).includes('gateway-client-token-on-disk'));
});

test('the profile snippet exports the gateway token from its file and stays silent without one', async () => {
  const script = resolve('scripts/agentgate-env.sh');
  const directory = await mkdtemp(join(tmpdir(), 'agentgate-env-'));
  const tokenFile = join(directory, 'token');
  await writeFile(tokenFile, 'gw-token-123', { mode: 0o600 });
  const run = async (env) => (await execute('sh', ['-c', `. ${script}; printf '%s' "\${ANTHROPIC_AUTH_TOKEN:-unset}"`], { env: { PATH: process.env.PATH, ...env } })).stdout;
  assert.equal(await run({ AGENTGATE_MODEL_GATEWAY_TOKEN_FILE: tokenFile }), 'gw-token-123');
  assert.equal(await run({ AGENTGATE_MODEL_GATEWAY_TOKEN_FILE: join(directory, 'missing') }), 'unset');
  assert.equal(await run({}), 'unset');
  const assertionFile = join(directory, 'assertion');
  await writeFile(assertionFile, 'aaa.bbb.ccc\n', { mode: 0o600 });
  const headers = async (env) => (await execute('sh', ['-c', `. ${script}; printf '%s' "\${ANTHROPIC_CUSTOM_HEADERS:-unset}"`], { env: { PATH: process.env.PATH, ...env } })).stdout;
  assert.equal(await headers({ AGENTGATE_RUNTIME_ASSERTION_FILE: assertionFile }), 'x-agentgate-runtime: aaa.bbb.ccc');
  const proxy = async (env) => (await execute('sh', ['-c', `. ${script}; printf '%s|%s|%s' "\${HTTPS_PROXY:-unset}" "\${https_proxy:-unset}" "\${HTTP_PROXY:-unset}"`], { env: { PATH: process.env.PATH, ...env } })).stdout;
  assert.equal(await proxy({ AGENTGATE_RUNTIME_ASSERTION_FILE: assertionFile, HTTPS_PROXY: 'http://egress-proxy:3128', https_proxy: 'http://egress-proxy:3128' }),
    'http://runtime:aaa.bbb.ccc@egress-proxy:3128|http://runtime:aaa.bbb.ccc@egress-proxy:3128|unset');
  assert.equal(await proxy({ AGENTGATE_RUNTIME_ASSERTION_FILE: assertionFile, HTTPS_PROXY: 'http://other:x@egress-proxy:3128' }), 'http://other:x@egress-proxy:3128|unset|unset', 'existing credentials are left alone');
  await writeFile(assertionFile, '', { mode: 0o600 });
  assert.equal(await headers({ AGENTGATE_RUNTIME_ASSERTION_FILE: assertionFile }), 'unset', 'an empty (static identity) file exports nothing');
  assert.equal(await proxy({ AGENTGATE_RUNTIME_ASSERTION_FILE: assertionFile, HTTPS_PROXY: 'http://egress-proxy:3128' }), 'http://egress-proxy:3128|unset|unset');
});

test('doctor never prints the assertion, the client token, or the gateway token', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const file = join(f.directory, 'assertion');
  const token = assertion({}, { clientToken: f.clientToken, ttlSeconds: 3600 });
  await writeFile(file, token);
  const { report } = await doctor(f, { AGENTGATE_RUNTIME_ASSERTION_FILE: file, ANTHROPIC_AUTH_TOKEN: 'gateway-client-token-value', ANTHROPIC_BASE_URL: 'http://127.0.0.1:9/anthropic' });
  const text = JSON.stringify(report);
  for (const secret of [token, token.split('.')[2], f.clientToken, 'gateway-client-token-value']) assert.ok(!text.includes(secret));
});

test('agentgate fingerprint prints the client token digest the issuer binds to, never the token', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const tokenFile = join(f.directory, 'client-token');
  await writeFile(tokenFile, `${f.clientToken}\n`, { mode: 0o600 });
  const env = { PATH: process.env.PATH, HOME: f.directory, AGENTGATE_URL: f.gate.url, AGENTGATE_CLIENT_TOKEN_FILE: tokenFile };
  const { stdout } = await execute(process.execPath, [cli, 'fingerprint'], { env });
  const output = JSON.parse(stdout);
  assert.equal(output.clientTokenSha256, createHash('sha256').update(f.clientToken).digest('hex'));
  assert.ok(!stdout.includes(f.clientToken));
  delete env.AGENTGATE_CLIENT_TOKEN_FILE;
  await assert.rejects(execute(process.execPath, [cli, 'fingerprint'], { env }), /AGENTGATE_CLIENT_TOKEN_FILE/);
});
