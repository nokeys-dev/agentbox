import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const execute = promisify(execFile);
const script = resolve('scripts/bootstrap-dev.sh');

async function run(cwd, dir) {
  return (await execute('sh', [script, dir], { cwd, env: { PATH: process.env.PATH, HOME: cwd } })).stdout;
}

test('bootstrap-dev generates owner-only secrets and TLS, wires .env, and is idempotent', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'agentgate-bootstrap-'));
  const dir = join(cwd, 'secrets');
  await writeFile(join(cwd, '.env'), 'GITHUB_APP_ID=42\nAGENTGATE_TLS_CERT_PATH=/old/path\n');
  const first = await run(cwd, dir);
  for (const file of ['client-token', 'model-gateway-token', 'tls/broker.key']) {
    assert.equal(((await stat(join(dir, file))).mode & 0o777), 0o600, `${file} is owner-only`);
  }
  assert.equal(((await stat(dir)).mode & 0o777), 0o700);
  const token = await readFile(join(dir, 'client-token'), 'utf8');
  assert.match(token, /^[0-9a-f]{64}$/, 'token has no trailing newline');
  assert.notEqual(token, await readFile(join(dir, 'model-gateway-token'), 'utf8'));
  let env = await readFile(join(cwd, '.env'), 'utf8');
  assert.equal(env.split('\n')[0], 'GITHUB_APP_ID=42', 'existing lines are preserved in place');
  assert.match(env, new RegExp(`^AGENTGATE_TLS_CERT_PATH=${dir}/tls/broker.crt$`, 'm'), 'an existing key is replaced, not duplicated');
  assert.ok(!env.includes('/old/path'));
  for (const key of ['AGENTGATE_CLIENT_TOKEN_PATH', 'AGENTGATE_MODEL_GATEWAY_CLIENT_TOKEN_PATH', 'AGENTGATE_TLS_KEY_PATH', 'AGENTGATE_CA_PATH']) {
    assert.equal(env.match(new RegExp(`^${key}=`, 'gm')).length, 1, `${key} set once`);
  }
  assert.match(first, /Still needed[\s\S]*GITHUB_PRIVATE_KEY_PATH[\s\S]*ANTHROPIC_API_KEY_PATH/);
  assert.doesNotMatch(first, /GITHUB_APP_ID {2}/, 'present settings are not listed as missing');
  assert.ok(!first.includes(token), 'the token is never printed');
  assert.equal(await readFile(join(cwd, 'config.local.json'), 'utf8'), await readFile(resolve('examples/config.json'), 'utf8'));

  const second = await run(cwd, dir);
  assert.equal(await readFile(join(dir, 'client-token'), 'utf8'), token, 'rerun keeps the token');
  assert.match(second, /kept {4}.*client-token/);
  assert.match(second, /kept {4}.*tls/);
  env = await readFile(join(cwd, '.env'), 'utf8');
  assert.equal(env.match(/^AGENTGATE_CLIENT_TOKEN_PATH=/gm).length, 1, 'rerun does not duplicate .env lines');
});

// The development certificates last 30 days. A rerun a month later must renew them, and the
// agentbox preflight must name the expiry instead of leaving TLS failures inside the stack.
test('a development certificate close to expiry is reported by agentbox check and renewed by a rerun', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'agentgate-renew-'));
  const dir = join(cwd, 'secrets');
  await run(cwd, dir);
  const tls = join(dir, 'tls');
  // Reissue the broker certificate from the same development CA with one day left.
  await execute('sh', ['-c', `cd "${tls}" && openssl req -newkey rsa:2048 -nodes -subj /CN=agentd -keyout broker.key -out b.csr 2>/dev/null && openssl x509 -req -in b.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 -out broker.crt 2>/dev/null && rm -f b.csr ca.srl`]);
  const shortLived = await readFile(join(tls, 'broker.crt'), 'utf8');
  const checked = await execute(process.execPath, [resolve('bin/agentbox.js'), 'check'], { cwd, env: { PATH: process.env.PATH, HOME: cwd } }).then(() => null, (error) => error);
  assert.match(checked.stderr, /broker\.crt \(AGENTGATE_TLS_CERT_PATH\) expires in [01] days?; run "agentbox init" to renew it/);
  assert.doesNotMatch(checked.stderr, /ca\.crt/, 'the CA still has a month left');
  const rerun = await run(cwd, dir);
  assert.match(rerun, /renewed .*tls .*--force-recreate/);
  assert.match(rerun, /kept {4}.*client-token/, 'renewing certificates leaves the tokens alone');
  assert.notEqual(await readFile(join(tls, 'broker.crt'), 'utf8'), shortLived);
  const after = await execute(process.execPath, [resolve('bin/agentbox.js'), 'check'], { cwd, env: { PATH: process.env.PATH, HOME: cwd } }).then(() => ({ stderr: '' }), (error) => error);
  assert.doesNotMatch(after.stderr, /expires|expired/);
});
