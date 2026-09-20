// Fleet-mode Docker smoke: one broker, two workspace containers with their own tokens and
// assertions, cross-token rejection, and revocation. Needs the images from `npm run test:docker`.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout } from 'node:timers/promises';
import { issueAssertion } from '../src/assertion.js';

const execute = promisify(execFile);
const image = process.env.AGENTGATE_WORKSPACE_IMAGE || 'agentgate-workspace:local';
const id = `agentgate-fleet-${randomBytes(4).toString('hex')}`;
const network = `${id}-network`;
const broker = `${id}-broker`;
const created = [];
const docker = async (...args) => (await execute('docker', args, { maxBuffer: 4 * 1024 * 1024, timeout: 90_000 })).stdout.trim();

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const state = mkdtempSync(join(tmpdir(), 'agentgate-fleet-'));
chmodSync(state, 0o755);
const revocations = join(state, 'revocations.json');
const runtimeDir = (name, token, assertion) => {
  const directory = join(state, name);
  rmSync(directory, { recursive: true, force: true });
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, 'token'), token, { mode: 0o644 });
  writeFileSync(join(directory, 'assertion'), assertion, { mode: 0o644 });
  chmodSync(directory, 0o755);
  return directory;
};

async function workspace(secrets, script) {
  return docker('run', '--rm', '--init', '--network', network, '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
    '--mount', `type=bind,source=${secrets},target=/run/secrets,readonly`,
    '--env', 'AGENTGATE_URL=http://agentd:7432', '--env', 'AGENTGATE_CLIENT_TOKEN_FILE=/run/secrets/token', '--env', 'AGENTGATE_RUNTIME_ASSERTION_FILE=/run/secrets/assertion',
    '--env', 'AGENTGATE_GIT_NAME=Fleet Smoke', '--env', 'AGENTGATE_GIT_EMAIL=fleet@example.com',
    image, 'sh', '-eu', '-c', script);
}

try {
  await docker('image', 'inspect', image);
  await docker('network', 'create', '--internal', network);
  created.push(['network', 'rm', network]);
  // The revocation file the script writes is owner-only, so the broker must run as the host uid
  // (on CI that is not the image's `node`); the harness writes only under /tmp.
  await docker('run', '-d', '--name', broker, '--init', '--network', network, '--network-alias', 'agentd', '--user', String(process.getuid()),
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
    '--mount', `type=bind,source=${resolve('src')},target=/app/src,readonly`,
    '--mount', `type=bind,source=${resolve('test')},target=/app/test,readonly`,
    '--mount', `type=bind,source=${resolve('package.json')},target=/app/package.json,readonly`,
    '--mount', `type=bind,source=${state},target=/fleet,readonly`,
    '--env', 'AGENTGATE_SMOKE_FLEET=1', '--env', `AGENTGATE_SMOKE_ISSUER_PUBLIC_KEY=${publicKey.export({ type: 'spki', format: 'pem' })}`,
    '--env', 'AGENTGATE_SMOKE_REVOCATIONS_FILE=/fleet/revocations.json',
    '--entrypoint', 'node', image, '/app/test/support/docker-broker.js');
  created.push(['rm', '-f', broker]);
  let ready = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    try { await docker('exec', broker, 'node', '-e', "fetch('http://127.0.0.1:7432/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"); ready = true; break; }
    catch { await setTimeout(200); }
  }
  if (!ready) { const { stdout, stderr } = await execute('docker', ['logs', broker]); throw new Error(`Fleet broker failed to start: ${stdout}${stderr}`); }

  const tokenA = randomBytes(32).toString('hex');
  const tokenB = randomBytes(32).toString('hex');
  const claims = (sub) => ({ iss: 'fleet-smoke', aud: 'agentgate:smoke', sub, human: 'dev@example.com', agent: 'smoke', team: 'payments', mode: 'build' });
  const assertA = issueAssertion(claims('rt-fleet-a'), { privateKey, kid: 'smoke', ttlSeconds: 600, clientToken: tokenA });
  const assertB = issueAssertion(claims('rt-fleet-b'), { privateKey, kid: 'smoke', ttlSeconds: 600, clientToken: tokenB });
  const dirA = runtimeDir('a', tokenA, assertA);
  const dirB = runtimeDir('b', tokenB, assertB);
  const dirMixed = runtimeDir('mixed', tokenA, assertB);

  const doctorA = await workspace(dirA, 'agentgate doctor | jq -r \'.checks[] | select(.check=="runtime assertion") | .runtime\'; git clone -q https://github.com/acme/demo repo && echo CLONED_A');
  assert.match(doctorA, /rt-fleet-a/);
  assert.match(doctorA, /CLONED_A/);
  assert.match(await workspace(dirB, 'git clone -q https://github.com/acme/demo repo && echo CLONED_B'), /CLONED_B/);
  console.log('Two workspaces with their own tokens and assertions were served by one broker.');
  const mixed = await workspace(dirMixed, 'if git clone -q https://github.com/acme/demo repo 2>/dev/null; then echo UNEXPECTED_OK; else echo REJECTED; fi');
  assert.match(mixed, /REJECTED/);
  console.log('A token presented with another runtime\'s assertion was rejected.');

  const jtiA = JSON.parse(Buffer.from(assertA.split('.')[1], 'base64url').toString('utf8')).jti;
  writeFileSync(revocations, JSON.stringify({ jtis: [jtiA], runtimeIds: [] }), { mode: 0o600 });
  const afterRevoke = await workspace(dirA, 'if git clone -q https://github.com/acme/demo repo 2>/dev/null; then echo UNEXPECTED_OK; else echo REVOKED; fi');
  assert.match(afterRevoke, /REVOKED/);
  assert.match(await workspace(dirB, 'git clone -q https://github.com/acme/demo repo && echo STILL_B'), /STILL_B/);
  console.log('Revoking one runtime cut it off and left its neighbour working.');
  const audit = await docker('exec', broker, 'sh', '-c', 'cat /tmp/agentgate-*/state/audit.jsonl 2>/dev/null || find / -name audit.jsonl -path "*state*" 2>/dev/null | head -1 | xargs cat');
  const served = new Set(audit.split('\n').filter(Boolean).map((line) => JSON.parse(line)).filter((event) => event.decision === 'allow').map((event) => event.runtime?.runtimeId));
  assert.deepEqual([...served].sort(), ['rt-fleet-a', 'rt-fleet-b']);
  assert.ok(!audit.includes(tokenA) && !audit.includes(tokenB), 'tokens never reach the audit log');
  console.log('Audit records name each runtime and contain no token.');
} finally {
  for (const args of created.reverse()) await docker(...args).catch(() => {});
  rmSync(state, { recursive: true, force: true });
}
