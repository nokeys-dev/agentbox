import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, chmodSync, renameSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';

import { TEST_TIMEOUT_MS, freePort, tempDir, writeOwnerOnly, makeTokenFile, makeConfigFile, baseEnv, spawnDaemon, startListening } from './support/daemon-harness.js';

test('starts with a valid configuration and serves /healthz', { timeout: TEST_TIMEOUT_MS }, async (t) => {
  const dir = tempDir('agentgate-daemon-ok-');
  let daemon;
  t.after(() => {
    if (daemon && daemon.child.exitCode === null) daemon.child.kill('SIGKILL');
    rmSync(dir, { recursive: true, force: true });
  });

  // Empty LFS/concurrency values (Compose passes them as ${VAR:-}) mean the defaults.
  const started = await startListening(dir, { AGENTGATE_CLIENT_TOKEN_FILE: makeTokenFile(dir), AGENTGATE_LFS_HOSTS: '', AGENTGATE_LFS_MAX_OBJECT_MIB: '', AGENTGATE_LFS_MAX_TRANSFERS: '', AGENTGATE_MAX_CONCURRENT: '' });
  daemon = started.daemon;
  const response = await fetch(`http://127.0.0.1:${started.port}/healthz`);
  assert.equal(response.status, 200);

  daemon.child.kill('SIGTERM');
  const code = await daemon.waitForExit();
  assert.equal(code, 0);
});

test('starts with AGENTGATE_ALLOW_UNAUTHENTICATED=1 and no token file', { timeout: TEST_TIMEOUT_MS }, async (t) => {
  const dir = tempDir('agentgate-daemon-unauth-');
  let daemon;
  t.after(() => {
    if (daemon && daemon.child.exitCode === null) daemon.child.kill('SIGKILL');
    rmSync(dir, { recursive: true, force: true });
  });

  const started = await startListening(dir, { AGENTGATE_ALLOW_UNAUTHENTICATED: '1' });
  daemon = started.daemon;
  const response = await fetch(`http://127.0.0.1:${started.port}/healthz`);
  assert.equal(response.status, 200);

  daemon.child.kill('SIGTERM');
  await daemon.waitForExit();
});

test('fails closed when AGENTGATE_CLIENT_TOKEN_FILE is missing', { timeout: TEST_TIMEOUT_MS }, async (t) => {
  const dir = tempDir('agentgate-daemon-no-token-');
  const port = await freePort();
  const env = baseEnv(dir, { AGENTGATE_PORT: String(port) });
  const daemon = spawnDaemon(env);
  t.after(() => {
    if (daemon.child.exitCode === null) daemon.child.kill('SIGKILL');
    rmSync(dir, { recursive: true, force: true });
  });

  const code = await daemon.waitForExit();
  assert.notEqual(code, 0);
  assert.match(daemon.stderr(), /AGENTGATE_CLIENT_TOKEN_FILE is required/);
  assert.doesNotMatch(daemon.stdout(), /listening/i);
});

test('fails closed when the client token file is not owner-only', { timeout: TEST_TIMEOUT_MS }, async (t) => {
  const dir = tempDir('agentgate-daemon-token-mode-');
  const port = await freePort();
  const env = baseEnv(dir, { AGENTGATE_PORT: String(port), AGENTGATE_CLIENT_TOKEN_FILE: makeTokenFile(dir, { mode: 0o644 }) });
  const daemon = spawnDaemon(env);
  t.after(() => {
    if (daemon.child.exitCode === null) daemon.child.kill('SIGKILL');
    rmSync(dir, { recursive: true, force: true });
  });

  const code = await daemon.waitForExit();
  assert.notEqual(code, 0);
  assert.match(daemon.stderr(), /owner-only/);
  assert.doesNotMatch(daemon.stdout(), /listening/i);
});

test('fails closed when only AGENTGATE_TLS_CERT_FILE is set', { timeout: TEST_TIMEOUT_MS }, async (t) => {
  const dir = tempDir('agentgate-daemon-tls-cert-only-');
  const port = await freePort();
  const env = baseEnv(dir, {
    AGENTGATE_PORT: String(port),
    AGENTGATE_CLIENT_TOKEN_FILE: makeTokenFile(dir),
    AGENTGATE_TLS_CERT_FILE: join(dir, 'broker.crt')
  });
  const daemon = spawnDaemon(env);
  t.after(() => {
    if (daemon.child.exitCode === null) daemon.child.kill('SIGKILL');
    rmSync(dir, { recursive: true, force: true });
  });

  const code = await daemon.waitForExit();
  assert.notEqual(code, 0);
  assert.match(daemon.stderr(), /Set both AGENTGATE_TLS_CERT_FILE and AGENTGATE_TLS_KEY_FILE/);
  assert.doesNotMatch(daemon.stdout(), /listening/i);
});

test('fails closed when AGENTGATE_HOST=0.0.0.0 without TLS', { timeout: TEST_TIMEOUT_MS }, async (t) => {
  const dir = tempDir('agentgate-daemon-host-plaintext-');
  const port = await freePort();
  const env = baseEnv(dir, {
    AGENTGATE_PORT: String(port),
    AGENTGATE_CLIENT_TOKEN_FILE: makeTokenFile(dir),
    AGENTGATE_HOST: '0.0.0.0'
  });
  const daemon = spawnDaemon(env);
  t.after(() => {
    if (daemon.child.exitCode === null) daemon.child.kill('SIGKILL');
    rmSync(dir, { recursive: true, force: true });
  });

  const code = await daemon.waitForExit();
  assert.notEqual(code, 0);
  assert.match(daemon.stderr(), /TLS is required when listening beyond loopback/);
  assert.doesNotMatch(daemon.stdout(), /listening/i);
});

test('reloads validated configuration on SIGHUP, rejecting an invalid config and applying a valid one',
  { timeout: TEST_TIMEOUT_MS, skip: process.platform === 'win32' ? 'SIGHUP is not supported on win32' : false },
  async (t) => {
    const dir = tempDir('agentgate-daemon-sighup-');
    let daemon;
    t.after(() => {
      if (daemon && daemon.child.exitCode === null) daemon.child.kill('SIGKILL');
      rmSync(dir, { recursive: true, force: true });
    });

    const configPath = makeConfigFile(dir);
    const started = await startListening(dir, { AGENTGATE_CONFIG: configPath, AGENTGATE_CLIENT_TOKEN_FILE: makeTokenFile(dir) });
    daemon = started.daemon;
    const baseline = JSON.parse(readFileSync(configPath, 'utf8'));

    const invalid = structuredClone(baseline);
    invalid.rules.push({ id: 'bad-rule', action: 'git.nope', repository: 'acme/demo', effect: 'allow' });
    writeOwnerOnly(configPath, JSON.stringify(invalid));
    daemon.child.kill('SIGHUP');
    await daemon.waitForStderr(/config\.reload_rejected/);

    const stillHealthy = await fetch(`http://127.0.0.1:${started.port}/healthz`);
    assert.equal(stillHealthy.status, 200);

    const valid = structuredClone(baseline);
    valid.rules.push({ id: 'notes-branch', action: 'git.push', repository: 'acme/demo', ref: 'refs/heads/notes', effect: 'allow' });
    writeOwnerOnly(configPath, JSON.stringify(valid));
    daemon.child.kill('SIGHUP');
    await daemon.waitForOutput(/"msg":"config\.reload"/);

    daemon.child.kill('SIGTERM');
    const code = await daemon.waitForExit();
    assert.equal(code, 0);
  });

test('fails closed when listening beyond loopback without AGENTGATE_PUBLIC_URL or with invalid LFS or concurrency settings', { timeout: TEST_TIMEOUT_MS }, async (t) => {
  const dir = tempDir('agentgate-daemon-public-url-');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const [extra, message] of [
    [{ AGENTGATE_HOST: '0.0.0.0', AGENTGATE_ALLOW_PLAINTEXT: '1' }, /AGENTGATE_PUBLIC_URL is required when AGENTGATE_HOST is not loopback/],
    [{ AGENTGATE_LFS_HOSTS: 'github-cloud.githubusercontent.com,*.example.com' }, /AGENTGATE_LFS_HOSTS must be/],
    [{ AGENTGATE_LFS_HOSTS: 'host.example.com:443' }, /AGENTGATE_LFS_HOSTS must be/],
    [{ AGENTGATE_MAX_CONCURRENT: '0' }, /AGENTGATE_MAX_CONCURRENT must be between 1 and 64/],
    [{ AGENTGATE_MAX_CONCURRENT: '65' }, /AGENTGATE_MAX_CONCURRENT must be between 1 and 64/],
    [{ AGENTGATE_LFS_MAX_TRANSFERS: '65' }, /AGENTGATE_LFS_MAX_TRANSFERS must be between 1 and 64/],
    [{ AGENTGATE_LFS_MAX_TRANSFERS: '2.5' }, /AGENTGATE_LFS_MAX_TRANSFERS must be between 1 and 64/]
  ]) {
    const env = baseEnv(dir, { AGENTGATE_PORT: String(await freePort()), AGENTGATE_CLIENT_TOKEN_FILE: makeTokenFile(dir), ...extra });
    const daemon = spawnDaemon(env);
    t.after(() => { if (daemon.child.exitCode === null) daemon.child.kill('SIGKILL'); });
    assert.notEqual(await daemon.waitForExit(), 0);
    assert.match(daemon.stderr(), message);
    assert.doesNotMatch(daemon.stdout(), /listening/i);
  }
});


test('local revocations file loads at startup, fails closed when invalid, and is re-read on SIGHUP',
  { timeout: TEST_TIMEOUT_MS, skip: process.platform === 'win32' ? 'SIGHUP is not supported on win32' : false },
  async (t) => {
    const dir = tempDir('agentgate-daemon-revocations-');
    let daemon;
    t.after(() => {
      if (daemon && daemon.child.exitCode === null) daemon.child.kill('SIGKILL');
      rmSync(dir, { recursive: true, force: true });
    });
    const configPath = makeConfigFile(dir);
    const tokenPath = makeTokenFile(dir);
    const revocationsPath = join(dir, 'revocations.json');

    writeOwnerOnly(revocationsPath, '{"jtis": [1]}');
    const refused = spawnDaemon(baseEnv(dir, { AGENTGATE_PORT: String(await freePort()), AGENTGATE_CONFIG: configPath, AGENTGATE_CLIENT_TOKEN_FILE: tokenPath, AGENTGATE_REVOCATIONS_FILE: revocationsPath }));
    assert.notEqual(await refused.waitForExit(), 0);
    assert.match(refused.stderr(), /AGENTGATE_REVOCATIONS_FILE must be JSON/);

    writeOwnerOnly(revocationsPath, JSON.stringify({ jtis: ['jti-1'], runtimeIds: ['rt-1'] }));
    const started = await startListening(dir, { AGENTGATE_CONFIG: configPath, AGENTGATE_CLIENT_TOKEN_FILE: tokenPath, AGENTGATE_REVOCATIONS_FILE: revocationsPath });
    daemon = started.daemon;
    writeOwnerOnly(revocationsPath, JSON.stringify({ jtis: ['jti-1'], runtimeIds: ['rt-1'] }), 0o644);
    daemon.child.kill('SIGHUP');
    await daemon.waitForStderr(/revocations\.reload_rejected/);
    writeOwnerOnly(revocationsPath, JSON.stringify({ jtis: ['jti-1', 'jti-2'] }));
    daemon.child.kill('SIGHUP');
    await daemon.waitForOutput(/"msg":"revocations\.reloaded".*"entries":2/);
    daemon.child.kill('SIGTERM');
    assert.equal(await daemon.waitForExit(), 0);
  });

test('local revocations file is re-read automatically when it changes, without SIGHUP',
  { timeout: TEST_TIMEOUT_MS },
  async (t) => {
    const dir = tempDir('agentgate-daemon-revocations-poll-');
    let daemon;
    t.after(() => {
      if (daemon && daemon.child.exitCode === null) daemon.child.kill('SIGKILL');
      rmSync(dir, { recursive: true, force: true });
    });
    const configPath = makeConfigFile(dir);
    const tokenPath = makeTokenFile(dir);
    const revocationsPath = join(dir, 'revocations.json');
    writeOwnerOnly(revocationsPath, JSON.stringify({ jtis: ['jti-1'] }));
    const started = await startListening(dir, { AGENTGATE_CONFIG: configPath, AGENTGATE_CLIENT_TOKEN_FILE: tokenPath, AGENTGATE_REVOCATIONS_FILE: revocationsPath, AGENTGATE_REVOCATIONS_POLL_MS: '100' });
    daemon = started.daemon;
    // The issuer writes atomically (temp file + rename), which changes the inode as well as mtime.
    const temporary = `${revocationsPath}.tmp`;
    writeOwnerOnly(temporary, JSON.stringify({ jtis: ['jti-1', 'jti-2', 'jti-3'] }));
    renameSync(temporary, revocationsPath);
    await daemon.waitForOutput(/"msg":"revocations\.reloaded".*"entries":3.*"reason":"poll"/);
    writeOwnerOnly(revocationsPath, '{"jtis": [1]}');
    await daemon.waitForStderr(/revocations\.reload_rejected.*"reason":"poll"/);
    daemon.child.kill('SIGTERM');
    assert.equal(await daemon.waitForExit(), 0);
  });
