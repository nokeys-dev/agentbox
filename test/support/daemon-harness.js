// Spawns the real broker daemon for tests: temp directories, owner-only fixture files, a free port,
// and a wrapper that captures output and waits for the listening line.
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, chmodSync, renameSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';

export const DAEMON_PATH = join(import.meta.dirname, '..', '..', 'src', 'daemon.js');
export const TEST_TIMEOUT_MS = 15_000;

// Finds a free loopback port by briefly listening on port 0 and closing again.
// The daemon's own port validation rejects 0 (`AGENTGATE_PORT must be between 1 and 65535`
// only allows 1-65535, and 0 is outside that once bound), so callers cannot just pass 0 through.
export async function freePort() {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolvePort(port));
    });
  });
}

export function tempDir(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

export function writeOwnerOnly(path, content, mode = 0o600) {
  writeFileSync(path, content);
  chmodSync(path, mode);
}

export function makePrivateKeyFile(dir) {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' }
  });
  const path = join(dir, 'app.pem');
  writeOwnerOnly(path, privateKey);
  return path;
}

export function makeTokenFile(dir, { mode = 0o600 } = {}) {
  const path = join(dir, 'client-token');
  writeOwnerOnly(path, randomBytes(32).toString('hex'), mode);
  return path;
}

export function makeConfigFile(dir) {
  const config = {
    runtime: { human: 'test@example.com', agent: 'daemon-test', runtimeId: 'daemon-test-runtime', task: 'daemon-startup-test' },
    repositories: [{ name: 'acme/demo', id: 123456789, installationId: 12345678, protectedBranches: ['main'] }],
    rules: [
      { id: 'read-repository', action: 'git.read', repository: 'acme/demo', effect: 'allow' },
      { id: 'feature-branches', action: 'git.push', repository: 'acme/demo', ref: 'refs/heads/agent/*', effect: 'allow' },
      { id: 'review-main', action: 'git.push', repository: 'acme/demo', ref: 'refs/heads/main', effect: 'approval' },
      { id: 'protect-tags', action: 'git.push', repository: '*', ref: 'refs/tags/*', effect: 'deny' },
      { id: 'protect-deletions', action: 'git.push', repository: '*', ref: '*', operation: 'delete', effect: 'deny' }
    ]
  };
  const path = join(dir, 'config.json');
  writeOwnerOnly(path, JSON.stringify(config));
  return path;
}

// Builds a minimal, fully explicit env for the daemon child process. Never spreads
// process.env: the daemon must not accidentally inherit the test runner's own
// GITHUB_*/AGENTGATE_* variables (or lack thereof).
export function baseEnv(dir, overrides = {}) {
  return {
    PATH: process.env.PATH,
    GITHUB_APP_ID: '1',
    GITHUB_PRIVATE_KEY_PATH: makePrivateKeyFile(dir),
    AGENTGATE_CONFIG: makeConfigFile(dir),
    AGENTGATE_STATE_DIR: join(dir, 'state'),
    AGENTGATE_SKIP_RULESET_CHECK: '1',
    ...overrides
  };
}

export function spawnDaemon(env) {
  const child = spawn(process.execPath, [DAEMON_PATH], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  return {
    child,
    stdout: () => stdout,
    stderr: () => stderr,
    waitForOutput(pattern, timeoutMs = TEST_TIMEOUT_MS - 2000) {
      return new Promise((resolveMatch, reject) => {
        if (pattern.test(stdout)) { resolveMatch(); return; }
        const cleanup = () => {
          clearTimeout(timer);
          child.stdout.off('data', onData);
          child.off('exit', onExit);
        };
        const onData = () => { if (pattern.test(stdout)) { cleanup(); resolveMatch(); } };
        const onExit = (code) => { cleanup(); reject(new Error(`daemon exited (code ${code}) before matching ${pattern}. stdout=${JSON.stringify(stdout)} stderr=${JSON.stringify(stderr)}`)); };
        const timer = setTimeout(() => { cleanup(); reject(new Error(`timed out waiting for ${pattern}. stdout=${JSON.stringify(stdout)} stderr=${JSON.stringify(stderr)}`)); }, timeoutMs);
        child.stdout.on('data', onData);
        child.once('exit', onExit);
      });
    },
    waitForStderr(pattern, timeoutMs = TEST_TIMEOUT_MS - 2000) {
      return new Promise((resolveMatch, reject) => {
        if (pattern.test(stderr)) { resolveMatch(); return; }
        const cleanup = () => {
          clearTimeout(timer);
          child.stderr.off('data', onData);
          child.off('exit', onExit);
        };
        const onData = () => { if (pattern.test(stderr)) { cleanup(); resolveMatch(); } };
        const onExit = (code) => { cleanup(); reject(new Error(`daemon exited (code ${code}) before matching ${pattern} on stderr. stdout=${JSON.stringify(stdout)} stderr=${JSON.stringify(stderr)}`)); };
        const timer = setTimeout(() => { cleanup(); reject(new Error(`timed out waiting for ${pattern} on stderr. stdout=${JSON.stringify(stdout)} stderr=${JSON.stringify(stderr)}`)); }, timeoutMs);
        child.stderr.on('data', onData);
        child.once('exit', onExit);
      });
    },
    waitForExit(timeoutMs = TEST_TIMEOUT_MS - 2000) {
      return new Promise((resolveExit, reject) => {
        if (child.exitCode !== null) { resolveExit(child.exitCode); return; }
        const timer = setTimeout(() => reject(new Error(`timed out waiting for exit. stdout=${JSON.stringify(stdout)} stderr=${JSON.stringify(stderr)}`)), timeoutMs);
        child.once('exit', (code) => { clearTimeout(timer); resolveExit(code); });
      });
    }
  };
}

// freePort() closes its probe listener before the daemon binds, leaving a window where another
// process on the machine could grab the same port (TOCTOU). AGENTGATE_PORT=0 (letting the OS
// choose atomically at bind time) is rejected by the daemon's own port validation, so instead we
// detect the race (the daemon exits with EADDRINUSE before ever logging "listening") and retry
// with a freshly chosen port, up to `attempts` times total.
export async function startListening(dir, overrides, attempts = 3) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const port = await freePort();
    const env = baseEnv(dir, { AGENTGATE_PORT: String(port), ...overrides });
    const daemon = spawnDaemon(env);
    try {
      await daemon.waitForOutput(/listening/i);
      return { daemon, port };
    } catch (error) {
      lastError = error;
      if (daemon.child.exitCode === null) daemon.child.kill('SIGKILL');
      if (attempt === attempts || !/EADDRINUSE/.test(daemon.stderr())) throw lastError;
    }
  }
  throw lastError;
}

