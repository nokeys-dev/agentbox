import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { request } from 'node:https';
import { join } from 'node:path';
import { fixture } from '../scripts/support/fixture.js';

function hasOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); return true; } catch { return false; }
}

function get(url, ca, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = request(url, { ca, headers }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('broker serves Git over TLS and rejects untrusted clients', { skip: !hasOpenssl() && 'openssl unavailable' }, async (t) => {
  const certDir = await import('node:fs/promises').then((fs) => fs.mkdtemp(join(import.meta.dirname, '..', '.tls-test-')));
  t.after(() => execFileSync('rm', ['-rf', certDir]));
  execFileSync('sh', ['scripts/make-dev-cert.sh', certDir], { stdio: 'ignore' });
  const tls = { cert: readFileSync(join(certDir, 'broker.crt')), key: readFileSync(join(certDir, 'broker.key')) };
  const ca = readFileSync(join(certDir, 'ca.crt'));
  const f = await fixture({ tls });
  t.after(() => f.close());
  assert.match(f.gate.url, /^https:\/\/127\.0\.0\.1:\d+$/);
  const health = await get(`${f.gate.url}/healthz`, ca);
  assert.equal(health.status, 200);
  await assert.rejects(fetch(`${f.gate.url}/healthz`), /fetch failed/);
  const clone = join(f.directory, 'tls-clone');
  await f.git(f.directory, '-c', `http.sslCAInfo=${join(certDir, 'ca.crt')}`, 'clone', f.remote, clone);
  assert.equal(readFileSync(join(clone, 'README.md'), 'utf8'), '# Demo repository\n');
});

test('make-dev-cert.sh creates a 0700 output directory and 0600 keys even under a permissive umask', { skip: !hasOpenssl() && 'openssl unavailable' }, async (t) => {
  const parent = await import('node:fs/promises').then((fs) => fs.mkdtemp(join(import.meta.dirname, '..', '.tls-test-')));
  t.after(() => execFileSync('rm', ['-rf', parent]));
  const target = join(parent, 'not-yet-created');
  const previousUmask = process.umask(0o022);
  try {
    execFileSync('sh', ['scripts/make-dev-cert.sh', target], { stdio: 'ignore' });
  } finally {
    process.umask(previousUmask);
  }
  assert.equal(statSync(target).mode & 0o777, 0o700);
  assert.equal(statSync(join(target, 'broker.key')).mode & 0o777, 0o600);
  assert.equal(statSync(join(target, 'ca.key')).mode & 0o777, 0o600);
});
