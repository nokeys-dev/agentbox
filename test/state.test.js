import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir, hostname } from 'node:os';
import { State } from '../src/state.js';

test('approval persists, expires, and is durably consumed only once', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-state-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  let now = 1000;
  let state = new State(directory, { now: () => now, ttlMs: 100 });
  const pending = state.request('key', { repository: 'acme/demo' });
  assert.equal(pending.created, true);
  assert(!Object.keys(pending).includes('created'), 'created must be non-enumerable');
  assert(!/"created"\s*:/.test(JSON.stringify(pending)), 'created must not be JSON-serialized (createdAt is a different, legitimate field)');
  const retried = state.request('key', {});
  assert.equal(retried.id, pending.id);
  assert.equal(retried.created, false);
  assert(!/"created"\s*:/.test(readFileSync(join(directory, 'approvals.json'), 'utf8')), 'created must not be persisted to approvals.json (createdAt is a different, legitimate field)');
  assert.equal(state.consume('key'), undefined);
  state.review(pending.id.slice(0, 8), true, 'local:tester');
  state.close();
  state = new State(directory, { now: () => now, ttlMs: 100 });
  assert.equal(state.consume('key'), pending.id);
  assert.equal(state.consume('key'), undefined);
  state.close();
  state = new State(directory, { now: () => now, ttlMs: 100 });
  assert.equal(state.consume('key'), undefined);
  const expiring = state.request('next', {});
  state.review(expiring.id, true, 'local:tester');
  now += 101;
  assert.equal(state.consume('next'), undefined);
  assert.equal(state.list().at(-1).status, 'expired');
  assert.throws(() => state.review(expiring.id, true, 'local:tester'), { code: 'APPROVAL_NOT_PENDING' });
  assert.equal(statSync(join(directory, 'approvals.json')).mode & 0o777, 0o600);
  state.close();
});

test('single writer lock and rejected reviews cannot grant access', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-state-'));
  const state = new State(directory);
  t.after(() => { state.close(); rmSync(directory, { recursive: true, force: true }); });
  assert.throws(() => new State(directory), { code: 'EEXIST' });
  const pending = state.request('key', {});
  assert.throws(() => state.review('abc', true, 'local:tester'), { code: 'INVALID_ID' });
  state.review(pending.id, false, 'local:tester');
  assert.equal(state.consume('key'), undefined);
  assert.throws(() => state.review(pending.id, true, 'local:tester'), { code: 'APPROVAL_NOT_PENDING' });
});

test('pending cap, retention pruning, disk floor, and audit rotation', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-state-'));
  let now = 1000;
  let free = 10 * 1024 * 1024 * 1024;
  const statfs = () => ({ bavail: free / 4096, bsize: 4096 });
  const state = new State(directory, { now: () => now, ttlMs: 100, maxPending: 2, retentionMs: 1000, maxAuditBytes: 200, maxAuditFiles: 2, statfs });
  t.after(() => { state.close(); rmSync(directory, { recursive: true, force: true }); });
  const first = state.request('one', {});
  state.request('two', {});
  assert.throws(() => state.request('three', {}), { code: 'TOO_MANY_PENDING', status: 429 });
  state.review(first.id, false, 'local:tester');
  state.request('three', {});
  now += 5000;
  state.request('four', {});
  assert.deepEqual(state.list().map((item) => item.key), ['four']);
  for (let i = 0; i < 20; i++) state.audit({ type: 'test', i, padding: 'x'.repeat(40) });
  const rotated = readdirSync(directory).filter((name) => /^audit-\d+-\d+\.jsonl$/.test(name));
  assert.equal(rotated.length, 2);
  free = 1024;
  assert.throws(() => state.audit({ type: 'test' }), { code: 'DISK_LOW', status: 503 });
});

test('stale locks from dead processes are reclaimed; live and foreign locks are not', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-state-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const lock = join(directory, 'daemon.lock');
  writeFileSync(lock, JSON.stringify({ pid: 999999, hostname: hostname(), startedAt: 1 }));
  const reclaimed = new State(directory, { isAlive: () => false });
  assert.equal(JSON.parse(readFileSync(lock, 'utf8')).pid, process.pid);
  assert.throws(() => new State(directory, { isAlive: () => false }), { code: 'EEXIST' });
  reclaimed.close();
  writeFileSync(lock, JSON.stringify({ pid: 4242, hostname: hostname(), startedAt: 1 }));
  assert.throws(() => new State(directory, { isAlive: () => true }), { code: 'EEXIST' });
  writeFileSync(lock, JSON.stringify({ pid: 4242, hostname: 'other-host', startedAt: 1 }));
  assert.throws(() => new State(directory, { isAlive: () => false }), { code: 'LOCK_FOREIGN' });
  writeFileSync(lock, '12345\n');
  const legacy = new State(directory, { isAlive: () => false });
  legacy.close();
});

test('a reclaim guard file blocks a concurrent reclaim and the guarded lock is left intact', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-state-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const lock = join(directory, 'daemon.lock');
  const guard = `${lock}.reclaim`;
  const stale = JSON.stringify({ pid: 999999, hostname: hostname(), startedAt: 1 });
  writeFileSync(lock, stale);
  writeFileSync(guard, '');
  t.after(() => rmSync(guard, { force: true }));
  assert.throws(() => new State(directory, { isAlive: () => false }), { code: 'EEXIST' });
  assert.equal(readFileSync(lock, 'utf8'), stale);
});

test('a lock that turns live during the guarded re-check is not deleted', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-state-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const lock = join(directory, 'daemon.lock');
  const stale = JSON.stringify({ pid: 4242, hostname: hostname(), startedAt: 1 });
  writeFileSync(lock, stale);
  let calls = 0;
  const isAlive = () => { calls += 1; return calls > 1; };
  assert.throws(() => new State(directory, { isAlive }), { code: 'EEXIST' });
  assert.equal(readFileSync(lock, 'utf8'), stale);
  assert.equal(calls, 2);
});

test('two-person approvals require distinct reviewers who are not the delegating human', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-state-'));
  const state = new State(directory);
  t.after(() => { state.close(); rmSync(directory, { recursive: true, force: true }); });
  const context = { runtime: { human: 'oidc:dev@example.com' } };
  const item = state.request('k', context, { requiredApprovals: 2 });
  assert.equal(item.requiredApprovals, 2);
  assert.throws(() => state.review(item.id, true, ''), { code: 'REVIEWER_REQUIRED' });
  assert.throws(() => state.review(item.id, true, 'oidc:dev@example.com'), { code: 'SELF_APPROVAL' });
  assert.equal(state.review(item.id, true, 'oidc:lead@example.com').status, 'pending');
  assert.throws(() => state.review(item.id, true, 'oidc:lead@example.com'), { code: 'DUPLICATE_REVIEWER' });
  assert.equal(state.consume('k'), undefined);
  const done = state.review(item.id, true, 'oidc:security@example.com');
  assert.equal(done.status, 'approved');
  assert.deepEqual(done.reviews.map((review) => review.reviewer), ['oidc:lead@example.com', 'oidc:security@example.com']);
  assert.equal(state.consume('k'), item.id);
  const other = state.request('k2', context, { requiredApprovals: 2 });
  state.review(other.id, true, 'oidc:lead@example.com');
  assert.equal(state.review(other.id, false, 'oidc:security@example.com').status, 'denied');
});

test('the duplicate-reviewer check compares identities across schemes and case, not raw strings', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-state-'));
  const state = new State(directory);
  t.after(() => { state.close(); rmSync(directory, { recursive: true, force: true }); });
  const context = { runtime: { human: 'oidc:dev@example.com' } };
  const item = state.request('dup', context, { requiredApprovals: 2 });
  assert.equal(state.review(item.id, true, 'local:Alice').status, 'pending');
  assert.throws(() => state.review(item.id, true, 'oidc:alice'), { code: 'DUPLICATE_REVIEWER' });
});
