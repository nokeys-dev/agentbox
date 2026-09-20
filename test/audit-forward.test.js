import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { setImmediate as tick } from 'node:timers/promises';
import { State } from '../src/state.js';
import { auditFiles } from '../src/audit-chain.js';
import { forwardOnce, httpSink } from '../src/audit-forward.js';

const execute = promisify(execFile);

const hasProcFd = existsSync('/proc/self/fd');

function setup(t, options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-forward-'));
  const state = new State(directory, options);
  t.after(() => { try { state.close(); } catch { /* closed in test */ } rmSync(directory, { recursive: true, force: true }); });
  return { directory, state, checkpointPath: join(directory, 'audit-forward.json') };
}

test('forwards in order, checkpoints only after success, and resumes', async (t) => {
  const { directory, state, checkpointPath } = setup(t, { maxAuditBytes: 250 });
  for (let i = 0; i < 7; i++) state.audit({ type: 'e', i });
  const received = [];
  let fail = true;
  const flaky = async (records) => { if (fail) { fail = false; throw new Error('sink down'); } received.push(...records); };
  await assert.rejects(forwardOnce({ directory, checkpointPath, send: flaky, batchSize: 3 }), /sink down/);
  assert.throws(() => readFileSync(checkpointPath));
  const first = await forwardOnce({ directory, checkpointPath, send: flaky, batchSize: 3 });
  assert.equal(first.sent, 7);
  assert.equal(first.lagRecords, 0);
  assert.deepEqual(received.map((record) => record.seq), [1, 2, 3, 4, 5, 6, 7]);
  state.audit({ type: 'later' });
  const second = await forwardOnce({ directory, checkpointPath, send: flaky });
  assert.equal(second.sent, 1);
  assert.equal(JSON.parse(readFileSync(checkpointPath, 'utf8')).seq, 8);
});

test('refuses to forward a broken chain or across an eviction gap', async (t) => {
  const { directory, state, checkpointPath } = setup(t);
  state.audit({ type: 'a' });
  state.audit({ type: 'b' });
  const path = join(directory, 'audit.jsonl');
  writeFileSync(path, readFileSync(path, 'utf8').replace('"b"', '"x"'));
  await assert.rejects(forwardOnce({ directory, checkpointPath, send: async () => {} }), { code: 'CHAIN_BROKEN' });
  writeFileSync(checkpointPath, JSON.stringify({ seq: -5, hash: '0'.repeat(64) }));
  writeFileSync(path, readFileSync(path, 'utf8').split('\n').slice(1).join('\n'));
  await assert.rejects(forwardOnce({ directory, checkpointPath, send: async () => {} }), { code: 'AUDIT_GAP' });
});

test('does not leak file descriptors across repeated CHAIN_BROKEN failures', { skip: hasProcFd ? false : 'requires /proc/self/fd (Linux only)' }, async (t) => {
  const { directory, state, checkpointPath } = setup(t);
  state.audit({ type: 'a' });
  state.audit({ type: 'b' });
  const path = join(directory, 'audit.jsonl');
  writeFileSync(path, readFileSync(path, 'utf8').replace('"b"', '"x"')); // permanently tampered: every call throws CHAIN_BROKEN
  const fdCount = () => readdirSync('/proc/self/fd').length;
  await tick();
  const before = fdCount();
  for (let i = 0; i < 20; i++) {
    await assert.rejects(forwardOnce({ directory, checkpointPath, send: async () => {} }), { code: 'CHAIN_BROKEN' });
  }
  await tick();
  const after = fdCount();
  assert.ok(after - before <= 2, `expected no fd growth from repeated failures, went from ${before} to ${after}`);
});

test('detects a full audit wipe after forwarding as a gap, not a silent no-op', async (t) => {
  const { directory, state, checkpointPath } = setup(t);
  state.audit({ type: 'a' });
  state.audit({ type: 'b' });
  const sent = [];
  await forwardOnce({ directory, checkpointPath, send: async (records) => sent.push(...records) });
  assert.equal(sent.length, 2);
  rmSync(join(directory, 'audit.jsonl'));
  await assert.rejects(forwardOnce({ directory, checkpointPath, send: async () => {} }), { code: 'AUDIT_GAP' });
});

test('detects a rewound (truncated) audit chain after forwarding as a gap', async (t) => {
  const { directory, state, checkpointPath } = setup(t);
  state.audit({ type: 'a' });
  state.audit({ type: 'b' });
  state.audit({ type: 'c' });
  await forwardOnce({ directory, checkpointPath, send: async () => {} });
  assert.equal(JSON.parse(readFileSync(checkpointPath, 'utf8')).seq, 3);
  const path = join(directory, 'audit.jsonl');
  const firstLine = readFileSync(path, 'utf8').split('\n')[0];
  writeFileSync(path, `${firstLine}\n`); // still a valid chain from genesis, just shorter than the checkpoint
  await assert.rejects(forwardOnce({ directory, checkpointPath, send: async () => {} }), { code: 'AUDIT_GAP' });
});

test('skips fully-forwarded rotated files by their tail seq alone, tolerating stale corruption inside them', async (t) => {
  const { directory, state, checkpointPath } = setup(t, { maxAuditBytes: 450 });
  for (let i = 0; i < 6; i++) state.audit({ type: 'e', i }); // rotates once: 3 records rotated out, 3 remain in audit.jsonl
  const rotatedFile = auditFiles(directory).find((file) => file !== join(directory, 'audit.jsonl'));
  const lines = readFileSync(rotatedFile, 'utf8').trim().split('\n');
  assert.equal(lines.length, 3);
  const lastRotatedRecord = JSON.parse(lines.at(-1));
  lines[0] = lines[0].replace('"type":"e"', '"type"'); // corrupt a non-last line: forwardOnce must never read it
  writeFileSync(rotatedFile, `${lines.join('\n')}\n`);
  writeFileSync(checkpointPath, JSON.stringify({ seq: lastRotatedRecord.seq, hash: lastRotatedRecord.hash }));
  state.audit({ type: 'later' }); // forces a second rotation, exercising the multi-file streaming path too
  const result = await forwardOnce({ directory, checkpointPath, send: async () => {} });
  assert.equal(result.sent, 4);
  assert.equal(result.head.seq, 7);
});

test('http sink posts JSON with bearer auth and fails on non-2xx', async () => {
  const calls = [];
  const sink = httpSink({ url: 'https://siem.example/ingest', token: 'tok', fetchImpl: async (url, options) => { calls.push({ url, options }); return new Response(null, { status: calls.length === 1 ? 202 : 500 }); } });
  await sink([{ seq: 1 }]);
  assert.equal(calls[0].options.headers.authorization, 'Bearer tok');
  assert.deepEqual(JSON.parse(calls[0].options.body), { records: [{ seq: 1 }] });
  assert.equal(calls[0].options.redirect, 'error');
  await assert.rejects(sink([{ seq: 2 }]), /500/);
  assert.throws(() => httpSink({ url: 'http://insecure.example' }), /https/);
});

function runAuditForwardCli(directory, overrides = {}) {
  return execute(process.execPath, [join(import.meta.dirname, '..', 'scripts', 'audit-forward.js')], {
    env: { PATH: process.env.PATH, AGENTGATE_AUDIT_SINK_URL: 'https://siem.example/ingest', AGENTGATE_STATE_DIR: directory, ...overrides }
  });
}

test('audit-forward.js fails closed when AGENTGATE_AUDIT_SINK_TOKEN_FILE is not owner-only', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-forward-cli-'));
  try {
    const tokenPath = join(directory, 'token');
    writeFileSync(tokenPath, 'secret-token');
    chmodSync(tokenPath, 0o644);
    await assert.rejects(runAuditForwardCli(directory, { AGENTGATE_AUDIT_SINK_TOKEN_FILE: tokenPath }), (error) => {
      assert.notEqual(error.code, 0);
      assert.match(error.stderr, /owner-only/);
      return true;
    });
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('audit-forward.js fails closed when AGENTGATE_AUDIT_SINK_TOKEN_FILE is empty', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-forward-cli-'));
  try {
    const tokenPath = join(directory, 'token');
    writeFileSync(tokenPath, '   \n');
    chmodSync(tokenPath, 0o600);
    await assert.rejects(runAuditForwardCli(directory, { AGENTGATE_AUDIT_SINK_TOKEN_FILE: tokenPath }), (error) => {
      assert.notEqual(error.code, 0);
      assert.match(error.stderr, /must not be empty/);
      return true;
    });
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
