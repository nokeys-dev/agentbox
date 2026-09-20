import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { GENESIS, auditFiles, canonical, chainRecord, readChainHead, verifyChain } from '../src/audit-chain.js';
import { State } from '../src/state.js';

test('canonical JSON sorts keys recursively', () => {
  assert.equal(canonical({ b: 1, a: { d: [2, { z: 1, y: 2 }], c: 3 } }), '{"a":{"c":3,"d":[2,{"y":2,"z":1}]},"b":1}');
});

test('chain detects edits, deletions, reordering, and truncation-with-rewrite', () => {
  let head = { seq: 0, hash: GENESIS };
  const lines = [];
  for (const type of ['a', 'b', 'c']) {
    const record = chainRecord({ type }, head);
    head = { seq: record.seq, hash: record.hash };
    lines.push(JSON.stringify(record));
  }
  assert.deepEqual(verifyChain(lines), { ok: true, head, count: 3 });
  const edited = [...lines];
  edited[1] = edited[1].replace('"b"', '"x"');
  assert.deepEqual(verifyChain(edited), { ok: false, line: 2, reason: 'hash mismatch' });
  assert.equal(verifyChain([lines[0], lines[2]]).reason, 'sequence gap');
  assert.equal(verifyChain([lines[1], lines[0]]).ok, false);
  assert.equal(verifyChain(['not json']).reason, 'invalid JSON');
});

test('State chains across restarts and rotation, and audit:verify reports tampering', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-chain-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  let state = new State(directory, { maxAuditBytes: 300 });
  for (let i = 0; i < 5; i++) state.audit({ type: 'event', i });
  state.close();
  state = new State(directory, { maxAuditBytes: 300 });
  state.audit({ type: 'after-restart' });
  state.close();
  assert(auditFiles(directory).length > 1);
  const all = auditFiles(directory).flatMap((file) => readFileSync(file, 'utf8').trim().split('\n'));
  const result = verifyChain(all);
  assert.equal(result.ok, true);
  assert.equal(result.count, 6);
  assert.deepEqual(readChainHead(directory), result.head);
  assert.match(execFileSync(process.execPath, ['scripts/audit-verify.js', directory], { encoding: 'utf8' }), /OK 6 records head 6:[0-9a-f]{64}/);
  const current = join(directory, 'audit.jsonl');
  writeFileSync(current, readFileSync(current, 'utf8').replace('after-restart', 'after-restarT'));
  assert.throws(() => execFileSync(process.execPath, ['scripts/audit-verify.js', directory], { stdio: 'pipe' }), (error) => /hash mismatch/.test(error.stderr.toString()));
  assert.throws(() => new State(directory), /Audit chain tail is invalid/);
});

test('audit-verify.js fails cleanly (not a stack trace) on invalid JSON in the first line', () => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-chain-badjson-'));
  try {
    writeFileSync(join(directory, 'audit.jsonl'), 'not json at all\n');
    assert.throws(() => execFileSync(process.execPath, ['scripts/audit-verify.js', directory], { stdio: 'pipe' }), (error) => {
      const stderr = error.stderr.toString();
      assert.match(stderr, /^FAIL .*audit\.jsonl:1 invalid JSON/m);
      assert.doesNotMatch(stderr, /SyntaxError/);
      return true;
    });
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
