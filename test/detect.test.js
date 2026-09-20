import test from 'node:test';
import assert from 'node:assert/strict';
import { detect } from '../scripts/detect.js';

// Deviations from the task-9 brief's illustrative test, made after grepping src/ for the real
// audit shapes (see task-9-report.md for the full trace):
//  - approval.review records carry the runtime at `context.runtime`, not top-level `runtime`
//    (src/state.js request()/review path persists `context` verbatim).
//  - The off-hours protected push (D5) is matched against a repository's configured
//    `protectedBranches` (src/config.js: bare branch names, no `refs/heads/` prefix), not a
//    pre-expanded `protectedRefs` list of full ref names; detect() takes `protectedBranches` and
//    expands `refs/heads/<name>` itself.
//  - `model.request` (src/model-gateway.js) and `egress` (src/egress-proxy.js) records never
//    carry a `runtime` field in the real code (those services never see the runtime assertion).
//    This task adds a `client` field (the socket's remote address) to both emitters as the best
//    available identity; the tests below reflect that, not a fabricated `runtime`.
//  - ASSERTION_INVALID (src/assertion.js) never reaches the audit stream as an individual event:
//    src/server.js batches it (and other pre-auth rejection codes) into periodic
//    `{ type: 'rejections', code, count, windowStart }` summaries with no identity at all. D6
//    sums `count` across those summaries instead of counting per-event occurrences.

const at = (minutes) => new Date(Date.UTC(2026, 8, 16, 12, 0) + minutes * 60_000).toISOString();

test('detections fire on thresholds and cite evidence by seq', () => {
  const decisionDeny = (seq, i) => ({ seq, type: 'decision', decision: 'deny', action: 'git.push', rule: 'default-deny',
    runtime: { runtimeId: 'rt-1' }, timestamp: at(i) });
  const contentBlocked = { seq: 11, type: 'decision', decision: 'content-blocked', code: 'CONTENT_BLOCKED',
    runtime: { runtimeId: 'rt-1' }, repository: 'acme/widgets', approvalId: 'appr-1', findings: ['path/to/secret'], timestamp: at(11) };
  const approvalDeny = (seq, i) => ({ seq, type: 'approval.review', decision: 'deny', reviewer: 'alice', source: 'local',
    approvals: [], requiredApprovals: 1, status: 'denied', context: { runtime: { runtimeId: 'rt-1' }, repository: 'acme/widgets' }, timestamp: at(20 + i) });
  const offHoursPush = { seq: 15, type: 'decision', decision: 'allow', action: 'git.push', rule: 'allow-main',
    runtime: { runtimeId: 'rt-1' }, changes: [{ ref: 'refs/heads/main', oldOid: 'a'.repeat(40), newOid: 'b'.repeat(40), operation: 'update', effect: 'allow', rule: 'allow-main' }],
    timestamp: new Date(Date.UTC(2026, 8, 16, 23, 30)).toISOString() };
  const modelVolume = { seq: 16, type: 'model.request', route: '/anthropic', path: '/v1/messages', status: 200,
    bytesUp: 60 * 1024 * 1024, bytesDown: 512, client: '10.0.0.5', timestamp: at(30) };

  const records = [
    ...Array.from({ length: 10 }, (_, i) => decisionDeny(i + 1, i)),
    contentBlocked,
    ...Array.from({ length: 3 }, (_, i) => approvalDeny(i + 12, i)),
    offHoursPush,
    modelVolume
  ];

  const alerts = detect(records, { protectedBranches: ['main'] });
  assert.deepEqual(alerts.map((alert) => alert.id).sort(), [
    'D1-denial-burst', 'D2-content-blocked', 'D4-approval-rejections', 'D5-off-hours-protected-push', 'D7-model-volume'
  ]);
  assert.deepEqual(alerts.find((alert) => alert.id === 'D1-denial-burst').evidence, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  assert.equal(alerts.find((alert) => alert.id === 'D1-denial-burst').runtimeId, 'rt-1');
  assert.deepEqual(alerts.find((alert) => alert.id === 'D2-content-blocked').evidence, [11]);
  assert.ok(!JSON.stringify(alerts.find((alert) => alert.id === 'D2-content-blocked')).includes('path/to/secret'), 'summary must not echo findings paths');
  assert.deepEqual(alerts.find((alert) => alert.id === 'D4-approval-rejections').evidence, [12, 13, 14]);
  assert.deepEqual(alerts.find((alert) => alert.id === 'D5-off-hours-protected-push').evidence, [15]);
  assert.deepEqual(alerts.find((alert) => alert.id === 'D7-model-volume').evidence, [16]);
  assert.equal(alerts.find((alert) => alert.id === 'D7-model-volume').runtimeId, 'client:10.0.0.5');

  // Below every threshold: nothing fires, and D5 needs a configured protected branch to match at all.
  assert.deepEqual(detect(records.slice(0, 9), { protectedBranches: [] }), []);
});

test('D3-egress-probing groups denied CONNECT attempts by client address, not runtime', () => {
  // Spaced 20 seconds apart so all 20 fit inside the 10-minute window.
  const records = Array.from({ length: 20 }, (_, i) => ({
    seq: i + 1, type: 'egress', decision: 'deny', host: `evil${i}.example`, port: 443, reason: 'not-allowlisted',
    bytesUp: 0, bytesDown: 0, client: '10.0.0.9', timestamp: at(i / 3)
  }));
  const alerts = detect(records, {});
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].id, 'D3-egress-probing');
  assert.equal(alerts[0].runtimeId, 'client:10.0.0.9');
  assert.equal(alerts[0].evidence.length, 20);

  // Nineteen deny events never reach the threshold.
  assert.deepEqual(detect(records.slice(0, 19), {}), []);
});

test('D6-assertion-failures sums rejection-summary counts broker-wide (no per-event identity exists)', () => {
  const records = [
    { seq: 1, type: 'rejections', code: 'ASSERTION_INVALID', count: 2, windowStart: Date.parse(at(0)), timestamp: at(1) },
    { seq: 2, type: 'rejections', code: 'ASSERTION_INVALID', count: 3, windowStart: Date.parse(at(2)), timestamp: at(3) },
    // A different rejection code must never contribute to this detection's total.
    { seq: 3, type: 'rejections', code: 'RATE_LIMITED', count: 100, windowStart: Date.parse(at(3)), timestamp: at(4) }
  ];
  const alerts = detect(records, {});
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].id, 'D6-assertion-failures');
  assert.equal(alerts[0].runtimeId, undefined);
  assert.deepEqual(alerts[0].evidence, [1, 2]);

  assert.deepEqual(detect(records.slice(0, 1), {}), []);
});

test('never throws on malformed, unsorted, or identity-less records', () => {
  const malformed = [
    null,
    undefined,
    42,
    'not an object',
    {},
    { type: 'decision', decision: 'deny' }, // no seq, no timestamp
    { seq: 'not-a-number', type: 'decision', decision: 'deny', timestamp: at(0) },
    { seq: 1, type: 'decision', decision: 'deny', timestamp: 'not-a-date' },
    { seq: 2, type: 'egress', decision: 'deny', timestamp: at(0) }, // no client at all
    { seq: 3, type: 'model.request', bytesUp: 'lots', timestamp: at(0) }, // non-numeric bytesUp
    { seq: 4, type: 'decision', decision: 'allow', action: 'git.push', changes: 'not-an-array', timestamp: at(0) },
    { seq: 5, code: 'CONTENT_BLOCKED' } // no timestamp, still yields evidence via seq
  ];
  assert.doesNotThrow(() => detect(malformed, { protectedBranches: ['main'] }));
  const alerts = detect(malformed, { protectedBranches: ['main'] });
  assert.deepEqual(alerts.map((alert) => alert.id), ['D2-content-blocked']);
  assert.deepEqual(alerts[0].evidence, [5]);
});

test('detect() is order-independent and returns records in deterministic order', () => {
  const records = Array.from({ length: 10 }, (_, i) => ({
    seq: i + 1, type: 'decision', decision: 'deny', action: 'git.push', runtime: { runtimeId: 'rt-2' }, timestamp: at(i)
  }));
  const forward = detect(records, {});
  const shuffled = [...records].reverse();
  const backward = detect(shuffled, {});
  assert.deepEqual(forward, backward);
});

test('detect() ignores non-array input instead of throwing', () => {
  assert.deepEqual(detect(undefined, {}), []);
  assert.deepEqual(detect(null, {}), []);
  assert.deepEqual(detect('nope', {}), []);
});

test('windowed detections alert once per burst and re-arm after the window drains', () => {
  const deny = (seq, minute) => ({ seq, type: 'decision', decision: 'deny', action: 'git.push', runtime: { runtimeId: 'rt-1' }, timestamp: at(minute) });
  // Burst 1: 15 denials within 10 minutes (one alert, not six). Quiet for an hour. Burst 2: 10 denials.
  const records = [
    ...Array.from({ length: 15 }, (_, i) => deny(i + 1, i * 0.5)),
    ...Array.from({ length: 10 }, (_, i) => deny(i + 16, 70 + i * 0.5))
  ];
  const alerts = detect(records).filter((alert) => alert.id === 'D1-denial-burst');
  assert.equal(alerts.length, 2);
  assert.deepEqual(alerts[0].evidence, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  assert.deepEqual(alerts[1].evidence, [16, 17, 18, 19, 20, 21, 22, 23, 24, 25]);
  // A sustained stream that never drops below the threshold stays one alert.
  const sustained = Array.from({ length: 200 }, (_, i) => deny(i + 1, i * 0.5));
  assert.equal(detect(sustained).filter((alert) => alert.id === 'D1-denial-burst').length, 1);
});

test('weighted and threshold-edge bursts re-arm on the window total before the current entry', () => {
  const summary = (seq, minute, count) => ({ seq, type: 'rejections', code: 'ASSERTION_INVALID', count, timestamp: at(minute) });
  const d6 = (records) => detect(records).filter((alert) => alert.id === 'D6-assertion-failures');
  // Two separated summaries that each alone meet the threshold: two alerts.
  assert.deepEqual(d6([summary(1, 0, 20), summary(2, 120, 20)]).map((alert) => alert.evidence), [[1], [2]]);
  // One continuous burst of over-threshold summaries: still one alert.
  assert.equal(d6([summary(1, 0, 20), summary(2, 3, 20), summary(3, 6, 20), summary(4, 9, 20)]).length, 1);
  // Unweighted: the window drains to threshold-1 between events, so the next event is a new burst.
  const deny = (seq, minute) => ({ seq, type: 'decision', decision: 'deny', runtime: { runtimeId: 'rt-1' }, timestamp: at(minute) });
  const records = [...Array.from({ length: 10 }, (_, i) => deny(i + 1, i * 0.1)), deny(11, 10.05)];
  // At minute 10.05 the entry at 0.0 has left the window (9 remain, below 10), then #11 brings it back to 10.
  assert.deepEqual(detect(records).filter((alert) => alert.id === 'D1-denial-burst').map((alert) => alert.evidence.at(-1)), [10, 11]);
});
