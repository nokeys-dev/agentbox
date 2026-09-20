import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Registry } from '../src/metrics.js';
import { fixture, pushBody } from './support/fixture.js';

test('registry renders counters, gauges, and cumulative histograms in Prometheus format', () => {
  const registry = new Registry();
  const requests = registry.counter('demo_requests_total', 'Requests');
  requests.inc({ route: 'git', status: '200' });
  requests.inc({ route: 'git', status: '200' }, 2);
  registry.gauge('demo_pending', 'Pending', () => 4);
  registry.gauge('demo_labeled', 'Labeled', () => [[{ kind: 'a"b' }, 1]]);
  const duration = registry.histogram('demo_seconds', 'Duration', [0.1, 1]);
  duration.observe({ route: 'git' }, 0.05);
  duration.observe({ route: 'git' }, 0.5);
  assert.equal(registry.render(), [
    '# HELP demo_requests_total Requests', '# TYPE demo_requests_total counter', 'demo_requests_total{route="git",status="200"} 3',
    '# HELP demo_pending Pending', '# TYPE demo_pending gauge', 'demo_pending 4',
    '# HELP demo_labeled Labeled', '# TYPE demo_labeled gauge', 'demo_labeled{kind="a\\"b"} 1',
    '# HELP demo_seconds Duration', '# TYPE demo_seconds histogram',
    'demo_seconds_bucket{route="git",le="0.1"} 1', 'demo_seconds_bucket{route="git",le="1"} 2', 'demo_seconds_bucket{route="git",le="+Inf"} 2',
    'demo_seconds_sum{route="git"} 0.55', 'demo_seconds_count{route="git"} 2', ''
  ].join('\n'));
});

test('broker exposes decision, approval, and audit lag metrics on a separate listener', async (t) => {
  const f = await fixture({ metrics: { host: '127.0.0.1', port: 0 } });
  t.after(() => f.close());
  assert.match(f.gate.metricsUrl, /^http:\/\/127\.0\.0\.1:\d+\/metrics$/);
  const blocked = await fetch(`${f.remote}/git-receive-pack`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/x-git-receive-pack-request' }, body: pushBody() });
  await blocked.arrayBuffer();
  const checkpointPath = join(f.directory, 'state', 'audit-forward.json');
  writeFileSync(checkpointPath, JSON.stringify({ seq: 0, hash: '0'.repeat(64) }));
  const text = await (await fetch(f.gate.metricsUrl)).text();
  assert.match(text, /agentgate_decisions_total\{action="git.push",decision="approval"\} 1/);
  assert.match(text, /agentgate_approvals_pending 1/);
  assert.match(text, /agentgate_requests_total\{route="git",status="403"\} 1/);
  assert.match(text, /agentgate_audit_head_seq [1-9]/);
  assert.match(text, /agentgate_audit_forward_lag_records [1-9]/);
  assert.equal((await fetch(f.gate.metricsUrl.replace('/metrics', '/other'))).status, 404);
  assert.equal((await fetch(`${f.gate.url}/metrics`, { headers: f.authHeaders })).status, 404);
});

test('errors_total counts rejected requests, including coalesced rejection codes, without double counting', async (t) => {
  const f = await fixture({ metrics: { host: '127.0.0.1', port: 0 } });
  t.after(() => f.close());
  // Unauthenticated request (no bearer token, though the broker requires one): coalesced
  // (UNAUTHENTICATED) into a rejection summary, not a per-request audit record, but must still
  // be counted in agentgate_errors_total.
  const unauth = await fetch(`${f.remote}/info/refs?service=git-upload-pack`);
  await unauth.arrayBuffer();
  assert.equal(unauth.status, 401);
  // Trigger an ordinary per-request-audited error (unknown repository -> DENIED).
  const denied = await fetch(`${f.gate.url}/acme/does-not-exist.git/info/refs?service=git-upload-pack`, { headers: f.authHeaders });
  await denied.arrayBuffer();
  assert.equal(denied.status, 403);
  const text = await (await fetch(f.gate.metricsUrl)).text();
  assert.match(text, /agentgate_errors_total\{code="UNAUTHENTICATED"\} 1/);
  assert.match(text, /agentgate_errors_total\{code="DENIED"\} 1/);
});

test('audit forward lag gauge reports -1 when the checkpoint is missing or unreadable', async (t) => {
  const f = await fixture({ metrics: { host: '127.0.0.1', port: 0 } });
  t.after(() => f.close());
  const text = await (await fetch(f.gate.metricsUrl)).text();
  assert.match(text, /agentgate_audit_forward_lag_records -1/);
});

test('auditCheckpointPath option controls where the forward-lag gauge reads its checkpoint', async (t) => {
  const checkpointDirectory = await mkdtemp(join(tmpdir(), 'agentgate-checkpoint-'));
  t.after(() => rm(checkpointDirectory, { recursive: true, force: true }));
  const checkpointPath = join(checkpointDirectory, 'custom-checkpoint.json');
  const f = await fixture({ metrics: { host: '127.0.0.1', port: 0 }, auditCheckpointPath: checkpointPath });
  t.after(() => f.close());
  writeFileSync(checkpointPath, JSON.stringify({ seq: 0, hash: '0'.repeat(64) }));
  await (await fetch(`${f.remote}/info/refs?service=git-upload-pack`, { headers: f.authHeaders })).arrayBuffer();
  const text = await (await fetch(f.gate.metricsUrl)).text();
  assert.match(text, /agentgate_audit_forward_lag_records [1-9]/);
});

test('DISK_LOW is counted in agentgate_errors_total even though State.audit() itself fails to write the record', async (t) => {
  // State.audit() calls ensureDisk() before it appends anything, so when the disk is (simulated)
  // full, the request handler's own attempt to audit `{ type: 'error', code: 'DISK_LOW' }` also
  // throws DISK_LOW and is swallowed. The metric must not depend on that audit write succeeding.
  const statfs = () => ({ bavail: 0, bsize: 4096 });
  const f = await fixture({ metrics: { host: '127.0.0.1', port: 0 }, stateOptions: { statfs } });
  t.after(() => f.close());
  const response = await fetch(`${f.remote}/info/refs?service=git-upload-pack`, { headers: f.authHeaders });
  await response.arrayBuffer();
  assert.equal(response.status, 503);
  const text = await (await fetch(f.gate.metricsUrl)).text();
  assert.match(text, /agentgate_errors_total\{code="DISK_LOW"\} 1/);
});

test('registry.render() omits a metric whose collector throws, without throwing itself or dropping other metrics', () => {
  const registry = new Registry();
  registry.gauge('demo_ok_before', 'OK before', () => 1);
  registry.gauge('demo_broken', 'Broken', () => { throw new Error('boom'); });
  registry.gauge('demo_ok_after', 'OK after', () => 2);
  const text = registry.render();
  assert.match(text, /demo_ok_before 1/);
  assert.match(text, /demo_ok_after 2/);
  assert.doesNotMatch(text, /demo_broken/);
});

test('the metrics HTTP handler returns 500 instead of crashing when rendering unexpectedly throws', async (t) => {
  const f = await fixture({ metrics: { host: '127.0.0.1', port: 0 } });
  t.after(() => f.close());
  const originalRender = f.gate.registry.render.bind(f.gate.registry);
  f.gate.registry.render = () => { throw new Error('boom'); };
  const broken = await fetch(f.gate.metricsUrl);
  await broken.arrayBuffer();
  assert.equal(broken.status, 500);
  f.gate.registry.render = originalRender;
  const recovered = await fetch(f.gate.metricsUrl);
  assert.equal(recovered.status, 200);
});

test('startGate defaults metrics.host to 127.0.0.1 when a caller passes metrics: { port }', async (t) => {
  const f = await fixture({ metrics: { port: 0 } });
  t.after(() => f.close());
  assert.match(f.gate.metricsUrl, /^http:\/\/127\.0\.0\.1:\d+\/metrics$/);
});
