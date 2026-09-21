import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough, Writable } from 'node:stream';
import { createLogger, redact } from '../src/log.js';
import { fixture } from '../scripts/support/fixture.js';

function capture() {
  const stream = new PassThrough();
  const lines = [];
  stream.on('data', (chunk) => lines.push(...chunk.toString().trim().split('\n').map(JSON.parse)));
  return { stream, lines };
}

test('logger writes JSON lines, filters by level, and redacts secrets recursively', () => {
  const { stream, lines } = capture();
  const log = createLogger({ stream, now: () => 0, level: 'info', base: { service: 'agentgate' } });
  log.debug('hidden');
  log.info('hello', { requestId: 'r1', headers: { authorization: 'Bearer x', accept: 'a' }, nested: [{ clientToken: 'y' }] });
  log.child({ component: 'admin' }).error('boom', { privateKeyPath: '/k' });
  assert.deepEqual(lines, [
    { time: '1970-01-01T00:00:00.000Z', level: 'info', msg: 'hello', service: 'agentgate', requestId: 'r1', headers: { authorization: '[REDACTED]', accept: 'a' }, nested: [{ clientToken: '[REDACTED]' }] },
    { time: '1970-01-01T00:00:00.000Z', level: 'error', msg: 'boom', service: 'agentgate', component: 'admin', privateKeyPath: '[REDACTED]' }
  ]);
  assert.deepEqual(redact({ keyId: 1 }), { keyId: 1 });
});

test('broker logs one completion line per request without credentials', async (t) => {
  const { stream, lines } = capture();
  const f = await fixture({ logger: createLogger({ stream }) });
  t.after(() => f.close());
  const response = await fetch(`${f.remote}/info/refs?service=git-upload-pack`, { headers: f.authHeaders });
  await response.arrayBuffer();
  await new Promise((resolve) => setImmediate(resolve));
  const done = lines.filter((line) => line.msg === 'request.complete');
  assert.equal(done.length, 1);
  assert.equal(done[0].status, 200);
  assert.equal(done[0].route, 'git');
  assert.equal(typeof done[0].durationMs, 'number');
  assert(!JSON.stringify(lines).includes(f.clientToken));
});

test('logger swallows stream write failures without throwing or crashing the process', async () => {
  let uncaught = null;
  const onUncaughtException = (error) => { uncaught = error; };
  process.on('uncaughtException', onUncaughtException);
  try {
    // write() reports failure asynchronously through its own callback, with no callback of ours
    // to receive it — Node re-raises that as an 'error' event on the stream.
    const asyncFailStream = new Writable({ write(chunk, encoding, callback) { callback(new Error('EPIPE')); } });
    const asyncLogger = createLogger({ stream: asyncFailStream, now: () => 0 });
    assert.doesNotThrow(() => asyncLogger.info('hello'));

    // write() itself throws synchronously.
    const syncThrowStream = new Writable();
    syncThrowStream.write = () => { throw new Error('ENOSPC'); };
    const syncLogger = createLogger({ stream: syncThrowStream, now: () => 0 });
    assert.doesNotThrow(() => syncLogger.info('hello'));

    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(uncaught, null);
  } finally {
    process.off('uncaughtException', onUncaughtException);
  }
});

test('request.complete fires exactly once for /healthz with status 200', async (t) => {
  const { stream, lines } = capture();
  const f = await fixture({ logger: createLogger({ stream }) });
  t.after(() => f.close());
  const response = await fetch(`${f.gate.url}/healthz`);
  await response.arrayBuffer();
  await new Promise((resolve) => setImmediate(resolve));
  const done = lines.filter((line) => line.msg === 'request.complete');
  assert.equal(done.length, 1);
  assert.equal(done[0].status, 200);
  assert.equal(done[0].route, 'healthz');
  assert(!JSON.stringify(lines).includes(f.clientToken));
});

test('request.complete fires exactly once for an unauthenticated request with status 401', async (t) => {
  const { stream, lines } = capture();
  const f = await fixture({ logger: createLogger({ stream }) });
  t.after(() => f.close());
  const response = await fetch(`${f.remote}/info/refs?service=git-upload-pack`); // no auth header
  await response.arrayBuffer();
  await new Promise((resolve) => setImmediate(resolve));
  const done = lines.filter((line) => line.msg === 'request.complete');
  assert.equal(response.status, 401);
  assert.equal(done.length, 1);
  assert.equal(done[0].status, 401);
  assert(!JSON.stringify(lines).includes(f.clientToken));
});

test('request.complete fires exactly once per request when rate limited', async (t) => {
  const { stream, lines } = capture();
  const f = await fixture({ logger: createLogger({ stream }), rateLimit: { capacity: 1, refillPerSecond: 0.001 } });
  t.after(() => f.close());
  const first = await fetch(`${f.remote}/info/refs?service=git-upload-pack`, { headers: f.authHeaders });
  await first.arrayBuffer();
  const second = await fetch(`${f.remote}/info/refs?service=git-upload-pack`, { headers: f.authHeaders });
  await second.arrayBuffer();
  assert.equal(first.status, 200);
  assert.equal(second.status, 429);
  await new Promise((resolve) => setImmediate(resolve));
  const done = lines.filter((line) => line.msg === 'request.complete');
  assert.equal(done.length, 2);
  assert.equal(done[0].status, 200);
  assert.equal(done[1].status, 429);
  assert(!JSON.stringify(lines).includes(f.clientToken));
});
