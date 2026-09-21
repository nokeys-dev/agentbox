import test from 'node:test';
import assert from 'node:assert/strict';
import { RateLimiter } from '../src/limits.js';
import { fixture } from '../scripts/support/fixture.js';

test('token bucket refills over time and isolates keys', () => {
  let now = 0;
  const limiter = new RateLimiter({ capacity: 2, refillPerSecond: 1, now: () => now, maxKeys: 2 });
  assert.equal(limiter.take('a').ok, true);
  assert.equal(limiter.take('a').ok, true);
  const blocked = limiter.take('a');
  assert.deepEqual(blocked, { ok: false, retryAfterSeconds: 1 });
  assert.equal(limiter.take('b').ok, true);
  now += 1000;
  assert.equal(limiter.take('a').ok, true);
  limiter.take('c');
  assert.equal(limiter.buckets.size, 2);
});

test('broker returns 429 with retry-after when a client exceeds its budget', async (t) => {
  const f = await fixture({ rateLimit: { capacity: 2, refillPerSecond: 0.001 } });
  t.after(() => f.close());
  const statuses = [];
  for (let i = 0; i < 3; i++) {
    const response = await fetch(`${f.remote}/info/refs?service=git-upload-pack`, { headers: f.authHeaders });
    statuses.push(response.status);
    if (response.status === 429) assert(Number(response.headers.get('retry-after')) >= 1);
    await response.arrayBuffer();
  }
  assert.deepEqual(statuses, [200, 200, 429]);
});

test('unauthenticated requests beyond the rate-limit budget get 429, not 401: the limiter runs before authentication', async (t) => {
  const f = await fixture({ rateLimit: { capacity: 1, refillPerSecond: 0.001 } });
  t.after(() => f.close());
  // Budget available: falls through past the limiter to authentication, which rejects it.
  const first = await fetch(`${f.remote}/info/refs?service=git-upload-pack`);
  assert.equal(first.status, 401);
  await first.arrayBuffer();
  // Budget exhausted: rejected by the limiter before authentication ever runs.
  const second = await fetch(`${f.remote}/info/refs?service=git-upload-pack`);
  assert.equal(second.status, 429);
  assert(Number(second.headers.get('retry-after')) >= 1);
  await second.arrayBuffer();
});
