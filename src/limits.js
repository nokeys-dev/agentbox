export class RateLimiter {
  constructor({ capacity, refillPerSecond, now = Date.now, maxKeys = 10_000 }) {
    this.capacity = capacity;
    this.refillPerMs = refillPerSecond / 1000;
    this.now = now;
    this.maxKeys = maxKeys;
    this.buckets = new Map();
  }

  take(key) {
    const now = this.now();
    let bucket = this.buckets.get(key);
    if (!bucket) {
      if (this.buckets.size >= this.maxKeys) this.buckets.delete(this.buckets.keys().next().value);
      bucket = { tokens: this.capacity, updatedAt: now };
    } else {
      bucket.tokens = Math.min(this.capacity, bucket.tokens + (now - bucket.updatedAt) * this.refillPerMs);
      bucket.updatedAt = now;
      this.buckets.delete(key);
    }
    // Re-insert so Map order approximates least-recently-used eviction.
    this.buckets.set(key, bucket);
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { ok: true, retryAfterSeconds: 0 };
    }
    return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil((1 - bucket.tokens) / this.refillPerMs / 1000)) };
  }
}
