const levels = { debug: 10, info: 20, warn: 30, error: 40 };
const sensitive = /token|authorization|secret|password|private|cookie|signature/i;

export function redact(value) {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sensitive.test(key) ? '[REDACTED]' : redact(item)]));
  }
  return value;
}

// A stream that starts rejecting writes (EPIPE, ENOSPC, a closed socket) must never crash the
// broker just because a log line couldn't be written. Node emits an 'error' event for stream
// write failures reported asynchronously (e.g. through the internal write callback) even when
// the caller supplied no callback of its own; with no listener that event throws. `attached`
// tracks which stream objects already have our no-op listener so repeated createLogger/child
// calls sharing the same stream (the common case) don't pile up duplicate listeners.
const attached = new WeakSet();
function tolerateStreamErrors(target) {
  if (!target || typeof target.on !== 'function' || attached.has(target)) return;
  attached.add(target);
  target.on('error', () => { /* Drop the failed write; never let logging crash the broker. */ });
}

// `stream` carries debug/info; `errorStream` (defaults to `stream`) carries warn/error, so
// callers who want error-level output split to stderr (e.g. the daemon) can pass it explicitly
// while everything else, including tests that capture a single stream, keeps one combined feed.
export function createLogger({ stream = process.stdout, errorStream = stream, now = Date.now, level = process.env.AGENTGATE_LOG_LEVEL || 'info', base = {} } = {}) {
  const threshold = levels[level] ?? levels.info;
  tolerateStreamErrors(stream);
  tolerateStreamErrors(errorStream);
  const write = (name, target, msg, fields) => {
    if (levels[name] < threshold) return;
    try {
      target.write(`${JSON.stringify({ time: new Date(now()).toISOString(), level: name, msg, ...redact({ ...base, ...fields }) })}\n`);
    } catch { /* A synchronously-throwing write must never crash the broker. */ }
  };
  return {
    debug: (msg, fields) => write('debug', stream, msg, fields),
    info: (msg, fields) => write('info', stream, msg, fields),
    warn: (msg, fields) => write('warn', errorStream, msg, fields),
    error: (msg, fields) => write('error', errorStream, msg, fields),
    child: (fields) => createLogger({ stream, errorStream, now, level, base: { ...base, ...fields } })
  };
}
