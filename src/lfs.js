import { createHash, randomBytes } from 'node:crypto';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { GateError } from './errors.js';
import { validateRef } from './git-protocol.js';

// GitHub LFS storage hosts that transfer hrefs may point at. Only hosts observed in a real GitHub
// batch response are trusted by default (Phase 3 Task 4 Step 1, anonymous download batch against a
// public repository, 2026-09-17): `download` hrefs were on github-cloud.githubusercontent.com (a
// presigned S3-style query, no `header`, no `verify` action). Upload batches cannot be observed
// anonymously (401), so upload storage hosts remain UNVERIFIED and are NOT trusted by default:
//   UNVERIFIED: github-cloud.s3.amazonaws.com, lfs.github.com
// Operators who confirm them can pass them via startGate's `lfsHosts` option.
export const DEFAULT_LFS_HOSTS = Object.freeze(['github-cloud.githubusercontent.com']);
// Lowercase DNS hostname: no ports, wildcards, IP-literal brackets, or empty labels.
export const isLfsHost = (value) => typeof value === 'string' && value.length <= 253 &&
  /^(?=.*[a-z])[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(value);
export const LFS_CONTENT_TYPE = 'application/vnd.git-lfs+json';
const MAX_OBJECTS = 100;
const MAX_OBJECT_SIZE = 5 * 1024 ** 3;
const OID = /^[0-9a-f]{64}$/;
const bad = (message) => { throw new GateError(400, 'INVALID_LFS_REQUEST', message); };
const isObject = (value) => Boolean(value) && typeof value === 'object' && !Array.isArray(value);

// `allowUnicode` is the repository's `allowUnicodeRefs` setting, so ref names follow the same
// rules as pushes to that repository.
export function validateBatchRequest(body, { allowUnicode = false } = {}) {
  let input;
  try { input = JSON.parse(body.toString('utf8')); } catch { bad('Expected JSON'); }
  if (!isObject(input)) bad('Expected a JSON object');
  if (!['download', 'upload'].includes(input.operation)) bad('operation must be download or upload');
  const transfers = input.transfers ?? ['basic'];
  if (!Array.isArray(transfers) || !transfers.includes('basic')) bad('Only the basic transfer adapter is supported');
  // git-lfs may send the ref being pushed/fetched. It is validated so malformed input fails closed,
  // but it is not used for policy (or forwarded) in this version. The batch API docs
  // (git-lfs docs/api/batch.md) define `ref` as optional, say servers must accept a missing or null
  // `ref`, and describe `name` as a fully-qualified refspec. The git-lfs client (tq/api.go) always
  // sends `ref`, omitting an empty `name` (`{}`), and git.Ref.Refspec() sends a bare name without a
  // `refs/` prefix for HEAD/other ref types (for example `HEAD` or a detached commit ID). Every
  // present name goes through the push ref validator, which rejects control, invisible, and (unless
  // the repository allows Unicode refs) non-ASCII characters.
  if (input.ref !== undefined && input.ref !== null) {
    const ref = input.ref;
    if (!isObject(ref) || Object.keys(ref).some((key) => key !== 'name')) bad('Invalid ref');
    if (ref.name !== undefined) {
      if (typeof ref.name !== 'string') bad('Invalid ref');
      try { validateRef(ref.name, { allowUnicode }); } catch { bad('Invalid ref'); }
    }
  }
  if (!Array.isArray(input.objects) || input.objects.length > MAX_OBJECTS) bad(`objects must be an array of at most ${MAX_OBJECTS}`);
  const objects = input.objects.map((object) => {
    if (!isObject(object) || typeof object.oid !== 'string' || !OID.test(object.oid) || !Number.isSafeInteger(object.size) || object.size < 0 || object.size > MAX_OBJECT_SIZE) bad('Invalid object');
    return { oid: object.oid, size: object.size };
  });
  return { operation: input.operation, objects, transfers: ['basic'] };
}

// Holds bearer transfer capabilities: a 256-bit random ID maps to the upstream href (which carries
// storage signatures). IDs and hrefs must never be logged or audited. Bounded globally by
// `maxEntries` and per repository by `maxPerRepository`, so one repository cannot exhaust the
// global cap. Every entry gets the same TTL, so Map insertion order is expiry order: prune() stops
// at the first unexpired entry (amortized O(1) per entry). register/take/claim are O(1).
export class TransferRegistry {
  constructor({ now = Date.now, ttlMs = 15 * 60_000, maxEntries = 10_000, maxPerRepository = 1000 } = {}) {
    Object.assign(this, { now, ttlMs, maxEntries, maxPerRepository, entries: new Map(), perRepository: new Map() });
  }

  prune() {
    const now = this.now();
    for (const [id, item] of this.entries) {
      if (item.expiresAt > now) break;
      this.delete(id, item);
    }
  }

  delete(id, entry) {
    this.entries.delete(id);
    const count = (this.perRepository.get(entry.repository) ?? 1) - 1;
    if (count > 0) this.perRepository.set(entry.repository, count);
    else this.perRepository.delete(entry.repository);
  }

  register(entry) {
    const count = this.perRepository.get(entry.repository) ?? 0;
    if (this.entries.size >= this.maxEntries || count >= this.maxPerRepository) throw new GateError(503, 'LFS_BUSY', 'Too many pending LFS transfers');
    const id = randomBytes(32).toString('hex');
    this.entries.set(id, { ...entry, expiresAt: this.now() + this.ttlMs });
    this.perRepository.set(entry.repository, count + 1);
    return id;
  }

  // Looks up a live entry without consuming it (used to check the request method first).
  peek(id) {
    const entry = this.entries.get(id);
    return entry && entry.expiresAt > this.now() ? entry : undefined;
  }

  take(id, { repository, operation }) {
    const entry = this.entries.get(id);
    if (!entry || entry.repository !== repository || entry.operation !== operation) return undefined;
    return this.claim(id);
  }

  // The transfer URL carries only the ID; the entry itself records its repository and operation.
  // The Task 5 transfer route must re-check that the repository is still configured.
  claim(id) {
    const entry = this.entries.get(id);
    if (!entry) return undefined;
    this.delete(id, entry);
    return entry.expiresAt > this.now() ? entry : undefined;
  }
}

const sanitizeHeader = (header) => isObject(header)
  ? Object.fromEntries(Object.entries(header).filter(([key, value]) => /^[A-Za-z0-9-]{1,64}$/.test(key) && typeof value === 'string' && !/[\r\n\0]/.test(value)))
  : {};

// True only for https://github.com/<repository>(.git)/info/lfs/... with no credentials, port, or
// query/fragment. Exported so the provider re-checks before attaching a token.
export function isVerifyHref(href, repository) {
  let url;
  try { url = new URL(href); } catch { return false; }
  if (url.protocol !== 'https:' || url.hostname !== 'github.com' || url.username || url.password || url.port || url.search || url.hash) return false;
  const path = url.pathname.toLowerCase();
  if (path.includes('/../') || path.includes('/./') || path.includes('%')) return false;
  return typeof repository !== 'string' || [`/${repository}.git/info/lfs/`, `/${repository}/info/lfs/`].some((prefix) => path.startsWith(prefix.toLowerCase()));
}

// `requested` (the validated client objects) limits capabilities to objects the client asked for;
// unexpected upstream objects are dropped. The broker always passes it.
export function rewriteBatchResponse(upstream, { registry, repository, operation, brokerUrl, allowedHosts, requested, owner }) {
  const wanted = requested && new Set(requested.map((object) => `${object.oid}:${object.size}`));
  const invalid = (message) => new GateError(502, 'INVALID_UPSTREAM', message);
  if (!isObject(upstream) || !Array.isArray(upstream.objects) || upstream.objects.length > MAX_OBJECTS) throw invalid('Invalid LFS batch response');
  // Validate every object and href before registering anything, so a rejected response leaves no
  // dangling capabilities behind.
  const planned = upstream.objects.map((object) => {
    if (!isObject(object) || typeof object.oid !== 'string' || !OID.test(object.oid) || !Number.isSafeInteger(object.size) || object.size < 0) throw invalid('Invalid LFS object');
    const projected = { oid: object.oid, size: object.size };
    if (wanted && !wanted.has(`${object.oid}:${object.size}`)) return undefined;
    if (object.error !== undefined) {
      const code = Number(object.error?.code);
      return { projected: { ...projected, error: { code: Number.isInteger(code) && code >= 400 && code <= 599 ? code : 500, message: 'LFS object unavailable' } } };
    }
    const action = isObject(object.actions) ? object.actions[operation] : undefined;
    if (action === undefined) return { projected };
    if (!isObject(action) || typeof action.href !== 'string') throw invalid('Invalid LFS action');
    let url;
    try { url = new URL(action.href); } catch { throw invalid('Invalid LFS href'); }
    if (url.protocol !== 'https:' || url.username || url.password || url.port || !allowedHosts.includes(url.hostname)) {
      throw new GateError(502, 'LFS_UNTRUSTED_HOST', 'LFS storage host is not allowlisted');
    }
    const header = sanitizeHeader(action.header);
    // A verify action (uploads only) is kept server-side and called by the broker after a verified
    // PUT. It must be an https github.com LFS endpoint for this same repository, because the broker
    // sends a write token to it; anything else fails the batch closed. Its own Authorization header
    // is dropped (the broker authenticates with its installation token).
    let verify;
    const verifyAction = operation === 'upload' && isObject(object.actions) ? object.actions.verify : undefined;
    if (verifyAction !== undefined) {
      if (!isObject(verifyAction) || typeof verifyAction.href !== 'string') throw invalid('Invalid LFS verify action');
      if (!isVerifyHref(verifyAction.href, repository)) throw new GateError(502, 'LFS_UNTRUSTED_HOST', 'LFS verify endpoint is not trusted');
      verify = { href: verifyAction.href, header: Object.fromEntries(Object.entries(sanitizeHeader(verifyAction.header)).filter(([key]) => key.toLowerCase() !== 'authorization')) };
    }
    return { projected, href: action.href, header, ...(verify ? { verify } : {}) };
  });
  registry.prune();
  return {
    transfer: 'basic',
    objects: planned.filter(Boolean).map(({ projected, href, header, verify }) => {
      if (!href) return projected;
      // owner: the requesting runtime (assertion jti, or runtimeId in static mode); the transfer
      // route refuses the capability for any other runtime.
      const id = registry.register({ ...(owner === undefined ? {} : { owner }), repository, operation, oid: projected.oid, size: projected.size, href, header, ...(verify ? { verify } : {}) });
      return { ...projected, authenticated: true, actions: { [operation]: { href: `${brokerUrl}/lfs-transfer/${id}`, expires_in: Math.floor(registry.ttlMs / 1000) } } };
    })
  };
}

// Reads an upstream Response body as JSON with a byte cap instead of an unbounded response.json().
export async function readUpstreamJson(response, maxBytes = 4 * 1024 * 1024) {
  const type = response.headers.get('content-type')?.split(';')[0].trim().toLowerCase();
  if (!['application/json', LFS_CONTENT_TYPE].includes(type) || !response.body) {
    await response.body?.cancel();
    throw new GateError(502, 'INVALID_UPSTREAM', 'GitHub LFS returned an unexpected content type');
  }
  const chunks = [];
  let length = 0;
  for await (const chunk of response.body) {
    length += chunk.length;
    if (length > maxBytes) {
      // Breaking out of for-await cancels the stream.
      throw new GateError(502, 'INVALID_UPSTREAM', 'GitHub LFS response is too large');
    }
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks, length).toString('utf8')); } catch { throw new GateError(502, 'INVALID_UPSTREAM', 'GitHub LFS returned invalid JSON'); }
}

export const MAX_LFS_OBJECT_BYTES = MAX_OBJECT_SIZE;
const STORAGE_TIMEOUT_MS = 30 * 60_000;
const mismatch = (message) => new GateError(400, 'LFS_HASH_MISMATCH', message);

// Counts and hashes bytes in transit. The final byte is withheld until the whole object has been
// checked against entry.size and entry.oid, so neither the client (downloads) nor storage (uploads)
// ever receives a complete object that fails verification.
function verifier(entry) {
  const hash = createHash('sha256');
  let bytes = 0;
  let held;
  const stream = new Transform({
    transform(chunk, _encoding, callback) {
      bytes += chunk.length;
      if (bytes > entry.size) return callback(mismatch('LFS object exceeds its declared size'));
      hash.update(chunk);
      if (bytes === entry.size && chunk.length > 0) {
        held = chunk.subarray(chunk.length - 1);
        return callback(null, chunk.length > 1 ? chunk.subarray(0, chunk.length - 1) : undefined);
      }
      callback(null, chunk);
    },
    flush(callback) {
      if (bytes !== entry.size || hash.digest('hex') !== entry.oid) return callback(mismatch('LFS object does not match its OID'));
      stream.verified = true;
      callback(null, held);
    }
  });
  stream.verified = false;
  return stream;
}

// Proxies one claimed basic-transfer action. Storage receives only the entry's own href and
// sanitized headers (never GitHub or client credentials); the client receives only content-type and
// content-length. `beforeUploadResponse` runs after a verified upload and before the 200 is sent
// (the broker calls the GitHub verify action there).
export async function proxyTransfer({ request, response, entry, fetchImpl = fetch, maxBytes = MAX_LFS_OBJECT_BYTES, signal, beforeUploadResponse }) {
  if (entry.size > maxBytes) throw new GateError(413, 'BODY_TOO_LARGE', 'LFS object exceeds broker limit');
  const headers = { ...entry.header, 'user-agent': 'AgentBox/0.1' };
  const signals = [AbortSignal.timeout(STORAGE_TIMEOUT_MS), ...(signal ? [signal] : [])];
  if (entry.operation === 'download') {
    if (request.method !== 'GET') throw new GateError(405, 'METHOD_NOT_ALLOWED', 'Use GET');
    // identity: the proxy hashes and length-checks the raw bytes, so storage must not encode them.
    const upstream = await fetchImpl(entry.href, { method: 'GET', headers: { ...Object.fromEntries(Object.entries(headers).filter(([key]) => key.toLowerCase() !== 'accept-encoding')), 'accept-encoding': 'identity' }, redirect: 'error', signal: AbortSignal.any(signals) });
    const length = upstream.headers.get('content-length');
    if (upstream.status !== 200 || !upstream.body || (length !== null && Number(length) !== entry.size)) {
      await upstream.body?.cancel().catch(() => {});
      throw new GateError(502, 'UPSTREAM_FAILED', `LFS download failed (${upstream.status})`);
    }
    response.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(entry.size), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
    // A mismatch errors the pipeline, which destroys the response before its last byte.
    await pipeline(Readable.fromWeb(upstream.body), verifier(entry), response);
    return;
  }
  if (request.method !== 'PUT') throw new GateError(405, 'METHOD_NOT_ALLOWED', 'Use PUT');
  if (request.headers['content-encoding'] && request.headers['content-encoding'] !== 'identity') throw new GateError(415, 'ENCODING_UNSUPPORTED', 'Compressed request bodies are not supported');
  const declared = request.headers['content-length'];
  if (declared === undefined || !/^\d+$/.test(declared) || Number(declared) !== entry.size) throw mismatch('content-length must equal the object size');
  const controller = new AbortController();
  const checked = verifier(entry);
  let failed;
  const failure = new Promise((_, reject) => {
    const fail = (error) => { if (failed) return; failed = error; controller.abort(); reject(error); };
    checked.once('error', fail);
    request.once('error', () => fail(new GateError(400, 'LFS_UPLOAD_INCOMPLETE', 'LFS upload body was interrupted')));
    request.once('aborted', () => fail(new GateError(400, 'LFS_UPLOAD_INCOMPLETE', 'LFS upload body was interrupted')));
  });
  failure.catch(() => {});
  request.pipe(checked);
  let upstream;
  try {
    upstream = await Promise.race([
      fetchImpl(entry.href, { method: 'PUT', headers: { ...headers, 'content-length': String(entry.size), 'content-type': 'application/octet-stream' },
        body: checked, duplex: 'half', redirect: 'error', signal: AbortSignal.any([controller.signal, ...signals]) }),
      failure
    ]);
  } catch (error) {
    checked.destroy();
    throw failed ?? error;
  }
  await upstream.body?.cancel().catch(() => {});
  if (failed) throw failed;
  if (upstream.status < 200 || upstream.status > 299) { checked.destroy(); throw new GateError(502, 'UPSTREAM_FAILED', `LFS upload failed (${upstream.status})`); }
  // A 2xx before the verified final byte was delivered is never treated as success.
  if (!checked.verified) throw mismatch('LFS object does not match its OID');
  if (beforeUploadResponse) await beforeUploadResponse();
  response.writeHead(200, { 'content-type': LFS_CONTENT_TYPE, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  response.end('{}');
}
