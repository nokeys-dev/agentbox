import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { createPublicKey, randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { chmodSync, createReadStream, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { validateConfig } from './config.js';
import { ASSERTION_HEADER, createAssertionVerifier } from './assertion.js';
import { createAssertionBoundAuth, createClientAuth } from './client-auth.js';
import { GateError, assert } from './errors.js';
import { RateLimiter } from './limits.js';
import { readPush } from './push-stream.js';
import { publicFindings, scanPush } from './scan.js';
import { decide, decidePush, fingerprint } from './policy.js';
import { buildEntitlements, envelopeSummary, unsourcedElevations } from './entitlements.js';
import { State, isSuperseded } from './state.js';
import { SIGNATURE_HEADER, TIMESTAMP_HEADER, verifyAdminRequest } from './admin-auth.js';
import { routeApi, handleApi } from './github-api.js';
import { routeGitlabApi, handleGitlabApi } from './gitlab-api.js';
import { createLogger } from './log.js';
import { Registry } from './metrics.js';
import { guardNotify } from './notify.js';
import { DEFAULT_LFS_HOSTS, isLfsHost, LFS_CONTENT_TYPE, MAX_LFS_OBJECT_BYTES, proxyTransfer, TransferRegistry, readUpstreamJson, rewriteBatchResponse, validateBatchRequest } from './lfs.js';
import { providerCapabilities } from './providers/index.js';

export const MAX_BODY_BYTES = 2048 * 1024 * 1024;
// Fetch negotiation bodies (git-upload-pack POST) are still buffered, so they keep a small cap.
const MAX_BUFFERED_GIT_BODY_BYTES = 32 * 1024 * 1024;
// A request socket that receives nothing for this long while its body is read is destroyed.
export const BODY_IDLE_TIMEOUT_MS = 120_000;

// Codes an unauthenticated or unauthorized caller can trigger at will. A per-request audit
// record for these would let anyone on the workspace network force unlimited fsync'd writes
// (rotation/eviction, then disk pressure) just by sending malformed or unauthenticated traffic.
// Instead these are tallied in memory and flushed as a single summary per code per window.
// ASSERTION_INVALID is only reachable with a valid client token, but is summarized the same way so
// a token holder cannot force a fsync'd audit write per bad assertion either.
const REJECTION_SUMMARY_CODES = new Set(['CLIENT_NOT_ALLOWED', 'UNAUTHENTICATED', 'RATE_LIMITED', 'ASSERTION_INVALID', 'POLICY_EXPIRED']);
const REJECTION_SUMMARY_WINDOW_MS = 60_000;

function json(response, status, value) {
  response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  response.end(`${JSON.stringify(value)}\n`);
}

async function readBody(request, maxBytes) {
  if (request.headers['content-encoding'] && request.headers['content-encoding'] !== 'identity') {
    throw new GateError(415, 'ENCODING_UNSUPPORTED', 'Compressed request bodies are not supported');
  }
  if (Number(request.headers['content-length']) > maxBytes) throw new GateError(413, 'BODY_TOO_LARGE', `Request exceeds ${maxBytes} bytes`);
  const chunks = [];
  let length = 0;
  // Keep the connection alive long enough to send a useful error when over limit.
  for await (const chunk of request.iterator({ destroyOnReturn: false })) {
    length += chunk.length;
    if (length > maxBytes) throw new GateError(413, 'BODY_TOO_LARGE', `Request exceeds ${maxBytes} bytes`);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, length);
}

// A rejected request (denied, approval required, oversized, malformed) may still have an unread
// pack in flight. Nothing is forwarded; after the response is flushed, drain briefly so the client
// can read it, then destroy the socket so a large or stalled upload cannot pin the connection.
function discardUnreadBody(request, response) {
  if (request.complete || request.destroyed) return;
  const discard = () => {
    request.resume();
    setTimeout(() => request.socket?.destroy(), 1000).unref();
  };
  if (response.writableFinished || response.destroyed) discard();
  else response.once('close', discard);
}

function route(request) {
  // OWNER/REPO for GitHub; GitLab project paths may nest (group/subgroup/project). Either way the
  // name is only ever matched against configured repositories, never interpolated unvalidated.
  const match = /^\/([A-Za-z0-9_.-]+)\/((?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+?)(?:\.git)?\/(?:info\/refs\?service=(git-upload-pack|git-receive-pack)|(git-upload-pack|git-receive-pack))$/.exec(request.url);
  if (!match || `${match[1]}/${match[2]}`.split('/').some((part) => ['.', '..'].includes(part))) throw new GateError(404, 'NOT_FOUND', 'Use /OWNER/REPO.git with Git smart HTTP');
  const discovery = Boolean(match[3]);
  if (request.method !== (discovery ? 'GET' : 'POST')) throw new GateError(405, 'METHOD_NOT_ALLOWED', 'Unsupported method');
  const service = match[3] || match[4];
  if (!discovery && request.headers['content-type'] !== `application/x-${service}-request`) throw new GateError(415, 'INVALID_CONTENT_TYPE', 'Expected a Git smart HTTP request');
  return { name: `${match[1]}/${match[2]}`.toLowerCase(), service, discovery };
}

// The origin workspaces use to reach the broker (e.g. https://agentd:7432 in Compose), embedded in
// rewritten LFS transfer hrefs. Must be a bare http(s) origin: no credentials, path, query, or hash.
function validatePublicUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('publicUrl must be an http(s) origin'); }
  assert(['http:', 'https:'].includes(url.protocol) && !url.username && !url.password && url.pathname === '/' && !url.search && !url.hash &&
    !/[?#]/.test(value) && value.replace(/\/$/, '') === url.origin, 'publicUrl must be an http(s) origin without path or credentials');
  return url.origin;
}

// LFS transfer capabilities are bound to this value: the assertion's jti in assertion mode (so a
// renewed or different assertion cannot use them), else the static runtimeId. Tagged with the mode
// so a value from one mode can never equal a value from the other across a reload.
function transferOwner(runtime) {
  if (typeof runtime?.jti === 'string') return `assertion:${runtime.jti}`;
  return typeof runtime?.runtimeId === 'string' ? `static:${runtime.runtimeId}` : undefined;
}

function listen(server, ...args) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(...args, () => { server.off('error', reject); resolve(); });
  });
}

function close(server) {
  server.closeAllConnections();
  return new Promise((resolve) => server.close(resolve));
}

export async function startGate({ config, provider, stateDirectory, host = '127.0.0.1', port = 7432, maxBodyBytes = MAX_BODY_BYTES, bodyIdleTimeoutMs = BODY_IDLE_TIMEOUT_MS, maxConcurrent = 4, lfsMaxTransfers = 8, clientToken, clientAuth = clientToken ? 'static' : 'none', tls, rateLimit = { capacity: 60, refillPerSecond: 2 }, runtimeRateLimit = rateLimit, stateOptions, now = Date.now, logger = createLogger({ base: { service: 'agentgate' } }), metrics, auditCheckpointPath = join(stateDirectory, 'audit-forward.json'), notify = () => {}, adminSecret, lfsHosts = DEFAULT_LFS_HOSTS, publicUrl, lfsMaxObjectBytes = MAX_LFS_OBJECT_BYTES, lfsFetch = fetch, revocations = () => new Set(), entitlementFetch = fetch, mirror, policyExpired = false, policyExpiresAt }) {
  if (publicUrl !== undefined) publicUrl = validatePublicUrl(publicUrl);
  assert(Array.isArray(lfsHosts) && lfsHosts.every((item) => typeof item === 'string' && isLfsHost(item)), 'lfsHosts must be a list of lowercase DNS hostnames');
  lfsHosts = [...lfsHosts];
  assert(Number.isSafeInteger(lfsMaxObjectBytes) && lfsMaxObjectBytes > 0 && lfsMaxObjectBytes <= MAX_LFS_OBJECT_BYTES, 'lfsMaxObjectBytes must be a positive integer up to 5 GiB');
  assert(typeof lfsFetch === 'function', 'lfsFetch must be a function');
  assert(Number.isSafeInteger(maxConcurrent) && maxConcurrent >= 1 && maxConcurrent <= 64, 'maxConcurrent must be an integer between 1 and 64');
  assert(Number.isSafeInteger(lfsMaxTransfers) && lfsMaxTransfers >= 1 && lfsMaxTransfers <= 64, 'lfsMaxTransfers must be an integer between 1 and 64');
  assert(typeof revocations === 'function', 'revocations must be a function returning a Set of revoked jti or sub:<runtimeId> values');
  if (adminSecret !== undefined && (typeof adminSecret !== 'string' || adminSecret.length < 32)) throw new Error('adminSecret must be at least 32 characters');
  // `live` holds the currently-served config/policyHash. Requests snapshot it at the top of the
  // handler so a reload never mutates a config object mid-request; applyConfig validates before
  // assigning, so a rejected reload leaves `live` (and therefore every in-flight and future
  // request) on the previous policy.
  const live = {};
  // Entitlements are built per validated config (WeakMap keyed by the config object), so a SIGHUP
  // reload rebuilds every source and drops every cached envelope.
  const entitlementsByConfig = new WeakMap();
  let sourceErrors;
  const onSourceError = (source) => {
    sourceErrors?.inc({ source });
    // Source name only: never the error, its message, a response body, or a token.
    logger.warn('entitlements.source_error', { source });
  };
  const applyConfig = (next) => {
    const validated = validateConfig(structuredClone(next));
    // An assertion must be bound to the workspace client token; without one there is nothing to
    // bind to, so refuse (at startup and on reload) rather than accept unbound assertions.
    assert(validated.identity?.mode !== 'assertion' || clientToken || clientAuth === 'assertion', 'identity.mode "assertion" requires a workspace client token (or clientAuth "assertion" for fleet mode)');
    assert(clientAuth !== 'assertion' || validated.identity?.mode === 'assertion', 'clientAuth "assertion" (fleet mode) requires identity.mode "assertion"');
    // One verifier (issuer keys + verification cache) per validated config: a reload that changes
    // issuers or audience gets a fresh cache, so no verification made under the old keys survives.
    // Fleet mode builds it without a fixed token: each request's bearer is checked per call.
    const verifier = validated.identity?.mode === 'assertion' ? createAssertionVerifier({
      keys: Object.fromEntries(validated.identity.issuers.map((issuer) => [issuer.kid, createPublicKey(issuer.publicKeyPem)])),
      audience: validated.identity.audience, ...(clientAuth === 'assertion' ? {} : { clientToken }), now
    }) : undefined;
    const entitlements = buildEntitlements(validated, { provider, fetchImpl: entitlementFetch, onSourceError });
    if (entitlements) entitlementsByConfig.set(validated, entitlements);
    for (const system of unsourcedElevations(validated)) logger.warn('entitlements.elevation_without_source', { system });
    live.config = validated;
    live.verifier = verifier;
    live.policyHash = fingerprint(validated);
    live.expired = false;
    return live.policyHash;
  };
  // Control-plane mode: a policy bundle past its expiresAt (or a broker started from an already
  // expired persisted bundle) denies every non-healthz request until a fresh reload arrives. The
  // deadline is enforced per request against `now()`, independent of the pull loop; the timer only
  // makes the state transition (audit/log) prompt.
  let expiryTimer;
  const setExpiry = (expiresAt) => {
    assert(expiresAt === undefined || Number.isSafeInteger(expiresAt), 'policyExpiresAt must be an integer epoch-millisecond timestamp');
    clearTimeout(expiryTimer);
    live.expiresAt = expiresAt;
    if (expiresAt !== undefined) {
      expiryTimer = setTimeout(() => expirePolicy(), Math.min(Math.max(expiresAt - now(), 0), 2 ** 31 - 1));
      expiryTimer.unref();
    }
  };
  const expirePolicy = () => {
    clearTimeout(expiryTimer);
    if (live.expired) return;
    live.expired = true;
    try { state.audit({ type: 'config.expired', policyHash: live.policyHash }); } catch { /* the deny is what matters */ }
    logger.error('config.expired', { policyHash: live.policyHash });
  };
  applyConfig(config);
  live.expired = policyExpired === true;
  if (metrics) metrics = { host: metrics.host ?? '127.0.0.1', port: metrics.port };
  // Notifying reviewers is best-effort and must never break the approval response itself: a
  // notifier is caller-supplied (tests, or a future alternate transport) and createNotifier's own
  // POST is already fire-and-forget, but a synchronous throw from the function itself must not
  // propagate into the request handler. Shared with github-api.js's PR-create path so both log
  // the same event.
  const safeNotify = guardNotify(notify, logger);
  assert(['static', 'assertion', 'none'].includes(clientAuth), 'clientAuth must be "static", "assertion", or "none"');
  assert(clientAuth !== 'static' || clientToken, 'clientAuth "static" requires a client token');
  assert(clientAuth !== 'assertion' || clientToken === undefined, 'clientAuth "assertion" takes no fixed client token');
  const authenticate = clientAuth === 'assertion' ? createAssertionBoundAuth() : createClientAuth(clientToken);
  const limiter = new RateLimiter(rateLimit);
  // Assertion mode: a second bucket per runtime (jti), so in fleet mode one workspace behind a
  // shared address cannot spend the whole address budget of its neighbours.
  const runtimeLimiter = new RateLimiter(runtimeRateLimit);
  const transfers = new TransferRegistry({ now });
  const registry = new Registry();
  const requestsTotal = registry.counter('agentgate_requests_total', 'HTTP requests by route and status');
  const duration = registry.histogram('agentgate_request_duration_seconds', 'HTTP request duration', [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120]);
  const decisions = registry.counter('agentgate_decisions_total', 'Policy decisions');
  const upstreamFailures = registry.counter('agentgate_upstream_failures_total', 'Upstream rejections');
  const reviews = registry.counter('agentgate_approval_reviews_total', 'Approval reviews');
  // agentgate_errors_total{code}: incremented directly in the request catch block below, for
  // every GateError code returned to the client, before any audit write is attempted. It must
  // not depend on the audit succeeding: a DISK_LOW error means State.audit()'s own ensureDisk()
  // check just failed, so an onAudit-based count (or a `type: 'error'` audit record) would never
  // fire for the one code operators most need to alert on. Never incremented from onAudit, so a
  // request can never be counted twice.
  const errors = registry.counter('agentgate_errors_total', 'Errors returned to clients');
  sourceErrors = registry.counter('agentgate_entitlement_source_errors_total', 'Entitlement source resolution failures by source');
  const onAudit = (record) => {
    if (record.type === 'decision') decisions.inc({ action: record.action ?? 'unknown', decision: record.decision });
    if (record.type === 'execution' && record.result === 'upstream-rejected') upstreamFailures.inc({ action: record.action ?? 'unknown' });
    if (record.type === 'approval.review') reviews.inc({ decision: record.decision });
  };
  const state = new State(stateDirectory, { ...stateOptions, onAudit });
  setExpiry(policyExpiresAt);
  const adminSocket = join(stateDirectory, 'admin.sock');
  let active = 0;
  // LFS object transfers get their own pool: git-lfs runs 8 transfers in parallel by default and each
  // holds its slot for the whole object, so sharing the main pool would starve Git and API requests
  // (and make pulls fail with BUSY). Batch requests stay in the main pool.
  let lfsActive = 0;
  registry.gauge('agentgate_approvals_pending', 'Pending approvals', () => state.list().filter((item) => item.status === 'pending').length);
  registry.gauge('agentgate_active_requests', 'In-flight broker requests', () => active);
  registry.gauge('agentgate_lfs_active_transfers', 'In-flight Git LFS object transfers', () => lfsActive);
  registry.gauge('agentgate_audit_head_seq', 'Latest audit sequence number', () => state.chainHead.seq);
  registry.gauge('agentgate_audit_forward_lag_records', 'Audit records not yet forwarded off-host', () => {
    try { return state.chainHead.seq - JSON.parse(readFileSync(auditCheckpointPath, 'utf8')).seq; } catch { return -1; }
  });
  // code -> { count, windowStart }. See REJECTION_SUMMARY_CODES above.
  const rejectionSummaries = new Map();
  const flushRejectionSummary = (code, entry) => {
    if (entry.count <= 0) return;
    try { state.audit({ type: 'rejections', code, count: entry.count, windowStart: entry.windowStart }); } catch { /* Never let a summary flush mask the request that triggered it. */ }
  };
  const recordRejection = (code) => {
    const timestamp = now();
    const entry = rejectionSummaries.get(code);
    if (!entry) {
      rejectionSummaries.set(code, { count: 1, windowStart: timestamp });
      return;
    }
    if (timestamp - entry.windowStart >= REJECTION_SUMMARY_WINDOW_MS) {
      flushRejectionSummary(code, entry);
      rejectionSummaries.set(code, { count: 1, windowStart: timestamp });
    } else {
      entry.count++;
    }
  };
  const serverOptions = { requestTimeout: 1_800_000, headersTimeout: 10_000, maxHeaderSize: 8192, ...(tls ? { cert: tls.cert, key: tls.key, minVersion: 'TLSv1.2' } : {}) };
  const server = (tls ? createHttpsServer : createServer)(serverOptions, async (request, response) => {
    // Snapshot the live config once per request. This shadows the outer `config` parameter
    // (and the removed outer `policyHash` const) on purpose: every reference below now reads
    // this request's snapshot, so a reload mid-request never changes the policy it is judged
    // against, and the rest of the handler and the handleApi(...) call stay unchanged.
    const { config, policyHash, verifier, expired, expiresAt } = live;
    const requestId = randomUUID();
    // Static mode: the configured runtime. Assertion mode: undefined until the per-request
    // assertion is verified below, then the verified claims (never the raw assertion).
    let runtime = config.runtime;
    const base = { requestId, runtime };
    const started = process.hrtime.bigint();
    // route/repository/action here reflect whatever `base` holds when the response closes; that
    // may be filled in later (git/api routes set base.repository/base.action while handling the
    // request), so this reads `base` at close time rather than capturing it now. Fires for every
    // request, including healthz, rate-limited, and unauthenticated ones.
    const routeName = request.url === '/healthz' ? 'healthz' : request.url.startsWith('/api/') ? 'api' : (/\/info\/lfs\//.test(request.url) || request.url.startsWith('/lfs-transfer/')) ? 'lfs' : /\/(info\/refs|git-(upload|receive)-pack)/.test(request.url) ? 'git' : 'other';
    response.once('close', () => {
      logger.info('request.complete', {
        requestId, route: routeName, method: request.method, status: response.statusCode,
        durationMs: Number(process.hrtime.bigint() - started) / 1e6, repository: base.repository, action: base.action
      });
      requestsTotal.inc({ route: routeName, status: String(response.statusCode) });
      duration.observe({ route: routeName }, Number(process.hrtime.bigint() - started) / 1e9);
    });
    let counted = false;
    let lfsCounted = false;
    try {
      if (request.url === '/healthz' && request.method === 'GET') return json(response, 200, {
        status: 'ok', service: 'agentgate', capabilities: providerCapabilities(provider)
      });
      // Rate limiting runs before the Host/Origin check and authentication so a flood of
      // unauthenticated or disallowed-origin requests is throttled instead of forcing unlimited
      // rejection handling (and, previously, unlimited fsync'd audit writes) per request.
      const budget = limiter.take(request.socket.remoteAddress ?? 'unknown');
      if (!budget.ok) {
        response.setHeader('retry-after', String(budget.retryAfterSeconds));
        throw new GateError(429, 'RATE_LIMITED', 'Too many requests from this client; retry later');
      }
      if (expired || (expiresAt !== undefined && now() >= expiresAt)) throw new GateError(503, 'POLICY_EXPIRED', 'Broker policy expired; contact the platform team');
      const allowedHosts = ['127.0.0.1', 'localhost', 'agentd', host].filter((value) => value !== '0.0.0.0').map((value) => `${value}:${request.socket.localPort}`);
      if (!allowedHosts.includes(request.headers.host) || request.headers.origin || request.headers['sec-fetch-site']) throw new GateError(403, 'CLIENT_NOT_ALLOWED', 'Only direct Git clients on the configured runtime network are allowed');
      const presentedToken = authenticate(request);
      if (verifier) {
        const revoked = revocations();
        if (!(revoked instanceof Set)) throw new GateError(500, 'INTERNAL_ERROR', 'Revocation list unavailable');
        const claims = clientAuth === 'assertion'
          ? verifier.verify(request.headers[ASSERTION_HEADER], revoked, presentedToken)
          : verifier.verify(request.headers[ASSERTION_HEADER], revoked);
        runtime = { human: claims.human, agent: claims.agent, runtimeId: claims.sub, task: claims.task ? `${claims.task.system}:${claims.task.id}` : 'none',
          team: claims.team, mode: claims.mode, jti: claims.jti, ...(claims.ghLogin ? { ghLogin: claims.ghLogin } : {}) };
        base.runtime = runtime;
        const runtimeBudget = runtimeLimiter.take(`runtime:${claims.jti}`);
        if (!runtimeBudget.ok) {
          response.setHeader('retry-after', String(runtimeBudget.retryAfterSeconds));
          throw new GateError(429, 'RATE_LIMITED', 'Too many requests from this runtime; retry later');
        }
      }
      // One entitlement envelope per request, resolved lazily right before the first policy decision
      // (after slot acquisition and cheap validation) and only when a rule uses `requires`; every
      // decision in this request receives the same envelope. Source failures never throw: they mark
      // the affected requirements unknown, which policy.js treats fail-closed.
      const entitlements = entitlementsByConfig.get(config);
      let envelopePromise;
      const resolveEnvelope = () => envelopePromise ??= (entitlements ? entitlements.envelope(runtime) : Promise.resolve(undefined)).then((value) => {
        if (value) base.entitlements = envelopeSummary(value);
        return value;
      });
      // Delegation bound at verification time: the assertion's team must be one the entitlement
      // sources report for its human. A source outage makes membership unknown, which "enforce"
      // treats as a refusal (503, retryable) rather than a pass. Runs before any route so an
      // over-claimed identity never reaches policy, LFS, or the API.
      const delegation = config.identity?.delegation;
      if (verifier && delegation && delegation !== 'off') {
        const envelope = await resolveEnvelope();
        const held = new Set([...(envelope?.teams ?? []), ...(envelope?.groups ?? [])]);
        if (!held.has(runtime.team)) {
          const unknown = !envelope || envelope.unknown.includes('teams') || envelope.unknown.includes('groups');
          const code = unknown ? 'DELEGATION_UNKNOWN' : 'DELEGATION_MISMATCH';
          state.audit({ ...base, type: 'decision', decision: delegation === 'enforce' ? 'delegation-refused' : 'delegation-warning', code, claimedTeam: runtime.team });
          if (delegation === 'enforce') {
            if (unknown) throw new GateError(503, code, 'Entitlement sources could not confirm the runtime\'s team; retry later');
            throw new GateError(403, code, 'The runtime claims a team its developer does not hold; contact the issuer');
          }
        }
      }
      // LFS runs only here: after rate limiting, the Host/Origin check, and authentication.
      // Transfer IDs are bearer capabilities: never put request.url, the ID, hrefs, or storage
      // headers into base, logs, or audit records.
      if (request.url.startsWith('/lfs-transfer/')) {
        if (lfsActive >= lfsMaxTransfers) {
          response.setHeader('retry-after', '1');
          throw new GateError(503, 'LFS_BUSY', 'Too many concurrent LFS transfers; retry later');
        }
        lfsActive++;
        lfsCounted = true;
        const transfer = /^\/lfs-transfer\/([0-9a-f]{64})$/.exec(request.url);
        // Check the method before claiming, so a wrong-method request cannot burn a capability.
        const pending = transfer && transfers.peek(transfer[1]);
        if (pending && request.method !== (pending.operation === 'upload' ? 'PUT' : 'GET')) {
          throw new GateError(405, 'METHOD_NOT_ALLOWED', pending.operation === 'upload' ? 'Use PUT' : 'Use GET');
        }
        const entry = transfer && transfers.claim(transfer[1]);
        if (!entry) throw new GateError(404, 'NOT_FOUND', 'Unknown or expired LFS transfer');
        // Bound to the runtime that requested the batch (assertion jti, or static runtimeId). A
        // different runtime gets the same 404 as an unknown ID; the claim above is consumed.
        if (typeof entry.owner !== 'string' || entry.owner !== transferOwner(runtime)) throw new GateError(404, 'NOT_FOUND', 'Unknown or expired LFS transfer');
        // The claim is consumed above either way. Policy may have changed (reload) since the batch,
        // so re-check the live snapshot: repository still configured, git.read still allowed, and
        // for uploads git.lfs.upload still allowed.
        const upload = entry.operation === 'upload';
        const envelope = await resolveEnvelope();
        Object.assign(base, { repository: entry.repository, action: upload ? 'git.lfs.upload' : 'git.read' });
        const repository = config.repositories.find((item) => item.name === entry.repository);
        const read = decide(config, 'git.read', entry.repository, undefined, envelope);
        const decision = !repository || read.effect !== 'allow' ? read : upload ? decide(config, 'git.lfs.upload', entry.repository, undefined, envelope) : read;
        const counts = { oid: entry.oid, size: entry.size };
        if (!repository || decision.effect !== 'allow') {
          state.audit({ ...base, type: 'decision', decision: 'deny', rule: decision.rule, ...counts });
          throw new GateError(403, 'DENIED', 'LFS transfer denied by policy');
        }
        const controller = new AbortController();
        const abort = () => { if (!response.writableFinished) controller.abort(); };
        response.once('close', abort);
        if (upload) {
          request.socket.setTimeout(bodyIdleTimeoutMs, () => request.socket.destroy());
          request.once('end', () => request.socket?.setTimeout(0));
        }
        try {
          await proxyTransfer({ request, response, entry, fetchImpl: lfsFetch, maxBytes: lfsMaxObjectBytes, signal: controller.signal,
            // Only when the batch response carried a verify action (see rewriteBatchResponse).
            beforeUploadResponse: entry.verify ? () => provider.lfsVerify({ repository, oid: entry.oid, size: entry.size, href: entry.verify.href, header: entry.verify.header, signal: controller.signal }) : undefined });
        } finally { response.off('close', abort); }
        state.audit({ ...base, type: 'execution', result: 'lfs-transfer', ...counts, verified: Boolean(entry.verify) });
        return;
      }
      if (active >= maxConcurrent) throw new GateError(503, 'BUSY', 'Broker is at capacity; retry later');
      active++;
      counted = true;
      if (request.url.startsWith('/api/')) {
        if (provider?.kind === 'gitlab') {
          const operation = routeGitlabApi(request);
          return await handleGitlabApi({ request, response, operation, config, runtime, resolveEnvelope, policyHash, state, provider, base, readBody, json, notify: safeNotify, logger });
        }
        const operation = routeApi(request);
        return await handleApi({ request, response, operation, config, runtime, resolveEnvelope, policyHash, state, provider, base, readBody, json, notify: safeNotify, logger });
      }
      const lfs = /^\/([A-Za-z0-9-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/info\/lfs\/(objects\/batch|locks(?:\/.*)?)$/.exec(request.url);
      if (lfs) {
        const name = `${lfs[1]}/${lfs[2]}`.toLowerCase();
        Object.assign(base, { repository: name, action: 'git.lfs' });
        // Locking is unsupported: a 404 makes git-lfs treat it as such.
        if (lfs[3] !== 'objects/batch' || request.method !== 'POST') throw new GateError(404, 'NOT_FOUND', 'LFS locking is not supported');
        const repository = config.repositories.find((item) => item.name === name);
        const envelope = await resolveEnvelope();
        const read = decide(config, 'git.read', name, undefined, envelope);
        if (!repository || read.effect !== 'allow') {
          state.audit({ ...base, type: 'decision', decision: 'deny', rule: read.rule });
          throw new GateError(403, 'DENIED', 'Repository read denied');
        }
        const payload = validateBatchRequest(await readBody(request, 256 * 1024), { allowUnicode: Boolean(repository.allowUnicodeRefs) });
        base.action = payload.operation === 'upload' ? 'git.lfs.upload' : 'git.read';
        // Downloads follow git.read; uploads additionally need an explicit git.lfs.upload allow.
        const decision = payload.operation === 'upload' ? decide(config, 'git.lfs.upload', name, undefined, envelope) : { effect: 'allow', rule: read.rule };
        const counts = { objects: payload.objects.length, bytes: payload.objects.reduce((sum, object) => sum + object.size, 0) };
        if (decision.effect !== 'allow') {
          state.audit({ ...base, type: 'decision', decision: 'deny', rule: decision.rule, ...counts });
          throw new GateError(403, 'DENIED', 'LFS upload denied by policy');
        }
        state.audit({ ...base, type: 'decision', decision: 'allow', rule: decision.rule, lfsOperation: payload.operation, ...counts });
        const controller = new AbortController();
        const abort = () => { if (!response.writableFinished) controller.abort(); };
        response.once('close', abort);
        try {
          if (typeof provider.lfsBatch !== 'function') throw new GateError(404, 'NOT_FOUND', 'Git LFS is not available for this provider');
          const upstream = await provider.lfsBatch({ repository, operation: payload.operation, payload, signal: controller.signal });
          if (upstream.status !== 200) {
            await upstream.body?.cancel();
            state.audit({ ...base, type: 'execution', result: 'upstream-rejected', upstreamStatus: upstream.status });
            throw new GateError(502, 'UPSTREAM_FAILED', `GitHub LFS rejected the batch (${upstream.status})`);
          }
          // Never audit or log the rewritten body: it contains bearer transfer IDs.
          const rewritten = rewriteBatchResponse(await readUpstreamJson(upstream), { registry: transfers, repository: name, operation: payload.operation, brokerUrl: publicUrl ?? gateUrl(), allowedHosts: lfsHosts, requested: payload.objects, owner: transferOwner(runtime) });
          state.audit({ ...base, type: 'execution', result: 'upstream-response', upstreamStatus: upstream.status, ...counts });
          response.writeHead(200, { 'content-type': LFS_CONTENT_TYPE, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
          return response.end(JSON.stringify(rewritten));
        } finally { response.off('close', abort); }
      }
      const { name, service, discovery } = route(request);
      base.repository = name;
      base.action = service === 'git-receive-pack' && !discovery ? 'git.push' : 'git.read';
      const repository = config.repositories.find((item) => item.name === name);
      const envelope = await resolveEnvelope();
      const read = decide(config, 'git.read', name, undefined, envelope);
      if (!repository || read.effect !== 'allow') {
        state.audit({ ...base, type: 'decision', decision: 'deny', rule: read.rule });
        throw new GateError(403, 'DENIED', `Repository read denied (${read.rule})`);
      }
      const protocol = request.headers['git-protocol'];
      if (protocol && !/^version=[012]$/.test(protocol)) throw new GateError(400, 'INVALID_PROTOCOL', 'Unsupported Git protocol header');
      let body;
      let push;
      if (!discovery) {
        // The 30-minute requestTimeout allows large streamed pushes; this inactivity bound stops a
        // client that sends headers and then stalls from holding a slot. Cleared once the body ends,
        // since GitHub may legitimately take a while to answer after receiving the last byte.
        request.socket.setTimeout(bodyIdleTimeoutMs, () => request.socket.destroy());
        request.once('end', () => request.socket?.setTimeout(0));
        if (base.action === 'git.push') {
          push = await readPush(request, { maxBodyBytes, allowUnicode: Boolean(repository.allowUnicodeRefs) });
          body = push.body;
        } else body = await readBody(request, Math.min(maxBodyBytes, MAX_BUFFERED_GIT_BODY_BYTES));
      }
      let approvalId;
      let mirrorSynced = false;
      const syncMirror = async () => {
        if (!mirror) throw new GateError(503, 'SCAN_UNAVAILABLE', 'Content scanning is configured but no mirror is available');
        await mirror.sync(repository);
        mirrorSynced = true;
      };
      if (base.action === 'git.push' && !push.probe) {
        const { changes } = push;
        // Push options are free text an agent fully controls (and may use to try to exfiltrate
        // data), so a denied option's value is never echoed back in the error, audit record, or
        // anywhere else — only the rule name/code. The allowlist is opt-in per repository and
        // supports exact strings or a trailing "prefix*" wildcard; a repository with none
        // configured denies every push option.
        const allowedOptions = repository.allowedPushOptions ?? [];
        const deniedOption = push.pushOptions.find((option) => !allowedOptions.some((pattern) => pattern.endsWith('*') ? option.startsWith(pattern.slice(0, -1)) : option === pattern));
        if (deniedOption !== undefined) {
          state.audit({ ...base, type: 'decision', decision: 'deny', rule: 'push-option-not-allowed' });
          throw new GateError(403, 'PUSH_OPTION_DENIED', 'A push option is not allowed for this repository');
        }
        const decision = decidePush(config, name, changes, envelope);
        base.changes = decision.decisions;
        if (decision.effect === 'deny') {
          state.audit({ ...base, type: 'decision', decision: 'deny' });
          throw new GateError(403, 'DENIED', 'At least one ref update is denied by policy');
        }
        if (decision.effect === 'approval') {
          // The context is persisted verbatim into approvals.json, the admin GET /approvals
          // response (read by the CLI and approval-web), and the approval.review audit record
          // (forwarded off-host), so the raw option values must never be stored here: a
          // `prefix*` allowlist entry lets an agent put arbitrary text after the prefix, which
          // would otherwise flow straight into all three. Only a count and a digest (sha256 of
          // the sorted values) are kept — the digest still makes different option sets produce
          // different fingerprints below (via `fingerprint(context)`), so an approval binds the
          // exact set of options requested without ever recording what they were.
          const sortedOptions = [...push.pushOptions].sort();
          const context = { runtime, repository: name, changes: [...changes].sort((a, b) => a.ref.localeCompare(b.ref)), policyHash,
            pushOptionsCount: sortedOptions.length, pushOptionsDigest: fingerprint(sortedOptions),
            ...(decision.reviewerSources ? { reviewerSources: decision.reviewerSources } : {}),
            // Shows reviewers why a `requires` rule matched; also binds the approval to these entitlements.
            ...(envelope ? { entitlements: envelopeSummary(envelope) } : {}) };
          const key = fingerprint(context);
          // With scanning, sync the mirror before spending a grant: the sync only reads upstream, so a
          // sync failure (GitHub unreachable, token error) leaves the approval unspent for a retry.
          if (repository.scan && state.hasGrant(key)) await syncMirror();
          approvalId = state.consume(key);
          if (!approvalId) {
            const pending = state.request(key, context, { requiredApprovals: decision.requiredApprovals });
            // Notify before auditing: the approval already exists, so an audit failure here must not
            // suppress its one-time notification forever (retries find it with created === false).
            if (pending.created) safeNotify(pending);
            state.audit({ ...base, type: 'decision', decision: 'approval', approvalId: pending.id });
            response.setHeader('connection', 'close');
            discardUnreadBody(request, response);
            return json(response, 403, { code: 'REQUIRE_APPROVAL', requestId: pending.id, requiredApprovals: pending.requiredApprovals, message: `Review ${pending.id} with the host approval CLI, then retry the same ref updates` });
          }
        }
      }
      // Content scanning runs after policy (and after any approval grant is consumed), so a finding
      // can never be approved around. The whole request is quarantined and indexed against the
      // repository mirror; only those exact bytes are forwarded, and only when nothing is found.
      let quarantine;
      if (base.action === 'git.push' && !push.probe && repository.scan) {
        if (!mirrorSynced) await syncMirror();
        quarantine = await mirror.quarantine(repository, body, { maxBytes: maxBodyBytes });
        try {
          const findings = await scanPush({ mirror, repository, env: quarantine.env, objectsDir: quarantine.objectsDir, changes: push.changes, settings: repository.scan });
          if (findings.length) {
            const reported = publicFindings(findings);
            state.audit({ ...base, type: 'decision', decision: 'content-blocked', code: 'CONTENT_BLOCKED', approvalId, findings: reported });
            // Remove the quarantined bytes before the client hears the verdict: once the 403 is on
            // the wire nothing must remain on disk from a push that was refused.
            await quarantine.cleanup().catch(() => {});
            quarantine = undefined;
            response.setHeader('connection', 'close');
            return json(response, 403, { code: 'CONTENT_BLOCKED', requestId, message: 'Push blocked by content scanning; remove the findings from history and push again', findings: reported });
          }
          body = createReadStream(quarantine.pack);
        } catch (error) {
          await quarantine.cleanup().catch(() => {});
          quarantine = undefined;
          throw error;
        } finally {
          if (quarantine && body?.path !== quarantine.pack) { await quarantine.cleanup().catch(() => {}); quarantine = undefined; }
        }
      }
      try {
        state.audit({ ...base, type: 'decision', decision: 'allow', approvalId, rule: base.action === 'git.read' ? read.rule : undefined, ...(push?.probe ? { probe: true } : {}) });
        const controller = new AbortController();
        const abort = () => { if (!response.writableFinished) controller.abort(); };
        response.once('close', abort);
        try {
          // A streamed push body that fails (e.g. BODY_TOO_LARGE mid-stream) must abort the upstream
          // request and surface its own error rather than a generic upstream failure.
          let bodyError;
          body?.on?.('error', (error) => { bodyError = error; controller.abort(); });
          let upstream;
          try {
            upstream = await provider.forward({ repository, service, discovery, body, protocol, signal: controller.signal });
          } catch (error) { throw bodyError ?? error; }
          if (bodyError) { await upstream.body?.cancel(); throw bodyError; }
          const expectedType = `application/x-${service}-${discovery ? 'advertisement' : 'result'}`;
          if (upstream.status !== 200 || upstream.headers.get('content-type')?.split(';')[0] !== expectedType || !upstream.body) {
            await upstream.body?.cancel();
            state.audit({ ...base, type: 'execution', result: 'upstream-rejected', upstreamStatus: upstream.status, approvalId });
            throw new GateError(502, 'UPSTREAM_FAILED', `GitHub rejected the Git request (${upstream.status})`);
          }
          // HTTP 200 does not prove a ref was updated: Git reports ref errors in its body.
          state.audit({ ...base, type: 'execution', result: 'upstream-response', upstreamStatus: upstream.status, approvalId });
          response.writeHead(200, { 'content-type': expectedType, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
          // Keep the response open until the quarantine (if any) is gone, so a client that acts on
          // the completed push never races the broker's cleanup of the forwarded bytes.
          await pipeline(Readable.fromWeb(upstream.body), response, { end: false });
          if (quarantine) { await quarantine.cleanup().catch(() => {}); quarantine = undefined; }
          response.end();
        } finally { response.off('close', abort); }
      } finally {
        if (quarantine) { body?.destroy?.(); await quarantine.cleanup().catch(() => {}); }
      }
    } catch (error) {
      const safe = error instanceof GateError ? error : new GateError(500, 'INTERNAL_ERROR', 'Request failed; inspect the broker audit log');
      // Count before attempting any audit write: ensureDisk() (called at the top of every
      // State.audit()) can itself be the source of a DISK_LOW error, in which case the audit
      // write below also throws and is swallowed — the metric must not depend on it succeeding.
      errors.inc({ code: safe.code });
      if (REJECTION_SUMMARY_CODES.has(safe.code)) {
        try { recordRejection(safe.code); } catch { /* Do not mask the failure or disclose credentials. */ }
      } else {
        try { state.audit({ ...base, type: 'error', code: safe.code }); } catch { /* Do not mask the failure or disclose credentials. */ }
      }
      if (!response.headersSent && !response.destroyed) {
        response.setHeader('connection', 'close');
        if (safe.status === 401) response.setHeader('www-authenticate', 'Bearer realm="agentgate"');
        json(response, safe.status, { code: safe.code, message: safe.message, requestId });
      } else response.destroy();
      discardUnreadBody(request, response);
    } finally {
      if (counted) active--;
      if (lfsCounted) lfsActive--;
    }
  });
  server.maxRequestsPerSocket = 100;
  const gateUrl = () => `${tls ? 'https' : 'http'}://${host}:${server.address().port}`;
  // The admin socket is reachable by both the host CLI and approval-web. `local:` reviewers are
  // accepted from either; an `oidc:` reviewer is accepted only on a request HMAC-signed with the
  // approval-web admin secret (see admin-auth.js), because only approval-web derives it from an
  // oauth2-proxy-verified email. The verified source is recorded on the review by State, never
  // taken from the client.
  const admin = createServer(async (request, response) => {
    try {
      if (request.method === 'GET' && request.url === '/approvals') {
        const { policyHash } = live;
        return json(response, 200, state.list().map((item) => isSuperseded(item, policyHash) ? { ...item, superseded: true } : item));
      }
      // Approval creation for out-of-broker governed events (the hosted-agents webhook receiver):
      // accepted only on a request HMAC-signed with the approval-web admin secret, so nothing that
      // merely reaches the socket can fill the pending queue. The context is stamped with the live
      // policy hash so the approval supersedes like any other; the caller never chooses it.
      if (request.method === 'POST' && request.url === '/approvals') {
        const raw = await readBody(request, 16384);
        const verified = Boolean(adminSecret) && verifyAdminRequest(adminSecret, {
          method: request.method, path: request.url, body: raw.toString('utf8'),
          timestamp: request.headers[TIMESTAMP_HEADER], signature: request.headers[SIGNATURE_HEADER]
        }, now());
        if (!verified) throw new GateError(403, 'UNAUTHENTICATED', 'Approval creation requires the admin secret signature');
        let input;
        try { input = JSON.parse(raw.toString('utf8')); } catch { throw new GateError(400, 'INVALID_JSON', 'Expected {"context": {...}, "requiredApprovals": N}'); }
        if (typeof input !== 'object' || input === null || Array.isArray(input) || typeof input.context !== 'object' || input.context === null) throw new GateError(400, 'INVALID_JSON', 'Expected {"context": {...}}');
        if (typeof input.context.action !== 'string' || !input.context.action.startsWith('github.pr.hosted')) throw new GateError(400, 'INVALID_CONTEXT', 'Only hosted-agent approvals can be created through the admin socket');
        const requiredApprovals = input.requiredApprovals ?? 1;
        if (!Number.isInteger(requiredApprovals) || requiredApprovals < 1 || requiredApprovals > 5) throw new GateError(400, 'INVALID_CONTEXT', 'requiredApprovals must be 1-5');
        const context = { ...input.context, policyHash: live.policyHash };
        const key = fingerprint(context);
        const existing = state.hasGrant(key) ? state.list().find((item) => item.key === key && item.status === 'approved') : undefined;
        if (existing) return json(response, 200, existing);
        const pending = state.request(key, context, { requiredApprovals });
        if (pending.created) safeNotify(pending);
        state.audit({ requestId: randomUUID(), runtime: context.runtime, type: 'decision', decision: 'approval', action: context.action, repository: context.repository, approvalId: pending.id, hosted: true });
        return json(response, 200, pending);
      }
      const match = /^\/approvals\/([0-9a-f-]+)\/(approve|deny)$/.exec(request.url);
      if (request.method !== 'POST' || !match) throw new GateError(404, 'NOT_FOUND', 'Unknown admin operation');
      let input = {};
      const raw = await readBody(request, 4096);
      if (raw.length) {
        try { input = JSON.parse(raw.toString('utf8')); } catch { throw new GateError(400, 'INVALID_JSON', 'Expected {"reviewer": "..."}'); }
        if (typeof input !== 'object' || input === null || Array.isArray(input)) throw new GateError(400, 'INVALID_JSON', 'Expected {"reviewer": "..."}');
      }
      let source;
      if (typeof input.reviewer === 'string' && input.reviewer.startsWith('oidc:')) {
        const verified = Boolean(adminSecret) && verifyAdminRequest(adminSecret, {
          method: request.method, path: request.url, body: raw.toString('utf8'),
          timestamp: request.headers[TIMESTAMP_HEADER], signature: request.headers[SIGNATURE_HEADER]
        }, now());
        if (!verified) throw new GateError(403, 'REVIEWER_SOURCE_UNVERIFIED', 'oidc: reviewers are accepted only from the authenticated approval web UI');
        source = 'oidc';
      } else if (typeof input.reviewer === 'string' && input.reviewer.startsWith('local:')) {
        source = 'local';
      }
      return json(response, 200, state.review(match[1], match[2] === 'approve', input.reviewer, { source, policyHash: live.policyHash }));
    } catch (error) {
      json(response, error instanceof GateError ? error.status : 500, { code: error instanceof GateError ? error.code : 'INTERNAL_ERROR', message: error instanceof GateError ? error.message : 'Admin operation failed' });
    }
  });
  let metricsServer;
  try {
    // Safe: State holds the exclusive lock, so no other broker owns this socket.
    rmSync(adminSocket, { force: true });
    await listen(admin, adminSocket);
    chmodSync(adminSocket, 0o600);
    await listen(server, port, host);
    if (metrics) {
      // Deliberately separate from the main listener: /metrics is unauthenticated (Prometheus
      // scrapers do not send the workspace bearer token), so it must never be reachable from the
      // main listener's network. Operators must not put this listener on the workspace network.
      metricsServer = createServer((request, response) => {
        if (request.method !== 'GET' || request.url !== '/metrics') { response.writeHead(404).end(); return; }
        // Render before writing any headers: registry.render() already isolates a single failing
        // collector, but this ordering is still a last resort so that an unexpected throw here
        // (rather than inside one metric's collect()) produces a 500 instead of a truncated 200
        // body or a crashed process.
        let body;
        try { body = registry.render(); } catch {
          response.writeHead(500).end();
          return;
        }
        response.writeHead(200, { 'content-type': 'text/plain; version=0.0.4', 'cache-control': 'no-store' });
        response.end(body);
      });
      await listen(metricsServer, metrics.port, metrics.host);
    }
  } catch (error) {
    await Promise.all([close(server), close(admin), metricsServer && close(metricsServer)]);
    state.close();
    throw error;
  }
  return { server, state, adminSocket, logger, registry, metricsUrl: metricsServer ? `http://${metrics.host}:${metricsServer.address().port}/metrics` : undefined, url: gateUrl(), transfers,
    // Read-only: callers (the daemon's SIGHUP handler and hourly ruleset recheck) must see the
    // live, currently-served config rather than the object passed to startGate at boot.
    get config() { return live.config; },
    // Digest of the live policy; approvals are bound to it (central reviews carry it back).
    get policyHash() { return live.policyHash; },
    // `expiresAt` (control-plane bundles only) is the new policy's deadline; omitted, the policy
    // never expires (local config file and SIGHUP reloads).
    reload: (next, { expiresAt } = {}) => {
      const previousPolicyHash = live.policyHash;
      try {
        assert(expiresAt === undefined || (Number.isSafeInteger(expiresAt) && expiresAt > now()), 'policy expiresAt must be in the future');
        const policyHash = applyConfig(next);
        setExpiry(expiresAt);
        state.audit({ type: 'config.reload', result: 'applied', policyHash, previousPolicyHash });
        logger.info('config.reload', { policyHash, previousPolicyHash });
        return { policyHash };
      } catch (error) {
        state.audit({ type: 'config.reload', result: 'rejected', previousPolicyHash, message: error.message });
        logger.error('config.reload_rejected', { message: error.message });
        throw error;
      }
    },
    get policyExpired() { return live.expired; },
    // Signed policy bundle expired with no fresh one: keep the last config object for read-only
    // consumers (ruleset recheck) but deny every request with 503 POLICY_EXPIRED until reload().
    expirePolicy,
    close: async () => {
      clearTimeout(expiryTimer);
      await Promise.all([close(server), close(admin), metricsServer && close(metricsServer)]);
      for (const [code, entry] of rejectionSummaries) flushRejectionSummary(code, entry);
      rejectionSummaries.clear();
      state.close();
    } };
}
