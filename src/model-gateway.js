import { createServer } from 'node:http';
import { readFileSync, statSync } from 'node:fs';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { pathToFileURL } from 'node:url';
import { createClientAuth } from './client-auth.js';
import { GateError } from './errors.js';
import { RateLimiter } from './limits.js';
import { ASSERTION_HEADER, createAssertionVerifier } from './assertion.js';
import { createPublicKey } from 'node:crypto';

const HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te', 'trailer',
  'transfer-encoding', 'upgrade', 'host', 'content-length', 'expect', 'forwarded', 'x-forwarded-for', 'x-forwarded-host',
  'x-forwarded-proto', 'x-real-ip']);
// Client credentials of every provider SDK we might front; the route secret replaces them.
const STRIP = new Set(['authorization', 'x-api-key', 'cookie', 'api-key', 'x-goog-api-key']);
const RESPONSE_STRIP = new Set(['set-cookie', 'set-cookie2', 'transfer-encoding', 'connection', 'keep-alive', 'proxy-authenticate',
  'proxy-connection', 'trailer', 'upgrade', 'content-encoding', 'content-length']);
const PREFIX = /^\/[a-z0-9][a-z0-9-]{0,62}$/;
const HEADER_NAME = /^[a-z0-9-]{1,64}$/;
// Budget fields that may be omitted; every other field must be a positive integer after defaults.
const OPTIONAL_BUDGET = new Set(['maxGlobalRequestsPerHour', 'maxRequestsPerHourPerRuntime']);
const BUDGET_KEYS = ['maxRequestsPerHour', 'maxRequestBytes', 'maxGlobalRequestsPerHour', 'maxBufferedBytes', 'maxRequestsPerHourPerRuntime'];
const DEFAULT_BUDGET = { maxRequestsPerHour: 600, maxRequestBytes: 8 * 1024 * 1024 };
const DEFAULT_MAX_CONCURRENT = 8;
const UPSTREAM_TIMEOUT_MS = 10 * 60_000;

// Rejects `|` outside groups and character classes: `^/a|/admin$` would otherwise allow `/admin`.
function hasTopLevelAlternation(source) {
  let depth = 0;
  let inClass = false;
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (char === '\\') { index += 1; continue; }
    if (inClass) { if (char === ']') inClass = false; continue; }
    if (char === '[') inClass = true;
    else if (char === '(') depth += 1;
    else if (char === ')') depth -= 1;
    else if (char === '|' && depth === 0) return true;
  }
  return false;
}

// A trailing `$` is an anchor only when preceded by an even number of backslashes (`\\$` is an
// escaped backslash then the anchor; `\$` is a literal dollar sign).
function endsWithAnchor(source) {
  if (!source.endsWith('$')) return false;
  let slashes = 0;
  for (let index = source.length - 2; index >= 0 && source[index] === '\\'; index -= 1) slashes += 1;
  return slashes % 2 === 0;
}

export function compileAllowPath(source) {
  if (typeof source !== 'string' || !source.startsWith('^') || !endsWithAnchor(source) || hasTopLevelAlternation(source)) {
    throw new Error('allowPaths entries must be anchored (^...$) regex sources without top-level alternation');
  }
  return new RegExp(`^(?:${source.slice(1, -1)})$`);
}

function validateIdentity(identity) {
  if (identity === undefined) return undefined;
  if (!identity || typeof identity !== 'object' || Array.isArray(identity)) throw new Error('Model gateway identity must be an object');
  for (const key of Object.keys(identity)) if (!['audience', 'issuers', 'required'].includes(key)) throw new Error(`Invalid identity.${key}`);
  if (typeof identity.audience !== 'string' || !/^[\x21-\x7e]{1,256}$/.test(identity.audience)) throw new Error('identity.audience must be a nonempty printable string');
  if (!Array.isArray(identity.issuers) || !identity.issuers.length || identity.issuers.length > 10) throw new Error('identity.issuers must list 1-10 issuers');
  if (identity.required !== undefined && typeof identity.required !== 'boolean') throw new Error('identity.required must be a boolean');
  const keys = {};
  for (const issuer of identity.issuers) {
    if (!issuer || typeof issuer.kid !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(issuer.kid) || keys[issuer.kid]) throw new Error('identity.issuers kid values must be unique and match ^[A-Za-z0-9_-]{1,64}$');
    let key;
    try { if (!/PRIVATE KEY/.test(issuer.publicKeyPem)) key = createPublicKey(issuer.publicKeyPem); } catch { /* reported below */ }
    if (key?.asymmetricKeyType !== 'ed25519') throw new Error(`identity issuer ${issuer.kid} publicKeyPem must be an ed25519 public key`);
    keys[issuer.kid] = key;
  }
  return { audience: identity.audience, keys, required: identity.required === true };
}

function validate({ routes, clientToken, budget, maxConcurrent }) {
  if (typeof clientToken !== 'string' || clientToken.length < 32) throw new Error('Model gateway requires a client token of at least 32 characters');
  if (!Array.isArray(routes) || routes.length === 0) throw new Error('Model gateway requires at least one route');
  const prefixes = new Set();
  for (const route of routes) {
    if (!route || !PREFIX.test(route.prefix ?? '')) throw new Error(`Invalid model route prefix ${JSON.stringify(route?.prefix)}`);
    if (prefixes.has(route.prefix)) throw new Error(`Duplicate model route prefix ${route.prefix}`);
    prefixes.add(route.prefix);
    let upstream;
    try { upstream = new URL(route.upstream); } catch { throw new Error(`Invalid upstream for ${route.prefix}`); }
    if (upstream.protocol !== 'https:' || upstream.username || upstream.password || upstream.search || upstream.hash || upstream.pathname !== '/' || route.upstream.endsWith('/')) {
      throw new Error(`Upstream for ${route.prefix} must be a bare https origin`);
    }
    if (!Array.isArray(route.allowPaths) || route.allowPaths.length === 0) throw new Error(`allowPaths for ${route.prefix} must be a non-empty array`);
    try { route.allowPaths.forEach(compileAllowPath); } catch (error) { throw new Error(`${error.message} (route ${route.prefix})`); }
    if (!route.inject || !HEADER_NAME.test(route.inject.header ?? '') || typeof route.inject.valueFile !== 'string' || !route.inject.valueFile) {
      throw new Error(`Invalid inject for ${route.prefix}`);
    }
  }
  for (const key of BUDGET_KEYS) {
    if ((budget[key] !== undefined || !OPTIONAL_BUDGET.has(key)) && (!Number.isInteger(budget[key]) || budget[key] < 1)) throw new Error(`Invalid budget.${key}`);
  }
  if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1) throw new Error('Invalid maxConcurrent');
}

// Read on every request so key rotation needs no restart; refuse anything group/other readable.
function readSecret(path) {
  if ((statSync(path).mode & 0o077) !== 0) throw new Error('Model API key file must be owner-only (chmod 600)');
  const value = readFileSync(path, 'utf8').trim();
  if (!/^[\x21-\x7e]{1,4096}$/.test(value)) throw new Error('Model API key file is empty or malformed');
  return value;
}

// Splits the raw request target without URL normalization, refusing anything that could make the
// allowlisted path differ from what the upstream interprets (dot segments, encoded separators).
function parseTarget(raw) {
  const index = raw.indexOf('?');
  const pathname = index === -1 ? raw : raw.slice(0, index);
  const search = index === -1 ? '' : raw.slice(index);
  if (!pathname.startsWith('/') || pathname.startsWith('//') || pathname.includes('//') || pathname.includes('\\')
    || /%(2f|5c|2e|00|25)/i.test(pathname) || /(^|\/)\.\.?(\/|$)/.test(pathname) || /[^\x21-\x7e]/.test(raw) || raw.includes('#')) {
    return undefined;
  }
  return { pathname, search };
}

/**
 * @param {object} options
 * @param {Array<{prefix: string, upstream: string, allowPaths: string[], inject: {header: string, valueFile: string}}>} options.routes
 * @param {string} options.clientToken Model-gateway client token (distinct from agentd's workspace token).
 * @param {{maxRequestsPerHour?: number, maxRequestBytes?: number, maxGlobalRequestsPerHour?: number, maxBufferedBytes?: number}} [options.budget]
 *   Per-client hourly requests, per-request bytes, optional shared hourly cap across all clients,
 *   and the global in-memory request-byte cap (default maxConcurrent x maxRequestBytes).
 */
export async function startModelGateway({ routes, clientToken, host = '0.0.0.0', port = 7434, fetchImpl = fetch, audit = () => {}, budget = DEFAULT_BUDGET, maxConcurrent = DEFAULT_MAX_CONCURRENT, identity, now = Date.now }) {
  budget = { ...DEFAULT_BUDGET, ...budget };
  // Global cap on request bytes held in memory at once; defaults to what the concurrency cap implies.
  budget.maxBufferedBytes ??= maxConcurrent * budget.maxRequestBytes;
  validate({ routes, clientToken, budget, maxConcurrent });
  const authenticate = createClientAuth(clientToken);
  // Optional runtime attribution: a workspace that sends its runtime assertion (Claude Code does
  // via ANTHROPIC_CUSTOM_HEADERS, exported by the workspace profile) is verified against the
  // issuer keys (signature, audience, lifetime, claims; the token binding cannot be checked here
  // because the gateway never sees the workspace token) and gets its own hourly budget and an
  // audit record naming the runtime. The client token is still required. A present but invalid
  // header is always refused; a missing one is refused only when identity.required is true.
  const runtimeIdentity = validateIdentity(identity);
  const verifier = runtimeIdentity ? createAssertionVerifier({ keys: runtimeIdentity.keys, audience: runtimeIdentity.audience, skipBinding: true, now }) : undefined;
  const runtimeLimiter = runtimeIdentity ? new RateLimiter({ capacity: budget.maxRequestsPerHourPerRuntime ?? budget.maxRequestsPerHour, refillPerSecond: (budget.maxRequestsPerHourPerRuntime ?? budget.maxRequestsPerHour) / 3600, maxKeys: 4096 }) : undefined;
  // Keyed per client address; RateLimiter evicts least-recently-used keys beyond maxKeys.
  const limiter = new RateLimiter({ capacity: budget.maxRequestsPerHour, refillPerSecond: budget.maxRequestsPerHour / 3600, maxKeys: 4096 });
  // One shared bucket across all clients: every workspace presents the same client token.
  const globalLimiter = budget.maxGlobalRequestsPerHour === undefined ? undefined
    : new RateLimiter({ capacity: budget.maxGlobalRequestsPerHour, refillPerSecond: budget.maxGlobalRequestsPerHour / 3600, maxKeys: 1 });
  const compiled = routes.map((route) => ({ ...route, patterns: route.allowPaths.map(compileAllowPath) }));
  let inFlight = 0;
  let bufferedBytes = 0;

  const server = createServer(async (request, response) => {
    let route;
    let path;
    let bytesUp = 0;
    let bytesDown = 0;
    let slot = false;
    let held = 0;
    // The gateway sees no runtime assertion, only the shared client token every workspace
    // presents, so the source address is the best available identity for SIEM correlation. See
    // docs/detections.md "Known gaps" for what this does and does not attribute.
    const client = request.socket.remoteAddress ?? 'unknown';
    let runtime;
    const release = () => {
      if (slot) { slot = false; inFlight -= 1; }
      bufferedBytes -= held;
      held = 0;
    };
    const controller = new AbortController();
    response.once('close', () => { controller.abort(); release(); });
    try {
      authenticate(request);
      if (verifier) {
        const header = request.headers[ASSERTION_HEADER];
        if (header !== undefined) {
          const claims = verifier.verify(header);
          runtime = { runtimeId: claims.sub, human: claims.human, agent: claims.agent, team: claims.team, jti: claims.jti };
        } else if (runtimeIdentity.required) throw new GateError(401, 'ASSERTION_INVALID', 'A runtime assertion is required by this model gateway');
      }
      const target = parseTarget(request.url ?? '');
      route = target && compiled.find((item) => target.pathname.startsWith(`${item.prefix}/`));
      path = route ? target.pathname.slice(route.prefix.length) : undefined;
      if (!route || !['GET', 'POST'].includes(request.method) || !route.patterns.some((pattern) => pattern.test(path))) {
        throw new GateError(404, 'NOT_FOUND', 'Model API path is not allowlisted');
      }
      const declared = request.headers['content-length'];
      if (declared !== undefined && !/^\d{1,15}$/.test(declared)) throw new GateError(400, 'BAD_REQUEST', 'Invalid content-length');
      if (declared !== undefined && Number(declared) > budget.maxRequestBytes) throw new GateError(413, 'BODY_TOO_LARGE', 'Model request too large');
      if (inFlight >= maxConcurrent) throw new GateError(503, 'GATEWAY_BUSY', 'Model gateway is at its concurrent request limit');
      inFlight += 1;
      slot = true;
      const chunks = [];
      for await (const chunk of request) {
        bytesUp += chunk.length;
        if (bytesUp > budget.maxRequestBytes) throw new GateError(413, 'BODY_TOO_LARGE', 'Model request too large');
        if (bufferedBytes + chunk.length > budget.maxBufferedBytes) throw new GateError(503, 'GATEWAY_BUSY', 'Model gateway memory budget is exhausted');
        bufferedBytes += chunk.length;
        held += chunk.length;
        chunks.push(chunk);
      }
      if (request.method === 'GET' && bytesUp > 0) throw new GateError(400, 'BAD_REQUEST', 'GET requests must not carry a body');
      // Tokens are taken only for complete, in-budget requests, so refused bodies never burn budget.
      const limit = limiter.take(request.socket.remoteAddress ?? 'unknown');
      if (!limit.ok) throw Object.assign(new GateError(429, 'RATE_LIMITED', 'Model API budget exceeded for this hour'), { retryAfter: limit.retryAfterSeconds });
      const runtimeLimit = runtime ? runtimeLimiter.take(`runtime:${runtime.jti}`) : undefined;
      if (runtimeLimit && !runtimeLimit.ok) throw Object.assign(new GateError(429, 'RATE_LIMITED', 'Model API budget exceeded for this runtime this hour'), { retryAfter: runtimeLimit.retryAfterSeconds });
      const globalLimit = globalLimiter?.take('global');
      if (globalLimit && !globalLimit.ok) throw Object.assign(new GateError(429, 'RATE_LIMITED', 'Model API global budget exceeded for this hour'), { retryAfter: globalLimit.retryAfterSeconds });
      let secret;
      try { secret = readSecret(route.inject.valueFile); } catch { throw new GateError(503, 'UNAVAILABLE', 'Model API credential is unavailable'); }
      const connectionTokens = new Set(String(request.headers.connection ?? '').toLowerCase().split(',').map((token) => token.trim()).filter(Boolean));
      const headers = Object.fromEntries(Object.entries(request.headers).filter(([key]) =>
        !HOP.has(key) && !STRIP.has(key) && !connectionTokens.has(key) && !key.startsWith('x-agentgate-')));
      headers[route.inject.header] = secret;
      const upstream = await fetchImpl(`${route.upstream}${path}${target.search}`, {
        method: request.method, headers, body: request.method === 'POST' ? Buffer.concat(chunks) : undefined, redirect: 'error',
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(UPSTREAM_TIMEOUT_MS)])
      });
      const responseHeaders = Object.fromEntries([...upstream.headers].filter(([key, value]) => !RESPONSE_STRIP.has(key) && !value.includes(secret)));
      response.writeHead(upstream.status, responseHeaders);
      if (upstream.body) {
        const body = Readable.fromWeb(upstream.body);
        body.on('data', (chunk) => { bytesDown += chunk.length; });
        await pipeline(body, response);
      } else response.end();
      audit({ type: 'model.request', route: route.prefix, path, status: upstream.status, bytesUp, bytesDown, client, ...(runtime ? { runtime } : {}) });
    } catch (error) {
      const safe = error instanceof GateError ? error : new GateError(502, 'UPSTREAM_FAILED', 'Model API request failed');
      audit({ type: 'model.request', route: route?.prefix, path, status: safe.status, code: safe.code, bytesUp, bytesDown, client, ...(runtime ? { runtime } : {}) });
      if (!response.headersSent && !response.destroyed) {
        response.writeHead(safe.status, { 'content-type': 'application/json', connection: 'close', ...(error.retryAfter ? { 'retry-after': String(error.retryAfter) } : {}) });
        response.end(JSON.stringify({ code: safe.code, message: safe.message }));
      } else response.destroy();
    } finally {
      release();
    }
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 60_000;

  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  const address = server.address();
  const urlHost = ['0.0.0.0', '::'].includes(address.address) ? '127.0.0.1' : address.family === 'IPv6' ? `[${address.address}]` : address.address;
  return {
    url: `http://${urlHost}:${address.port}`,
    close: () => new Promise((resolve) => { server.closeAllConnections(); server.close(() => resolve()); })
  };
}

export function loadModelGatewayConfig(path) {
  const config = JSON.parse(readFileSync(path, 'utf8'));
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('Invalid model gateway config: expected an object');
  for (const key of Object.keys(config)) {
    if (!['routes', 'budget', 'maxConcurrent', 'identity'].includes(key)) throw new Error(`Invalid model gateway config: unknown key ${JSON.stringify(key)}`);
  }
  return config;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { createLogger } = await import('./log.js');
  const { loadClientToken } = await import('./client-auth.js');
  const logger = createLogger({ base: { service: 'agentgate-model-gateway' }, errorStream: process.stderr });
  try {
    const config = loadModelGatewayConfig(process.env.AGENTGATE_MODEL_GATEWAY_CONFIG || '/etc/agentgate/model-gateway.json');
    // A token of its own, so a compromised gateway never holds agentd's workspace token. The
    // shared AGENTGATE_CLIENT_TOKEN_FILE is accepted only as a fallback for older deployments.
    const tokenFile = process.env.AGENTGATE_MODEL_GATEWAY_CLIENT_TOKEN_FILE || process.env.AGENTGATE_CLIENT_TOKEN_FILE;
    if (!tokenFile) throw new Error('AGENTGATE_MODEL_GATEWAY_CLIENT_TOKEN_FILE is required');
    if (!process.env.AGENTGATE_MODEL_GATEWAY_CLIENT_TOKEN_FILE) {
      logger.warn('model_gateway.shared_client_token', { reason: 'AGENTGATE_MODEL_GATEWAY_CLIENT_TOKEN_FILE is unset; using AGENTGATE_CLIENT_TOKEN_FILE, which shares the agentd workspace token with this gateway' });
    }
    const port = Number(process.env.AGENTGATE_MODEL_GATEWAY_PORT || 7434);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid AGENTGATE_MODEL_GATEWAY_PORT');
    const gateway = await startModelGateway({
      routes: config.routes, budget: config.budget, ...(config.maxConcurrent === undefined ? {} : { maxConcurrent: config.maxConcurrent }), ...(config.identity === undefined ? {} : { identity: config.identity }), clientToken: loadClientToken(tokenFile),
      host: process.env.AGENTGATE_MODEL_GATEWAY_HOST || '0.0.0.0', port,
      audit: (event) => (event.status >= 400 ? logger.warn('model.request', event) : logger.info('model.request', event))
    });
    logger.info('model_gateway.listening', { url: gateway.url, routes: config.routes.map((route) => route.prefix) });
    for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => gateway.close().then(() => process.exit(0)));
  } catch (error) {
    logger.error('model_gateway.startup_failed', { error: error.message });
    process.exit(1);
  }
}
