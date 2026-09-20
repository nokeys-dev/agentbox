import { createServer } from 'node:http';
import { createAssertionVerifier } from './assertion.js';
import { createPublicKey } from 'node:crypto';
import { BlockList, connect as netConnect, isIP } from 'node:net';
import { lookup } from 'node:dns/promises';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

// GitHub is reachable only through the broker. Not overridable by the allowlist.
const GITHUB = ['github.com', '*.github.com', 'githubusercontent.com', '*.githubusercontent.com', 'githubassets.com', '*.githubassets.com',
  'github.io', '*.github.io', 'ghcr.io', '*.ghcr.io'];

const blockedV4 = new BlockList();
for (const [network, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24],
  ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4]
]) blockedV4.addSubnet(network, prefix, 'ipv4');
const blockedV6 = new BlockList();
for (const [network, prefix] of [
  // ::ffff:0:0/96 (IPv4-mapped) is refused outright: a legitimate public name never resolves to one.
  ['::', 96], ['::ffff:0:0', 96], ['100::', 64], ['2001::', 23], ['2001:db8::', 32], ['64:ff9b:1::', 48], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8], ['3fff::', 20]
]) blockedV6.addSubnet(network, prefix, 'ipv6');

function parseIPv4(text) {
  const parts = text.split('.');
  if (parts.length !== 4 || !parts.every((part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)) return null;
  return parts.map(Number);
}

function parseIPv6(text) {
  if (!/^[0-9a-f:.]+$/i.test(text)) return null;
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const groups = (half) => {
    if (half === '') return [];
    const bytes = [];
    const parts = half.split(':');
    for (const [index, part] of parts.entries()) {
      if (part.includes('.')) {
        const v4 = index === parts.length - 1 ? parseIPv4(part) : null;
        if (!v4) return null;
        bytes.push(...v4);
      } else if (/^[0-9a-f]{1,4}$/i.test(part)) {
        const value = parseInt(part, 16);
        bytes.push(value >> 8, value & 0xff);
      } else return null;
    }
    return bytes;
  };
  const head = groups(halves[0]);
  const tail = halves.length === 2 ? groups(halves[1]) : [];
  if (!head || !tail) return null;
  if (halves.length === 1) return head.length === 16 ? head : null;
  if (head.length + tail.length > 14) return null;
  return [...head, ...new Array(16 - head.length - tail.length).fill(0), ...tail];
}

const v4At = (bytes, offset) => bytes.slice(offset, offset + 4).join('.');

// Fails closed: anything that is not a well-formed IP address counts as blocked.
export function isBlockedAddress(address) {
  if (typeof address !== 'string') return true;
  if (isIP(address) === 4) return !parseIPv4(address) || blockedV4.check(address, 'ipv4');
  if (isIP(address) !== 6) return true;
  const bytes = parseIPv6(address);
  if (!bytes) return true;
  const zero = (from, to) => bytes.slice(from, to).every((byte) => byte === 0);
  // IPv4-mapped (::ffff:0:0/96) is always blocked; the NAT64 well-known prefix (64:ff9b::/96)
  // embeds an IPv4 address that is checked against the IPv4 list.
  if (zero(0, 10) && bytes[10] === 0xff && bytes[11] === 0xff) return true;
  if (bytes[0] === 0 && bytes[1] === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b && zero(4, 12)) return blockedV4.check(v4At(bytes, 12), 'ipv4');
  // 6to4 (2002::/16) embeds an IPv4 address in bytes 2-5.
  if (bytes[0] === 0x20 && bytes[1] === 0x02 && blockedV4.check(v4At(bytes, 2), 'ipv4')) return true;
  const canonical = Array.from({ length: 8 }, (_, index) => ((bytes[index * 2] << 8) | bytes[index * 2 + 1]).toString(16)).join(':');
  return blockedV6.check(canonical, 'ipv6');
}

// Lowercases and strips a single trailing dot. Returns null for anything that is not a plain DNS name.
export function normalizeHost(value) {
  if (typeof value !== 'string') return null;
  let host = value.toLowerCase();
  if (host.endsWith('.')) host = host.slice(0, -1);
  if (!host || host.length > 253) return null;
  const labels = host.split('.');
  return labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ? host : null;
}

const looksNumeric = (host) => isIP(host) !== 0 || /^(0x[0-9a-f]*|\d+)$/.test(host.split('.').at(-1));
const hostMatches = (pattern, host) => pattern.startsWith('*.') ? host.endsWith(pattern.slice(1)) : pattern === host;

function parseHostPattern(pattern, context) {
  const wildcard = typeof pattern === 'string' && pattern.startsWith('*.');
  const host = normalizeHost(wildcard ? pattern.slice(2) : pattern);
  if (!host || looksNumeric(host) || (wildcard && host.split('.').length < 2)) throw new Error(`Invalid egress ${context} entry: ${JSON.stringify(pattern)}`);
  return wildcard ? `*.${host}` : host;
}

function parseAllow(entry) {
  const index = typeof entry === 'string' ? entry.lastIndexOf(':') : -1;
  const portText = index > 0 ? entry.slice(index + 1) : '';
  const port = Number(portText);
  if (!/^\d{1,5}$/.test(portText) || port < 1 || port > 65535) throw new Error(`Invalid egress allow entry: ${JSON.stringify(entry)}`);
  return { host: parseHostPattern(entry.slice(0, index), 'allow'), port };
}

const STATUS = { 400: 'Bad Request', 403: 'Forbidden', 407: 'Proxy Authentication Required', 429: 'Too Many Requests', 502: 'Bad Gateway' };

function withTimeout(promise, ms) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), ms); })]).finally(() => clearTimeout(timer));
}

// Optional runtime attribution: a workspace whose proxy URL carries `runtime:<assertion>` as
// credentials (HTTPS_PROXY=http://runtime:<assertion>@egress-proxy:3128, exported by the workspace
// profile) sends `Proxy-Authorization: Basic ...` on every CONNECT. The assertion is verified against
// the issuer keys (signature, audience, lifetime, claims; not the token binding, which the proxy
// cannot see), the tunnel is attributed to that runtime, and byte quotas are kept per runtime
// instead of per address. A present but invalid credential is refused (407); a missing one is
// refused only with `required: true`.
export function validateEgressIdentity(identity) {
  if (identity === undefined) return undefined;
  if (!identity || typeof identity !== 'object' || Array.isArray(identity)) throw new Error('Invalid egress identity: expected an object');
  for (const key of Object.keys(identity)) if (!['audience', 'issuers', 'required'].includes(key)) throw new Error(`Invalid egress identity.${key}`);
  if (typeof identity.audience !== 'string' || !/^[\x21-\x7e]{1,256}$/.test(identity.audience)) throw new Error('egress identity.audience must be a nonempty printable string');
  if (!Array.isArray(identity.issuers) || !identity.issuers.length || identity.issuers.length > 10) throw new Error('egress identity.issuers must list 1-10 issuers');
  if (identity.required !== undefined && typeof identity.required !== 'boolean') throw new Error('egress identity.required must be a boolean');
  const keys = {};
  for (const issuer of identity.issuers) {
    if (!issuer || typeof issuer.kid !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(issuer.kid) || keys[issuer.kid]) throw new Error('egress identity.issuers kid values must be unique');
    let key;
    try { if (!/PRIVATE KEY/.test(issuer.publicKeyPem)) key = createPublicKey(issuer.publicKeyPem); } catch { /* reported below */ }
    if (key?.asymmetricKeyType !== 'ed25519') throw new Error(`egress identity issuer ${issuer.kid} publicKeyPem must be an ed25519 public key`);
    keys[issuer.kid] = key;
  }
  return { audience: identity.audience, keys, required: identity.required === true };
}

function proxyCredential(header) {
  if (typeof header !== 'string' || !/^Basic [A-Za-z0-9+/=]+$/.test(header)) return undefined;
  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const separator = decoded.indexOf(':');
  if (separator < 0 || decoded.slice(0, separator) !== 'runtime') return undefined;
  return decoded.slice(separator + 1);
}

// Where outbound traffic must leave through a company forward proxy, allowed tunnels are chained
// through it with CONNECT instead of dialled directly. Every decision above (allow list, deny list,
// GitHub, IP literals, quotas) is made here first; the corporate proxy only carries what passed.
export function parseUpstreamProxy(value) {
  if (value === undefined || value === null || value === '') return undefined;
  let url;
  try { url = new URL(value); } catch { throw new Error('Invalid egress upstream proxy: expected a URL such as http://proxy.example.com:8080'); }
  if (url.protocol !== 'http:') throw new Error('Invalid egress upstream proxy: only http:// proxies are supported (the tunnel inside it stays TLS end to end)');
  if ((url.pathname !== '/' && url.pathname !== '') || url.search || url.hash) throw new Error('Invalid egress upstream proxy: expected only a host and port');
  const authorization = url.username ? `Basic ${Buffer.from(`${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`).toString('base64')}` : undefined;
  return { host: url.hostname.replace(/^\[|\]$/g, ''), port: Number(url.port || 80), authorization };
}

// Asks the corporate proxy for a tunnel on an already connected socket. Resolves to the bytes that
// followed its response head (normally none) or null when it refused or answered with nonsense.
function requestUpstreamTunnel(socket, corporate, hostname, targetPort, deadline) {
  return new Promise((settle) => {
    let buffered = Buffer.alloc(0);
    const done = (result) => { clearTimeout(timer); socket.off('data', onData); socket.off('close', onClose); socket.off('error', onClose); settle(result); };
    const onClose = () => done(null);
    const onData = (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);
      const end = buffered.indexOf('\r\n\r\n');
      if (end < 0) return buffered.length > 8192 ? done(null) : undefined;
      socket.pause();
      done(/^HTTP\/1\.[01] 2\d\d(?: |\r)/.test(buffered.subarray(0, end + 2).toString('latin1')) ? buffered.subarray(end + 4) : null);
    };
    const timer = setTimeout(onClose, Math.max(0, deadline - Date.now()));
    socket.on('data', onData);
    socket.once('close', onClose);
    socket.once('error', onClose);
    const authority = `${hostname.includes(':') ? `[${hostname}]` : hostname}:${targetPort}`;
    socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n${corporate.authorization ? `Proxy-Authorization: ${corporate.authorization}\r\n` : ''}\r\n`);
  });
}

export async function startEgressProxy({ allow, deny = [], host = '0.0.0.0', port = 3128, audit = () => {}, maxBytesPerHost = 2 * 1024 ** 3, identity, now = Date.now,
  idleTimeoutMs = 5 * 60_000, maxUsageKeys = 16_384, maxTunnelsPerClient = 32, headerTimeoutMs = 10_000, connectTimeoutMs = 10_000, resolveTimeoutMs = 10_000,
  resolve = async (hostname) => (await lookup(hostname, { all: true, verbatim: true })).map((entry) => entry.address),
  connect = (targetPort, address) => netConnect({ port: targetPort, host: address }), upstreamProxy }) {
  if (!Array.isArray(allow)) throw new Error('Invalid egress allow list: expected an array');
  if (!Array.isArray(deny)) throw new Error('Invalid egress deny list: expected an array');
  if (!Number.isSafeInteger(maxBytesPerHost) || maxBytesPerHost < 1) throw new Error('Invalid egress maxBytesPerHost: expected a positive integer');
  const corporate = parseUpstreamProxy(upstreamProxy);
  const runtimeIdentity = validateEgressIdentity(identity);
  const verifier = runtimeIdentity ? createAssertionVerifier({ keys: runtimeIdentity.keys, audience: runtimeIdentity.audience, skipBinding: true, now }) : undefined;
  const rules = allow.map(parseAllow);
  const denied = [...GITHUB, ...deny.map((pattern) => parseHostPattern(pattern, 'deny'))];
  // Byte usage per client per matched allow rule (not per hostname), so a wildcard rule cannot be
  // multiplied by visiting many subdomains. Bounded LRU: the least recently used entry is evicted
  // beyond maxUsageKeys (an evicted entry restarts at zero; the cap bounds memory).
  const usage = new Map();
  const touchUsage = (key, value) => {
    usage.delete(key);
    usage.set(key, value);
    while (usage.size > maxUsageKeys) usage.delete(usage.keys().next().value);
  };
  const active = new Map();
  const tunnels = new Set();
  const emit = (event) => { try { audit({ type: 'egress', ...event }); } catch { /* Auditing must never break the proxy. */ } };

  const server = createServer({ maxHeaderSize: 8192, headersTimeout: headerTimeoutMs, requestTimeout: headerTimeoutMs,
    connectionsCheckingInterval: Math.min(1000, headerTimeoutMs) }, (_request, response) => {
    response.writeHead(405, { connection: 'close', 'content-type': 'text/plain' });
    response.end('CONNECT only\n');
  });

  server.on('connect', async (request, client, head) => {
    client.on('error', () => {});
    tunnels.add(client);
    client.once('close', () => tunnels.delete(client));
    const clientKey = client.remoteAddress ?? 'unknown';
    let runtime;
    let credentialError;
    if (verifier) {
      const header = request.headers['proxy-authorization'];
      if (header !== undefined) {
        const assertion = proxyCredential(header);
        try {
          const claims = verifier.verify(assertion ?? '');
          runtime = { runtimeId: claims.sub, human: claims.human, agent: claims.agent, team: claims.team, jti: claims.jti };
        } catch { credentialError = 'assertion-invalid'; }
      } else if (runtimeIdentity.required) credentialError = 'assertion-required';
    }
    const target = typeof request.url === 'string' && request.url.length <= 261
      ? /^(\[[^\]]*\]|[^:[\]]+):(\d{1,5})$/.exec(request.url) : null;
    const rawHost = target?.[1];
    const targetPort = target ? Number(target[2]) : 0;
    let hostname = normalizeHost(rawHost) ?? 'invalid';
    const reject = (status, reason) => {
      // No runtime assertion reaches this proxy (it only sees a raw CONNECT tunnel), so the
      // client's source address is the best available identity for SIEM correlation. See
      // docs/detections.md "Known gaps" for what this does and does not attribute.
      emit({ host: hostname, port: targetPort, decision: 'deny', reason, bytesUp: 0, bytesDown: 0, client: clientKey, ...(runtime ? { runtime } : {}) });
      client.end(`HTTP/1.1 ${status} ${STATUS[status]}\r\n${status === 407 ? 'proxy-authenticate: Basic realm="agentbox-runtime"\r\n' : ''}connection: close\r\ncontent-length: 0\r\n\r\n`);
    };
    if (credentialError) return reject(407, credentialError);
    if (!target || targetPort < 1 || targetPort > 65535) return reject(400, 'invalid-target');
    if (rawHost.startsWith('[') || isIP(rawHost)) { hostname = rawHost.replace(/^\[|\]$/g, '').toLowerCase(); return reject(403, 'ip-literal'); }
    if (hostname === 'invalid') return reject(400, 'invalid-target');
    if (looksNumeric(hostname)) return reject(403, 'ip-literal');
    if (GITHUB.some((pattern) => hostMatches(pattern, hostname))) return reject(403, 'github-via-broker');
    if (denied.some((pattern) => hostMatches(pattern, hostname))) return reject(403, 'denied');
    if (hostname.split('.').some((label) => label.startsWith('xn--')) && !rules.some((rule) => rule.host === hostname)) return reject(403, 'idn-not-allowlisted');
    const rule = rules.find((candidate) => candidate.port === targetPort && hostMatches(candidate.host, hostname));
    if (!rule) return reject(403, 'not-allowlisted');
    // Quota per runtime when the tunnel is attributed, otherwise per client address.
    const usageKey = `${runtime ? `runtime:${runtime.jti}` : clientKey}\0${rule.host}:${rule.port}`;
    if ((usage.get(usageKey) ?? 0) >= maxBytesPerHost) return reject(403, 'quota-exceeded');
    if ((active.get(clientKey) ?? 0) >= maxTunnelsPerClient) return reject(429, 'too-many-tunnels');

    active.set(clientKey, (active.get(clientKey) ?? 0) + 1);
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      const remaining = active.get(clientKey) - 1;
      if (remaining > 0) active.set(clientKey, remaining); else active.delete(clientKey);
    };
    client.once('close', release);

    let addresses;
    try {
      addresses = await withTimeout(Promise.resolve().then(() => resolve(hostname)), resolveTimeoutMs);
    } catch {
      // Behind a corporate proxy the local resolver often cannot see public names at all; the
      // proxy resolves them. Without one, a name that does not resolve cannot be dialled.
      if (!corporate) { release(); return reject(502, 'resolution-failed'); }
      addresses = [];
    }
    if (!Array.isArray(addresses) || addresses.some((address) => isIP(address) === 0) || (!corporate && addresses.length === 0)) { release(); return reject(502, 'resolution-failed'); }
    // Still enforced through a corporate proxy whenever the name resolves here.
    if (addresses.some(isBlockedAddress)) { release(); return reject(403, 'private-address'); }
    let dialPort = targetPort;
    if (corporate) {
      dialPort = corporate.port;
      try {
        addresses = isIP(corporate.host) ? [corporate.host] : await withTimeout(Promise.resolve().then(() => resolve(corporate.host)), resolveTimeoutMs);
      } catch { addresses = []; }
      if (!Array.isArray(addresses) || addresses.length === 0) { release(); return reject(502, 'upstream-proxy-unreachable'); }
    }
    if (client.destroyed) { release(); return; }

    let upstream = null;
    // One deadline for the whole connect phase, across every resolved address.
    const connectDeadline = Date.now() + connectTimeoutMs;
    for (const address of addresses) {
      if (Date.now() >= connectDeadline) break;
      upstream = await new Promise((settle) => {
        let socket;
        try { socket = connect(dialPort, address); } catch { return settle(null); }
        if (!socket) return settle(null);
        tunnels.add(socket);
        const fail = () => { cleanup(); tunnels.delete(socket); socket.destroy(); settle(null); };
        const ok = () => { cleanup(); settle(socket); };
        const timer = setTimeout(fail, Math.max(0, connectDeadline - Date.now()));
        const cleanup = () => { clearTimeout(timer); socket.off('connect', ok); socket.off('error', fail); socket.off('close', fail); };
        socket.on('error', () => {});
        if (!socket.connecting && !socket.destroyed && socket.remoteAddress) return ok();
        socket.once('connect', ok);
        socket.once('error', fail);
        socket.once('close', fail);
      });
      if (upstream || client.destroyed) break;
    }
    if (!upstream) { release(); return reject(502, corporate ? 'upstream-proxy-unreachable' : 'upstream-unreachable'); }
    let early = Buffer.alloc(0);
    if (corporate) {
      early = await requestUpstreamTunnel(upstream, corporate, hostname, targetPort, connectDeadline);
      if (!early) { tunnels.delete(upstream); upstream.destroy(); release(); return reject(502, 'upstream-proxy-refused'); }
    }
    if (client.destroyed) { upstream.destroy(); tunnels.delete(upstream); release(); return; }

    let bytesUp = 0;
    let bytesDown = 0;
    let closeReason;
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      release();
      tunnels.delete(upstream);
      client.destroy();
      upstream.destroy();
      emit({ host: hostname, port: targetPort, decision: 'allow', ...(closeReason ? { reason: closeReason } : {}), bytesUp, bytesDown, client: clientKey, ...(runtime ? { runtime } : {}) });
    };
    const close = (reason) => { closeReason ??= reason; finish(); };
    const forward = (from, to, direction) => {
      const push = (chunk) => {
        if (finished) return;
        const used = usage.get(usageKey) ?? 0;
        if (used + chunk.length > maxBytesPerHost) return close('quota-exceeded');
        touchUsage(usageKey, used + chunk.length);
        if (direction === 'up') bytesUp += chunk.length; else bytesDown += chunk.length;
        if (!to.write(chunk)) from.pause();
      };
      from.on('data', push);
      to.on('drain', () => from.resume());
      from.once('end', () => { if (!finished) to.end(); });
      return push;
    };
    upstream.once('close', finish);
    client.once('close', finish);
    upstream.on('error', () => close('upstream-error'));
    client.on('error', finish);
    client.setTimeout(idleTimeoutMs, () => close('idle-timeout'));
    client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    const pushUp = forward(client, upstream, 'up');
    const pushDown = forward(upstream, client, 'down');
    if (early.length) pushDown(early);
    upstream.resume();
    if (head?.length) pushUp(head);
    client.resume();
  });

  await new Promise((resolveListen, rejectListen) => { server.once('error', rejectListen); server.listen(port, host, resolveListen); });
  const address = server.address();
  const urlHost = address.address === '0.0.0.0' || address.address === '::' ? '127.0.0.1' : address.family === 'IPv6' ? `[${address.address}]` : address.address;
  return {
    url: `http://${urlHost}:${address.port}`,
    close: () => new Promise((resolveClose) => {
      for (const socket of tunnels) socket.destroy();
      server.closeAllConnections();
      server.close(() => resolveClose());
    })
  };
}

export function loadEgressConfig(path) {
  const config = JSON.parse(readFileSync(path, 'utf8'));
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('Invalid egress config: expected an object');
  for (const key of Object.keys(config)) {
    if (!['allow', 'deny', 'maxBytesPerHost', 'identity'].includes(key)) throw new Error(`Invalid egress config: unknown key ${JSON.stringify(key)}`);
  }
  return config;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { createLogger } = await import('./log.js');
  const logger = createLogger({ base: { service: 'agentgate-egress' }, errorStream: process.stderr });
  try {
    const config = loadEgressConfig(process.env.AGENTGATE_EGRESS_CONFIG || '/etc/agentgate/egress.json');
    const port = Number(process.env.AGENTGATE_EGRESS_PORT || 3128);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid AGENTGATE_EGRESS_PORT');
    const proxy = await startEgressProxy({
      allow: config.allow, deny: config.deny ?? [], host: process.env.AGENTGATE_EGRESS_HOST || '0.0.0.0', port,
      ...(config.maxBytesPerHost === undefined ? {} : { maxBytesPerHost: config.maxBytesPerHost }), ...(config.identity === undefined ? {} : { identity: config.identity }),
      upstreamProxy: process.env.AGENTGATE_EGRESS_UPSTREAM_PROXY,
      audit: (event) => (event.decision === 'deny' ? logger.warn('egress', event) : logger.info('egress', event))
    });
    logger.info('egress.listening', { url: proxy.url, rules: config.allow.length, ...(process.env.AGENTGATE_EGRESS_UPSTREAM_PROXY ? { upstreamProxy: new URL(process.env.AGENTGATE_EGRESS_UPSTREAM_PROXY).host } : {}) });
    for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => proxy.close().then(() => process.exit(0)));
  } catch (error) {
    logger.error('egress.startup_failed', { error: error.message });
    process.exit(1);
  }
}
