import { createHash, randomBytes, sign, timingSafeEqual, verify } from 'node:crypto';
import { GateError } from './errors.js';

// Signed runtime assertions: a compact JWS (EdDSA over Ed25519) issued on the trusted host that
// created the workspace. It carries the runtime identity (who delegated, which agent, which task)
// and is bound to the workspace's client token by its SHA-256 (cnf.tokenSha256), so an assertion
// copied out of one workspace is useless without that workspace's bearer token.

export const ASSERTION_HEADER = 'x-agentgate-runtime';
export const ASSERTION_TYPE = 'agentgate-runtime+jwt';
export const MAX_ASSERTION_LENGTH = 8192;
const MODES = ['build', 'operate', 'readonly'];
const TASK_SYSTEMS = ['jira', 'servicenow', 'pagerduty'];
const CLOCK_SKEW_SECONDS = 60;

const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const invalid = (reason) => new GateError(401, 'ASSERTION_INVALID', `Runtime assertion rejected: ${reason}`);
const digest = (token) => createHash('sha256').update(token).digest('hex');
const printable = (value, max) => typeof value === 'string' && value.length <= max && /^[\x20-\x7e]+$/.test(value) && value.trim().length > 0;
const plainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
// Decodes a base64url segment and requires it to be the canonical encoding of its bytes, so
// one token has exactly one spelling (no spare-bit or padding variants of the same signature).
function canonical(segment) {
  const bytes = Buffer.from(segment, 'base64url');
  if (bytes.toString('base64url') !== segment) throw invalid('non-canonical encoding');
  return bytes;
}

// JSON.parse keeps the last of duplicate members and treats "exp" and "Exp" as unrelated, so a
// token could carry two spellings of a claim and be read differently by different verifiers.
// Reject any object with a repeated member or with two members that differ only by case.
const KNOWN_MEMBERS = ['alg', 'typ', 'kid', 'iss', 'aud', 'sub', 'human', 'agent', 'team', 'mode', 'task', 'application', 'ghlogin', 'iat', 'exp', 'nbf', 'jti', 'cnf', 'tokensha256', 'system', 'id'];
export function strictJson(text) {
  const value = JSON.parse(text);
  // Walk the text once to collect member names per object; JSON.parse already proved it is JSON.
  const stack = [];
  let i = 0;
  const readString = () => {
    let out = '';
    i++; // opening quote
    while (i < text.length) {
      const char = text[i];
      if (char === '"') { i++; return out; }
      if (char === '\\') {
        const next = text[i + 1];
        if (next === 'u') { out += String.fromCharCode(parseInt(text.slice(i + 2, i + 6), 16)); i += 6; continue; }
        out += { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }[next] ?? next;
        i += 2;
        continue;
      }
      out += char;
      i++;
    }
    throw invalid('malformed');
  };
  while (i < text.length) {
    const char = text[i];
    if (char === '{') { stack.push({ keys: new Set(), folded: new Set(), expectKey: true }); i++; continue; }
    if (char === '[') { stack.push(null); i++; continue; }
    if (char === '}' || char === ']') { stack.pop(); i++; continue; }
    if (char === '"') {
      const top = stack[stack.length - 1];
      const string = readString();
      if (top && top.expectKey) {
        const folded = string.toLowerCase();
        // Two spellings that fold to the same name are one duplicate, whatever their case.
        if (top.folded.has(folded)) throw invalid('duplicate member');
        // A lone member that is a known name in the wrong case is a smuggling attempt, not a claim.
        const spelled = folded === 'ghlogin' ? 'ghLogin' : folded === 'tokensha256' ? 'tokenSha256' : folded;
        if (KNOWN_MEMBERS.includes(folded) && string !== spelled) throw invalid('case-variant member');
        top.keys.add(string);
        top.folded.add(folded);
        top.expectKey = false;
      }
      continue;
    }
    if (char === ':') { i++; continue; }
    if (char === ',') { const top = stack[stack.length - 1]; if (top) top.expectKey = true; i++; continue; }
    i++;
  }
  return value;
}

// Binding takes either the workspace client token or its SHA-256 fingerprint (what the assertion
// actually carries), so an issuer on another host never needs to hold the token itself.
export function issueAssertion(claims, { privateKey, kid, now = Date.now, ttlSeconds = 8 * 3600, clientToken, clientTokenSha256 }) {
  if (clientToken !== undefined && clientTokenSha256 !== undefined) throw new Error('issueAssertion takes clientToken or clientTokenSha256, not both');
  let tokenSha256;
  if (clientTokenSha256 !== undefined) {
    if (typeof clientTokenSha256 !== 'string' || !/^[0-9a-fA-F]{64}$/.test(clientTokenSha256)) throw new Error('clientTokenSha256 must be 64 hex characters');
    tokenSha256 = clientTokenSha256.toLowerCase();
  } else {
    if (typeof clientToken !== 'string' || !clientToken) throw new Error('issueAssertion requires the workspace client token (or its SHA-256) to bind to');
    tokenSha256 = digest(clientToken);
  }
  const iat = Math.floor(now() / 1000);
  const body = { ...claims, iat, exp: iat + ttlSeconds, jti: randomBytes(16).toString('hex'), cnf: { tokenSha256 } };
  const unsigned = `${b64({ alg: 'EdDSA', typ: ASSERTION_TYPE, kid })}.${b64(body)}`;
  return `${unsigned}.${sign(null, Buffer.from(unsigned), privateKey).toString('base64url')}`;
}

// Everything except revocation, which callers must check on every use (see isRevoked).
function checkToken(token, { keys, audience, clientToken, now, maxTtlSeconds, skipBinding = false }) {
  if (typeof token !== 'string' || !token || token.length > MAX_ASSERTION_LENGTH) throw invalid('missing');
  const parts = token.split('.');
  if (parts.length !== 3 || !parts.every((part) => /^[A-Za-z0-9_-]*$/.test(part))) throw invalid('malformed');
  const [headerBytes, claimBytes, signature] = parts.map(canonical);
  let header;
  let claims;
  try {
    header = strictJson(headerBytes.toString('utf8'));
    claims = strictJson(claimBytes.toString('utf8'));
  } catch (error) {
    throw error instanceof GateError && /member/.test(error.message) ? error : invalid('malformed');
  }
  if (!plainObject(header) || !plainObject(claims)) throw invalid('malformed');
  if (Object.keys(header).some((key) => !['alg', 'typ', 'kid'].includes(key))) throw invalid('unsupported header field');
  if (header.alg !== 'EdDSA' || header.typ !== ASSERTION_TYPE) throw invalid('unsupported algorithm or type');
  if (typeof header.kid !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(header.kid) || !Object.hasOwn(keys, header.kid)) throw invalid('unknown key');
  if (signature.length !== 64 || !verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), keys[header.kid], signature)) throw invalid('signature');
  const seconds = Math.floor(now() / 1000);
  if (claims.aud !== audience) throw invalid('audience');
  if (!Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) || claims.iat > seconds + CLOCK_SKEW_SECONDS || claims.exp <= seconds ||
    claims.exp <= claims.iat || claims.exp - claims.iat > maxTtlSeconds) throw invalid('lifetime');
  if (claims.nbf !== undefined && (!Number.isSafeInteger(claims.nbf) || claims.nbf > seconds + CLOCK_SKEW_SECONDS)) throw invalid('not yet valid');
  // skipBinding is for services that attribute rather than authorize (the model gateway): they
  // never see the workspace token, so they verify signature, audience, lifetime, and claims only.
  if (!skipBinding && (typeof clientToken !== 'string' || !clientToken || claims.cnf?.tokenSha256 !== digest(clientToken))) throw invalid('client token binding');
  if (skipBinding && !(typeof claims.cnf?.tokenSha256 === 'string' && /^[0-9a-f]{64}$/.test(claims.cnf.tokenSha256))) throw invalid('client token binding');
  if (typeof claims.jti !== 'string' || !/^[0-9a-f]{32}$/.test(claims.jti)) throw invalid('claim jti');
  if (typeof claims.sub !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(claims.sub)) throw invalid('claim sub');
  if (!printable(claims.iss, 256)) throw invalid('claim iss');
  if (!printable(claims.human, 256)) throw invalid('claim human');
  for (const field of ['agent', 'team']) if (!printable(claims[field], 128)) throw invalid(`claim ${field}`);
  if (claims.application !== undefined && !printable(claims.application, 128)) throw invalid('claim application');
  if (!MODES.includes(claims.mode)) throw invalid('claim mode');
  if (claims.task !== undefined && !(plainObject(claims.task) && TASK_SYSTEMS.includes(claims.task.system) &&
    typeof claims.task.id === 'string' && /^[A-Za-z0-9._:-]{1,64}$/.test(claims.task.id))) throw invalid('claim task');
  if (claims.ghLogin !== undefined && !(typeof claims.ghLogin === 'string' && /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(claims.ghLogin))) throw invalid('claim ghLogin');
  return claims;
}

function isRevoked(claims, revoked) {
  return revoked.has(claims.jti) || revoked.has(`sub:${claims.sub}`);
}

export function verifyAssertion(token, { keys, audience, clientToken, now = Date.now, maxTtlSeconds = 86400, revoked = new Set() }) {
  const claims = checkToken(token, { keys, audience, clientToken, now, maxTtlSeconds });
  if (isRevoked(claims, revoked)) throw invalid('revoked');
  return claims;
}

// Caches successful verifications by token hash until the assertion's exp, so a busy workspace
// does not pay an Ed25519 verify per request. Bound to one key set/audience/client token: build
// a new verifier when any of those change (the broker keys one per validated config). Expiry and
// revocation are re-checked on every call, cached or not.
// With `clientToken` omitted (fleet mode: one broker, many workspaces) every verify call must pass
// the bearer token the request presented; the assertion's own cnf binding then decides which
// workspace it belongs to, so the broker never needs to know any workspace token in advance.
export function createAssertionVerifier({ keys, audience, clientToken, now = Date.now, maxTtlSeconds = 86400, maxEntries = 1024, skipBinding = false }) {
  const cache = new Map();
  const stats = { signatureChecks: 0, get size() { return cache.size; } };
  if (skipBinding && clientToken !== undefined) throw new Error('skipBinding takes no client token');
  const perCall = clientToken === undefined && !skipBinding;
  return {
    stats,
    verify(token, revoked = new Set(), presented) {
      if (!perCall && presented !== undefined) throw new Error('This verifier is bound to a fixed client token; per-call tokens are not accepted');
      const binding = perCall ? presented : clientToken;
      if (perCall && (typeof binding !== 'string' || !binding)) throw invalid('client token binding');
      const key = typeof token === 'string' && token.length <= MAX_ASSERTION_LENGTH ? digest(token) : undefined;
      let claims = key && cache.get(key);
      if (claims && claims.exp <= Math.floor(now() / 1000)) {
        cache.delete(key);
        claims = undefined;
      }
      // A cache hit proves the signature, not that this request holds the bound token.
      if (claims && perCall && !timingSafeEqual(Buffer.from(claims.cnf.tokenSha256, 'hex'), Buffer.from(digest(binding), 'hex'))) throw invalid('client token binding');
      if (!claims) {
        stats.signatureChecks++;
        claims = checkToken(token, { keys, audience, clientToken: binding, now, maxTtlSeconds, skipBinding });
        if (cache.size >= maxEntries) {
          const seconds = Math.floor(now() / 1000);
          for (const [entry, value] of cache) if (value.exp <= seconds) cache.delete(entry);
          while (cache.size >= maxEntries) cache.delete(cache.keys().next().value);
        }
        cache.set(key, Object.freeze(structuredClone(claims)));
      }
      if (isRevoked(claims, revoked)) throw invalid('revoked');
      return claims;
    }
  };
}
