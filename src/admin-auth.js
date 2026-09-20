import { createHmac, timingSafeEqual } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';

// Authenticates approval-web to agentd's admin socket. Both the host CLI and approval-web reach
// the same Unix socket, so without this the socket cannot tell a CLI-submitted `oidc:` reviewer
// (an arbitrary claimed identity) from one approval-web derived from an oauth2-proxy-verified
// email. Only a holder of this shared secret can submit `oidc:` reviewers.
export const TIMESTAMP_HEADER = 'x-agentgate-admin-timestamp';
export const SIGNATURE_HEADER = 'x-agentgate-admin-signature';
export const MAX_CLOCK_SKEW_MS = 60_000;

export function readAdminSecret(path, label = 'AGENTGATE_APPROVAL_WEB_ADMIN_SECRET_FILE') {
  if (!path) throw new Error(`Set ${label}`);
  if ((statSync(path).mode & 0o077) !== 0) throw new Error(`${label} must be owner-only (chmod 600)`);
  const secret = readFileSync(path, 'utf8');
  if (/\s/.test(secret)) throw new Error(`${label} must not contain whitespace or a trailing newline (create it with: openssl rand -hex 32 | tr -d '\\n' > file)`);
  if (secret.length < 32) throw new Error(`${label} must hold at least 32 characters`);
  return secret;
}

export function signAdminRequest(secret, { method, path, body, timestamp }) {
  return createHmac('sha256', secret).update(`${method}\n${path}\n${body}\n${timestamp}`).digest('hex');
}

// Returns true only for a well-formed, fresh (within ±60 s), constant-time-verified signature.
export function verifyAdminRequest(secret, { method, path, body, timestamp, signature }, now = Date.now()) {
  if (typeof secret !== 'string' || secret.length < 32) return false;
  if (typeof timestamp !== 'string' || !/^[0-9]{1,16}$/.test(timestamp)) return false;
  if (typeof signature !== 'string' || !/^[0-9a-f]{64}$/.test(signature)) return false;
  if (Math.abs(now - Number(timestamp)) > MAX_CLOCK_SKEW_MS) return false;
  const expected = Buffer.from(signAdminRequest(secret, { method, path, body, timestamp }), 'hex');
  return timingSafeEqual(expected, Buffer.from(signature, 'hex'));
}
