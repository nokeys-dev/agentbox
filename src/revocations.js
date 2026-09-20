import { readFileSync, statSync } from 'node:fs';

// How the broker represents revoked runtimes: assertion ids as they are, runtime ids tagged. Shared by
// the local file below and, in the commercial edition, the control plane's signed lists.
export const revocationSet = (payload) => new Set([...payload.jtis, ...payload.runtimeIds.map((id) => `sub:${id}`)]);

// Local revocation list for assertion mode without a control plane (AGENTGATE_REVOCATIONS_FILE).
// JSON { "jtis": [...], "runtimeIds": [...] }, owner-only. Any read or format error throws, so
// startup fails closed and a SIGHUP re-read keeps enforcing the previous list.
export function loadRevocationsFile(path) {
  if ((statSync(path).mode & 0o077) !== 0) throw new Error('AGENTGATE_REVOCATIONS_FILE must be owner-only (chmod 600)');
  let value;
  try { value = JSON.parse(readFileSync(path, 'utf8')); } catch { throw new Error('AGENTGATE_REVOCATIONS_FILE must be JSON { "jtis": [], "runtimeIds": [] }'); }
  const list = (items) => Array.isArray(items) && items.every((item) => typeof item === 'string' && item.length > 0 && item.length <= 256);
  if (!value || typeof value !== 'object' || Array.isArray(value) || !Object.keys(value).every((key) => key === 'jtis' || key === 'runtimeIds')
    || !list(value.jtis ?? []) || !list(value.runtimeIds ?? [])) {
    throw new Error('AGENTGATE_REVOCATIONS_FILE must be JSON { "jtis": [], "runtimeIds": [] } with non-empty string entries');
  }
  return revocationSet({ jtis: value.jtis ?? [], runtimeIds: value.runtimeIds ?? [] });
}
