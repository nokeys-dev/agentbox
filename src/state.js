import { appendFileSync, chmodSync, closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, statSync, statfsSync, unlinkSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { GateError } from './errors.js';
import { auditFiles, chainRecord, readChainHead } from './audit-chain.js';

const heldLocks = new Set();

function defaultIsAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (error) { return error.code === 'EPERM'; }
}

function lockError(code, message) {
  return Object.assign(new Error(message), { code });
}

// Strips a `local:`/`oidc:` prefix (or any leading `scheme:`) and lowercases, so identities from
// different schemes but the same name compare equal for both self-approval and duplicate checks.
// For email-form identities the `+tag` of the local part is removed too, so
// `oidc:dev+x@example.com` is the same reviewer as `oidc:dev@example.com`.
function identityOf(value) {
  const raw = String(value ?? '');
  const identity = raw.slice(raw.indexOf(':') + 1).toLowerCase();
  const at = identity.lastIndexOf('@');
  return at < 0 ? identity : `${untagged(identity.slice(0, at))}${identity.slice(at)}`;
}

function untagged(localPart) {
  const plus = localPart.indexOf('+');
  return plus < 0 ? localPart : localPart.slice(0, plus);
}

// Fail closed on self-approval: besides an exact identity match, a `local:<name>` reviewer is the
// delegating human when <name> equals the local part (lowercased, `+tag` removed) of an
// email-form runtime.human, since host usernames rarely carry the email domain.
function isSelf(reviewer, human) {
  const identity = identityOf(reviewer);
  const humanIdentity = identityOf(human);
  if (identity === humanIdentity) return true;
  const at = humanIdentity.lastIndexOf('@');
  return reviewer.startsWith('local:') && at > 0 && untagged(identity) === humanIdentity.slice(0, at);
}

// 'control' reviews arrive as signed documents from the control plane (see central-approvals.js);
// the reviewer identity is the OIDC email the control plane's UI verified.
export const REVIEWER_SOURCES = ['local', 'oidc', 'control'];

function readLockOwner(lockPath) {
  const raw = readFileSync(lockPath, 'utf8').trim();
  try { return /^\d+$/.test(raw) ? { pid: Number(raw), hostname: hostname() } : JSON.parse(raw); } catch { return undefined; }
}

// Throws if the lock at lockPath is still valid (foreign host, or same-host and alive) or
// unreadable. Returns quietly if it looks stale (same host, dead pid) — the caller must not
// treat that as license to unlink without re-checking under the reclaim guard, since the
// owner can change between this call and the guarded re-check.
function assertNotHeld(lockPath, isAlive) {
  const owner = readLockOwner(lockPath);
  if (!owner || !Number.isSafeInteger(owner.pid)) throw lockError('LOCK_CORRUPT', `Unreadable lock ${lockPath}; inspect and remove it manually`);
  if (owner.hostname !== hostname() && process.env.AGENTGATE_FORCE_UNLOCK !== '1') {
    throw lockError('LOCK_FOREIGN', `Lock is held by ${owner.hostname} pid ${owner.pid}; set AGENTGATE_FORCE_UNLOCK=1 only after confirming it stopped`);
  }
  if (owner.hostname === hostname() && isAlive(owner.pid)) throw lockError('EEXIST', `Another broker (pid ${owner.pid}) holds ${lockPath}`);
}

// Reclaiming a stale lock is check-then-act (read owner, decide stale, unlink) and racy if two
// processes do it concurrently: both could see the same stale lock, both unlink, and both then
// believe they hold it. A guard file, created exclusively, serializes the check-then-act section
// across processes so only one of them ever unlinks the stale lock.
function reclaimStaleLock(lockPath, isAlive) {
  const guardPath = `${lockPath}.reclaim`;
  let guardFd;
  try {
    guardFd = openSync(guardPath, 'wx', 0o600);
  } catch (error) {
    if (error.code === 'EEXIST') throw lockError('EEXIST', `Another broker is reclaiming ${lockPath}; if none is running, remove ${guardPath}`);
    throw error;
  }
  closeSync(guardFd);
  try {
    assertNotHeld(lockPath, isAlive);
    unlinkSync(lockPath);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  } finally {
    try { unlinkSync(guardPath); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

function acquireLock(lockPath, isAlive) {
  if (heldLocks.has(lockPath)) throw lockError('EEXIST', 'State directory is already locked by this process');
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(lockPath, 'wx', 0o600);
      try { writeFileSync(fd, `${JSON.stringify({ pid: process.pid, hostname: hostname(), startedAt: Date.now() })}\n`); } finally { closeSync(fd); }
      heldLocks.add(lockPath);
      return;
    } catch (error) {
      if (error.code !== 'EEXIST' || attempt > 0) throw error;
    }
    try {
      assertNotHeld(lockPath, isAlive);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      continue; // the lock disappeared since the failed create; retry it
    }
    reclaimStaleLock(lockPath, isAlive);
  }
}

// A pending approval is superseded when it was requested under a policy other than the live one:
// its key embeds the old policyHash, so it could never be consumed anyway.
export function isSuperseded(item, policyHash) {
  return item?.status === 'pending' && typeof item.context?.policyHash === 'string' && item.context.policyHash !== policyHash;
}

export class State {
  constructor(directory, { now = Date.now, ttlMs = 15 * 60_000, maxPending = 50, retentionMs = 7 * 86_400_000,
    maxAuditBytes = 64 * 1024 * 1024, maxAuditFiles = 20, minFreeBytes = 256 * 1024 * 1024, statfs = statfsSync,
    isAlive = defaultIsAlive, onAudit } = {}) {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    chmodSync(directory, 0o700);
    this.directory = directory;
    this.now = now;
    this.ttlMs = ttlMs;
    this.onAudit = onAudit;
    Object.assign(this, { maxPending, retentionMs, maxAuditBytes, maxAuditFiles, minFreeBytes, statfs });
    this.auditPath = join(directory, 'audit.jsonl');
    this.path = join(directory, 'approvals.json');
    this.lockPath = join(directory, 'daemon.lock');
    acquireLock(this.lockPath, isAlive);
    try {
      this.items = existsSync(this.path) ? JSON.parse(readFileSync(this.path, 'utf8')) : [];
      if (!Array.isArray(this.items)) throw new Error('Invalid approval store');
      this.chainHead = readChainHead(directory);
    } catch (error) {
      this.close();
      throw error;
    }
  }

  close() {
    heldLocks.delete(this.lockPath);
    unlinkSync(this.lockPath);
  }

  ensureDisk() {
    const stats = this.statfs(this.directory);
    if (stats.bavail * stats.bsize < this.minFreeBytes) throw new GateError(503, 'DISK_LOW', 'Broker state volume is nearly full');
  }

  rotateAudit() {
    let size = 0;
    try { size = statSync(this.auditPath).size; } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (size < this.maxAuditBytes) return;
    renameSync(this.auditPath, join(this.directory, `audit-${this.now()}-${process.hrtime.bigint()}.jsonl`));
    const rotated = auditFiles(this.directory).filter((file) => !file.endsWith('/audit.jsonl'));
    for (const file of rotated.slice(0, Math.max(0, rotated.length - this.maxAuditFiles))) unlinkSync(file);
  }

  audit(event) {
    this.ensureDisk();
    this.rotateAudit();
    const record = chainRecord({ ...event, timestamp: new Date(this.now()).toISOString() }, this.chainHead);
    appendFileSync(this.auditPath, `${JSON.stringify(record)}\n`, { mode: 0o600, flush: true });
    this.chainHead = { seq: record.seq, hash: record.hash };
    try { this.onAudit?.(record); } catch { /* Metrics must never break auditing. */ }
  }

  save() {
    const cutoff = this.now() - this.retentionMs;
    this.items = this.items.filter((item) => !(item.expiresAt < cutoff || (['consumed', 'denied'].includes(item.status) && (item.consumedAt ?? item.expiresAt) < cutoff)));
    const temporary = `${this.path}.${randomUUID()}.tmp`;
    writeFileSync(temporary, `${JSON.stringify(this.items, null, 2)}\n`, { mode: 0o600, flush: true });
    renameSync(temporary, this.path);
    const directory = openSync(this.directory, 'r');
    try { fsyncSync(directory); } finally { closeSync(directory); }
  }

  list() {
    return this.items.map((item) => ({ ...item, status: item.expiresAt <= this.now() && ['pending', 'approved'].includes(item.status) ? 'expired' : item.status }));
  }

  request(key, context, { requiredApprovals = 1 } = {}) {
    const existing = this.items.find((item) => item.key === key && ['pending', 'approved'].includes(item.status) && item.expiresAt > this.now());
    // `created` is a non-enumerable marker so it never survives into JSON.stringify (approvals.json,
    // the admin GET /approvals response): only the caller inspecting the returned object in-process
    // (to decide whether to fire a notification) ever sees it.
    if (existing) return Object.defineProperty(existing, 'created', { value: false, configurable: true });
    const pending = this.items.filter((item) => item.status === 'pending' && item.expiresAt > this.now()).length;
    if (pending >= this.maxPending) throw new GateError(429, 'TOO_MANY_PENDING', 'Too many approvals are pending; review or wait for expiry');
    this.ensureDisk();
    const item = { id: randomUUID(), key, context, status: 'pending', createdAt: this.now(), expiresAt: this.now() + this.ttlMs, requiredApprovals, reviews: [] };
    this.items.push(item);
    try { this.save(); } catch (error) { this.items = this.items.filter((candidate) => candidate !== item); throw error; }
    return Object.defineProperty(item, 'created', { value: true, configurable: true });
  }

  // `source` is the verified reviewer source ('local' or 'oidc'). The admin API sets it only after
  // authenticating the caller (see server.js); in-process callers default to the reviewer prefix.
  // `policyHash`, when given, is the live policy: a pending approval created under a different
  // policy is superseded and can no longer be reviewed.
  review(prefix, approved, reviewer, { source, policyHash, controlVersion } = {}) {
    if (typeof reviewer !== 'string' || !/^(local|oidc|control):[A-Za-z0-9._@+-]{1,200}$/.test(reviewer)) {
      throw new GateError(400, 'REVIEWER_REQUIRED', 'A reviewer identity like oidc:name@example.com is required');
    }
    const reviewerSource = reviewer.slice(0, reviewer.indexOf(':'));
    if (source !== undefined && source !== reviewerSource) throw new GateError(403, 'REVIEWER_SOURCE_UNVERIFIED', 'Reviewer source does not match the reviewer identity');
    if (!/^[0-9a-f-]{8,36}$/.test(prefix)) throw new GateError(400, 'INVALID_ID', 'Use at least eight characters of the approval ID');
    const matches = this.items.filter((item) => item.id.startsWith(prefix));
    if (matches.length !== 1) throw new GateError(404, 'APPROVAL_NOT_FOUND', 'Approval ID is missing or ambiguous');
    const item = matches[0];
    if (item.status !== 'pending' || item.expiresAt <= this.now()) throw new GateError(409, 'APPROVAL_NOT_PENDING', 'Approval is no longer pending');
    if (policyHash !== undefined && isSuperseded(item, policyHash)) {
      throw new GateError(409, 'APPROVAL_SUPERSEDED', 'The policy changed since this approval was requested; retry the operation to create a new approval');
    }
    const allowedSources = item.context?.reviewerSources;
    if (allowedSources !== undefined && (!Array.isArray(allowedSources) || !allowedSources.includes(reviewerSource))) {
      throw new GateError(403, 'REVIEWER_SOURCE_NOT_ALLOWED', 'Policy does not accept reviews from this reviewer source');
    }
    if (isSelf(reviewer, item.context?.runtime?.human)) {
      throw new GateError(403, 'SELF_APPROVAL', 'The delegating human cannot review their own agent\'s request');
    }
    const identity = identityOf(reviewer);
    item.reviews ??= [];
    if (item.reviews.some((review) => identityOf(review.reviewer) === identity)) {
      throw new GateError(409, 'DUPLICATE_REVIEWER', 'This reviewer already reviewed the request');
    }
    const previous = { status: item.status, reviews: [...item.reviews] };
    item.reviews.push({ reviewer, source: reviewerSource, decision: approved ? 'approve' : 'deny', at: this.now() });
    const approvals = item.reviews.filter((review) => review.decision === 'approve').length;
    item.status = !approved ? 'denied' : approvals >= (item.requiredApprovals ?? 1) ? 'approved' : 'pending';
    try {
      this.audit({ type: 'approval.review', approvalId: item.id, decision: approved ? 'approve' : 'deny', reviewer, source: reviewerSource, approvals, requiredApprovals: item.requiredApprovals ?? 1, status: item.status, context: item.context,
        ...(controlVersion === undefined ? {} : { controlVersion }) });
      this.save();
    } catch (error) { Object.assign(item, previous); throw error; }
    return item;
  }

  // Read-only check for an unexpired approved grant; consume() still decides atomically.
  hasGrant(key) {
    return this.items.some((candidate) => candidate.key === key && candidate.status === 'approved' && candidate.expiresAt > this.now());
  }

  consume(key) {
    const item = this.items.find((candidate) => candidate.key === key && candidate.status === 'approved' && candidate.expiresAt > this.now());
    if (!item) return undefined;
    item.status = 'consumed';
    item.consumedAt = this.now();
    // Synchronous, durable consumption happens before any upstream request.
    // If persistence fails, the request fails closed and the in-memory grant stays spent.
    this.save();
    return item.id;
  }
}
