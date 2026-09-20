// SIEM-style detections over AgentBox's forwarded audit stream.
//
// `detect(records, options)` is a pure function over an array of already-parsed audit/log
// records; it never throws on a malformed or unexpected record, it only skips what it cannot
// use. See docs/detections.md for what each detection means, its exact fields and thresholds,
// an equivalent SIEM query sketch, and known gaps in what the underlying services can attribute.
//
// The real record shapes (verified against src/, not assumed) are documented alongside the
// detections that consume them; the shapes below reflect that research.

import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const MIB = 1024 * 1024;

function isRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

// state.audit() (src/state.js) stamps every chained record with an ISO timestamp; the standalone
// egress-proxy and model-gateway loggers (src/log.js) do the same for the merged stream. A
// missing or unparsable timestamp makes a record impossible to place in a window, so it is
// dropped rather than guessed at.
function timeOf(record) {
  const value = Date.parse(record.timestamp);
  return Number.isFinite(value) ? value : undefined;
}

// Every chained audit record carries an integer seq (src/audit-chain.js chainRecord); it is the
// only handle an analyst has back to the original record, so a record without one cannot serve
// as evidence.
function seqOf(record) {
  return Number.isSafeInteger(record.seq) ? record.seq : undefined;
}

// Best available identity for a record, verified against real emission sites:
//  - Decision/error audit records (src/server.js, src/github-api.js) carry `runtime.runtimeId`,
//    the verified assertion subject (or the static config.runtime for single-runtime brokers).
//  - approval.review records (src/state.js `request()`/review path) do not carry a top-level
//    `runtime`; the runtime lives in the persisted approval `context.runtime` instead.
//  - The egress proxy and model gateway (src/egress-proxy.js, src/model-gateway.js) run as
//    separate, unauthenticated-adjacent services that never see the runtime assertion. They are
//    patched (this task) to log the client socket address as `client`, which is the best
//    available correlation key there — see docs/detections.md "Known gaps".
//  - Broker-wide `type: 'rejections'` summaries (src/server.js recordRejection) carry no identity
//    at all by design (they exist precisely so an unauthenticated caller cannot force a
//    per-request, per-identity audit write); such records always fall back to 'unknown'.
function identityOf(record) {
  if (typeof record.runtime?.runtimeId === 'string' && record.runtime.runtimeId) return record.runtime.runtimeId;
  if (typeof record.context?.runtime?.runtimeId === 'string' && record.context.runtime.runtimeId) return record.context.runtime.runtimeId;
  if (typeof record.client === 'string' && record.client) return `client:${record.client}`;
  return 'unknown';
}

function alertOf(id, severity, key, summary, evidence) {
  return { id, severity, ...(key === 'unknown' ? {} : { runtimeId: key }), summary, evidence: [...evidence].sort((a, b) => a - b) };
}

function byRuntimeThenFirstSeq(a, b) {
  return (a.runtimeId ?? '').localeCompare(b.runtimeId ?? '') || a.evidence[0] - b.evidence[0];
}

// Generic sliding-window threshold detection: groups matching records by identityOf(), sorts
// each group by time (input may arrive unsorted), then slides a [start, end] window over it
// summing `weight` (default: one per record) and firing once per burst per group when the
// running total reaches `threshold` within `windowMs` (then re-arming once the window drains below
// the threshold, so each separate burst alerts once). Evidence cites every seq in the window
// that tripped the alert, not just the triggering record. Runs in O(n log n) (the per-group
// sort) with a single linear scan per group, so it stays practical on large merged files.
function slidingWindow(records, { id, severity, filter, windowMs, threshold, weight = () => 1, summary }) {
  const groups = new Map();
  for (const record of records) {
    if (!isRecord(record) || !filter(record)) continue;
    const seq = seqOf(record);
    const time = timeOf(record);
    const w = weight(record);
    if (seq === undefined || time === undefined || !Number.isFinite(w) || w < 0) continue;
    const key = identityOf(record);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push({ seq, time, w });
  }
  const alerts = [];
  for (const [key, entries] of groups) {
    entries.sort((a, b) => a.time - b.time || a.seq - b.seq);
    let start = 0;
    let total = 0;
    let armed = true;
    for (let end = 0; end < entries.length; end++) {
      // Slide first: drop entries that fall out of the window ending at this entry.
      while (start < end && entries[end].time - entries[start].time > windowMs) total -= entries[start++].w;
      // One alert per burst: re-arm once the window (before this entry) has drained below the
      // threshold, so a later, separate burst alerts again even if one entry alone meets it.
      if (total < threshold) armed = true;
      total += entries[end].w;
      if (armed && total >= threshold) {
        const evidence = entries.slice(start, end + 1).map((entry) => entry.seq);
        alerts.push(alertOf(id, severity, key, summary(key, total), evidence));
        armed = false;
      }
    }
  }
  return alerts.sort(byRuntimeThenFirstSeq);
}

// Per-record (unwindowed) detection: every matching record becomes its own alert.
function everyMatch(records, { id, severity, filter, summary }) {
  const alerts = [];
  for (const record of records) {
    if (!isRecord(record) || !filter(record)) continue;
    const seq = seqOf(record);
    if (seq === undefined) continue;
    const key = identityOf(record);
    alerts.push(alertOf(id, severity, key, summary(record, key), [seq]));
  }
  return alerts.sort(byRuntimeThenFirstSeq);
}

const asArray = (value) => (Array.isArray(value) ? value : []);
const isOffHoursUtc = (hour) => hour >= 22 || hour < 6;

export function detect(records, { protectedBranches = [] } = {}) {
  if (!Array.isArray(records)) return [];
  const protectedRefs = new Set(protectedBranches.map((branch) => `refs/heads/${branch}`));

  return [
    // D1-denial-burst: src/server.js and src/github-api.js both write
    // `{ type: 'decision', decision: 'deny', runtime: { runtimeId }, action, ... }` on every
    // policy denial (git.push, git.read, LFS, GitHub API operations, merges). Ten or more in ten
    // minutes from one runtime reads as automated probing of the policy surface.
    slidingWindow(records, {
      id: 'D1-denial-burst', severity: 'medium', windowMs: 10 * MINUTE_MS, threshold: 10,
      filter: (r) => r.type === 'decision' && r.decision === 'deny',
      summary: (runtimeId, count) => `${count} policy denials for runtime ${runtimeId} within 10 minutes`
    }),

    // D2-content-blocked: src/server.js emits exactly one shape for a scanned push that trips
    // content scanning: `{ type: 'decision', decision: 'content-blocked', code: 'CONTENT_BLOCKED',
    // runtime, approvalId, findings }`. Any occurrence is worth an immediate look (possible
    // secret exfiltration or a leaked credential reaching the mirror), so this is unwindowed and
    // high severity. The summary never repeats `findings` (which may hold blocked file paths).
    everyMatch(records, {
      id: 'D2-content-blocked', severity: 'high',
      filter: (r) => r.code === 'CONTENT_BLOCKED',
      summary: (r, runtimeId) => `Push blocked by content scanning for runtime ${runtimeId}${typeof r.repository === 'string' ? ` (${r.repository})` : ''}`
    }),

    // D3-egress-probing: src/egress-proxy.js emits `{ type: 'egress', decision, host, port,
    // reason, bytesUp, bytesDown, client }` per CONNECT attempt (client added by this task; see
    // module comment). Twenty or more denied tunnels from one client in ten minutes reads as
    // probing the egress allowlist (host/port scanning, or hunting for an open path off the
    // allowlisted registries).
    slidingWindow(records, {
      id: 'D3-egress-probing', severity: 'medium', windowMs: 10 * MINUTE_MS, threshold: 20,
      filter: (r) => r.type === 'egress' && r.decision === 'deny',
      summary: (key, count) => `${count} denied egress attempts for ${key} within 10 minutes`
    }),

    // D4-approval-rejections: src/state.js writes `{ type: 'approval.review', decision: 'deny' |
    // 'approve', context }` on every human review; the runtime lives at `context.runtime`, not at
    // the record's top level (identityOf() falls back to it). Three or more rejections for one
    // runtime in 24 hours suggests it keeps requesting operations reviewers keep turning down.
    slidingWindow(records, {
      id: 'D4-approval-rejections', severity: 'medium', windowMs: 24 * HOUR_MS, threshold: 3,
      filter: (r) => r.type === 'approval.review' && r.decision === 'deny',
      summary: (runtimeId, count) => `${count} rejected approvals for runtime ${runtimeId} within 24 hours`
    }),

    // D5-off-hours-protected-push: an *allowed* `git.push` decision record whose `changes`
    // (src/server.js `base.changes = decision.decisions`, each a change with `.ref`) includes a
    // ref under a repository's configured `protectedBranches` (src/config.js: bare branch names,
    // no `refs/heads/` prefix), landing between 22:00 and 06:00 UTC. Policy allowed the push, so
    // this is not a denial; it flags pushes to sensitive branches outside normal working hours
    // for follow-up, not necessarily malicious activity.
    everyMatch(records, {
      id: 'D5-off-hours-protected-push', severity: 'medium',
      filter: (r) => r.type === 'decision' && r.decision === 'allow' && r.action === 'git.push' &&
        asArray(r.changes).some((change) => isRecord(change) && protectedRefs.has(change.ref)) &&
        isOffHoursUtc(new Date(r.timestamp).getUTCHours()),
      summary: (r, runtimeId) => `Protected branch push by runtime ${runtimeId} at ${r.timestamp}`
    }),

    // D6-assertion-failures: ASSERTION_INVALID (src/assertion.js) is one of the codes
    // src/server.js batches into REJECTION_SUMMARY_CODES rather than auditing per-request
    // (deliberately, so an attacker cannot force a fsync'd audit write per bad assertion). It
    // only ever reaches the audit stream as periodic
    // `{ type: 'rejections', code: 'ASSERTION_INVALID', count, windowStart }` summaries, with no
    // per-runtime or per-caller identity (that is the whole point of the summary). This detection
    // therefore sums `count` across summaries within ten minutes, broker-wide, instead of
    // counting individual events; see docs/detections.md "Known gaps" for the detection-latency
    // consequence of how these summaries flush.
    slidingWindow(records, {
      id: 'D6-assertion-failures', severity: 'high', windowMs: 10 * MINUTE_MS, threshold: 5,
      filter: (r) => r.type === 'rejections' && r.code === 'ASSERTION_INVALID',
      weight: (r) => (Number.isSafeInteger(r.count) && r.count > 0 ? r.count : 0),
      summary: (_key, count) => `${count} rejected runtime assertions broker-wide within 10 minutes`
    }),

    // D7-model-volume: src/model-gateway.js emits `{ type: 'model.request', route, path, status,
    // bytesUp, bytesDown, client }` per proxied call (client added by this task; the gateway has
    // no runtime identity either, only the shared client token every workspace presents). More
    // than 50 MiB sent upstream by one client within an hour may be bulk data leaving through a
    // model API rather than a normal prompt/response exchange.
    slidingWindow(records, {
      id: 'D7-model-volume', severity: 'medium', windowMs: HOUR_MS, threshold: 50 * MIB,
      filter: (r) => r.type === 'model.request',
      weight: (r) => (Number.isFinite(r.bytesUp) && r.bytesUp > 0 ? r.bytesUp : 0),
      summary: (key) => `Over 50 MiB sent to model APIs by ${key} within an hour`
    })
  ].flat();
}

// --- CLI: reads newline-delimited audit/log records (file argument, or stdin), streams them
// line by line (so a large merged file is never held as one giant string), and prints each
// alert as one JSON line to stdout. A record that fails to parse is skipped and noted on
// stderr by line number only (never its content, which may hold findings paths or other
// sensitive fields); --strict makes any parse failure exit non-zero after all input is read.

function usage() {
  return 'Usage: node scripts/detect.js [file|-] [--strict] [--protected-branches=main,release/1.0]\n' +
    '  Reads newline-delimited JSON audit/log records from the file argument, or stdin when omitted or "-".\n' +
    '  --protected-branches also reads AGENTGATE_PROTECTED_BRANCHES (comma-separated) when unset.\n' +
    '  --strict exits non-zero if any input line failed to parse.\n';
}

async function readRecords(input, { strict }) {
  const records = [];
  let hadError = false;
  const rl = createInterface({ input, crlfDelay: Infinity });
  let lineNumber = 0;
  for await (const line of rl) {
    lineNumber += 1;
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      records.push(JSON.parse(trimmed));
    } catch {
      hadError = true;
      process.stderr.write(`detect: skipping unparseable record at line ${lineNumber}\n`);
      if (strict) break;
    }
  }
  rl.close();
  return { records, hadError };
}

export async function runCli(argv) {
  if (argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(usage());
    return 0;
  }
  const strict = argv.includes('--strict');
  const branchesFlag = argv.find((arg) => arg.startsWith('--protected-branches='));
  const branchesSource = branchesFlag ? branchesFlag.slice('--protected-branches='.length) : (process.env.AGENTGATE_PROTECTED_BRANCHES ?? '');
  const protectedBranches = branchesSource.split(',').map((value) => value.trim()).filter(Boolean);
  const fileArg = argv.find((arg) => !arg.startsWith('--'));
  const input = fileArg && fileArg !== '-' ? createReadStream(fileArg, { encoding: 'utf8' }) : process.stdin.setEncoding('utf8');
  const { records, hadError } = await readRecords(input, { strict });
  for (const alert of detect(records, { protectedBranches })) process.stdout.write(`${JSON.stringify(alert)}\n`);
  return strict && hadError ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCli(process.argv.slice(2)).then((code) => { process.exitCode = code; }).catch((error) => {
    process.stderr.write(`detect: ${error.message}\n`);
    process.exitCode = 1;
  });
}
