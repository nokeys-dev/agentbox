import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { GateError } from './errors.js';
import { decide, fingerprint } from './policy.js';
import { envelopeSummary } from './entitlements.js';
import { guardNotify } from './notify.js';

const bad = (message) => { throw new GateError(400, 'INVALID_API_REQUEST', message); };
const positiveId = '[1-9][0-9]{0,14}';

// Confirmed live 2026-09-17 against repos/actions/checkout and repos/actions/setup-node job logs:
// both redirected (302) to productionresultssa7.blob.core.windows.net. Only this host family was
// ever observed, so the pattern is scoped to exactly that (per controller ruling): a bare
// `productionresultssa\d+` (or the `pipelines`/`results-receiver`/`actions.githubusercontent.com`
// families from GitHub's docs, never independently observed) would accept far more of the Azure
// Blob account-name space than GitHub actually uses -- Azure account names are attacker-
// registrable, so a wider pattern risks matching a squatted `productionresultssaN` account this
// broker was never shown to need. The digit count is capped at 3 (GitHub's shard numbering, e.g.
// ...sa7, has never been observed beyond a small number of digits) to shrink that space further.
export const LOG_HOST_PATTERN = /^productionresultssa\d{1,3}\.blob\.core\.windows\.net$/;
// GitHub has been observed to answer with 302; 301/307/308 are accepted too as equally valid
// non-caching redirect semantics for a single-use signed URL, per controller ruling (e).
const LOG_REDIRECT_STATUSES = new Set([301, 302, 307, 308]);
const MAX_LOG_BYTES = 64 * 1024 * 1024;

export function routeApi(request) {
  // Match the raw path, before URL normalization, and never accept an upstream URL.
  const match = /^\/api\/repos\/([A-Za-z0-9-]+)\/([A-Za-z0-9_.-]+)\/(pulls(?:\/[1-9][0-9]{0,14}(?:\/(?:comments|reviews|merge))?)?|issues\/[1-9][0-9]{0,14}\/comments|actions\/runs(?:\/[1-9][0-9]{0,14}(?:\/jobs)?)?|actions\/jobs\/[1-9][0-9]{0,14}\/logs)(?:\?([^#]*))?$/.exec(request.url);
  if (!match || ['.', '..'].includes(match[2])) throw new GateError(404, 'NOT_FOUND', 'Unsupported GitHub API operation');
  const name = `${match[1]}/${match[2]}`.toLowerCase();
  const resource = match[3];
  const method = request.method;
  // Explicit method/action/permission table (rather than deriving from the resource shape) so
  // every route's least-privilege permission and policy action is visible at a glance, and so a
  // resource matched by the path regex but requested with the wrong method reports 405 (a
  // recognized resource) instead of a misleading 404.
  const table = [
    [/^pulls$/, 'GET', 'github.pr.read', { pull_requests: 'read' }, true],
    [/^pulls$/, 'POST', 'github.pr.create', { pull_requests: 'write' }, false],
    [/^pulls\/\d+$/, 'GET', 'github.pr.read', { pull_requests: 'read' }, false],
    [/^pulls\/\d+\/comments$/, 'GET', 'github.pr.read', { pull_requests: 'read' }, true],
    [/^pulls\/\d+\/reviews$/, 'POST', 'github.pr.comment', { pull_requests: 'write' }, false],
    // GitHub's "permissions required for GitHub Apps" lists this endpoint under Contents: write
    // only (not Pull requests), so the merge token gets exactly that. A merge that would change
    // .github/workflows additionally needs Workflows: write, which is deliberately never granted.
    [/^pulls\/\d+\/merge$/, 'PUT', 'github.pr.merge', { contents: 'write' }, false],
    [/^issues\/\d+\/comments$/, 'GET', 'github.pr.read', { pull_requests: 'read' }, true],
    [/^issues\/\d+\/comments$/, 'POST', 'github.pr.comment', { pull_requests: 'write' }, false],
    [/^actions\/runs$/, 'GET', 'github.actions.read', { actions: 'read' }, true],
    [/^actions\/runs\/\d+$/, 'GET', 'github.actions.read', { actions: 'read' }, false],
    [/^actions\/runs\/\d+\/jobs$/, 'GET', 'github.actions.read', { actions: 'read' }, true],
    [/^actions\/jobs\/\d+\/logs$/, 'GET', 'github.actions.read', { actions: 'read' }, false]
  ];
  const candidates = table.filter(([pattern]) => pattern.test(resource));
  const entry = candidates.find(([, allowedMethod]) => allowedMethod === method);
  if (!entry) throw new GateError(candidates.length ? 405 : 404, candidates.length ? 'METHOD_NOT_ALLOWED' : 'NOT_FOUND', 'Unsupported GitHub API operation');
  const [, , action, permissions, list] = entry;
  const create = method === 'POST' || method === 'PUT';
  const query = new URLSearchParams(match[4]);
  const allowed = create || !list ? [] : ['page', 'per_page', ...(resource === 'pulls' ? ['state'] : resource === 'actions/runs' ? ['branch'] : [])];
  for (const [key, value] of query) {
    if (!allowed.includes(key) || query.getAll(key).length !== 1) bad(`Unsupported or duplicate query parameter: ${key}`);
    if (key === 'page' && !new RegExp(`^${positiveId}$`).test(value)) bad('Invalid page');
    if (key === 'per_page' && (!/^[1-9][0-9]{0,2}$/.test(value) || Number(value) > 100)) bad('per_page must be between 1 and 100');
    if (key === 'state' && !['open', 'closed', 'all'].includes(value)) bad('Invalid pull request state');
    if (key === 'branch' && !validBranch(value)) bad('Invalid branch');
  }
  if (list && !create) {
    if (!query.has('per_page')) query.set('per_page', '30');
    if (!query.has('page')) query.set('page', '1');
  }
  query.sort();
  // kind drives handleApi's payload validator and expected upstream status; it is a small,
  // explicit classification rather than re-deriving intent from resource/method at each call site.
  const kind = resource === 'pulls' && create ? 'pr-create'
    : resource.endsWith('/merge') ? 'merge'
      : resource.endsWith('/reviews') ? 'review'
        : resource.endsWith('/comments') && create ? 'comment'
          : resource.endsWith('/logs') ? 'logs'
            : 'read';
  return {
    name, method, resource, create, action, permissions, kind,
    path: `${resource}${query.size ? `?${query}` : ''}`
  };
}

function validBranch(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 &&
    /^[A-Za-z0-9_./-]+$/.test(value) && !value.startsWith('-') && !value.endsWith('.') &&
    !value.includes('..') && value.split('/').every((part) => part && !part.startsWith('.') && !part.endsWith('.lock'));
}

const OWNER = /^[A-Za-z0-9-]{1,39}$/;

// Resolves a cross-repository head "owner:branch" against the configured forks of the target
// ({ owner, name }[], owners lowercase). Returns undefined for a same-repository head; throws
// for a malformed head, an unknown owner, or an owner shared by several configured forks.
export function forkHead(head, forks = []) {
  if (typeof head !== 'string' || !head.includes(':')) return undefined;
  const parts = head.split(':');
  if (parts.length !== 2 || !OWNER.test(parts[0]) || !validBranch(parts[1])) bad('Fork heads must be OWNER:BRANCH');
  const matching = forks.filter((fork) => fork.owner === parts[0].toLowerCase());
  if (matching.length !== 1) bad('Fork heads must name exactly one configured fork of this repository');
  return { owner: matching[0].owner, name: matching[0].name, branch: parts[1] };
}

export function pullRequestPayload(body, { forks = [] } = {}) {
  let input;
  try { input = JSON.parse(body.toString('utf8')); } catch { bad('Expected a JSON object'); }
  if (!input || typeof input !== 'object' || Array.isArray(input)) bad('Expected a JSON object');
  if (Object.keys(input).some((key) => !['title', 'head', 'base', 'body', 'draft'].includes(key))) bad('Unsupported pull request field');
  if (typeof input.title !== 'string' || !input.title.trim() || input.title.length > 256 || /[\r\n\0]/.test(input.title)) bad('A title of at most 256 characters is required');
  const fork = forkHead(input.head, forks);
  if (!validBranch(fork ? fork.branch : input.head) || !validBranch(input.base) || input.head === input.base) bad('Provide different head and base branches');
  if (input.body !== undefined && (typeof input.body !== 'string' || input.body.length > 60000 || input.body.includes('\0'))) bad('Invalid pull request body');
  if (input.draft !== undefined && typeof input.draft !== 'boolean') bad('draft must be a boolean');
  return { title: input.title, head: input.head, base: input.base, body: input.body ?? '', draft: input.draft ?? true };
}

// Comment/review bodies are agent-authored free text that is posted publicly on GitHub. Never
// log or audit the text itself (callers should audit only its length); this validator only
// bounds size and rejects NUL, it does not otherwise inspect content.
export function commentPayload(body) {
  let input;
  try { input = JSON.parse(body.toString('utf8')); } catch { bad('Expected a JSON object'); }
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some((key) => key !== 'body')) bad('Only body is supported');
  if (typeof input.body !== 'string' || !input.body.trim() || input.body.length > 65536 || input.body.includes('\0')) bad('body must be 1-65536 characters');
  return { body: input.body };
}

// Agents may only leave COMMENT reviews: approving or requesting changes on their own work needs
// a human, so those events are rejected here rather than left to GitHub or policy to catch.
export function reviewPayload(body) {
  let input;
  try { input = JSON.parse(body.toString('utf8')); } catch { bad('Expected a JSON object'); }
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some((key) => !['body', 'event'].includes(key))) bad('Only body and event are supported');
  if (input.event !== 'COMMENT') throw new GateError(403, 'REVIEW_EVENT_DENIED', 'Agents may only leave COMMENT reviews; approvals and change requests need a human');
  return { ...commentPayload(Buffer.from(JSON.stringify({ body: input.body }))), event: 'COMMENT' };
}

// A merge carries only the head SHA the reviewer approved and the merge method. Commit titles and
// messages are never accepted from the agent: GitHub builds them from the PR itself.
export function mergePayload(body) {
  let input;
  try { input = JSON.parse(body.toString('utf8')); } catch { bad('Expected a JSON object'); }
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some((key) => !['sha', 'merge_method'].includes(key))) bad('Only sha and merge_method are supported');
  if (typeof input.sha !== 'string' || !/^[0-9a-f]{40}$/.test(input.sha)) bad('sha must be the full 40-character lowercase head commit SHA');
  if (!['merge', 'squash', 'rebase'].includes(input.merge_method)) bad('merge_method must be merge, squash, or rebase');
  return { sha: input.sha, merge_method: input.merge_method };
}

function pick(input, fields) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new GateError(502, 'INVALID_UPSTREAM', 'Invalid GitHub response');
  return Object.fromEntries(fields.filter((key) => input[key] === null || ['string', 'number', 'boolean'].includes(typeof input[key])).map((key) => [key, input[key]]));
}

function listOf(value, project) {
  if (!Array.isArray(value)) throw new GateError(502, 'INVALID_UPSTREAM', 'Invalid GitHub list response');
  return value.map(project);
}

function pull(value) {
  return {
    ...pick(value, ['number', 'title', 'body', 'state', 'draft', 'html_url', 'created_at', 'updated_at', 'merged', 'mergeable']),
    head: pick(value.head ?? {}, ['ref', 'sha']), base: pick(value.base ?? {}, ['ref', 'sha']),
    user: pick(value.user ?? {}, ['login'])
  };
}

function run(value) {
  return pick(value, ['id', 'name', 'head_branch', 'head_sha', 'event', 'status', 'conclusion', 'html_url', 'created_at', 'updated_at', 'run_number', 'run_attempt']);
}

function comment(value) {
  return { ...pick(value, ['id', 'body', 'html_url', 'created_at', 'updated_at']), user: pick(value.user ?? {}, ['login']) };
}

// GitHub's nested repository objects can contain temp_clone_token. Return only
// the fields needed by this client, never raw provider objects or headers.
export function projectApiResponse(operation, data) {
  if (operation.resource.endsWith('/comments')) return operation.create ? comment(data) : listOf(data, comment);
  if (operation.kind === 'merge') return pick(data, ['merged', 'sha']);
  if (operation.resource.endsWith('/reviews')) return pick(data, ['id', 'state', 'body', 'html_url', 'submitted_at']);
  if (operation.resource === 'pulls' && !operation.create) return listOf(data, pull);
  if (operation.resource.startsWith('pulls')) return pull(data);
  if (operation.resource === 'actions/runs') return { ...pick(data, ['total_count']), workflow_runs: listOf(data.workflow_runs, run) };
  if (operation.resource.endsWith('/jobs')) return {
    ...pick(data, ['total_count']), jobs: listOf(data.jobs, (job) => ({
      ...pick(job, ['id', 'name', 'status', 'conclusion', 'html_url', 'started_at', 'completed_at']),
      steps: listOf(job.steps ?? [], (step) => pick(step, ['name', 'number', 'status', 'conclusion', 'started_at', 'completed_at']))
    }))
  };
  return run(data);
}

async function readJson(response) {
  if (!response.headers.get('content-type')?.includes('json') || !response.body) throw new GateError(502, 'INVALID_UPSTREAM', 'Expected GitHub JSON response');
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > 4 * 1024 * 1024) throw new GateError(502, 'UPSTREAM_TOO_LARGE', 'GitHub response too large; reduce per_page');
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString()); } catch { throw new GateError(502, 'INVALID_UPSTREAM', 'Invalid GitHub JSON response'); }
}

// Enforces MAX_LOG_BYTES on a piped log body. On overflow this errors the pipeline instead of
// silently dropping bytes: per controller ruling, a truncated log must never look like a
// complete, successful download, so pipeline()'s standard on-error behavior -- destroy every
// other stream in the chain, including the client response, with no clean end and no trailer --
// is exactly what should happen here. `bytes`/`truncated` are read back by the caller afterwards
// for the (byte-count-only) audit record.
function capStream(maxBytes) {
  let bytes = 0;
  const stream = new Transform({
    transform(chunk, _encoding, callback) {
      bytes += chunk.length;
      if (bytes > maxBytes) { stream.truncated = true; return callback(new GateError(502, 'LOG_TOO_LARGE', 'Log exceeds the broker cap')); }
      callback(null, chunk);
    }
  });
  stream.truncated = false;
  Object.defineProperty(stream, 'bytes', { get: () => bytes });
  return stream;
}

// Downloads a CI job's log. `provider.apiRaw` hits GitHub with the installation token and a
// manual redirect: GitHub answers with a redirect to a short-lived, presigned URL on its log
// storage, never a body. That URL is a bearer capability -- it is never logged, audited, or
// forwarded anywhere else -- and is only followed at all once its scheme and host are confirmed
// against LOG_HOST_PATTERN, so a compromised or unexpected redirect can never turn this endpoint
// into an open-ended fetch proxy. The storage fetch itself (`provider.fetchLog`) carries no
// Authorization header and no GitHub or client token. The response is relayed to the client as
// plain text via `pipeline`, capped at MAX_LOG_BYTES (see capStream above): pipeline's own
// backpressure handling (rather than a manual write/drain loop, which never settles once the
// client disconnects mid-backpressure -- destroyed streams never emit 'drain') and its automatic
// stream-teardown-on-error together guarantee the handler always settles and the upstream body is
// always released, whether the client disconnects or the cap is hit.
async function streamLog({ provider, repository, operation, controller, response, state, base, approvalId }) {
  const redirect = await provider.apiRaw({ repository, operation, signal: controller.signal });
  await redirect.body?.cancel().catch(() => {});
  const location = LOG_REDIRECT_STATUSES.has(redirect.status) ? redirect.headers.get('location') : undefined;
  let target;
  try { target = new URL(location); } catch { throw new GateError(502, 'UPSTREAM_FAILED', `GitHub did not return a log location (${redirect.status})`); }
  // Only the host is checked against LOG_HOST_PATTERN; a URL with embedded userinfo
  // (`https://user:pass@productionresultssa1.blob.core.windows.net/x`) or an explicit port still
  // reports that same allowlisted hostname, so both are rejected outright rather than trusted.
  if (target.protocol !== 'https:' || target.username || target.password || target.port || !LOG_HOST_PATTERN.test(target.hostname)) {
    throw new GateError(502, 'LOG_UNTRUSTED_HOST', 'Log storage host is not allowlisted');
  }
  const log = await provider.fetchLog(target.href, {
    method: 'GET', headers: { 'user-agent': 'AgentBox/0.1' }, redirect: 'error',
    signal: AbortSignal.any([controller.signal, AbortSignal.timeout(120_000)])
  });
  if (log.status !== 200 || !log.body) {
    await log.body?.cancel().catch(() => {});
    throw new GateError(502, 'UPSTREAM_FAILED', `Log download failed (${log.status})`);
  }
  // Fail closed, like every other action here: if this write fails (e.g. disk pressure), it
  // throws before writeHead below, so nothing has reached the client and the outer handler
  // reports a clean 500 instead of a download nobody can prove happened. Only the status is
  // known yet -- the byte count is recorded in a second, best-effort record once the transfer
  // settles, since blocking completion on it would serve no purpose (the bytes are already gone).
  state.audit({ ...base, type: 'execution', approvalId, upstreamStatus: log.status, result: 'upstream-response' });
  response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  const cap = capStream(MAX_LOG_BYTES);
  let outcome = 'log-complete';
  try {
    await pipeline(Readable.fromWeb(log.body), cap, response);
  } catch (error) {
    // A disconnect mid-stream (destroyed response never emits 'drain' or otherwise settles on
    // its own -- pipeline's own teardown is what makes this branch reachable at all instead of
    // hanging) or an upstream failure mid-stream is not a truncation; let the outer handler
    // settle it exactly as it would for any other action.
    outcome = cap.truncated ? 'log-truncated' : 'log-interrupted';
    if (!cap.truncated) throw error;
  } finally {
    // Never log/audit the storage Location URL or its query -- only the status (above) and this
    // final byte count. Best-effort: by the time this runs the response has already been ended
    // or destroyed, so a failure here must never turn a settled download into a spurious 500.
    try { state.audit({ ...base, type: 'execution', approvalId, result: outcome, bytes: Math.min(cap.bytes, MAX_LOG_BYTES), truncated: cap.truncated }); } catch { /* Never mask a settled download. */ }
  }
}

export async function handleApi({ request, response, operation, config, runtime = config.runtime, resolveEnvelope = async () => undefined, policyHash, state, provider, base, readBody, json, notify = () => {}, logger = { warn() {} } }) {
  // Wrapping here (not just trusting an already-guarded `notify` from the caller) means a
  // synchronous throw can never escape this function even when handleApi is exercised directly,
  // and it logs with the same event name/shape as server.js's push-approval path.
  const safeNotify = guardNotify(notify, logger);
  // Fail closed: approval contexts and self-approval checks need the verified runtime identity.
  if (!runtime?.human) throw new GateError(500, 'INTERNAL_ERROR', 'Runtime identity unavailable');
  const repository = config.repositories.find((repo) => repo.name === operation.name);
  Object.assign(base, { repository: operation.name, action: operation.action });
  // Resolved once, right before the first decision; every decision below uses this envelope.
  const envelope = await resolveEnvelope();
  if (!repository || decide(config, 'git.read', operation.name, undefined, envelope).effect !== 'allow') {
    state.audit({ ...base, type: 'decision', decision: 'deny' });
    throw new GateError(403, 'DENIED', 'Repository read denied');
  }
  // Configured forks of this repository that the broker may read (and so could have pushed to).
  // The PR itself is created with this (upstream) repository's installation token; no token is
  // ever requested for the fork here, so the fork must be reachable by the same App installation.
  const forks = operation.kind === 'pr-create' ? config.repositories
    .filter((repo) => repo.forkOf === operation.name && decide(config, 'git.read', repo.name, undefined, envelope).effect === 'allow')
    .map((repo) => ({ owner: repo.name.split('/')[0], name: repo.name })) : [];
  let payload;
  if (operation.create) {
    if (request.headers['content-type']?.split(';')[0] !== 'application/json') throw new GateError(415, 'INVALID_CONTENT_TYPE', 'Expected application/json');
    const body = await readBody(request, 64 * 1024);
    payload = operation.kind === 'pr-create' ? pullRequestPayload(body, { forks })
      : operation.kind === 'merge' ? mergePayload(body)
        : operation.kind === 'review' ? reviewPayload(body) : commentPayload(body);
  }
  const controller = new AbortController();
  const abort = () => { if (!response.writableFinished) controller.abort(); };
  response.once('close', abort);
  try {
    return await authorizeAndExecute({ response, operation, config, runtime, envelope, policyHash, state, provider, base, json, safeNotify, repository, forks, payload, controller });
  } finally {
    controller.abort();
    response.off('close', abort);
  }
}

// Reads the pull request with a read-only token. A 403/404 is reported as not found; a GitHub
// 5xx (or anything else) is an upstream failure, not a missing PR.
async function readPull({ provider, repository, number, controller, state, base, audit }) {
  const current = await provider.api({ repository, operation: { method: 'GET', resource: `pulls/${number}`, path: `pulls/${number}`, permissions: { pull_requests: 'read' } }, payload: undefined, signal: controller.signal });
  if (current.status !== 200) {
    await current.body?.cancel();
    state.audit({ ...base, ...audit, upstreamStatus: current.status, result: 'pull-request-unavailable' });
    if ([403, 404].includes(current.status)) throw new GateError(404, 'UPSTREAM_FAILED', 'Pull request not found or unavailable to this App');
    throw new GateError(502, 'UPSTREAM_FAILED', `GitHub failed to return the pull request (${current.status})`);
  }
  const pr = await readJson(current);
  if (!pr || typeof pr !== 'object' || typeof pr.base?.ref !== 'string' || !validBranch(pr.base.ref) || typeof pr.head?.sha !== 'string') {
    throw new GateError(502, 'INVALID_UPSTREAM', 'Invalid GitHub pull request response');
  }
  return pr;
}

// Checks the pull request before any policy decision or approval consumption, so a draft/closed PR,
// a moved head, or a disallowed base never burns a grant. authorizeAndExecute re-reads it right
// before the PUT (see there); GitHub's own `sha` merge parameter still guards the head.
async function preMerge({ provider, repository, operation, payload, controller, state, base }) {
  const number = Number(operation.resource.split('/')[1]);
  const pr = await readPull({ provider, repository, number, controller, state, base, audit: { type: 'decision', decision: 'deny' } });
  // A head in another repository is decided as a fork head (policy.js requires a configured fork
  // of this repository and a matching headRepository rule). A missing head repository (for
  // example a deleted fork) cannot be attributed, so it is refused.
  const headName = typeof pr.head.repo?.full_name === 'string' ? pr.head.repo.full_name.toLowerCase() : undefined;
  const headRepository = headName === operation.name ? undefined : headName ?? '';
  // Every later decision/execution record for this merge carries the fork head repository.
  if (headRepository) base.headRepository = headRepository;
  if (pr.state !== 'open' || pr.draft !== false) {
    state.audit({ ...base, type: 'decision', decision: 'deny', result: 'pr-not-mergeable' });
    throw new GateError(409, 'PR_NOT_MERGEABLE', 'Pull request must be open and ready for review');
  }
  if (pr.head.sha !== payload.sha) {
    state.audit({ ...base, type: 'decision', decision: 'deny', result: 'head-moved' });
    throw new GateError(409, 'HEAD_MOVED', 'Pull request head changed; review the new commits and request approval again');
  }
  // PR titles are author-controlled display text only (never part of the approval key).
  const title = typeof pr.title === 'string' ? pr.title.replace(/[\u0000-\u001f\u007f]+/g, ' ').slice(0, 256) : '';
  return { number, base: pr.base.ref, title, headRepository, change: { ref: `refs/heads/${pr.base.ref}`, ...(headRepository === undefined ? {} : { headRepository }) } };
}

async function authorizeAndExecute({ response, operation, config, runtime, envelope, policyHash, state, provider, base, json, safeNotify, repository, forks, payload, controller }) {
  let fork;
  const merge = operation.kind === 'merge' ? await preMerge({ provider, repository, operation, payload, controller, state, base }) : undefined;
  // Only pr-create ties the decision to a ref pattern (the head branch being opened against).
  // Comments and reviews are decided purely on repository + action; the body never enters
  // the policy fingerprint, so a comment's text can never appear in an approval context or audit.
  if (operation.kind === 'pr-create') fork = forkHead(payload.head, forks);
  if (fork) base.headRepository = fork.name;
  const decision = decide(config, operation.action, operation.name, merge ? merge.change : operation.kind !== 'pr-create' ? undefined
    : fork ? { ref: `refs/heads/${fork.branch}`, headRepository: fork.name } : { ref: `refs/heads/${payload.head}` }, envelope);
  // config.js never lets a merge rule allow; this is a second, local fail-closed check.
  if (merge && decision.effect === 'allow') throw new GateError(500, 'INVALID_POLICY', 'Merges require an approval rule');
  // Never audit or log comment/review body text (it is agent-authored free text posted publicly);
  // only its length is recorded, and only for these two kinds.
  const bodyAudit = payload && (operation.kind === 'comment' || operation.kind === 'review') ? { bodyLength: payload.body.length } : {};
  let approvalId;
  if (decision.effect !== 'deny' && merge && !decision.mergeMethods?.includes(payload.merge_method)) {
    state.audit({ ...base, type: 'decision', decision: 'deny', rule: decision.rule, result: 'merge-method-denied' });
    throw new GateError(403, 'DENIED', `Merge method ${payload.merge_method} is not allowed by policy`);
  }
  if (decision.effect === 'deny') {
    state.audit({ ...base, ...bodyAudit, type: 'decision', decision: 'deny', rule: decision.rule });
    throw new GateError(403, 'DENIED', 'GitHub API operation denied by policy');
  }
  if (decision.effect === 'approval') {
    const context = merge
      ? { runtime, repository: operation.name, action: operation.action, number: merge.number, sha: payload.sha, base: merge.base,
        ...(merge.headRepository ? { headRepository: merge.headRepository } : {}), mergeMethod: payload.merge_method, policyHash }
      : { runtime, repository: operation.name, action: operation.action, payload, policyHash, ...(fork ? { headRepository: fork.name } : {}) };
    if (decision.reviewerSources) context.reviewerSources = decision.reviewerSources;
    // Shows reviewers why a `requires` rule matched; also binds the approval to these entitlements.
    if (envelope) context.entitlements = envelopeSummary(envelope);
    // The merge key deliberately excludes the PR title: anyone can edit a title while a request
    // waits, and a title change must neither invalidate a reviewed approval nor create a new one.
    // What gets merged is pinned by number + head sha + base + method instead.
    const key = fingerprint(context);
    approvalId = state.consume(key);
    if (!approvalId) {
      const pending = state.request(key, merge ? { ...context, title: merge.title } : context, { requiredApprovals: decision.requiredApprovals });
      // Notify before auditing so an audit failure cannot suppress this one-time notification.
      if (pending.created) safeNotify(pending);
      state.audit({ ...base, ...bodyAudit, type: 'decision', decision: 'approval', approvalId: pending.id });
      return json(response, 403, { code: 'REQUIRE_APPROVAL', requestId: pending.id, requiredApprovals: pending.requiredApprovals, message: `Review ${pending.id} on the trusted host, then retry the same command` });
    }
  }
  state.audit({ ...base, ...bodyAudit, type: 'decision', decision: 'allow', rule: decision.rule, approvalId });
  if (merge) {
    // Close the race between the pre-check and the PUT: GitHub's `sha` parameter pins the head but
    // not the base, and a PR's base branch can be edited while approval is pending or after the
    // pre-check. Re-read the PR immediately before merging and abort (without calling the merge
    // endpoint) if the base or head no longer matches what was approved. The approval was already
    // consumed above, so an abort here requires a new approval; that is deliberate (fail closed).
    // Only the millisecond window between this read and the PUT remains.
    const recheck = await readPull({ provider, repository, number: merge.number, controller, state, base, audit: { type: 'execution', approvalId } });
    if (recheck.base.ref !== merge.base) {
      state.audit({ ...base, type: 'execution', approvalId, result: 'base-changed' });
      throw new GateError(409, 'BASE_CHANGED', 'Pull request base branch changed before the merge; request approval again');
    }
    if (recheck.head.sha !== payload.sha) {
      state.audit({ ...base, type: 'execution', approvalId, result: 'head-moved' });
      throw new GateError(409, 'HEAD_MOVED', 'Pull request head changed before the merge; request approval again');
    }
  }
  if (operation.kind === 'logs') return await streamLog({ provider, repository, operation, controller, response, state, base, approvalId });
  // A comment on `issues/:n/comments` is only ever valid on a pull request conversation.
  // GitHub's issue-comments endpoint accepts a comment on any issue, so the broker checks
  // `GET issues/:n` first and requires `pull_request` to be present. The issue object itself
  // is never returned to the client or logged; only whether it is a pull request matters.
  const issueMatch = operation.kind === 'comment' && /^issues\/(\d+)\/comments$/.exec(operation.resource);
  if (issueMatch) {
    const checkOperation = { method: 'GET', resource: `issues/${issueMatch[1]}`, path: `issues/${issueMatch[1]}`, permissions: { pull_requests: 'read' } };
    const check = await provider.api({ repository, operation: checkOperation, payload: undefined, signal: controller.signal });
    const isPullRequest = check.status === 200 && Boolean((await readJson(check)).pull_request);
    if (check.status !== 200) await check.body?.cancel();
    if (!isPullRequest) {
      // 404 (issue not found), 403 (no access), and 200-but-not-a-PR are all reported
      // identically: a client that cannot already read the issue learns nothing new.
      state.audit({ ...base, type: 'execution', approvalId, upstreamStatus: check.status, result: 'not-a-pull-request' });
      throw new GateError(404, 'NOT_A_PULL_REQUEST', 'That issue is not a pull request');
    }
  }
  const upstream = await provider.api({ repository, operation, payload, signal: controller.signal });
  state.audit({ ...base, type: 'execution', approvalId, upstreamStatus: upstream.status, result: upstream.ok ? 'upstream-response' : 'upstream-rejected' });
  const expectedStatus = operation.kind === 'review' || operation.kind === 'merge' ? 200 : operation.create ? 201 : 200;
  if (upstream.status !== expectedStatus) {
    await upstream.body?.cancel();
    if (operation.kind === 'merge') {
      // Upstream bodies are never relayed; only these fixed messages.
      if (upstream.status === 405) throw new GateError(409, 'PR_NOT_MERGEABLE', 'GitHub refused the merge (checks, reviews, conflicts, or branch protection)');
      if (upstream.status === 409) throw new GateError(409, 'HEAD_MOVED', 'Pull request head changed before the merge; request approval again');
      if (upstream.status === 422) throw new GateError(422, 'MERGE_REJECTED', 'GitHub rejected the merge request as invalid');
    }
    const messages = { 403: 'Check GitHub App permissions or rate limits', 404: 'Resource not found or unavailable to this App', 422: 'Check branches and whether a pull request already exists' };
    throw new GateError([404, 422].includes(upstream.status) ? upstream.status : 502, 'UPSTREAM_FAILED', `GitHub rejected the request (${upstream.status}). ${messages[upstream.status] ?? 'Inspect broker configuration'}`);
  }
  return json(response, upstream.status, projectApiResponse(operation, await readJson(upstream)));
}
