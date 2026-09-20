// GitLab merge request and pipeline proxy behind the same broker paths the workspace CLI already
// uses for GitHub (/api/repos/<project>/pulls..., /actions/runs..., /actions/jobs/<id>/logs), so
// `agentgate pr` and `agentgate ci` work unchanged. Requests are translated to the GitLab REST
// API v4, responses are projected to the GitHub-shaped field names the CLI prints, and upstream
// bodies and headers are never forwarded. Mirrors github-api.js: read it first for the security
// reasoning behind each step; the differences are marked "GitLab:" below.
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { GateError } from './errors.js';
import { decide, fingerprint } from './policy.js';
import { envelopeSummary } from './entitlements.js';
import { guardNotify } from './notify.js';
import { commentPayload, mergePayload, reviewPayload } from './github-api.js';

const bad = (message) => { throw new GateError(400, 'INVALID_API_REQUEST', message); };
const positiveId = '[1-9][0-9]{0,14}';
const MAX_LOG_BYTES = 64 * 1024 * 1024;

function validBranch(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 &&
    /^[A-Za-z0-9_./-]+$/.test(value) && !value.startsWith('-') && !value.endsWith('.') &&
    !value.includes('..') && value.split('/').every((part) => part && !part.startsWith('.') && !part.endsWith('.lock'));
}

export function routeGitlabApi(request) {
  // GitLab: project paths may nest (group/subgroup/project); the resource keeps GitHub's names.
  const match = /^\/api\/repos\/((?:[A-Za-z0-9_.-]+\/)+[A-Za-z0-9_.-]+)\/(pulls(?:\/[1-9][0-9]{0,14}(?:\/(?:comments|reviews|merge))?)?|issues\/[1-9][0-9]{0,14}\/comments|actions\/runs(?:\/[1-9][0-9]{0,14}(?:\/jobs)?)?|actions\/jobs\/[1-9][0-9]{0,14}\/logs)(?:\?([^#]*))?$/.exec(request.url);
  if (!match || match[1].split('/').some((part) => ['.', '..'].includes(part) || part.startsWith('-'))) throw new GateError(404, 'NOT_FOUND', 'Unsupported GitLab API operation');
  const name = match[1].toLowerCase();
  const resource = match[2];
  const method = request.method;
  // GitLab: OAuth tokens are user-scoped, so `permissions` is informational; policy actions are
  // the least-privilege boundary. See docs/providers/gitlab.md section 3.
  const table = [
    [/^pulls$/, 'GET', 'gitlab.mr.read', true],
    [/^pulls$/, 'POST', 'gitlab.mr.create', false],
    [/^pulls\/\d+$/, 'GET', 'gitlab.mr.read', false],
    [/^pulls\/\d+\/comments$/, 'GET', 'gitlab.mr.read', true],
    [/^pulls\/\d+\/reviews$/, 'POST', 'gitlab.mr.comment', false],
    [/^pulls\/\d+\/merge$/, 'PUT', 'gitlab.mr.merge', false],
    [/^issues\/\d+\/comments$/, 'GET', 'gitlab.mr.read', true],
    [/^issues\/\d+\/comments$/, 'POST', 'gitlab.mr.comment', false],
    [/^actions\/runs$/, 'GET', 'gitlab.pipelines.read', true],
    [/^actions\/runs\/\d+$/, 'GET', 'gitlab.pipelines.read', false],
    [/^actions\/runs\/\d+\/jobs$/, 'GET', 'gitlab.pipelines.read', true],
    [/^actions\/jobs\/\d+\/logs$/, 'GET', 'gitlab.pipelines.read', false]
  ];
  const candidates = table.filter(([pattern]) => pattern.test(resource));
  const entry = candidates.find(([, allowedMethod]) => allowedMethod === method);
  if (!entry) throw new GateError(candidates.length ? 405 : 404, candidates.length ? 'METHOD_NOT_ALLOWED' : 'NOT_FOUND', 'Unsupported GitLab API operation');
  const [, , action, list] = entry;
  const create = method === 'POST' || method === 'PUT';
  const query = new URLSearchParams(match[3]);
  const allowed = create || !list ? [] : ['page', 'per_page', ...(resource === 'pulls' ? ['state'] : resource === 'actions/runs' ? ['branch'] : [])];
  for (const [key, value] of query) {
    if (!allowed.includes(key) || query.getAll(key).length !== 1) bad(`Unsupported or duplicate query parameter: ${key}`);
    if (key === 'page' && !new RegExp(`^${positiveId}$`).test(value)) bad('Invalid page');
    if (key === 'per_page' && (!/^[1-9][0-9]{0,2}$/.test(value) || Number(value) > 100)) bad('per_page must be between 1 and 100');
    if (key === 'state' && !['open', 'closed', 'all'].includes(value)) bad('Invalid pull request state');
    if (key === 'branch' && !validBranch(value)) bad('Invalid branch');
  }
  const kind = resource === 'pulls' && create ? 'pr-create'
    : resource.endsWith('/merge') ? 'merge'
      : resource.endsWith('/reviews') ? 'review'
        : resource.endsWith('/comments') && create ? 'comment'
          : resource.endsWith('/logs') ? 'logs'
            : 'read';
  const id = /\/(\d+)/.exec(resource)?.[1];
  // GitLab: translate the GitHub-shaped resource to the v4 project sub-path.
  const upstream = new URLSearchParams();
  if (list && !create) {
    upstream.set('per_page', query.get('per_page') ?? '30');
    upstream.set('page', query.get('page') ?? '1');
  }
  let path;
  if (resource === 'pulls') {
    if (!create) upstream.set('state', { open: 'opened', closed: 'closed', all: 'all' }[query.get('state') ?? 'open']);
    path = 'merge_requests';
  } else if (/^pulls\/\d+$/.test(resource)) path = `merge_requests/${id}`;
  else if (resource.endsWith('/merge')) path = `merge_requests/${id}/merge`;
  else if (resource.endsWith('/comments') || resource.endsWith('/reviews')) { path = `merge_requests/${id}/notes`; if (!create) upstream.set('sort', 'asc'); }
  else if (resource === 'actions/runs') { if (query.has('branch')) upstream.set('ref', query.get('branch')); path = 'pipelines'; }
  else if (/^actions\/runs\/\d+$/.test(resource)) path = `pipelines/${id}`;
  else if (resource.endsWith('/jobs')) path = `pipelines/${id}/jobs`;
  else path = `jobs/${id}/trace`;
  upstream.sort();
  return { name, method, resource, create, action, kind, permissions: 'oauth', id, path: `${path}${upstream.size ? `?${upstream}` : ''}` };
}

// GitLab: a fork head is "NAMESPACE:BRANCH" where NAMESPACE is the fork's first path segment,
// matching what the workspace CLI sends for --upstream. Resolved against configured forks.
export function gitlabForkHead(head, forks = []) {
  if (typeof head !== 'string' || !head.includes(':')) return undefined;
  const parts = head.split(':');
  if (parts.length !== 2 || !/^[\w.-]{1,255}$/.test(parts[0]) || !validBranch(parts[1])) bad('Fork heads must be NAMESPACE:BRANCH');
  const matching = forks.filter((fork) => fork.owner === parts[0].toLowerCase());
  if (matching.length !== 1) bad('Fork heads must name exactly one configured fork of this project');
  return { owner: matching[0].owner, name: matching[0].name, projectId: matching[0].projectId, branch: parts[1] };
}

export function mergeRequestPayload(body, { forks = [] } = {}) {
  let input;
  try { input = JSON.parse(body.toString('utf8')); } catch { bad('Expected a JSON object'); }
  if (!input || typeof input !== 'object' || Array.isArray(input)) bad('Expected a JSON object');
  if (Object.keys(input).some((key) => !['title', 'head', 'base', 'body', 'draft'].includes(key))) bad('Unsupported pull request field');
  if (typeof input.title !== 'string' || !input.title.trim() || input.title.length > 256 || /[\r\n\0]/.test(input.title)) bad('A title of at most 256 characters is required');
  const fork = gitlabForkHead(input.head, forks);
  if (!validBranch(fork ? fork.branch : input.head) || !validBranch(input.base) || input.head === input.base) bad('Provide different head and base branches');
  if (input.body !== undefined && (typeof input.body !== 'string' || input.body.length > 60000 || input.body.includes('\0'))) bad('Invalid pull request body');
  if (input.draft !== undefined && typeof input.draft !== 'boolean') bad('draft must be a boolean');
  return { title: input.title, head: input.head, base: input.base, body: input.body ?? '', draft: input.draft ?? true };
}

function pick(input, fields) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new GateError(502, 'INVALID_UPSTREAM', 'Invalid GitLab response');
  return Object.fromEntries(fields.filter((key) => input[key] === null || ['string', 'number', 'boolean'].includes(typeof input[key])).map((key) => [key, input[key]]));
}

function listOf(value, project) {
  if (!Array.isArray(value)) throw new GateError(502, 'INVALID_UPSTREAM', 'Invalid GitLab list response');
  return value.map(project);
}

// GitLab merge request -> GitHub pull request shape the CLI prints.
function pull(value) {
  if (!value || typeof value !== 'object') throw new GateError(502, 'INVALID_UPSTREAM', 'Invalid GitLab response');
  const state = value.state === 'opened' ? 'open' : value.state === 'merged' ? 'closed' : value.state;
  return {
    number: value.iid, title: value.title, body: value.description ?? null, state, draft: value.draft ?? value.work_in_progress ?? false,
    html_url: value.web_url, created_at: value.created_at, updated_at: value.updated_at, merged: value.state === 'merged',
    mergeable: value.detailed_merge_status === undefined ? null : value.detailed_merge_status === 'mergeable',
    head: { ref: value.source_branch, sha: value.sha ?? value.diff_refs?.head_sha ?? null }, base: { ref: value.target_branch, sha: value.diff_refs?.base_sha ?? null },
    user: { login: value.author?.username }
  };
}

// GitLab pipeline/job status -> GitHub status + conclusion.
function conclusionOf(status) {
  return { success: ['completed', 'success'], failed: ['completed', 'failure'], canceled: ['completed', 'cancelled'], skipped: ['completed', 'skipped'], manual: ['completed', 'action_required'] }[status] ?? [['created', 'waiting_for_resource', 'preparing', 'pending', 'scheduled'].includes(status) ? 'queued' : 'in_progress', null];
}

function run(value) {
  const [status, conclusion] = conclusionOf(value?.status);
  return { ...pick(value, ['id', 'name']), head_branch: value.ref, head_sha: value.sha, event: value.source ?? null, status, conclusion, html_url: value.web_url, created_at: value.created_at, updated_at: value.updated_at, run_number: value.iid ?? null, run_attempt: null };
}

function job(value) {
  const [status, conclusion] = conclusionOf(value?.status);
  return { ...pick(value, ['id', 'name']), status, conclusion, html_url: value.web_url, started_at: value.started_at, completed_at: value.finished_at, steps: [] };
}

function comment(value) {
  return { ...pick(value, ['id', 'body', 'created_at', 'updated_at']), html_url: null, user: { login: value.author?.username } };
}

export function projectGitlabResponse(operation, data) {
  if (operation.kind === 'review') return { id: data?.id, state: 'COMMENTED', body: data?.body, html_url: null, submitted_at: data?.created_at };
  if (operation.resource.endsWith('/comments')) return operation.create ? comment(data) : listOf(data, comment);
  if (operation.kind === 'merge') return { merged: data?.state === 'merged', sha: data?.merge_commit_sha ?? data?.squash_commit_sha ?? data?.sha ?? null };
  if (operation.resource === 'pulls' && !operation.create) return listOf(data, pull);
  if (operation.resource.startsWith('pulls')) return pull(data);
  if (operation.resource === 'actions/runs') { const runs = listOf(data, run); return { total_count: runs.length, workflow_runs: runs }; }
  if (operation.resource.endsWith('/jobs')) { const jobs = listOf(data, job); return { total_count: jobs.length, jobs }; }
  return run(data);
}

async function readJson(response) {
  if (!response.headers.get('content-type')?.includes('json') || !response.body) throw new GateError(502, 'INVALID_UPSTREAM', 'Expected GitLab JSON response');
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > 4 * 1024 * 1024) throw new GateError(502, 'UPSTREAM_TOO_LARGE', 'GitLab response too large; reduce per_page');
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString()); } catch { throw new GateError(502, 'INVALID_UPSTREAM', 'Invalid GitLab JSON response'); }
}

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

// GitLab: the job trace is returned in the response body with the token still attached upstream.
// A redirect is never followed (apiRaw uses redirect: 'manual'), so no storage host is contacted.
async function streamTrace({ provider, repository, operation, controller, response, state, base, approvalId }) {
  const trace = await provider.apiRaw({ repository, operation, signal: controller.signal });
  if (trace.status !== 200 || !trace.body) {
    await trace.body?.cancel().catch(() => {});
    throw new GateError(trace.status === 404 ? 404 : 502, 'UPSTREAM_FAILED', `Job trace download failed (${trace.status})`);
  }
  state.audit({ ...base, type: 'execution', approvalId, upstreamStatus: trace.status, result: 'upstream-response' });
  response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  const cap = capStream(MAX_LOG_BYTES);
  let outcome = 'log-complete';
  try {
    await pipeline(Readable.fromWeb(trace.body), cap, response);
  } catch (error) {
    outcome = cap.truncated ? 'log-truncated' : 'log-interrupted';
    if (!cap.truncated) throw error;
  } finally {
    try { state.audit({ ...base, type: 'execution', approvalId, result: outcome, bytes: Math.min(cap.bytes, MAX_LOG_BYTES), truncated: cap.truncated }); } catch { /* Never mask a settled download. */ }
  }
}

export async function handleGitlabApi({ request, response, operation, config, runtime = config.runtime, resolveEnvelope = async () => undefined, policyHash, state, provider, base, readBody, json, notify = () => {}, logger = { warn() {} } }) {
  const safeNotify = guardNotify(notify, logger);
  if (!runtime?.human) throw new GateError(500, 'INTERNAL_ERROR', 'Runtime identity unavailable');
  const repository = config.repositories.find((repo) => repo.name === operation.name);
  Object.assign(base, { repository: operation.name, action: operation.action });
  const envelope = await resolveEnvelope();
  if (!repository || decide(config, 'git.read', operation.name, undefined, envelope).effect !== 'allow') {
    state.audit({ ...base, type: 'decision', decision: 'deny' });
    throw new GateError(403, 'DENIED', 'Repository read denied');
  }
  const forks = operation.kind === 'pr-create' ? config.repositories
    .filter((repo) => repo.forkOf === operation.name && decide(config, 'git.read', repo.name, undefined, envelope).effect === 'allow')
    .map((repo) => ({ owner: repo.name.split('/')[0], name: repo.name, projectId: repo.projectId })) : [];
  let payload;
  if (operation.create) {
    if (request.headers['content-type']?.split(';')[0] !== 'application/json') throw new GateError(415, 'INVALID_CONTENT_TYPE', 'Expected application/json');
    const body = await readBody(request, 64 * 1024);
    payload = operation.kind === 'pr-create' ? mergeRequestPayload(body, { forks })
      : operation.kind === 'merge' ? mergePayload(body)
        : operation.kind === 'review' ? reviewPayload(body) : commentPayload(body);
    // GitLab: no rebase merge through the accept API; the project's merge method setting governs.
    if (operation.kind === 'merge' && payload.merge_method === 'rebase') bad('GitLab merges support merge or squash; rebase is a project setting');
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

async function readMergeRequest({ provider, repository, iid, controller, state, base, audit }) {
  const current = await provider.api({ repository, operation: { method: 'GET', path: `merge_requests/${iid}` }, payload: undefined, signal: controller.signal });
  if (current.status !== 200) {
    await current.body?.cancel();
    state.audit({ ...base, ...audit, upstreamStatus: current.status, result: 'pull-request-unavailable' });
    if ([403, 404].includes(current.status)) throw new GateError(404, 'UPSTREAM_FAILED', 'Merge request not found or unavailable');
    throw new GateError(502, 'UPSTREAM_FAILED', `GitLab failed to return the merge request (${current.status})`);
  }
  const mr = await readJson(current);
  if (!mr || typeof mr !== 'object' || typeof mr.target_branch !== 'string' || !validBranch(mr.target_branch) || typeof mr.sha !== 'string') {
    throw new GateError(502, 'INVALID_UPSTREAM', 'Invalid GitLab merge request response');
  }
  return mr;
}

async function preMerge({ provider, repository, operation, payload, controller, state, base, config }) {
  const iid = Number(operation.id);
  const mr = await readMergeRequest({ provider, repository, iid, controller, state, base, audit: { type: 'decision', decision: 'deny' } });
  // GitLab: a fork head is identified by source_project_id; map it back to a configured fork.
  let headRepository;
  if (Number.isSafeInteger(mr.source_project_id) && mr.source_project_id !== repository.projectId) {
    headRepository = config.repositories.find((repo) => repo.projectId === mr.source_project_id && repo.forkOf === repository.name)?.name ?? '';
  }
  if (headRepository) base.headRepository = headRepository;
  const draft = mr.draft ?? mr.work_in_progress ?? false;
  if (mr.state !== 'opened' || draft !== false) {
    state.audit({ ...base, type: 'decision', decision: 'deny', result: 'pr-not-mergeable' });
    throw new GateError(409, 'PR_NOT_MERGEABLE', 'Merge request must be open and not a draft');
  }
  if (mr.sha !== payload.sha) {
    state.audit({ ...base, type: 'decision', decision: 'deny', result: 'head-moved' });
    throw new GateError(409, 'HEAD_MOVED', 'Merge request head changed; review the new commits and request approval again');
  }
  const title = typeof mr.title === 'string' ? mr.title.replace(/[ -]+/g, ' ').slice(0, 256) : '';
  return { number: iid, base: mr.target_branch, title, headRepository, change: { ref: `refs/heads/${mr.target_branch}`, ...(headRepository === undefined ? {} : { headRepository }) } };
}

async function authorizeAndExecute({ response, operation, config, runtime, envelope, policyHash, state, provider, base, json, safeNotify, repository, forks, payload, controller }) {
  let fork;
  const merge = operation.kind === 'merge' ? await preMerge({ provider, repository, operation, payload, controller, state, base, config }) : undefined;
  if (operation.kind === 'pr-create') fork = gitlabForkHead(payload.head, forks);
  if (fork) base.headRepository = fork.name;
  const decision = decide(config, operation.action, operation.name, merge ? merge.change : operation.kind !== 'pr-create' ? undefined
    : fork ? { ref: `refs/heads/${fork.branch}`, headRepository: fork.name } : { ref: `refs/heads/${payload.head}` }, envelope);
  if (merge && decision.effect === 'allow') throw new GateError(500, 'INVALID_POLICY', 'Merges require an approval rule');
  const bodyAudit = payload && (operation.kind === 'comment' || operation.kind === 'review') ? { bodyLength: payload.body.length } : {};
  let approvalId;
  if (decision.effect !== 'deny' && merge && !decision.mergeMethods?.includes(payload.merge_method)) {
    state.audit({ ...base, type: 'decision', decision: 'deny', rule: decision.rule, result: 'merge-method-denied' });
    throw new GateError(403, 'DENIED', `Merge method ${payload.merge_method} is not allowed by policy`);
  }
  if (decision.effect === 'deny') {
    state.audit({ ...base, ...bodyAudit, type: 'decision', decision: 'deny', rule: decision.rule });
    throw new GateError(403, 'DENIED', 'GitLab API operation denied by policy');
  }
  if (decision.effect === 'approval') {
    const context = merge
      ? { runtime, repository: operation.name, action: operation.action, number: merge.number, sha: payload.sha, base: merge.base,
        ...(merge.headRepository ? { headRepository: merge.headRepository } : {}), mergeMethod: payload.merge_method, policyHash }
      : { runtime, repository: operation.name, action: operation.action, payload, policyHash, ...(fork ? { headRepository: fork.name } : {}) };
    if (decision.reviewerSources) context.reviewerSources = decision.reviewerSources;
    if (envelope) context.entitlements = envelopeSummary(envelope);
    const key = fingerprint(context);
    approvalId = state.consume(key);
    if (!approvalId) {
      const pending = state.request(key, merge ? { ...context, title: merge.title } : context, { requiredApprovals: decision.requiredApprovals });
      if (pending.created) safeNotify(pending);
      state.audit({ ...base, ...bodyAudit, type: 'decision', decision: 'approval', approvalId: pending.id });
      return json(response, 403, { code: 'REQUIRE_APPROVAL', requestId: pending.id, requiredApprovals: pending.requiredApprovals, message: `Review ${pending.id} on the trusted host, then retry the same command` });
    }
  }
  state.audit({ ...base, ...bodyAudit, type: 'decision', decision: 'allow', rule: decision.rule, approvalId });
  if (merge) {
    const recheck = await readMergeRequest({ provider, repository, iid: merge.number, controller, state, base, audit: { type: 'execution', approvalId } });
    if (recheck.target_branch !== merge.base) {
      state.audit({ ...base, type: 'execution', approvalId, result: 'base-changed' });
      throw new GateError(409, 'BASE_CHANGED', 'Merge request target branch changed before the merge; request approval again');
    }
    if (recheck.sha !== payload.sha) {
      state.audit({ ...base, type: 'execution', approvalId, result: 'head-moved' });
      throw new GateError(409, 'HEAD_MOVED', 'Merge request head changed before the merge; request approval again');
    }
  }
  if (operation.kind === 'logs') return await streamTrace({ provider, repository, operation, controller, response, state, base, approvalId });
  // GitLab: translate the validated payload to the v4 request body.
  let upstreamPayload = payload;
  if (operation.kind === 'pr-create') {
    upstreamPayload = { source_branch: fork ? fork.branch : payload.head, target_branch: payload.base, title: payload.draft ? `Draft: ${payload.title}` : payload.title, description: payload.body,
      ...(fork ? { target_project_id: repository.projectId } : {}) };
  } else if (operation.kind === 'merge') upstreamPayload = { sha: payload.sha, squash: payload.merge_method === 'squash' };
  else if (operation.kind === 'review' || operation.kind === 'comment') upstreamPayload = { body: payload.body };
  // GitLab: a fork MR is created on the fork project (source) targeting the upstream project.
  const target = fork ? { ...repository, projectId: fork.projectId } : repository;
  const upstream = await provider.api({ repository: target, operation, payload: upstreamPayload, signal: controller.signal });
  state.audit({ ...base, type: 'execution', approvalId, upstreamStatus: upstream.status, result: upstream.ok ? 'upstream-response' : 'upstream-rejected' });
  const expectedStatus = operation.kind === 'merge' ? 200 : operation.create ? 201 : 200;
  if (upstream.status !== expectedStatus) {
    await upstream.body?.cancel();
    if (operation.kind === 'merge') {
      if ([405, 406].includes(upstream.status)) throw new GateError(409, 'PR_NOT_MERGEABLE', 'GitLab refused the merge (pipeline, approvals, conflicts, or branch protection)');
      if (upstream.status === 409) throw new GateError(409, 'HEAD_MOVED', 'Merge request head changed before the merge; request approval again');
      if (upstream.status === 422) throw new GateError(422, 'MERGE_REJECTED', 'GitLab rejected the merge request as invalid');
    }
    const messages = { 403: 'Check the OAuth token scopes or project permissions', 404: 'Resource not found or unavailable to this token', 409: 'A merge request for this branch may already exist', 422: 'Check branches and whether a merge request already exists' };
    throw new GateError([404, 409, 422].includes(upstream.status) ? upstream.status : 502, 'UPSTREAM_FAILED', `GitLab rejected the request (${upstream.status}). ${messages[upstream.status] ?? 'Inspect broker configuration'}`);
  }
  return json(response, upstream.status, projectGitlabResponse(operation, await readJson(upstream)));
}
