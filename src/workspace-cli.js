import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { chmodSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { connect } from 'node:net';
import { brokerUrl, clientAuthHeader, runtimeHeader, repositoryName, repositoryFromRemote } from './workspace-config.js';

const usage = `Usage:
  agentgate doctor
  agentgate fingerprint
  agentgate renew
  agentgate pr list [--repo OWNER/REPO] [--state open|closed|all] [--page N] [--per-page N]
  agentgate pr view NUMBER [--repo OWNER/REPO]
  agentgate pr create --title TITLE --base BRANCH [--head BRANCH] [--body-file FILE] [--ready] [--upstream OWNER/REPO] [--repo OWNER/REPO]
  agentgate pr comment NUMBER --body-file FILE [--repo OWNER/REPO]
  agentgate pr review NUMBER --body-file FILE [--repo OWNER/REPO]
  agentgate pr merge NUMBER --sha HEAD_SHA [--method squash|merge|rebase] [--repo OWNER/REPO]
  agentgate ci list [--repo OWNER/REPO] [--branch BRANCH] [--page N] [--per-page N]
  agentgate ci view RUN_ID [--repo OWNER/REPO]
  agentgate ci jobs RUN_ID [--repo OWNER/REPO] [--page N] [--per-page N]
  agentgate ci logs JOB_ID [--repo OWNER/REPO] [--output FILE] [--force]

Repository defaults to origin. PR head defaults to the current branch.
pr create --upstream opens the PR against OWNER/REPO with head OWNER_OF_REPO:BRANCH (a fork PR).
New PRs are drafts unless --ready is supplied. Output is JSON, except ci logs (plain text).
ci logs writes to FILE (mode 0600, refusing to overwrite one that exists unless --force given)
or to stdout when --output is omitted.
pr review always submits a COMMENT review; agents cannot approve or request changes.
pr merge needs a human approval and the full 40-character head SHA that was reviewed;
it fails if the PR head moved. --method defaults to squash.
renew re-runs workspace setup so Git picks up a renewed AGENTGATE_RUNTIME_ASSERTION_FILE.
fingerprint prints the SHA-256 of this workspace's client token; give it to whoever issues your
runtime assertion (issue-runtime.js --client-token-sha256) so the token itself never leaves here.
AGENTGATE_URL defaults to http://agentd:7432. No GitHub token is needed.`;

function git(...args) {
  try { return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim(); }
  catch { throw new Error(`git ${args.join(' ')} failed; check your repository and Git configuration`); }
}

function parse(args, allowed) {
  const options = {};
  while (args.length) {
    const key = args.shift();
    if (!allowed.includes(key) || Object.hasOwn(options, key)) throw new Error(`Unknown or duplicate option: ${key}`);
    if (key === '--ready' || key === '--force') options[key] = true;
    else {
      if (!args.length || args[0].startsWith('--')) throw new Error(`${key} requires a value`);
      options[key] = args.shift();
    }
  }
  return options;
}

async function request(broker, path, payload, method = payload === undefined ? 'GET' : 'POST') {
  const response = await fetch(`${broker}${path}`, {
    method,
    headers: { ...clientAuthHeader(), ...runtimeHeader(), ...(payload === undefined ? {} : { 'content-type': 'application/json' }) },
    body: payload === undefined ? undefined : JSON.stringify(payload),
    redirect: 'error', signal: AbortSignal.timeout(45_000)
  });
  const data = await response.json();
  if (!response.ok) throw new Error(`${data.code ?? response.status}: ${data.message ?? 'Broker request failed'}`);
  return data;
}

// CI job logs are plain text (never JSON): a large log body could otherwise be misparsed or
// truncated by a JSON parser, and the broker itself deliberately returns text/plain for this route.
async function requestLog(broker, path) {
  const response = await fetch(`${broker}${path}`, { headers: { ...clientAuthHeader(), ...runtimeHeader() }, redirect: 'error', signal: AbortSignal.timeout(150_000) });
  if (!response.ok) {
    let data = {};
    try { data = await response.json(); } catch { /* Broker errors are JSON; fall back to the status alone. */ }
    throw new Error(`${data.code ?? response.status}: ${data.message ?? 'Broker request failed'}`);
  }
  // A log that hit the broker's 64 MiB cap ends with the connection destroyed, not a clean end
  // (see src/github-api.js's streamLog): it must never be mistaken for a short-but-complete log,
  // so a body-read failure here is reported as a distinct, explicit error rather than silently
  // returning whatever partial text came through.
  try { return await response.text(); }
  catch (error) { throw new Error(`Log download was interrupted before it finished (the broker likely hit its size cap): ${error.message}`); }
}

// Reads the assertion the workspace will send without verifying its signature (the workspace has
// no issuer keys; only agentd verifies). It answers the developer's questions: who am I acting as,
// in which mode, until when, and is this assertion bound to the client token I actually hold.
function assertionCheck() {
  const check = { check: 'runtime assertion', ok: true, present: false };
  let header;
  try { header = runtimeHeader(); } catch (error) { return { ...check, ok: false, message: error.message }; }
  const token = header['x-agentgate-runtime'];
  if (!token) return { ...check, note: 'No runtime assertion; the broker identifies this workspace from its static configuration.' };
  let claims;
  try { claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')); }
  catch { return { ...check, ok: false, present: true, message: 'Runtime assertion payload is not valid JSON' }; }
  const seconds = Math.floor(Date.now() / 1000);
  const expiresIn = Number.isSafeInteger(claims.exp) ? claims.exp - seconds : undefined;
  let bound;
  try {
    const auth = clientAuthHeader().authorization;
    if (auth) bound = claims.cnf?.tokenSha256 === createHash('sha256').update(auth.slice('Bearer '.length)).digest('hex');
  } catch { bound = false; }
  const result = {
    ...check, present: true, runtime: claims.sub, human: claims.human, agent: claims.agent, team: claims.team, mode: claims.mode,
    ...(claims.task ? { task: `${claims.task.system}:${claims.task.id}` } : {}),
    ...(expiresIn === undefined ? {} : { expiresAt: new Date(claims.exp * 1000).toISOString(), expiresInSeconds: expiresIn }),
    ...(bound === undefined ? {} : { boundToClientToken: bound })
  };
  if (expiresIn === undefined) return { ...result, ok: false, message: 'Runtime assertion has no expiry' };
  if (expiresIn <= 0) return { ...result, ok: false, message: 'Runtime assertion has expired; ask its issuer for a new one, replace the file, and run agentgate renew' };
  if (bound === false) return { ...result, ok: false, message: 'Runtime assertion is bound to a different client token; the broker will reject it' };
  if (expiresIn < 3600) return { ...result, message: 'Runtime assertion expires within the hour; replace the file and run agentgate renew' };
  return result;
}

function reachable(url) {
  return new Promise((done) => {
    const target = new URL(url);
    const socket = connect({ host: target.hostname, port: Number(target.port) || (target.protocol === 'https:' ? 443 : 80) });
    const finish = (ok, message) => { socket.destroy(); done(ok ? { ok } : { ok, message }); };
    socket.setTimeout(3000, () => finish(false, 'connection timed out'));
    socket.once('connect', () => finish(true));
    socket.once('error', (error) => finish(false, error.message));
  });
}

// The gateway and proxy expose no health route to the workspace; TCP reachability is what a
// developer can act on (is it running, is the workspace network attached).
async function serviceCheck(name, url, extra = {}) {
  if (!url) return { check: name, ok: true, configured: false, ...extra };
  let probe;
  try { probe = await reachable(url); } catch (error) { probe = { ok: false, message: error.message }; }
  return { check: name, ok: probe.ok, configured: true, url, ...extra, ...(probe.message ? { message: `${url}: ${probe.message}` } : {}) };
}

async function doctor(broker) {
  const checks = [];
  for (const [label, args] of [['git', ['--version']], ['git-lfs', ['lfs', 'version']], ['commit name', ['config', 'user.name']], ['commit email', ['config', 'user.email']]]) {
    try { const value = git(...args); checks.push({ check: label, ok: Boolean(value), value }); }
    catch { checks.push({ check: label, ok: false }); }
  }
  try {
    // /healthz is unauthenticated, so a broken token or assertion file cannot mask an unreachable
    // broker (or the other way round); those files get their own checks below.
    const response = await fetch(`${broker}/healthz`, { redirect: 'error', signal: AbortSignal.timeout(10_000) });
    const health = await response.json();
    checks.push({ check: 'broker', ok: response.ok && health.status === 'ok', url: broker, capabilities: health.capabilities });
  } catch (error) { checks.push({ check: 'broker', ok: false, url: broker, message: error.message }); }
  try {
    clientAuthHeader();
    checks.push({ check: 'client token', ok: true, configured: Boolean(process.env.AGENTGATE_CLIENT_TOKEN_FILE) });
  } catch (error) { checks.push({ check: 'client token', ok: false, message: error.message }); }
  checks.push(assertionCheck());
  const gatewayUrl = process.env.ANTHROPIC_BASE_URL;
  const tokenExported = Boolean(process.env.ANTHROPIC_AUTH_TOKEN);
  let tokenFile = false;
  try { tokenFile = Boolean(process.env.AGENTGATE_MODEL_GATEWAY_TOKEN_FILE) && readFileSync(process.env.AGENTGATE_MODEL_GATEWAY_TOKEN_FILE, 'utf8').trim().length > 0; } catch { tokenFile = false; }
  const gateway = await serviceCheck('model gateway', gatewayUrl, { tokenExported, tokenFile });
  if (gateway.configured && !tokenExported) {
    const note = tokenFile
      // docker exec and IDE attaches bypass the entrypoint; login and interactive shells source
      // /etc/profile.d/agentgate.sh, so only a bare non-interactive exec is missing the token.
      ? 'ANTHROPIC_AUTH_TOKEN is not exported in this shell; login and interactive shells source /etc/profile.d/agentgate.sh, so run tools via `bash -lc` from non-interactive exec sessions'
      : 'ANTHROPIC_AUTH_TOKEN is not exported and no readable AGENTGATE_MODEL_GATEWAY_TOKEN_FILE is set: model calls will reach the gateway without a client token';
    if (!tokenFile) gateway.ok = false;
    gateway.message = `${gateway.message ? `${gateway.message}; ` : ''}${note}`;
  }
  checks.push(gateway);
  checks.push(await serviceCheck('egress proxy', process.env.HTTPS_PROXY || process.env.https_proxy));
  console.log(JSON.stringify({ checks, notes: [
    'Use agentgate pr/ci for brokered GitHub access; gh requires separate API connectivity and authentication.',
    'Model traffic is governed only for tools that honour ANTHROPIC_BASE_URL; an IDE\'s own assistant talks to its vendor directly.'
  ] }, null, 2));
  if (checks.some((check) => !check.ok)) process.exitCode = 1;
}

async function main() {
  const args = process.argv.slice(2);
  if (!args.length || args[0] === '--help' || args[0] === 'help') return console.log(usage);
  if (args[0] === 'renew' && args.length === 1) {
    execFileSync(process.execPath, [fileURLToPath(new URL('./workspace-setup.js', import.meta.url))], { stdio: 'inherit' });
    return console.log(JSON.stringify({ renewed: true }));
  }
  const broker = brokerUrl();
  const group = args.shift();
  if (group === 'doctor' && !args.length) return doctor(broker);
  if (group === 'fingerprint' && !args.length) {
    if (!process.env.AGENTGATE_CLIENT_TOKEN_FILE) throw new Error('AGENTGATE_CLIENT_TOKEN_FILE is not set; there is no client token to fingerprint');
    const token = clientAuthHeader().authorization.slice('Bearer '.length);
    return console.log(JSON.stringify({ clientTokenSha256: createHash('sha256').update(token).digest('hex') }));
  }
  const command = args.shift();
  const mode = `${group} ${command}`;
  const allowed = {
    'pr list': ['--state', '--page', '--per-page'], 'pr view': [],
    'pr create': ['--title', '--base', '--head', '--body-file', '--ready', '--upstream'],
    'pr comment': ['--body-file'], 'pr review': ['--body-file'], 'pr merge': ['--sha', '--method'],
    'ci list': ['--branch', '--page', '--per-page'], 'ci view': [], 'ci jobs': ['--page', '--per-page'],
    'ci logs': ['--output', '--force']
  };
  if (!Object.hasOwn(allowed, mode)) throw new Error(usage);
  let id;
  if (['pr view', 'pr comment', 'pr review', 'pr merge', 'ci view', 'ci jobs', 'ci logs'].includes(mode)) {
    id = args.shift();
    if (!/^[1-9][0-9]{0,14}$/.test(id || '')) throw new Error('A positive pull request number or run/job ID is required');
  }
  const options = parse(args, ['--repo', ...allowed[mode]]);
  const repository = options['--repo'] ? repositoryName(options['--repo']) : repositoryFromRemote(git('config', '--get', 'remote.origin.url'), broker);
  if (mode === 'ci logs') {
    const text = await requestLog(broker, `/api/repos/${repository}/actions/jobs/${id}/logs`);
    if (!options['--output']) { process.stdout.write(text); return; }
    try { writeFileSync(options['--output'], text, { mode: 0o600, flag: options['--force'] ? 'w' : 'wx' }); }
    catch (error) { throw error.code === 'EEXIST' ? new Error(`${options['--output']} already exists; use --force to overwrite`) : error; }
    // `mode` above only applies to a newly created file; force-overwriting an existing file
    // (which may have looser permissions from elsewhere) still ends with 0600.
    chmodSync(options['--output'], 0o600);
    return;
  }
  let path;
  const upstream = options['--upstream'] ? repositoryName(options['--upstream']) : undefined;
  if (upstream) path = `/api/repos/${upstream}/pulls`;
  else if (mode === 'pr comment') path = `/api/repos/${repository}/issues/${id}/comments`;
  else if (mode === 'pr review') path = `/api/repos/${repository}/pulls/${id}/reviews`;
  else if (mode === 'pr merge') path = `/api/repos/${repository}/pulls/${id}/merge`;
  else {
    path = `/api/repos/${repository}/${group === 'pr' ? 'pulls' : 'actions/runs'}`;
    if (id) path += `/${id}${command === 'jobs' ? '/jobs' : ''}`;
    const query = new URLSearchParams();
    for (const [flag, key] of [['--page', 'page'], ['--per-page', 'per_page'], ['--state', 'state'], ['--branch', 'branch']]) {
      if (options[flag]) query.set(key, options[flag]);
    }
    if (query.size) path += `?${query}`;
  }
  let payload;
  if (mode === 'pr create') {
    if (!options['--title'] || !options['--base']) throw new Error('pr create requires --title and --base');
    payload = {
      title: options['--title'], base: options['--base'], head: options['--head'] || git('branch', '--show-current'),
      body: options['--body-file'] ? readFileSync(options['--body-file'], 'utf8') : '', draft: !options['--ready']
    };
    if (!payload.head) throw new Error('Detached HEAD; provide --head BRANCH');
    if (upstream) {
      if (payload.head.includes(':')) throw new Error('--head must be a branch name when --upstream is used');
      payload.head = `${repository.split('/')[0]}:${payload.head}`;
    }
  } else if (mode === 'pr comment' || mode === 'pr review') {
    if (!options['--body-file']) throw new Error(`${mode} requires --body-file`);
    payload = { body: readFileSync(options['--body-file'], 'utf8'), ...(mode === 'pr review' ? { event: 'COMMENT' } : {}) };
  } else if (mode === 'pr merge') {
    if (!/^[0-9a-f]{40}$/.test(options['--sha'] ?? '')) throw new Error('pr merge requires --sha with the full 40-character lowercase head commit SHA');
    const method = options['--method'] ?? 'squash';
    if (!['squash', 'merge', 'rebase'].includes(method)) throw new Error('--method must be squash, merge, or rebase');
    payload = { sha: options['--sha'], merge_method: method };
  }
  console.log(JSON.stringify(await request(broker, path, payload, mode === 'pr merge' ? 'PUT' : undefined), null, 2));
}

main().catch((error) => {
  console.error(`AgentBox: ${error.message}`);
  process.exitCode = 1;
});
