import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import { adminRequest } from '../src/admin-client.js';
import { GitHub } from '../src/github.js';
import { verifyProtectedBranches } from '../src/rulesets.js';
import { startGate } from '../src/server.js';
import { signerFromEnv } from '../src/signer.js';

const execute = promisify(execFile);
const env = process.env;
for (const name of ['LIVE_GITHUB_APP_ID', 'LIVE_REPO', 'LIVE_REPO_ID', 'LIVE_INSTALLATION_ID']) assert(env[name], `${name} is required`);
const run = randomUUID().slice(0, 8);
const branch = `agent/live-${run}`;
const approvalBranch = `live-approval/${run}`;
const repository = { name: env.LIVE_REPO.toLowerCase(), id: Number(env.LIVE_REPO_ID), installationId: Number(env.LIVE_INSTALLATION_ID), protectedBranches: ['main'] };
const config = {
  runtime: { human: 'live-smoke@ci', agent: 'live-smoke', runtimeId: `live-${run}`, task: 'live-smoke' },
  repositories: [repository],
  rules: [
    { id: 'read', action: 'git.read', repository: repository.name, effect: 'allow' },
    { id: 'pr-read', action: 'github.pr.read', repository: repository.name, effect: 'allow' },
    { id: 'pr-create', action: 'github.pr.create', repository: repository.name, ref: 'refs/heads/agent/*', effect: 'allow' },
    { id: 'pr-comment', action: 'github.pr.comment', repository: repository.name, effect: 'allow' },
    { id: 'ci-read', action: 'github.actions.read', repository: repository.name, effect: 'allow' },
    { id: 'feature', action: 'git.push', repository: repository.name, ref: 'refs/heads/agent/*', effect: 'allow' },
    { id: 'approval', action: 'git.push', repository: repository.name, ref: 'refs/heads/live-approval/*', effect: 'approval' },
    { id: 'main', action: 'git.push', repository: repository.name, ref: 'refs/heads/main', effect: 'deny' },
    { id: 'lfs-upload', action: 'git.lfs.upload', repository: repository.name, effect: 'allow' }
  ]
};
const provider = new GitHub({ appId: env.LIVE_GITHUB_APP_ID, signer: signerFromEnv({ ...env, GITHUB_PRIVATE_KEY_PATH: env.LIVE_GITHUB_PRIVATE_KEY_PATH }) });
const directory = await mkdtemp(join(tmpdir(), 'agentgate-live-'));
const clientToken = randomBytes(32).toString('hex');
const gitEnv = { PATH: env.PATH, HOME: directory, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0',
  GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'http.extraHeader', GIT_CONFIG_VALUE_0: `Authorization: Bearer ${clientToken}` };
const git = async (cwd, ...args) => (await execute('git', args, { cwd, env: gitEnv })).stdout.trim();
let gate;
let prNumber;
const step = (name) => console.log(`live-smoke: ${name}`);
try {
  step('verify branch rules');
  assert.deepEqual(await verifyProtectedBranches(config, provider), []);
  // Upload storage hosts are unverified by default (see src/lfs.js); LIVE_LFS_HOSTS adds confirmed ones.
  const lfsHosts = env.LIVE_LFS_HOSTS ? env.LIVE_LFS_HOSTS.split(',').map((item) => item.trim()) : undefined;
  gate = await startGate({ config, provider, stateDirectory: join(directory, 'state'), port: 0, clientToken, ...(lfsHosts ? { lfsHosts } : {}) });
  const remote = `${gate.url}/${repository.name}.git`;
  const auth = { authorization: `Bearer ${clientToken}` };
  const clone = join(directory, 'clone');
  step('clone');
  await git(directory, 'clone', remote, clone);
  await git(clone, 'config', 'user.name', 'AgentBox Live Smoke');
  await git(clone, 'config', 'user.email', 'live-smoke@example.com');
  await git(clone, 'switch', '-c', branch);
  await writeFile(join(clone, `live-${run}.txt`), `${run}\n`);
  await git(clone, 'add', '.');
  await git(clone, 'commit', '-m', `live smoke ${run}`);
  step('allowed push');
  await git(clone, 'push', 'origin', `HEAD:refs/heads/${branch}`);
  step('denied push to main');
  await assert.rejects(git(clone, 'push', 'origin', 'HEAD:refs/heads/main'));
  step('approval-gated push');
  await assert.rejects(git(clone, 'push', 'origin', `HEAD:refs/heads/${approvalBranch}`));
  const [pending] = await adminRequest(gate.adminSocket, 'GET', '/approvals');
  await adminRequest(gate.adminSocket, 'POST', `/approvals/${pending.id}/approve`, { reviewer: 'local:reviewer' });
  await git(clone, 'push', 'origin', `HEAD:refs/heads/${approvalBranch}`);
  step('LFS round trip');
  const lfsFile = `live-${run}.bin`;
  const lfsBytes = randomBytes(1024 * 1024);
  await git(clone, 'lfs', 'install', '--local');
  await git(clone, 'lfs', 'track', '*.bin');
  await writeFile(join(clone, lfsFile), lfsBytes);
  await git(clone, 'add', '.gitattributes', lfsFile);
  await git(clone, 'commit', '-m', `live smoke LFS ${run}`);
  await git(clone, 'push', 'origin', `HEAD:refs/heads/${branch}`);
  const lfsClone = join(directory, 'lfs-clone');
  await execute('git', ['clone', '--branch', branch, remote, lfsClone], { env: { ...gitEnv, GIT_LFS_SKIP_SMUDGE: '1' } });
  await git(lfsClone, 'lfs', 'install', '--local');
  await git(lfsClone, 'lfs', 'pull');
  assert((await readFile(join(lfsClone, lfsFile))).equals(lfsBytes), 'LFS object bytes differ after round trip');
  step('fetch after push');
  await git(clone, 'fetch', 'origin');
  step('create draft PR');
  const created = await fetch(`${gate.url}/api/repos/${repository.name}/pulls`, { method: 'POST', headers: { ...auth, 'content-type': 'application/json' },
    body: JSON.stringify({ title: `Live smoke ${run}`, head: branch, base: 'main', body: 'Automated; closed by the test.', draft: true }) });
  assert.equal(created.status, 201, await created.clone().text());
  prNumber = (await created.json()).number;
  step('comment on draft PR');
  const commented = await fetch(`${gate.url}/api/repos/${repository.name}/issues/${prNumber}/comments`, { method: 'POST', headers: { ...auth, 'content-type': 'application/json' },
    body: JSON.stringify({ body: `Automated live-smoke comment ${run}.` }) });
  assert.equal(commented.status, 201, await commented.clone().text());
  step('list PRs and CI runs');
  const pulls = await (await fetch(`${gate.url}/api/repos/${repository.name}/pulls?state=open`, { headers: auth })).json();
  assert(pulls.some((pull) => pull.number === prNumber));
  let runs;
  for (let attempt = 0; attempt < 30; attempt++) {
    runs = await (await fetch(`${gate.url}/api/repos/${repository.name}/actions/runs?branch=${encodeURIComponent(branch)}`, { headers: auth })).json();
    if (runs.workflow_runs?.length) break;
    await new Promise((resolve) => setTimeout(resolve, 5000));
  }
  assert(runs.workflow_runs.length > 0, 'No CI run appeared for the pushed branch');
  step('ci job logs');
  // Job logs are only published once the job finishes; wait for the first job of the observed
  // run to complete, then download its log through the brokered, allowlisted-redirect route.
  const runId = runs.workflow_runs[0].id;
  let jobs;
  for (let attempt = 0; attempt < 30; attempt++) {
    jobs = await (await fetch(`${gate.url}/api/repos/${repository.name}/actions/runs/${runId}/jobs`, { headers: auth })).json();
    if (jobs.jobs?.some((job) => job.status === 'completed')) break;
    await new Promise((resolve) => setTimeout(resolve, 5000));
  }
  const job = jobs.jobs?.find((item) => item.status === 'completed') ?? jobs.jobs?.[0];
  assert(job, 'No job appeared for the CI run');
  const logs = await fetch(`${gate.url}/api/repos/${repository.name}/actions/jobs/${job.id}/logs`, { headers: auth });
  assert.equal(logs.status, 200, `job log download failed (${logs.status}): ${await logs.clone().text()}`);
  assert.equal(logs.headers.get('content-type'), 'text/plain; charset=utf-8');
  const logText = await logs.text();
  assert(logText.length > 0, 'job log body was empty');
  step('token leakage check');
  const audit = await readFile(join(directory, 'state', 'audit.jsonl'), 'utf8');
  assert(!/ghs_[A-Za-z0-9]{20,}/.test(audit), 'Installation token found in audit log');
  console.log('live-smoke: PASS');
} finally {
  // Cleanup uses the trusted provider directly; the broker intentionally cannot delete refs or close PRs.
  const cleanup = async (operation) => {
    try {
      const response = await provider.api({ repository, operation, payload: operation.payload, signal: AbortSignal.timeout(15_000) });
      await response.body?.cancel();
      // A ref DELETE returning 404/422 means the ref is already gone (e.g. the approval-gated
      // push never landed) — that is a clean outcome, not a cleanup failure.
      const alreadyGone = operation.method === 'DELETE' && (response.status === 404 || response.status === 422);
      if (!alreadyGone && (response.status < 200 || response.status >= 300)) throw new Error(`status ${response.status}`);
    } catch (error) { console.error(`live-smoke cleanup: ${operation.method} ${operation.path}: ${error.message}`); process.exitCode = 1; }
  };
  if (prNumber) await cleanup({ method: 'PATCH', path: `pulls/${prNumber}`, payload: { state: 'closed' }, permissions: { pull_requests: 'write' } });
  await cleanup({ method: 'DELETE', path: `git/refs/heads/${branch}`, permissions: { contents: 'write' } });
  await cleanup({ method: 'DELETE', path: `git/refs/heads/${approvalBranch}`, permissions: { contents: 'write' } });
  await gate?.close();
  await rm(directory, { recursive: true, force: true });
}
