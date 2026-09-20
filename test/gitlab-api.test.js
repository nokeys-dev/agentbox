import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join, resolve } from 'node:path';
import { readFile, writeFile } from 'node:fs/promises';
import { fixture } from './support/fixture.js';
import { adminRequest } from '../src/admin-client.js';
import { gitlabForkHead, mergeRequestPayload, projectGitlabResponse, routeGitlabApi } from '../src/gitlab-api.js';
import { verifyProtectedBranches } from '../src/rulesets.js';
import { validateConfig } from '../src/config.js';

const execute = promisify(execFile);

function gitlabConfig(mergeEffect = 'approval') {
  return {
    provider: 'gitlab',
    runtime: { human: 'dev@example.com', agent: 'cursor', runtimeId: 'rt-gl', task: 'none' },
    repositories: [
      { name: 'acme/demo', projectId: 42, protectedBranches: ['main'] },
      { name: 'agent-bot/demo', projectId: 77, forkOf: 'acme/demo' }
    ],
    rules: [
      { id: 'read', action: 'git.read', repository: '*', effect: 'allow' },
      { id: 'push', action: 'git.push', repository: '*', ref: 'refs/heads/agent/*', effect: 'allow' },
      { id: 'main', action: 'git.push', repository: '*', ref: 'refs/heads/main', effect: 'approval' },
      { id: 'mr-read', action: 'gitlab.mr.read', repository: '*', effect: 'allow' },
      { id: 'mr-create', action: 'gitlab.mr.create', repository: 'acme/demo', ref: 'refs/heads/agent/*', effect: 'allow' },
      { id: 'mr-create-fork', action: 'gitlab.mr.create', repository: 'acme/demo', ref: 'refs/heads/agent/*', effect: 'allow', headRepository: 'agent-bot/demo' },
      { id: 'mr-comment', action: 'gitlab.mr.comment', repository: '*', effect: 'allow' },
      { id: 'pipelines', action: 'gitlab.pipelines.read', repository: '*', effect: 'allow' },
      { id: 'mr-merge', action: 'gitlab.mr.merge', repository: 'acme/demo', ref: 'refs/heads/main', effect: mergeEffect, mergeMethods: ['squash', 'merge'] }
    ]
  };
}

test('config validates GitLab projects and actions and refuses GitHub-only fields and allow-merges', () => {
  assert.doesNotThrow(() => validateConfig(gitlabConfig()));
  const nested = gitlabConfig(); nested.repositories[0].name = 'Acme/Platform/Demo'; nested.repositories[1].forkOf = 'acme/platform/demo'; nested.rules = nested.rules.filter((rule) => !['acme/demo', 'agent-bot/demo'].includes(rule.repository ?? '') && rule.headRepository === undefined);
  assert.equal(validateConfig(nested).repositories[0].name, 'acme/platform/demo');
  for (const [patch, pattern] of [
    [(c) => { c.repositories[0].id = 1; }, /Unknown repository field: id/],
    [(c) => { c.repositories[0].name = 'acme/../demo'; }, /GitLab project names/],
    [(c) => { c.repositories[0].name = 'demo'; }, /GitLab project names/],
    [(c) => { delete c.repositories[0].projectId; }, /projectId/],
    [(c) => { c.rules.push({ id: 'gh', action: 'github.pr.read', repository: '*', effect: 'allow' }); }, /Invalid action in gh for provider gitlab/],
    [(c) => { c.rules.at(-1).effect = 'allow'; }, /must use approval or deny/],
    [(c) => { c.rules.at(-1).mergeMethods = ['rebase']; }, /merge\/squash/],
    [(c) => { c.provider = 'bitbucket'; }, /provider must be/]
  ]) {
    const config = gitlabConfig(); patch(config);
    assert.throws(() => validateConfig(config), pattern);
  }
  const github = { runtime: gitlabConfig().runtime, repositories: [{ name: 'acme/demo', id: 1, installationId: 2 }], rules: [] };
  assert.doesNotThrow(() => validateConfig(github), 'GitHub validation is unchanged');
});

test('routeGitlabApi maps the GitHub-shaped broker paths to GitLab v4 project paths', () => {
  const route = (url, method = 'GET') => routeGitlabApi({ url, method });
  assert.deepEqual(route('/api/repos/acme/demo/pulls?state=open&per_page=5').path, 'merge_requests?page=1&per_page=5&state=opened');
  assert.equal(route('/api/repos/acme/platform/demo/pulls/7').name, 'acme/platform/demo');
  assert.equal(route('/api/repos/acme/demo/pulls/7').path, 'merge_requests/7');
  assert.equal(route('/api/repos/acme/demo/pulls/7/comments').path, 'merge_requests/7/notes?page=1&per_page=30&sort=asc');
  assert.equal(route('/api/repos/acme/demo/issues/7/comments', 'POST').path, 'merge_requests/7/notes');
  assert.equal(route('/api/repos/acme/demo/pulls/7/reviews', 'POST').kind, 'review');
  assert.deepEqual([route('/api/repos/acme/demo/pulls/7/merge', 'PUT').path, route('/api/repos/acme/demo/pulls/7/merge', 'PUT').action], ['merge_requests/7/merge', 'gitlab.mr.merge']);
  assert.equal(route('/api/repos/acme/demo/actions/runs?branch=agent/x').path, 'pipelines?page=1&per_page=30&ref=agent%2Fx');
  assert.equal(route('/api/repos/acme/demo/actions/runs/3/jobs').path, 'pipelines/3/jobs?page=1&per_page=30');
  assert.deepEqual([route('/api/repos/acme/demo/actions/jobs/9/logs').path, route('/api/repos/acme/demo/actions/jobs/9/logs').kind], ['jobs/9/trace', 'logs']);
  assert.throws(() => route('/api/repos/acme/demo/pulls/7/merge', 'POST'), { code: 'METHOD_NOT_ALLOWED' });
  assert.throws(() => route('/api/repos/acme/../demo/pulls'), { code: 'NOT_FOUND' });
  assert.throws(() => route('/api/repos/acme/demo/pulls?state=merged'), { code: 'INVALID_API_REQUEST' });
  assert.throws(() => route('/api/repos/acme/demo/pulls?per_page=500'), { code: 'INVALID_API_REQUEST' });
});

test('payloads and projections keep the CLI output shape and drop everything else', () => {
  const forks = [{ owner: 'agent-bot', name: 'agent-bot/demo', projectId: 77 }];
  assert.deepEqual(gitlabForkHead('agent-bot:agent/x', forks), { owner: 'agent-bot', name: 'agent-bot/demo', projectId: 77, branch: 'agent/x' });
  assert.throws(() => gitlabForkHead('nobody:agent/x', forks), { code: 'INVALID_API_REQUEST' });
  assert.equal(mergeRequestPayload(Buffer.from(JSON.stringify({ title: 'T', head: 'agent/x', base: 'main' }))).draft, true);
  assert.throws(() => mergeRequestPayload(Buffer.from(JSON.stringify({ title: 'T', head: 'main', base: 'main' }))), { code: 'INVALID_API_REQUEST' });
  const mr = { iid: 7, title: 'T', description: 'd', state: 'opened', draft: false, web_url: 'https://gitlab.example.com/x', sha: 'a'.repeat(40), source_branch: 'agent/x', target_branch: 'main', author: { username: 'bot', email: 'secret@example.com' }, detailed_merge_status: 'mergeable', diff_refs: { base_sha: 'b'.repeat(40) } };
  const projected = projectGitlabResponse({ resource: 'pulls/7', kind: 'read', create: false }, mr);
  assert.equal(projected.number, 7);
  assert.equal(projected.state, 'open');
  assert.deepEqual(projected.head, { ref: 'agent/x', sha: 'a'.repeat(40) });
  assert.deepEqual(projected.user, { login: 'bot' });
  assert.ok(!JSON.stringify(projected).includes('secret@example.com'));
  const runs = projectGitlabResponse({ resource: 'actions/runs', kind: 'read', create: false }, [{ id: 3, ref: 'agent/x', sha: 'c'.repeat(40), status: 'failed', web_url: 'u', source: 'push', iid: 12 }, { id: 4, status: 'running' }]);
  assert.equal(runs.total_count, 2);
  assert.deepEqual([runs.workflow_runs[0].status, runs.workflow_runs[0].conclusion, runs.workflow_runs[1].status, runs.workflow_runs[1].conclusion], ['completed', 'failure', 'in_progress', null]);
  const jobs = projectGitlabResponse({ resource: 'actions/runs/3/jobs', kind: 'read', create: false }, [{ id: 9, name: 'test', status: 'success', web_url: 'u', started_at: 's', finished_at: 'f' }]);
  assert.deepEqual(jobs.jobs[0], { id: 9, name: 'test', status: 'completed', conclusion: 'success', html_url: 'u', started_at: 's', completed_at: 'f', steps: [] });
  assert.deepEqual(projectGitlabResponse({ resource: 'pulls/7/merge', kind: 'merge', create: true }, { state: 'merged', merge_commit_sha: 'm' }), { merged: true, sha: 'm' });
  assert.throws(() => projectGitlabResponse({ resource: 'pulls', kind: 'read', create: false }, { not: 'a list' }), { code: 'INVALID_UPSTREAM' });
});

test('GitLab protected-branch verification requires no direct push and no force push, failing closed', async () => {
  const provider = { kind: 'gitlab', api: async ({ repository, operation }) => {
    if (operation.path.endsWith('/main')) return Response.json({ name: 'main', push_access_levels: [{ access_level: 0 }], allow_force_push: false });
    if (operation.path.endsWith('release%2Fv1')) return Response.json({ name: 'release/v1', push_access_levels: [{ access_level: 40 }], allow_force_push: true });
    return new Response('', { status: 404 });
  } };
  const config = { repositories: [{ name: 'acme/demo', projectId: 42, protectedBranches: ['main', 'release/v1', 'staging'] }] };
  assert.deepEqual(await verifyProtectedBranches(config, provider), [
    { repository: 'acme/demo', branch: 'release/v1', missing: ['no-direct-push', 'no-force-push'] },
    { repository: 'acme/demo', branch: 'staging', missing: ['protected'] }
  ]);
  await assert.rejects(verifyProtectedBranches(config, { kind: 'gitlab', api: async () => new Response('secret', { status: 500 }) }), { code: 'RULESET_CHECK_FAILED' });
  await assert.rejects(verifyProtectedBranches(config, { kind: 'gitlab', api: async () => Response.json({ push_access_levels: 'x' }) }), { code: 'RULESET_CHECK_FAILED' });
});

async function gitlabFixture(t, calls, options = {}) {
  const f = await fixture({ config: gitlabConfig(options.mergeEffect) });
  t.after(f.close);
  // The fixture's Git upstream is provider-neutral; mark the provider as GitLab so the broker
  // dispatches the GitLab API proxy, and mock the v4 API the way github-api tests mock GitHub's.
  f.provider.kind = 'gitlab';
  const mr = () => ({ iid: 7, title: 'MR', description: '', state: options.state ?? 'opened', draft: false, web_url: 'u', sha: options.sha ?? 'a'.repeat(40), source_branch: 'agent/feature', target_branch: 'main', author: { username: 'bot' }, source_project_id: options.sourceProjectId ?? 42 });
  f.provider.api = async ({ repository, operation, payload }) => {
    calls.push({ repository, operation, payload });
    const path = operation.path.split('?')[0];
    if (path === 'merge_requests' && operation.method === 'GET') return Response.json([mr()]);
    if (path === 'merge_requests' && operation.method === 'POST') return Response.json({ ...mr(), iid: 8, title: payload.title, source_branch: payload.source_branch }, { status: 201 });
    if (path === 'merge_requests/7') return Response.json(mr());
    if (path === 'merge_requests/7/notes' && operation.method === 'POST') return Response.json({ id: 1, body: payload.body, author: { username: 'bot' }, created_at: 'c' }, { status: 201 });
    if (path === 'merge_requests/7/notes') return Response.json([{ id: 1, body: 'hi', author: { username: 'lead' } }]);
    if (path === 'merge_requests/7/merge') return Response.json({ ...mr(), state: 'merged', squash_commit_sha: 'q'.repeat(40) });
    if (path === 'pipelines') return Response.json([{ id: 3, ref: 'agent/feature', sha: 'c'.repeat(40), status: 'failed', web_url: 'u' }]);
    if (path === 'pipelines/3') return Response.json({ id: 3, status: 'failed' });
    if (path === 'pipelines/3/jobs') return Response.json([{ id: 9, name: 'test', status: 'failed' }]);
    return new Response('', { status: 404 });
  };
  f.provider.apiRaw = async ({ operation }) => {
    calls.push({ operation });
    return new Response('line 1\nline 2\n', { status: 200, headers: { 'content-type': 'text/plain' } });
  };
  return f;
}

test('a GitLab-configured broker clones and pushes over Git and serves the unchanged workspace CLI', async (t) => {
  const calls = [];
  const f = await gitlabFixture(t, calls);
  const workspace = join(f.directory, 'workspace');
  await f.git(f.directory, 'clone', f.remote, workspace);
  await f.git(workspace, 'config', 'user.name', 'GL Agent');
  await f.git(workspace, 'config', 'user.email', 'gl@example.com');
  await f.git(workspace, 'checkout', '-b', 'agent/feature');
  await writeFile(join(workspace, 'x.txt'), 'x\n');
  await f.git(workspace, 'add', 'x.txt');
  await f.git(workspace, 'commit', '-m', 'x');
  await f.git(workspace, 'push', 'origin', 'HEAD:refs/heads/agent/feature');
  await assert.rejects(f.git(workspace, 'push', 'origin', 'HEAD:refs/heads/main'), 'main needs approval');
  const tokenFile = join(f.directory, 'client-token');
  await writeFile(tokenFile, f.clientToken, { mode: 0o600 });
  const bodyFile = join(f.directory, 'body.md');
  await writeFile(bodyFile, 'A note\n');
  const env = { PATH: process.env.PATH, HOME: f.directory, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', AGENTGATE_URL: f.gate.url, AGENTGATE_CLIENT_TOKEN_FILE: tokenFile, AGENTGATE_PROVIDER_HOST: 'gitlab.example.com' };
  await f.git(workspace, 'remote', 'set-url', 'origin', 'https://gitlab.example.com/acme/demo.git');
  const cli = async (...args) => JSON.parse((await execute(process.execPath, [resolve('src/workspace-cli.js'), ...args], { cwd: workspace, env })).stdout);
  const raw = (...args) => execute(process.execPath, [resolve('src/workspace-cli.js'), ...args], { cwd: workspace, env });
  assert.equal((await cli('pr', 'list', '--state', 'all'))[0].number, 7);
  assert.equal(calls.at(-1).operation.path, 'merge_requests?page=1&per_page=30&state=all');
  assert.equal((await cli('pr', 'view', '7')).head.ref, 'agent/feature');
  assert.equal((await cli('ci', 'list', '--branch', 'agent/feature')).workflow_runs[0].conclusion, 'failure');
  assert.equal(calls.at(-1).operation.path, 'pipelines?page=1&per_page=30&ref=agent%2Ffeature');
  assert.equal((await cli('ci', 'view', '3')).status, 'completed');
  assert.equal((await cli('ci', 'jobs', '3')).jobs[0].id, 9);
  assert.equal((await raw('ci', 'logs', '9')).stdout, 'line 1\nline 2\n');
  assert.equal(calls.at(-1).operation.path, 'jobs/9/trace');
  const created = await cli('pr', 'create', '--title', 'Add x', '--base', 'main', '--body-file', bodyFile);
  assert.equal(created.number, 8);
  assert.deepEqual(calls.at(-1).payload, { source_branch: 'agent/feature', target_branch: 'main', title: 'Draft: Add x', description: 'A note\n' });
  assert.equal(calls.at(-1).repository.projectId, 42);
  await cli('pr', 'comment', '7', '--body-file', bodyFile);
  assert.deepEqual([calls.at(-1).operation.path, calls.at(-1).payload], ['merge_requests/7/notes', { body: 'A note\n' }]);
  const review = await cli('pr', 'review', '7', '--body-file', bodyFile);
  assert.equal(review.state, 'COMMENTED');
  await assert.rejects(raw('pr', 'list', '--repo', 'acme/not-configured'));
  const audit = (await readFile(join(f.directory, 'state', 'audit.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.ok(audit.some((event) => event.action === 'gitlab.mr.create' && event.decision === 'allow'));
  assert.ok(!audit.some((event) => JSON.stringify(event).includes('A note')), 'comment bodies are never audited');
});

test('a GitLab fork MR is created on the fork project against the upstream, decided as a fork head', async (t) => {
  const calls = [];
  const f = await gitlabFixture(t, calls);
  const tokenFile = join(f.directory, 'client-token');
  await writeFile(tokenFile, f.clientToken, { mode: 0o600 });
  await f.git(f.seed, 'remote', 'add', 'origin', 'https://gitlab.example.com/agent-bot/demo.git');
  await f.git(f.seed, 'switch', '-c', 'agent/feature');
  const env = { PATH: process.env.PATH, HOME: f.directory, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', AGENTGATE_URL: f.gate.url, AGENTGATE_CLIENT_TOKEN_FILE: tokenFile, AGENTGATE_PROVIDER_HOST: 'gitlab.example.com' };
  await execute(process.execPath, [resolve('src/workspace-cli.js'), 'pr', 'create', '--title', 'Fork', '--base', 'main', '--upstream', 'acme/demo'], { cwd: f.seed, env });
  assert.equal(calls.at(-1).repository.projectId, 77, 'created on the fork project');
  assert.deepEqual(calls.at(-1).payload, { source_branch: 'agent/feature', target_branch: 'main', title: 'Draft: Fork', description: '', target_project_id: 42 });
  const audit = (await readFile(join(f.directory, 'state', 'audit.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  const decision = audit.find((event) => event.action === 'gitlab.mr.create' && event.decision === 'allow');
  assert.equal(decision.headRepository, 'agent-bot/demo');
  assert.equal(decision.rule, 'mr-create-fork');
});

test('GitLab merges need approval bound to iid, sha, target, and method; head moves and rebase are refused', async (t) => {
  const calls = [];
  const f = await gitlabFixture(t, calls);
  const tokenFile = join(f.directory, 'client-token');
  await writeFile(tokenFile, f.clientToken, { mode: 0o600 });
  await f.git(f.seed, 'remote', 'add', 'origin', 'https://gitlab.example.com/acme/demo.git');
  const env = { PATH: process.env.PATH, HOME: f.directory, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', AGENTGATE_URL: f.gate.url, AGENTGATE_CLIENT_TOKEN_FILE: tokenFile, AGENTGATE_PROVIDER_HOST: 'gitlab.example.com' };
  const merge = (sha = 'a'.repeat(40), ...extra) => execute(process.execPath, [resolve('src/workspace-cli.js'), 'pr', 'merge', '7', '--sha', sha, ...extra], { cwd: f.seed, env });
  await assert.rejects(merge(undefined, '--method', 'rebase'), /rebase/);
  await assert.rejects(merge('b'.repeat(40)), /HEAD_MOVED/);
  await assert.rejects(merge(), /REQUIRE_APPROVAL/);
  const pending = (await adminRequest(f.gate.adminSocket, 'GET', '/approvals')).find((item) => item.status === 'pending');
  assert.deepEqual([pending.context.number, pending.context.sha, pending.context.base, pending.context.mergeMethod, pending.context.action], [7, 'a'.repeat(40), 'main', 'squash', 'gitlab.mr.merge']);
  await adminRequest(f.gate.adminSocket, 'POST', `/approvals/${pending.id}/approve`, { reviewer: 'local:lead' });
  const merged = JSON.parse((await merge()).stdout);
  assert.deepEqual(merged, { merged: true, sha: 'q'.repeat(40) });
  assert.deepEqual(calls.at(-1).payload, { sha: 'a'.repeat(40), squash: true });
  assert.equal(calls.at(-1).operation.method, 'PUT');
  await assert.rejects(merge(), /REQUIRE_APPROVAL/, 'the grant was consumed');
});
