import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GitLab, gitlabBaseUrl } from '../src/gitlab.js';
import { assertProvider, providerCapabilities, runProviderContract } from '../src/providers/index.js';

function refreshFile(value = 'refresh-token-0001', mode = 0o600) {
  const directory = mkdtempSync(join(tmpdir(), 'agentbox-gitlab-'));
  const path = join(directory, 'refresh');
  writeFileSync(path, `${value}\n`, { mode });
  return path;
}

const make = (fetchImpl, extra = {}) => new GitLab({ baseUrl: 'https://gitlab.example.com', clientId: 'app', clientSecret: 'client-secret-value', refreshTokenFile: refreshFile(), fetchImpl, ...extra });

test('gitlab base url must be a bare https origin', () => {
  assert.equal(gitlabBaseUrl(), 'https://gitlab.com');
  assert.equal(gitlabBaseUrl('https://gitlab.example.com/'), 'https://gitlab.example.com');
  for (const bad of ['http://gitlab.com', 'https://u:p@gitlab.com', 'https://gitlab.com/group', 'https://gitlab.com/?x=1', 'not a url']) assert.throws(() => gitlabBaseUrl(bad), /https/);
});

test('exchanges the refresh token once, caches the access token, persists the rotated refresh token atomically, and refreshes near expiry', async () => {
  let now = 1_800_000_000_000;
  const calls = [];
  const path = refreshFile();
  const gitlab = new GitLab({ baseUrl: 'https://gitlab.example.com', clientId: 'app', clientSecret: 'client-secret-value', refreshTokenFile: path, now: () => now, fetchImpl: async (url, options) => {
    calls.push({ url, options });
    const form = new URLSearchParams(options.body);
    return Response.json({ access_token: `access-${calls.length}-for-${form.get('refresh_token')}`, refresh_token: `refresh-token-000${calls.length + 1}`, expires_in: 7200, created_at: Math.floor(now / 1000) });
  } });
  assert.equal(await gitlab.token(), 'access-1-for-refresh-token-0001');
  assert.equal(await gitlab.token(), 'access-1-for-refresh-token-0001');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://gitlab.example.com/oauth/token');
  assert.equal(calls[0].options.redirect, 'error');
  const form = new URLSearchParams(calls[0].options.body);
  assert.equal(form.get('grant_type'), 'refresh_token');
  assert.equal(form.get('client_secret'), 'client-secret-value');
  assert.equal(readFileSync(path, 'utf8').trim(), 'refresh-token-0002', 'rotated refresh token persisted');
  assert.equal(statSync(path).mode & 0o777, 0o600);
  now += 7200_000 - 30_000;
  assert.equal(await gitlab.token(), 'access-2-for-refresh-token-0002', 'the persisted refresh token is the one used next');
  gitlab.invalidate();
  const [a, b] = await Promise.all([gitlab.token(), gitlab.token()]);
  assert.equal(a, b, 'parallel first calls share one exchange');
  assert.equal(calls.length, 3);
});

test('token exchange failures are TOKEN_FAILED without exposing bodies, and the refresh file must be owner-only', async () => {
  await assert.rejects(make(async () => new Response('the refresh token is secret-abc', { status: 401 })).token(), (error) => error.code === 'TOKEN_FAILED' && !error.message.includes('secret-abc'));
  await assert.rejects(make(async () => Response.json({ access_token: 'short-lived', expires_in: 10 })).token(), { code: 'TOKEN_FAILED' });
  await assert.rejects(make(async () => new Response('nope', { status: 200 })).token(), { code: 'TOKEN_FAILED' });
  assert.throws(() => new GitLab({ baseUrl: 'https://gitlab.example.com', clientId: 'app', clientSecret: 'client-secret-value', refreshTokenFile: refreshFile('x'.repeat(20), 0o644) }), /owner-only/);
});

test('forward, api, and apiRaw hit only the configured host, never follow redirects, and drop the token on 401', async () => {
  const calls = [];
  let status = 200;
  const gitlab = make(async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/oauth/token')) return Response.json({ access_token: `token-value-${calls.length}`, refresh_token: 'r2', expires_in: 7200 });
    return new Response('', { status });
  });
  const repository = { name: 'acme/demo', projectId: 42 };
  const signal = new AbortController().signal;
  await gitlab.forward({ repository, service: 'git-upload-pack', discovery: true, signal });
  assert.equal(calls[1].url, 'https://gitlab.example.com/acme/demo.git/info/refs?service=git-upload-pack');
  assert.equal(calls[1].options.headers.authorization, `Basic ${Buffer.from('oauth2:token-value-1').toString('base64')}`);
  assert.equal(calls[1].options.redirect, 'error');
  await gitlab.api({ repository, operation: { method: 'GET', path: 'merge_requests/7' }, signal });
  assert.equal(calls[2].url, 'https://gitlab.example.com/api/v4/projects/42/merge_requests/7');
  assert.equal(calls[2].options.headers.authorization, 'Bearer token-value-1');
  assert.equal(calls[2].options.redirect, 'error');
  const raw = await gitlab.apiRaw({ repository, operation: { method: 'GET', path: 'jobs/9/trace' }, signal });
  assert.equal(calls[3].options.redirect, 'manual');
  await raw.body?.cancel();
  status = 401;
  await gitlab.api({ repository, operation: { method: 'GET', path: 'merge_requests' }, signal });
  await gitlab.api({ repository, operation: { method: 'GET', path: 'merge_requests' }, signal });
  assert.equal(calls.filter((call) => call.url.endsWith('/oauth/token')).length, 2, 'a 401 drops the cached token and re-exchanges');
  const remote = await gitlab.mirrorRemote(repository);
  assert.equal(remote.url, 'https://gitlab.example.com/acme/demo.git');
  assert.match(remote.extraHeader, /^Authorization: Basic /);
});

test('GitLab satisfies the provider contract for git, api, and logs; lfs is not offered', async () => {
  assert.doesNotThrow(() => assertProvider(make(async () => new Response('')), { capabilities: ['git', 'api', 'logs'] }));
  assert.throws(() => assertProvider(make(async () => new Response('')), { capabilities: ['lfs'] }), /lfsBatch/);
  assert.deepEqual(providerCapabilities(make(async () => new Response(''))), { git: true, pullRequests: true, actionsRead: true, lfs: false });
  await runProviderContract(make, { isTokenCall: (url) => url.endsWith('/oauth/token'), tokenResponse: () => Response.json({ access_token: 'contract-access-token', refresh_token: 'r', expires_in: 7200 }), perPermissionTokens: false });
});
