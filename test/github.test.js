import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, verify } from 'node:crypto';
import { GitHub } from '../src/github.js';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });

test('signs an RS256 App JWT and isolates cached tokens by repository and permission', async () => {
  let now = 1_800_000_000_000;
  const calls = [];
  const github = new GitHub({ appId: '123', privateKey: pem, now: () => now, fetchImpl: async (url, options) => {
    calls.push({ url, options });
    return Response.json({ token: `token-${calls.length}`, expires_at: new Date(now + 3600_000).toISOString() });
  } });
  const repo = { name: 'acme/demo', id: 42, installationId: 7 };
  assert.equal(await github.token(repo, 'read'), 'token-1');
  assert.equal(await github.token(repo, 'read'), 'token-1');
  assert.equal(await github.token(repo, 'write'), 'token-2');
  assert.equal(await github.token({ ...repo, id: 43 }, 'read'), 'token-3');
  const first = calls[0];
  assert.equal(first.url, 'https://api.github.com/app/installations/7/access_tokens');
  assert.deepEqual(JSON.parse(first.options.body), { repository_ids: [42], permissions: { contents: 'read' } });
  assert.equal(first.options.redirect, 'error');
  const [header, payload, signature] = first.options.headers.authorization.slice(7).split('.');
  assert.equal(JSON.parse(Buffer.from(header, 'base64url')).alg, 'RS256');
  assert.equal(JSON.parse(Buffer.from(payload, 'base64url')).iss, '123');
  assert(verify('RSA-SHA256', Buffer.from(`${header}.${payload}`), publicKey, Buffer.from(signature, 'base64url')));
  now += 3600_000;
  assert.equal(await github.token(repo, 'read'), 'token-4');
});

test('forwards only Git headers to the fixed upstream with redirect rejection', async () => {
  const calls = [];
  const github = new GitHub({ appId: '123', privateKey: pem, fetchImpl: async (url, options) => {
    calls.push({ url, options });
    return url.startsWith('https://api.')
      ? Response.json({ token: 'upstream-secret', expires_at: new Date(Date.now() + 3600_000).toISOString() })
      : new Response('ok');
  } });
  await github.forward({ repository: { name: 'acme/demo', id: 1, installationId: 2 }, service: 'git-upload-pack', discovery: true, protocol: 'version=2', signal: new AbortController().signal });
  const forwarded = calls[1];
  assert.equal(forwarded.url, 'https://github.com/acme/demo.git/info/refs?service=git-upload-pack');
  assert.equal(forwarded.options.redirect, 'error');
  assert.equal(forwarded.options.headers['git-protocol'], 'version=2');
  assert.equal(Buffer.from(forwarded.options.headers.authorization.slice(6), 'base64').toString(), 'x-access-token:upstream-secret');
});

test('upstream token error bodies are never exposed', async () => {
  const github = new GitHub({ appId: '123', privateKey: pem, fetchImpl: async () => new Response('sensitive upstream content', { status: 401 }) });
  await assert.rejects(github.token({ id: 1, installationId: 2 }, 'read'), (error) => error.code === 'TOKEN_FAILED' && !error.message.includes('sensitive'));
});

test('workflow writes require opt-in and API tokens never inherit Contents or Workflows authority', async () => {
  const calls = [];
  const github = new GitHub({ appId: '123', privateKey: pem, fetchImpl: async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/access_tokens')) return Response.json({ token: `secret-${calls.length}`, expires_at: new Date(Date.now() + 3600_000).toISOString() });
    return Response.json([]);
  } });
  const repo = { name: 'acme/demo', id: 1, installationId: 2 };
  await github.token(repo, 'write');
  await github.token({ ...repo, allowWorkflowWrites: true }, 'write');
  await github.token({ ...repo, allowWorkflowWrites: true }, 'read');
  assert.deepEqual(calls.map((call) => JSON.parse(call.options.body).permissions), [
    { contents: 'write' }, { contents: 'write', workflows: 'write' }, { contents: 'read' }
  ]);
  const operation = { method: 'GET', path: 'pulls?state=open', permissions: { pull_requests: 'read' } };
  await github.api({ repository: repo, operation, signal: new AbortController().signal });
  assert.deepEqual(JSON.parse(calls[3].options.body).permissions, { pull_requests: 'read' });
  assert.equal(calls[4].url, 'https://api.github.com/repos/acme/demo/pulls?state=open');
  assert.equal(calls[4].options.redirect, 'error');
  assert.equal(calls[4].options.headers.authorization, 'Bearer secret-4');
});

test('lfsBatch posts to github.com with the narrowest contents token and no redirects', async () => {
  const calls = [];
  const github = new GitHub({ appId: '123', privateKey: pem, fetchImpl: async (url, options) => {
    calls.push({ url, options });
    if (url.startsWith('https://api.github.com/')) return Response.json({ token: `token-${calls.length}`, expires_at: new Date(Date.now() + 3600_000).toISOString() });
    return Response.json({ objects: [] });
  } });
  const repo = { name: 'acme/demo', id: 42, installationId: 7, allowWorkflowWrites: true };
  const payload = { operation: 'upload', transfers: ['basic'], objects: [{ oid: 'a'.repeat(64), size: 1 }], extra: 'dropped' };
  await github.lfsBatch({ repository: repo, operation: 'upload', payload, signal: new AbortController().signal });
  await github.lfsBatch({ repository: repo, operation: 'download', payload, signal: new AbortController().signal });
  const tokens = calls.filter((call) => call.url.startsWith('https://api.github.com/'));
  assert.deepEqual(tokens.map((call) => JSON.parse(call.options.body).permissions), [{ contents: 'write' }, { contents: 'read' }]);
  const batches = calls.filter((call) => !call.url.startsWith('https://api.github.com/'));
  assert.deepEqual(batches.map((call) => call.url), Array(2).fill('https://github.com/acme/demo.git/info/lfs/objects/batch'));
  assert.equal(batches[0].options.redirect, 'error');
  assert.deepEqual(JSON.parse(batches[0].options.body), { operation: 'upload', transfers: ['basic'], objects: payload.objects });
});

test('lfsVerify posts to the github.com verify href with a write token and fails closed', async () => {
  const calls = [];
  let status = 200;
  const github = new GitHub({ appId: '123', privateKey: pem, fetchImpl: async (url, options) => {
    calls.push({ url, options });
    return url.startsWith('https://api.')
      ? Response.json({ token: 'write-secret', expires_at: new Date(Date.now() + 3600_000).toISOString() })
      : new Response('{}', { status });
  } });
  const repository = { name: 'acme/demo', id: 42, installationId: 7 };
  const href = 'https://github.com/acme/demo.git/info/lfs/objects/verify';
  await github.lfsVerify({ repository, oid: 'a'.repeat(64), size: 3, href, header: { 'X-Extra': 'e' } });
  assert.deepEqual(JSON.parse(calls[0].options.body).permissions, { contents: 'write' });
  const verify = calls[1];
  assert.equal(verify.url, href);
  assert.equal(verify.options.redirect, 'error');
  assert.equal(verify.options.headers.authorization, `Basic ${Buffer.from('x-access-token:write-secret').toString('base64')}`);
  assert.equal(verify.options.headers['X-Extra'], 'e');
  assert.deepEqual(JSON.parse(verify.options.body), { oid: 'a'.repeat(64), size: 3 });
  status = 422;
  await assert.rejects(github.lfsVerify({ repository, oid: 'a'.repeat(64), size: 3, href, header: {} }), { code: 'UPSTREAM_FAILED' });
  const count = calls.length;
  await assert.rejects(github.lfsVerify({ repository, oid: 'a'.repeat(64), size: 3, href: 'https://lfs.github.com/verify', header: {} }), { code: 'LFS_UNTRUSTED_HOST' });
  assert.equal(calls.length, count);
});
