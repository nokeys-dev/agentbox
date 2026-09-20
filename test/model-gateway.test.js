import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { startModelGateway } from '../src/model-gateway.js';

const clientToken = 'c'.repeat(64);

test('gateway injects the provider key, strips client credentials, allowlists paths, streams, and rate limits', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-model-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const keyFile = join(directory, 'anthropic');
  writeFileSync(keyFile, 'sk-ant-real\n', { mode: 0o600 });
  const upstreamCalls = [];
  const events = [];
  const gateway = await startModelGateway({
    clientToken, port: 0, audit: (event) => events.push(event), budget: { maxRequestsPerHour: 2, maxRequestBytes: 1024 },
    routes: [{ prefix: '/anthropic', upstream: 'https://api.anthropic.com', allowPaths: ['^/v1/messages$', '^/v1/models$'], inject: { header: 'x-api-key', valueFile: keyFile } }],
    fetchImpl: async (url, options) => {
      upstreamCalls.push({ url, headers: options.headers, redirect: options.redirect });
      return new Response(new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode('event: ping\n\n')); controller.close(); } }), { status: 200, headers: { 'content-type': 'text/event-stream', 'set-cookie': 'x=y' } });
    }
  });
  t.after(() => gateway.close());
  const call = (path, headers = {}, body = '{}') => fetch(`${gateway.url}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body });

  assert.equal((await call('/anthropic/v1/messages')).status, 401);
  assert.equal((await call('/anthropic/v1/messages', { 'x-api-key': clientToken })).status, 401);
  const ok = await call('/anthropic/v1/messages', { authorization: `Bearer ${clientToken}`, cookie: 'session=1', 'anthropic-version': '2023-06-01' });
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get('set-cookie'), null);
  assert.equal(await ok.text(), 'event: ping\n\n');
  assert.equal(upstreamCalls[0].url, 'https://api.anthropic.com/v1/messages');
  assert.equal(upstreamCalls[0].headers['x-api-key'], 'sk-ant-real');
  assert.equal(upstreamCalls[0].headers.authorization, undefined);
  assert.equal(upstreamCalls[0].headers.cookie, undefined);
  assert.equal(upstreamCalls[0].headers['anthropic-version'], '2023-06-01');
  assert.equal(upstreamCalls[0].redirect, 'error');
  assert.equal((await call('/anthropic/v1/files', { authorization: `Bearer ${clientToken}` })).status, 404);
  assert.equal((await call('/openai/v1/chat', { authorization: `Bearer ${clientToken}` })).status, 404);
  assert.equal((await call('/anthropic/v1/messages', { authorization: `Bearer ${clientToken}` }, 'x'.repeat(2048))).status, 413);
  assert.equal((await call('/anthropic/v1/messages', { authorization: `Bearer ${clientToken}` })).status, 200);
  assert.equal((await call('/anthropic/v1/messages', { authorization: `Bearer ${clientToken}` })).status, 429);
  assert(events.every((event) => !JSON.stringify(event).includes('sk-ant-real')));
});

const raw = (url, path, headers = {}, body) => new Promise((resolve, reject) => {
  const target = new URL(url);
  const request = httpRequest({ host: target.hostname, port: target.port, path, method: body === undefined ? 'GET' : 'POST', headers }, (response) => {
    let text = '';
    response.setEncoding('utf8');
    response.on('data', (chunk) => { text += chunk; });
    response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, text }));
  });
  request.on('error', reject);
  if (body !== undefined && body !== null) request.write(body);
  request.end();
});

test('gateway refuses path smuggling, insecure key files, and never echoes the key on failures', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-model-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const keyFile = join(directory, 'key');
  writeFileSync(keyFile, 'sk-secret-value', { mode: 0o600 });
  const calls = [];
  let mode = 'ok';
  const gateway = await startModelGateway({
    clientToken, port: 0, budget: { maxRequestsPerHour: 1000, maxRequestBytes: 64 },
    routes: [{ prefix: '/anthropic', upstream: 'https://api.anthropic.com', allowPaths: ['^/v1/models$', '^/v1/messages$'], inject: { header: 'x-api-key', valueFile: keyFile } }],
    fetchImpl: async (url, options) => {
      calls.push({ url, headers: options.headers });
      if (mode === 'throw') throw new Error('network sk-secret-value');
      return new Response('{}', { status: 200, headers: { 'x-echo': 'sk-secret-value', connection: 'keep-alive' } });
    }
  });
  t.after(() => gateway.close());
  const auth = { authorization: `Bearer ${clientToken}` };

  for (const path of ['/anthropic/v1/models/../messages', '/anthropic/v1/%2e%2e/models', '/anthropic/v1%2fmodels', '/anthropic//v1/models',
    '/anthropic/v1/models%3f', '/anthropic/./v1/models', '/anthropic/v1\\models', '//evil.example/anthropic/v1/models', '/anthropic/v1/models%00']) {
    assert.equal((await raw(gateway.url, path, auth)).status, 404, path);
  }
  assert.equal(calls.length, 0);

  const listed = await raw(gateway.url, '/anthropic/v1/models?limit=5&after=x', { ...auth, 'x-agentgate-runtime': 'assertion', connection: 'x-custom', 'x-custom': '1', 'x-goog-api-key': 'k' });
  assert.equal(listed.status, 200);
  assert.equal(listed.headers['x-echo'], undefined);
  assert.equal(calls[0].url, 'https://api.anthropic.com/v1/models?limit=5&after=x');
  assert.equal(calls[0].headers['x-agentgate-runtime'], undefined);
  assert.equal(calls[0].headers['x-custom'], undefined);
  assert.equal(calls[0].headers['x-goog-api-key'], undefined);

  assert.equal((await raw(gateway.url, '/anthropic/v1/messages', { ...auth, 'transfer-encoding': 'chunked' }, 'y'.repeat(200))).status, 413);
  assert.equal((await raw(gateway.url, '/anthropic/v1/models', auth, null)).status, 200);
  const put = await fetch(`${gateway.url}/anthropic/v1/messages`, { method: 'PUT', headers: auth, body: '{}' });
  assert.equal(put.status, 404);

  mode = 'throw';
  const failed = await raw(gateway.url, '/anthropic/v1/models', auth);
  assert.equal(failed.status, 502);
  assert(!failed.text.includes('sk-secret-value'));

  mode = 'ok';
  chmodSync(keyFile, 0o644);
  const insecure = await raw(gateway.url, '/anthropic/v1/models', auth);
  assert.equal(insecure.status, 503);
  assert(!insecure.text.includes('sk-secret-value'));
  chmodSync(keyFile, 0o600);
  writeFileSync(keyFile, 'sk-rotated');
  const before = calls.length;
  assert.equal((await raw(gateway.url, '/anthropic/v1/models', auth)).status, 200);
  assert.equal(calls[before].headers['x-api-key'], 'sk-rotated');
});

test('gateway refuses invalid configuration', async () => {
  const route = { prefix: '/anthropic', upstream: 'https://api.anthropic.com', allowPaths: ['^/v1/models$'], inject: { header: 'x-api-key', valueFile: '/nonexistent' } };
  await assert.rejects(startModelGateway({ routes: [route], clientToken: undefined, port: 0 }), /client token/);
  await assert.rejects(startModelGateway({ routes: [{ ...route, upstream: 'http://api.anthropic.com' }], clientToken, port: 0 }), /https origin/);
  await assert.rejects(startModelGateway({ routes: [{ ...route, allowPaths: ['/v1/models'] }], clientToken, port: 0 }), /anchored/);
  await assert.rejects(startModelGateway({ routes: [{ ...route, prefix: 'anthropic' }], clientToken, port: 0 }), /prefix/);
  await assert.rejects(startModelGateway({ routes: [route], clientToken, port: 0, budget: { maxRequestsPerHour: 0 } }), /budget/);
});

test('gateway caps concurrency, releases slots, and enforces global and body-size budgets without burning tokens', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-model-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const keyFile = join(directory, 'key');
  writeFileSync(keyFile, 'sk-secret-value', { mode: 0o600 });
  let unblock;
  let blocked = new Promise((resolve) => { unblock = resolve; });
  let started = 0;
  const gateway = await startModelGateway({
    clientToken, port: 0, maxConcurrent: 2, budget: { maxRequestsPerHour: 1000, maxGlobalRequestsPerHour: 4, maxRequestBytes: 64 },
    routes: [{ prefix: '/anthropic', upstream: 'https://api.anthropic.com', allowPaths: ['^/v1/messages$'], inject: { header: 'x-api-key', valueFile: keyFile } }],
    fetchImpl: async () => { started += 1; await blocked; return new Response('ok'); }
  });
  t.after(() => gateway.close());
  const auth = { authorization: `Bearer ${clientToken}` };
  const post = () => raw(gateway.url, '/anthropic/v1/messages', auth, '{}');

  const first = post();
  const second = post();
  while (started < 2) await new Promise((resolve) => setImmediate(resolve));
  const busy = await post();
  assert.equal(busy.status, 503);
  assert.match(busy.text, /GATEWAY_BUSY/);
  unblock();
  assert.equal((await first).status, 200);
  assert.equal((await second).status, 200);

  // Refused bodies (oversized chunked, invalid content-length) take no rate-limit token.
  for (let index = 0; index < 5; index += 1) {
    assert.equal((await raw(gateway.url, '/anthropic/v1/messages', { ...auth, 'transfer-encoding': 'chunked' }, 'y'.repeat(200))).status, 413);
    assert.equal((await raw(gateway.url, '/anthropic/v1/messages', { ...auth, 'content-length': '2x' }, null)).status, 400);
  }
  blocked = Promise.resolve();
  assert.equal((await post()).status, 200);
  assert.equal((await post()).status, 200);
  const global = await post();
  assert.equal(global.status, 429);
  assert.match(global.text, /RATE_LIMITED/);
});

test('allowPaths cannot escape their anchors through top-level alternation', async () => {
  const { compileAllowPath } = await import('../src/model-gateway.js');
  assert.throws(() => compileAllowPath('^/v1/messages|/admin$'), /alternation/);
  const grouped = compileAllowPath('^/v1/(messages|models)$');
  assert(grouped.test('/v1/models'));
  assert(!grouped.test('/admin'));
  assert(!compileAllowPath('^/v1/[a|b]$').test('/admin'));
  await assert.rejects(startModelGateway({ clientToken, port: 0, routes: [{ prefix: '/anthropic', upstream: 'https://api.anthropic.com', allowPaths: ['^/v1/messages|/admin$'], inject: { header: 'x-api-key', valueFile: '/nonexistent' } }] }), /alternation/);
});

test('allowPaths anchors count preceding backslashes and only maxGlobalRequestsPerHour is optional', async () => {
  const { compileAllowPath } = await import('../src/model-gateway.js');
  assert.throws(() => compileAllowPath('^/v1/price\\$'), /anchored/);
  assert(compileAllowPath('^/v1/a\\\\$').test('/v1/a\\'));
  assert.throws(() => compileAllowPath('^/v1/a\\\\\\$'), /anchored/);
  const routes = [{ prefix: '/anthropic', upstream: 'https://api.anthropic.com', allowPaths: ['^/v1/messages$'], inject: { header: 'x-api-key', valueFile: '/nonexistent' } }];
  await assert.rejects(startModelGateway({ clientToken, port: 0, routes, budget: { maxGlobalRequestsPerHour: 0 } }), /maxGlobalRequestsPerHour/);
  await assert.rejects(startModelGateway({ clientToken, port: 0, routes, budget: { maxRequestsPerHour: undefined } }), /maxRequestsPerHour/);
  const gateway = await startModelGateway({ clientToken, port: 0, routes, host: '127.0.0.1' });
  await gateway.close();
});

test('compose gives the model gateway its own client token, never the agentd workspace token', async () => {
  const { readFile } = await import('node:fs/promises');
  const compose = await readFile(new URL('../compose.yaml', import.meta.url), 'utf8');
  const block = (name) => compose.split(new RegExp(`\\n  ${name}:\\n`))[1].split(/\n  [a-z0-9-]+:\n/)[0];
  const gateway = block('model-gateway');
  assert.doesNotMatch(gateway, /agentgate_client_token/);
  assert.match(gateway, /AGENTGATE_MODEL_GATEWAY_CLIENT_TOKEN_FILE: \/run\/secrets\/model_gateway_client_token/);
  assert.match(block('workspace'), /AGENTGATE_MODEL_GATEWAY_TOKEN_FILE: \/run\/secrets\/model_gateway_client_token/);
  assert.doesNotMatch(block('agentd'), /model_gateway_client_token/);
});

test('gateway attributes requests and budgets to a verified runtime assertion, refuses forged ones, and never forwards the header', async (t) => {
  const { generateKeyPairSync } = await import('node:crypto');
  const { issueAssertion } = await import('../src/assertion.js');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const other = generateKeyPairSync('ed25519');
  const directory = mkdtempSync(join(tmpdir(), 'agentgate-model-runtime-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const keyFile = join(directory, 'anthropic');
  writeFileSync(keyFile, 'sk-ant-real\n', { mode: 0o600 });
  const events = [];
  const forwarded = [];
  const start = (identity, budget) => startModelGateway({
    clientToken, port: 0, audit: (event) => events.push(event), budget: { maxRequestsPerHour: 100, maxRequestBytes: 1024, ...budget },
    routes: [{ prefix: '/anthropic', upstream: 'https://api.anthropic.com', allowPaths: ['^/v1/messages$'], inject: { header: 'x-api-key', valueFile: keyFile } }],
    identity: { audience: 'agentgate:acme', issuers: [{ kid: 'k1', publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) }], ...identity },
    fetchImpl: async (url, options) => { forwarded.push(options.headers); return Response.json({ ok: true }); }
  });
  const gateway = await start({}, { maxRequestsPerHourPerRuntime: 1 });
  t.after(() => gateway.close());
  const issue = (sub, key = privateKey) => issueAssertion({ iss: 'issuer', aud: 'agentgate:acme', sub, human: 'dev@example.com', agent: 'claude-code', team: 'payments', mode: 'build' }, { privateKey: key, kid: 'k1', ttlSeconds: 600, clientToken: 'workspace-token-unknown-to-the-gateway-0123' });
  const call = (headers = {}) => fetch(`${gateway.url}/anthropic/v1/messages`, { method: 'POST', headers: { authorization: `Bearer ${clientToken}`, 'content-type': 'application/json', ...headers }, body: '{}' });
  const a = issue('rt-a');
  const b = issue('rt-b');
  assert.equal((await call({ 'x-agentgate-runtime': a })).status, 200);
  assert.deepEqual(events.at(-1).runtime, { runtimeId: 'rt-a', human: 'dev@example.com', agent: 'claude-code', team: 'payments', jti: events.at(-1).runtime.jti });
  assert.equal(forwarded.at(-1)['x-agentgate-runtime'], undefined, 'the assertion never reaches the provider');
  assert.equal((await call({ 'x-agentgate-runtime': a })).status, 429, 'per-runtime budget');
  assert.equal((await call({ 'x-agentgate-runtime': b })).status, 200, 'another runtime at the same address is unaffected');
  assert.equal((await call()).status, 200, 'without a header the request is attributed to the address only');
  assert.equal(events.at(-1).runtime, undefined);
  assert.equal((await call({ 'x-agentgate-runtime': issue('rt-forged', other.privateKey) })).status, 401, 'a forged assertion is refused');
  assert.equal((await call({ 'x-agentgate-runtime': 'not.a.token' })).status, 401);
  assert.equal((await call({ authorization: 'Bearer wrong', 'x-agentgate-runtime': a })).status, 401, 'the client token is still required');
  const strict = await start({ required: true }, {});
  t.after(() => strict.close());
  assert.equal((await fetch(`${strict.url}/anthropic/v1/messages`, { method: 'POST', headers: { authorization: `Bearer ${clientToken}` }, body: '{}' })).status, 401);
  await assert.rejects(startModelGateway({ clientToken, port: 0, routes: [{ prefix: '/a', upstream: 'https://a.example', allowPaths: ['^/x$'], inject: { header: 'x', valueFile: keyFile } }], identity: { audience: 'x', issuers: [{ kid: 'k1', publicKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }) }] } }), /ed25519 public key/);
});
