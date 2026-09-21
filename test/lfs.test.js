import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { proxyTransfer, rewriteBatchResponse, TransferRegistry, validateBatchRequest } from '../src/lfs.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { validateConfig } from '../src/config.js';
import { createLogger } from '../src/log.js';
import { exampleConfig, fixture } from '../scripts/support/fixture.js';

const oid = 'a'.repeat(64);
const batch = (operation, objects = [{ oid, size: 3 }]) => Buffer.from(JSON.stringify({ operation, transfers: ['basic'], objects }));

test('validates batch requests strictly', () => {
  assert.deepEqual(validateBatchRequest(batch('download')), { operation: 'download', objects: [{ oid, size: 3 }], transfers: ['basic'] });
  for (const body of [batch('delete'), batch('upload', [{ oid: 'x', size: 1 }]), batch('upload', [{ oid, size: -1 }]),
    batch('upload', Array.from({ length: 101 }, () => ({ oid, size: 1 }))), Buffer.from('{"operation":"download","transfers":["tus"],"objects":[]}'), Buffer.from('nope')]) {
    assert.throws(() => validateBatchRequest(body), { code: 'INVALID_LFS_REQUEST' });
  }
});

test('rewrites hrefs to single-use broker transfers bound to repository and operation', () => {
  let now = 0;
  const registry = new TransferRegistry({ now: () => now, ttlMs: 1000 });
  const upstream = { transfer: 'basic', objects: [{ oid, size: 3, actions: {
    upload: { href: 'https://github-cloud.s3.amazonaws.com/x?sig=secret', header: { 'x-amz-meta': 'v' }, expires_in: 3600 },
    verify: { href: 'https://github.com/acme/demo.git/info/lfs/objects/verify', header: { Authorization: 'RemoteAuth secret' } }
  } }] };
  const rewritten = rewriteBatchResponse(upstream, { registry, repository: 'acme/demo', operation: 'upload', brokerUrl: 'https://agentd:7432', allowedHosts: ['github-cloud.s3.amazonaws.com'] });
  const href = rewritten.objects[0].actions.upload.href;
  assert.match(href, /^https:\/\/agentd:7432\/lfs-transfer\/[0-9a-f]{64}$/);
  assert.equal(rewritten.objects[0].actions.upload.header, undefined);
  assert.equal(rewritten.objects[0].actions.verify, undefined);
  assert(!JSON.stringify(rewritten).includes('secret'));
  const id = href.split('/').at(-1);
  assert.equal(registry.take(id, { repository: 'acme/other', operation: 'upload' }), undefined);
  assert.equal(registry.take(id, { repository: 'acme/demo', operation: 'upload' }).href, 'https://github-cloud.s3.amazonaws.com/x?sig=secret');
  assert.equal(registry.take(id, { repository: 'acme/demo', operation: 'upload' }), undefined);
  const late = rewriteBatchResponse(upstream, { registry, repository: 'acme/demo', operation: 'upload', brokerUrl: 'https://agentd:7432', allowedHosts: ['github-cloud.s3.amazonaws.com'] });
  now += 1001;
  assert.equal(registry.take(late.objects[0].actions.upload.href.split('/').at(-1), { repository: 'acme/demo', operation: 'upload' }), undefined);
  assert.throws(() => rewriteBatchResponse({ objects: [{ oid, size: 3, actions: { download: { href: 'https://evil.example/x' } } }] },
    { registry, repository: 'acme/demo', operation: 'download', brokerUrl: 'https://agentd:7432', allowedHosts: ['github-cloud.githubusercontent.com'] }), { code: 'LFS_UNTRUSTED_HOST' });
});

test('broker enforces policy on LFS batch and hides locks', async (t) => {
  const calls = [];
  const provider = { lfsBatch: async ({ operation }) => { calls.push(operation); return Response.json({ transfer: 'basic', objects: [{ oid, size: 3, actions: { [operation]: { href: 'https://github-cloud.githubusercontent.com/o' } } }] }, { headers: { 'content-type': 'application/vnd.git-lfs+json' } }); } };
  const f = await fixture({ provider });
  t.after(() => f.close());
  const post = (path, body) => fetch(`${f.remote}/info/lfs/${path}`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/vnd.git-lfs+json', accept: 'application/vnd.git-lfs+json' }, body });
  const download = await post('objects/batch', batch('download'));
  assert.equal(download.status, 200);
  assert.match((await download.json()).objects[0].actions.download.href, /\/lfs-transfer\/[0-9a-f]{64}$/);
  const upload = await post('objects/batch', batch('upload'));
  assert.equal(upload.status, 403);
  assert.deepEqual(calls, ['download']);
  assert.equal((await post('locks/verify', Buffer.from('{}'))).status, 404);
});

test('rejects an invalid ref field but accepts a valid or absent one', () => {
  const withRef = (ref) => Buffer.from(JSON.stringify({ operation: 'download', ref, objects: [{ oid, size: 1 }] }));
  assert.equal(validateBatchRequest(withRef({ name: 'refs/heads/main' })).operation, 'download');
  for (const ref of ['refs/heads/main', { name: '' }, { name: 'refs/heads/a..b' }, { name: `refs/heads/${'x'.repeat(1100)}` }, { name: 'refs/heads/a b' }, { name: 'refs/heads/main', extra: 1 }]) {
    assert.throws(() => validateBatchRequest(withRef(ref)), { code: 'INVALID_LFS_REQUEST' });
  }
});

test('registry is bounded globally and per repository, and prunes expired entries in insertion order', () => {
  let now = 0;
  const registry = new TransferRegistry({ now: () => now, ttlMs: 10, maxEntries: 3, maxPerRepository: 2 });
  const entry = { repository: 'acme/demo', operation: 'download', oid, size: 1, href: 'https://h/x', header: {} };
  registry.register(entry);
  registry.register(entry);
  assert.throws(() => registry.register(entry), { code: 'LFS_BUSY', status: 503 });
  registry.register({ ...entry, repository: 'acme/other' });
  assert.throws(() => registry.register({ ...entry, repository: 'acme/third' }), { code: 'LFS_BUSY' });
  now = 11;
  registry.prune();
  assert.equal(registry.entries.size, 0);
  assert.equal(registry.perRepository.size, 0);
  const id = registry.register(entry);
  now = 12;
  registry.prune();
  assert.equal(registry.entries.size, 1);
  assert.equal(registry.take(id, { repository: 'acme/demo', operation: 'download' }).oid, oid);
  assert.equal(registry.perRepository.size, 0);
});

test('only objects the client requested receive capabilities', () => {
  const registry = new TransferRegistry();
  const other = 'b'.repeat(64);
  const action = { download: { href: 'https://github-cloud.githubusercontent.com/x' } };
  const rewritten = rewriteBatchResponse({ objects: [{ oid, size: 3, actions: action }, { oid: other, size: 3, actions: action }, { oid, size: 4, actions: action }] },
    { registry, repository: 'acme/demo', operation: 'download', brokerUrl: 'https://agentd:7432', allowedHosts: ['github-cloud.githubusercontent.com'], requested: [{ oid, size: 3 }] });
  assert.deepEqual(rewritten.objects.map((object) => `${object.oid}:${object.size}`), [`${oid}:3`]);
  assert.equal(registry.entries.size, 1);
});

test('batch ref follows the repository Unicode setting and accepts the documented ref forms', () => {
  const withRef = (ref) => Buffer.from(JSON.stringify({ operation: 'download', transfers: ['basic'], ref, objects: [{ oid, size: 3 }], hash_algo: 'sha256' }));
  const unicode = 'refs/heads/caf\u00e9-\u6a5f\u80fd';
  assert.equal(validateBatchRequest(withRef({ name: unicode }), { allowUnicode: true }).operation, 'download');
  assert.throws(() => validateBatchRequest(withRef({ name: unicode })), { code: 'INVALID_LFS_REQUEST' });
  assert.throws(() => validateBatchRequest(withRef({ name: unicode }), { allowUnicode: false }), { code: 'INVALID_LFS_REQUEST' });
  // Documented: ref may be missing or null; the client omits an empty name; Refspec() sends bare
  // names such as HEAD or a detached commit ID.
  for (const ref of [null, {}, { name: 'refs/heads/main' }, { name: 'HEAD' }, { name: 'b'.repeat(40) }]) {
    assert.equal(validateBatchRequest(withRef(ref)).operation, 'download', JSON.stringify(ref));
  }
  for (const ref of [{ name: '' }, { name: 3 }, { name: 'refs/heads/a..b' }, { name: 'refs/heads/a\u0000b' }, { name: 'refs/heads/a b' },
    { name: 'refs/heads/a\u200bb' }, { name: 'refs/heads/a\u202eb' }, { name: 'refs/heads/x.lock' }, { name: 'main', extra: 1 }, 'refs/heads/main', []]) {
    for (const allowUnicode of [false, true]) assert.throws(() => validateBatchRequest(withRef(ref), { allowUnicode }), { code: 'INVALID_LFS_REQUEST' }, JSON.stringify(ref));
  }
});

test('rewrite rejects non-https, credentialed, non-default-port, or malformed upstream objects', () => {
  const registry = new TransferRegistry();
  const opts = { registry, repository: 'acme/demo', operation: 'download', brokerUrl: 'https://agentd:7432', allowedHosts: ['github-cloud.githubusercontent.com'] };
  for (const href of ['http://github-cloud.githubusercontent.com/x', 'https://u:p@github-cloud.githubusercontent.com/x', 'https://github-cloud.githubusercontent.com:444/x']) {
    assert.throws(() => rewriteBatchResponse({ objects: [{ oid, size: 3, actions: { download: { href } } }] }, opts), { code: 'LFS_UNTRUSTED_HOST' });
  }
  assert.throws(() => rewriteBatchResponse({ objects: [{ oid: 'zz', size: 3 }] }, opts), { code: 'INVALID_UPSTREAM' });
  assert.throws(() => rewriteBatchResponse({ objects: 'nope' }, opts), { code: 'INVALID_UPSTREAM' });
  assert.equal(registry.entries.size, 0);
});

test('LFS batch runs after auth, uses the lfs route label, keeps secrets out of logs and audit, and honors upload policy', async (t) => {
  const stream = new PassThrough();
  const lines = [];
  stream.on('data', (chunk) => lines.push(chunk.toString()));
  const calls = [];
  const provider = { lfsBatch: async ({ operation }) => {
    calls.push(operation);
    return new Response(JSON.stringify({ objects: [{ oid, size: 3, actions: { [operation]: { href: 'https://github-cloud.githubusercontent.com/o?X-Amz-Signature=topsecret', header: { Authorization: 'RemoteAuth topsecret' } } } }] }),
      { headers: { 'content-type': 'application/json; charset=utf-8' } });
  } };
  const config = exampleConfig();
  config.rules.push({ id: 'lfs-up', action: 'git.lfs.upload', repository: 'acme/demo', effect: 'allow' });
  const f = await fixture({ provider, config, logger: createLogger({ stream }), publicUrl: 'https://agentd:7432' });
  t.after(() => f.close());
  const post = (path, body, headers = f.authHeaders) => fetch(`${f.remote}/info/lfs/${path}`, { method: 'POST', headers: { ...headers, 'content-type': 'application/vnd.git-lfs+json' }, body });
  assert.equal((await post('objects/batch', batch('download'), {})).status, 401);
  assert.equal((await post('locks/verify', Buffer.from('{}'), {})).status, 401);
  assert.deepEqual(calls, []);
  const upload = await post('objects/batch', batch('upload'));
  assert.equal(upload.status, 200);
  assert.equal(upload.headers.get('content-type'), 'application/vnd.git-lfs+json');
  const text = await upload.text();
  const href = JSON.parse(text).objects[0].actions.upload.href;
  assert.match(href, /^https:\/\/agentd:7432\/lfs-transfer\/[0-9a-f]{64}$/);
  assert(!text.includes('topsecret'));
  assert.equal((await post('objects/batch', Buffer.from('{"operation":"download","ref":{"name":""},"objects":[]}'))).status, 400);
  await new Promise((resolve) => setTimeout(resolve, 50));
  const logged = lines.join('');
  assert.match(logged, /"route":"lfs"/);
  const audit = readFileSync(join(f.directory, 'state', 'audit.jsonl'), 'utf8');
  assert.match(audit, /"action":"git.lfs.upload"/);
  for (const secret of [href.split('/').at(-1), 'topsecret', 'X-Amz']) assert(!logged.includes(secret) && !audit.includes(secret));
  assert.deepEqual(calls, ['upload']);
});

test('LFS batch rejects oversized or non-JSON upstream responses and an invalid publicUrl', async (t) => {
  let body = '{"objects":[]}';
  let type = 'application/vnd.git-lfs+json';
  const provider = { lfsBatch: async () => new Response(body, { headers: { 'content-type': type } }) };
  const f = await fixture({ provider });
  t.after(() => f.close());
  const post = () => fetch(`${f.remote}/info/lfs/objects/batch`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/vnd.git-lfs+json' }, body: batch('download') });
  assert.equal((await post()).status, 200);
  body = `{"objects":[],"pad":"${'x'.repeat(5 * 1024 * 1024)}"}`;
  assert.equal((await post()).status, 502);
  body = '{"objects":[]}';
  type = 'text/html';
  assert.equal((await post()).status, 502);
  for (const publicUrl of ['ftp://agentd', 'https://agentd:7432/path', 'https://user:pw@agentd', 'https://agentd?x=1', 'not a url']) {
    await assert.rejects(fixture({ provider, publicUrl }), /publicUrl/);
  }
});

test('LFS batch applies the repository allowUnicodeRefs setting to ref.name', async (t) => {
  const provider = { lfsBatch: async () => new Response('{"objects":[]}', { headers: { 'content-type': 'application/vnd.git-lfs+json' } }) };
  const body = Buffer.from(JSON.stringify({ operation: 'download', ref: { name: 'refs/heads/caf\u00e9' }, objects: [{ oid, size: 3 }] }));
  const post = (f) => fetch(`${f.remote}/info/lfs/objects/batch`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/vnd.git-lfs+json' }, body });
  const ascii = await fixture({ provider });
  t.after(() => ascii.close());
  const rejected = await post(ascii);
  assert.equal(rejected.status, 400);
  assert.equal((await rejected.json()).code, 'INVALID_LFS_REQUEST');
  const config = exampleConfig();
  config.repositories[0].allowUnicodeRefs = true;
  const unicode = await fixture({ provider, config });
  t.after(() => unicode.close());
  assert.equal((await post(unicode)).status, 200);
});

test('config accepts git.lfs.upload as allow/deny only', () => {
  const make = (rule) => { const config = exampleConfig(); config.rules.push({ id: 'lfs', action: 'git.lfs.upload', repository: 'acme/demo', ...rule }); return config; };
  validateConfig(make({ effect: 'allow' }));
  assert.throws(() => validateConfig(make({ effect: 'approval' })));
  assert.throws(() => validateConfig(make({ effect: 'allow', ref: '*' })));
});

test('transfer proxy verifies size and SHA-256 in both directions without leaking credentials', async (t) => {
  const content = Buffer.from('hello lfs');
  const oid = createHash('sha256').update(content).digest('hex');
  const storage = [];
  const fetchImpl = async (href, options) => {
    storage.push({ href, headers: options.headers, method: options.method });
    if (options.method === 'PUT') { const chunks = []; for await (const chunk of options.body) chunks.push(chunk); storage.at(-1).body = Buffer.concat(chunks); return new Response(null, { status: 200 }); }
    return new Response(href.includes('corrupt') ? Buffer.from('hello lfZ') : content, { status: 200 });
  };
  const run = (entry, { method = 'GET', body } = {}) => new Promise((resolve) => {
    const server = createServer(async (request, response) => {
      try { await proxyTransfer({ request, response, entry, fetchImpl, maxBytes: 1024 }); } catch (error) { if (!response.headersSent) { response.writeHead(error.status ?? 500); response.end(error.code); } else response.destroy(); }
    }).listen(0, async () => {
      t.after(() => server.close());
      try {
        const reply = await fetch(`http://127.0.0.1:${server.address().port}/`, { method, body, headers: body ? { 'content-length': String(body.length) } : {} });
        resolve({ status: reply.status, body: Buffer.from(await reply.arrayBuffer()) });
      } catch (error) { resolve({ error }); }
    });
  });
  const download = await run({ operation: 'download', oid, size: content.length, href: 'https://github-cloud.githubusercontent.com/ok', header: { 'x-sig': 'v' } });
  assert.deepEqual(download.body, content);
  assert.equal(storage[0].headers.authorization, undefined);
  assert.equal(storage[0].headers['x-sig'], 'v');
  assert.equal(storage[0].headers['accept-encoding'], 'identity');
  const corrupt = await run({ operation: 'download', oid, size: content.length, href: 'https://github-cloud.githubusercontent.com/corrupt', header: {} });
  assert(corrupt.error || !corrupt.body.equals(content), 'corrupt download must not complete cleanly');
  const upload = await run({ operation: 'upload', oid, size: content.length, href: 'https://github-cloud.s3.amazonaws.com/put', header: {} }, { method: 'PUT', body: content });
  assert.equal(upload.status, 200);
  assert.deepEqual(storage.at(-1).body, content);
  const wrong = await run({ operation: 'upload', oid, size: content.length, href: 'https://github-cloud.s3.amazonaws.com/put', header: {} }, { method: 'PUT', body: Buffer.from('hello lfZ') });
  assert.equal(wrong.status, 400);
});

test('rewrite stores a github.com verify action for uploads only and rejects other verify hosts', () => {
  const registry = new TransferRegistry();
  const opts = { registry, repository: 'acme/demo', operation: 'upload', brokerUrl: 'https://agentd:7432', allowedHosts: ['github-cloud.s3.amazonaws.com'] };
  const put = { href: 'https://github-cloud.s3.amazonaws.com/x' };
  const verifyHref = 'https://github.com/acme/demo.git/info/lfs/objects/verify';
  const withVerify = rewriteBatchResponse({ objects: [{ oid, size: 3, actions: { upload: put, verify: { href: verifyHref, header: { Authorization: 'RemoteAuth s', 'X-Extra': 'e' } } } }] }, opts);
  assert.equal(withVerify.objects[0].actions.verify, undefined);
  const entry = registry.claim(withVerify.objects[0].actions.upload.href.split('/').at(-1));
  assert.deepEqual(entry.verify, { href: verifyHref, header: { 'X-Extra': 'e' } });
  const without = rewriteBatchResponse({ objects: [{ oid, size: 3, actions: { upload: put } }] }, opts);
  assert.equal(registry.claim(without.objects[0].actions.upload.href.split('/').at(-1)).verify, undefined);
  for (const href of ['https://lfs.github.com/verify', 'https://github-cloud.s3.amazonaws.com/verify', 'https://github.com/acme/other.git/info/lfs/objects/verify', 'http://github.com/acme/demo.git/info/lfs/objects/verify']) {
    assert.throws(() => rewriteBatchResponse({ objects: [{ oid, size: 3, actions: { upload: put, verify: { href } } }] }, opts), { code: 'LFS_UNTRUSTED_HOST' });
  }
  assert.equal(registry.entries.size, 0);
});

test('broker proxies LFS transfers end to end with verification, single use, and live policy', async (t) => {
  const content = Buffer.from('end to end lfs object');
  const good = createHash('sha256').update(content).digest('hex');
  const stream = new PassThrough();
  const lines = [];
  stream.on('data', (chunk) => lines.push(chunk.toString()));
  let verifyAction;
  const verifies = [];
  const storage = [];
  let served = content;
  const provider = {
    lfsBatch: async ({ operation, payload }) => Response.json({ objects: payload.objects.map((object) => ({ ...object, actions: {
      [operation]: { href: `https://github-cloud.githubusercontent.com/${operation}?X-Amz-Signature=storagesecret`, header: { 'x-ms-sig': 'hdrsecret' } },
      ...(operation === 'upload' && verifyAction ? { verify: verifyAction } : {})
    } })) }),
    lfsVerify: async (input) => { verifies.push(input); }
  };
  const lfsFetch = async (href, options) => {
    assert.equal(options.headers.authorization, undefined);
    storage.push({ href, method: options.method, headers: options.headers });
    if (options.method === 'PUT') {
      const chunks = [];
      try { for await (const chunk of options.body) chunks.push(chunk); } catch (error) { storage.at(-1).aborted = true; throw error; }
      storage.at(-1).body = Buffer.concat(chunks);
      return new Response(null, { status: 200, headers: { 'x-amz-request-id': 'leak' } });
    }
    return new Response(served, { status: 200, headers: { 'content-type': 'text/html', 'set-cookie': 'leak=1' } });
  };
  const config = exampleConfig();
  config.rules.push({ id: 'lfs-up', action: 'git.lfs.upload', repository: 'acme/demo', effect: 'allow' });
  const f = await fixture({ provider, config, lfsFetch, logger: createLogger({ stream }) });
  t.after(() => f.close());
  const batchFor = async (operation, object = { oid: good, size: content.length }) => {
    const reply = await fetch(`${f.remote}/info/lfs/objects/batch`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/vnd.git-lfs+json' }, body: batch(operation, [object]) });
    assert.equal(reply.status, 200);
    return (await reply.json()).objects[0].actions[operation].href.replace(/^https?:\/\/[^/]+/, f.gate.url);
  };
  const hrefs = [];
  const transfer = (href, init = {}) => { hrefs.push(href); return fetch(href, { ...init, headers: { ...f.authHeaders, ...init.headers } }); };

  // Download success: bytes, only content-type/length forwarded, no storage headers.
  const downloadHref = await batchFor('download');
  const unauthenticated = await fetch(downloadHref);
  assert.equal(unauthenticated.status, 401);
  const download = await transfer(downloadHref);
  assert.equal(download.status, 200);
  assert.deepEqual(Buffer.from(await download.arrayBuffer()), content);
  assert.equal(download.headers.get('content-type'), 'application/octet-stream');
  assert.equal(download.headers.get('content-length'), String(content.length));
  assert.equal(download.headers.get('set-cookie'), null);
  assert.equal(storage[0].headers['x-ms-sig'], 'hdrsecret');
  // Replay of a consumed ID, and an unknown ID.
  assert.equal((await transfer(downloadHref)).status, 404);
  assert.equal((await transfer(`${f.gate.url}/lfs-transfer/${'0'.repeat(64)}`)).status, 404);

  // Download mismatch: the client never sees a complete body, and the broker keeps serving.
  served = Buffer.from('end to end lfs objecX');
  await assert.rejects(async () => { const reply = await transfer(await batchFor('download')); await reply.arrayBuffer(); });
  served = content;

  // Upload without verify action: no verify call.
  const put = (href, body, headers = {}) => transfer(href, { method: 'PUT', body, headers: { 'content-type': 'application/octet-stream', ...headers } });
  const upload = await put(await batchFor('upload'), content);
  assert.equal(upload.status, 200);
  assert.equal(upload.headers.get('x-amz-request-id'), null);
  assert.deepEqual(storage.at(-1).body, content);
  assert.equal(verifies.length, 0);

  // Upload with a verify action: verify called with the stored href.
  verifyAction = { href: 'https://github.com/acme/demo.git/info/lfs/objects/verify', header: { Authorization: 'RemoteAuth verifysecret' } };
  assert.equal((await put(await batchFor('upload'), content)).status, 200);
  assert.equal(verifies.length, 1);
  assert.equal(verifies[0].href, verifyAction.href);
  assert.equal(verifies[0].oid, good);
  assert.equal(verifies[0].repository.name, 'acme/demo');

  // Upload hash mismatch: 400, the last byte is withheld from storage, and no verify.
  const mismatch = await put(await batchFor('upload'), Buffer.from('end to end lfs objecX'));
  assert.equal(mismatch.status, 400);
  assert.equal((await mismatch.json()).code, 'LFS_HASH_MISMATCH');
  assert.notEqual(storage.at(-1).body?.length, content.length);
  assert.equal(verifies.length, 1);
  // Upload with a wrong content-length is rejected before contacting storage.
  const before = storage.length;
  assert.equal((await put(await batchFor('upload'), Buffer.concat([content, Buffer.from('x')]))).status, 400);
  assert.equal(storage.length, before);
  // Operation binding: a download capability cannot be used to PUT, and the wrong method does not
  // consume it (nor does GET on an upload capability).
  const wrongMethod = await batchFor('download');
  assert.equal((await put(wrongMethod, content)).status, 405);
  assert.equal(storage.length, before);
  const retried = await transfer(wrongMethod);
  assert.equal(retried.status, 200);
  assert.deepEqual(Buffer.from(await retried.arrayBuffer()), content);
  const savedVerify = verifyAction;
  verifyAction = undefined;
  const uploadWrongMethod = await batchFor('upload');
  verifyAction = savedVerify;
  assert.equal((await transfer(uploadWrongMethod)).status, 405);
  assert.equal((await put(uploadWrongMethod, content)).status, 200);

  // Expired transfer.
  const expiring = await batchFor('download');
  for (const entry of f.gate.transfers.entries.values()) entry.expiresAt = 0;
  assert.equal((await transfer(expiring)).status, 404);

  // Policy change between batch and transfer (SIGHUP reload): upload rule removed, then repository.
  const pendingUpload = await batchFor('upload');
  const pendingDownload = await batchFor('download');
  const noUpload = exampleConfig();
  f.gate.reload(noUpload);
  assert.equal((await put(pendingUpload, content)).status, 403);
  assert.equal((await put(pendingUpload, content)).status, 404, 'claim is consumed on deny');
  const noRepo = { ...exampleConfig(), repositories: [{ name: 'acme/other', id: 9, installationId: 2 }], rules: [{ id: 'read', action: 'git.read', repository: 'acme/other', effect: 'allow' }] };
  f.gate.reload(noRepo);
  assert.equal((await transfer(pendingDownload)).status, 403);
  assert.equal(verifies.length, 1);

  await new Promise((resolve) => setTimeout(resolve, 50));
  const logged = lines.join('');
  assert.match(logged, /"route":"lfs"/);
  assert(!/"route":"other"/.test(logged));
  const audit = readFileSync(join(f.directory, 'state', 'audit.jsonl'), 'utf8');
  assert.match(audit, /"result":"lfs-transfer"/);
  assert.match(audit, new RegExp(`"oid":"${good}"`));
  for (const secret of [...hrefs.map((href) => href.split('/').at(-1)).filter((id) => id !== '0'.repeat(64)), 'storagesecret', 'hdrsecret', 'verifysecret', 'X-Amz', 'github-cloud']) {
    assert(!logged.includes(secret), `log leaks ${secret}`);
    assert(!audit.includes(secret), `audit leaks ${secret}`);
  }
  const health = await (await fetch(`${f.gate.url}/healthz`)).json();
  assert.equal(health.capabilities.lfs, true);
});

test('LFS transfers use their own pool so git-lfs parallel transfers do not exhaust the main pool', async (t) => {
  const content = Buffer.from('pooled lfs object');
  const good = createHash('sha256').update(content).digest('hex');
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let started = 0;
  let notify;
  const lfsFetch = async () => {
    started++;
    notify?.();
    await gate;
    return new Response(content, { status: 200 });
  };
  const provider = { lfsBatch: async ({ operation, payload }) => Response.json({ objects: payload.objects.map((object) => ({ ...object, actions: { [operation]: { href: 'https://github-cloud.githubusercontent.com/o' } } })) }) };
  const f = await fixture({ provider, lfsFetch, maxConcurrent: 4, lfsMaxTransfers: 8, metrics: { port: 0 } });
  t.after(async () => { release(); await f.close(); });
  const batchFor = async () => {
    const reply = await fetch(`${f.remote}/info/lfs/objects/batch`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/vnd.git-lfs+json' }, body: batch('download', [{ oid: good, size: content.length }]) });
    assert.equal(reply.status, 200);
    return (await reply.json()).objects[0].actions.download.href.replace(/^https?:\/\/[^/]+/, f.gate.url);
  };
  const hrefs = [];
  for (let index = 0; index < 9; index++) hrefs.push(await batchFor());
  const allStarted = new Promise((resolve) => { notify = () => { if (started === 8) resolve(); }; });
  const downloads = hrefs.slice(0, 8).map((href) => fetch(href, { headers: f.authHeaders }));
  await allStarted;
  const metrics = await (await fetch(f.gate.metricsUrl)).text();
  assert.match(metrics, /^agentgate_lfs_active_transfers 8$/m);
  assert.match(metrics, /^agentgate_active_requests 0$/m);
  const busy = await fetch(hrefs[8], { headers: f.authHeaders });
  assert.equal(busy.status, 503);
  assert.equal(busy.headers.get('retry-after'), '1');
  assert.equal((await busy.json()).code, 'LFS_BUSY');
  // The main pool is untouched: a batch still succeeds while 8 transfers are in flight.
  assert.equal((await fetch(`${f.remote}/info/lfs/objects/batch`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/vnd.git-lfs+json' }, body: batch('download', []) })).status, 200);
  release();
  for (const reply of await Promise.all(downloads)) {
    assert.equal(reply.status, 200);
    assert.deepEqual(Buffer.from(await reply.arrayBuffer()), content);
  }
  // The rejected capability was not consumed.
  const late = await fetch(hrefs[8], { headers: f.authHeaders });
  assert.equal(late.status, 200);
  await late.arrayBuffer();
  for (const options of [{ maxConcurrent: 0 }, { maxConcurrent: 65 }, { lfsMaxTransfers: 0 }, { lfsMaxTransfers: 65 }, { lfsMaxTransfers: 1.5 }]) {
    await assert.rejects(fixture({ provider, ...options }), /maxConcurrent|lfsMaxTransfers/);
  }
});
