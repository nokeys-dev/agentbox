import { EventEmitter } from 'node:events';
import test from 'node:test';
import assert from 'node:assert/strict';
import { connect, createServer } from 'node:net';
import { once } from 'node:events';
import { isBlockedAddress, normalizeHost, parseUpstreamProxy, startEgressProxy } from '../src/egress-proxy.js';

function tunnel(proxyUrl, target) {
  const { hostname, port } = new URL(proxyUrl);
  return new Promise((resolve, reject) => {
    const socket = connect(Number(port), hostname, () => socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let data = '';
    socket.on('data', (chunk) => {
      data += chunk;
      if (data.includes('\r\n\r\n')) resolve({ status: Number(data.split(' ')[1]), socket, rest: data.slice(data.indexOf('\r\n\r\n') + 4) });
    });
    socket.on('error', reject);
  });
}

async function echoServer(t) {
  const echo = createServer((socket) => { socket.on('error', () => {}); socket.pipe(socket); }).listen(0, '127.0.0.1');
  await once(echo, 'listening');
  t.after(() => echo.close());
  return echo;
}

test('proxy tunnels only allowlisted hosts to vetted public addresses and audits', async (t) => {
  const echo = await echoServer(t);
  const events = [];
  const addresses = { 'registry.npmjs.org': ['104.16.0.1'], 'files.pythonhosted.org': ['151.101.0.223'], 'rebind.example.com': ['10.0.0.5'], 'metadata.example.com': ['169.254.169.254'], 'mapped.example.com': ['::ffff:127.0.0.1'] };
  const connected = [];
  const proxy = await startEgressProxy({
    allow: ['registry.npmjs.org:443', '*.pythonhosted.org:443', 'rebind.example.com:443', 'metadata.example.com:80', 'mapped.example.com:443', 'api.github.com:443'],
    port: 0, audit: (event) => events.push(event),
    resolve: async (hostname) => addresses[hostname] ?? [],
    connect: (port, address) => { connected.push(`${address}:${port}`); return connect(echo.address().port, '127.0.0.1'); }
  });
  t.after(() => proxy.close());

  const ok = await tunnel(proxy.url, 'registry.npmjs.org:443');
  assert.equal(ok.status, 200);
  ok.socket.write('ping');
  await new Promise((resolve) => ok.socket.once('data', (chunk) => { assert.equal(chunk.toString(), 'ping'); resolve(); }));
  ok.socket.destroy();
  assert.deepEqual(connected, ['104.16.0.1:443']);
  assert.equal((await tunnel(proxy.url, 'files.pythonhosted.org:443')).status, 200);

  for (const [target, reason] of [['evil.example.com:443', 'not-allowlisted'], ['registry.npmjs.org:22', 'not-allowlisted'], ['104.16.0.1:443', 'ip-literal'],
    ['rebind.example.com:443', 'private-address'], ['metadata.example.com:80', 'private-address'], ['mapped.example.com:443', 'private-address'], ['api.github.com:443', 'github-via-broker']]) {
    const denied = await tunnel(proxy.url, target);
    assert.equal(denied.status, 403, target);
    denied.socket.destroy();
    assert.equal(events.findLast((event) => event.host === target.split(':')[0])?.reason, reason, target);
  }
  assert.equal(connected.length, 2);
});

test('any blocked address among several resolved addresses denies the tunnel', async (t) => {
  const events = [];
  const connected = [];
  const proxy = await startEgressProxy({
    allow: ['mixed.example.com:443', 'mixed6.example.com:443'], port: 0, host: '127.0.0.1', audit: (event) => events.push(event),
    resolve: async (hostname) => hostname === 'mixed.example.com' ? ['104.16.0.1', '104.16.0.2', '192.168.1.1'] : ['2606:4700::1', 'fe80::1'],
    connect: (port, address) => { connected.push(address); throw new Error('must not connect'); }
  });
  t.after(() => proxy.close());
  for (const target of ['mixed.example.com:443', 'mixed6.example.com:443']) {
    const denied = await tunnel(proxy.url, target);
    assert.equal(denied.status, 403);
    denied.socket.destroy();
    assert.equal(events.at(-1).reason, 'private-address');
  }
  assert.deepEqual(connected, []);
});

test('proxy tries each vetted address in order and never re-resolves', async (t) => {
  const echo = await echoServer(t);
  const attempts = [];
  let resolutions = 0;
  const proxy = await startEgressProxy({
    allow: ['multi.example.com:443'], port: 0, host: '127.0.0.1',
    resolve: async () => { resolutions++; return ['104.16.0.1', '104.16.0.2']; },
    connect: (port, address) => {
      attempts.push(address);
      return address === '104.16.0.1' ? connect(1, '127.0.0.1') : connect(echo.address().port, '127.0.0.1');
    }
  });
  t.after(() => proxy.close());
  const ok = await tunnel(proxy.url, 'multi.example.com:443');
  assert.equal(ok.status, 200);
  ok.socket.destroy();
  assert.deepEqual(attempts, ['104.16.0.1', '104.16.0.2']);
  assert.equal(resolutions, 1);
});

test('blocked address ranges include special-purpose, documentation, and embedded IPv4 forms', () => {
  for (const address of ['0.1.2.3', '10.1.1.1', '100.64.0.1', '100.127.255.255', '127.0.0.1', '169.254.169.254', '172.16.5.4', '192.0.0.8', '192.0.2.1',
    '192.168.0.1', '198.18.0.1', '198.51.100.7', '203.0.113.9', '224.0.0.1', '240.0.0.1', '255.255.255.255',
    '::', '::1', '::ffff:10.0.0.1', '::ffff:a00:1', '::ffff:169.254.169.254', '64:ff9b::a9fe:a9fe', '64:ff9b::10.0.0.1', '2001:db8::1',
    'fc00::1', 'fd00:ec2::254', 'fe80::1', 'febf::1', 'ff02::1', '::127.0.0.1', '2002:a00:1::1', '::ffff:104.16.0.1', '3fff::1', '3fff:fff::1']) {
    assert.equal(isBlockedAddress(address), true, address);
  }
  for (const address of ['104.16.0.1', '8.8.8.8', '100.128.0.1', '172.32.0.1', '2606:4700::1', '64:ff9b::808:808', '2a00:1450::1', '3fff:1000::1']) {
    assert.equal(isBlockedAddress(address), false, address);
  }
  for (const invalid of ['', 'example.com', '1.2.3', '::ffff:999.0.0.1', 'fe80::1%eth0']) assert.equal(isBlockedAddress(invalid), true, invalid);
});

test('host matching normalizes case and a trailing dot, keeps wildcards off the bare suffix, and restricts punycode', async (t) => {
  assert.equal(normalizeHost('Registry.NPMJS.org.'), 'registry.npmjs.org');
  assert.equal(normalizeHost('registry.npmjs.org..'), null);
  const echo = await echoServer(t);
  const events = [];
  const proxy = await startEgressProxy({
    allow: ['registry.npmjs.org:443', '*.pythonhosted.org:443', 'xn--bcher-kva.example:443'], port: 0, host: '127.0.0.1', audit: (event) => events.push(event),
    resolve: async () => ['104.16.0.1'],
    connect: () => connect(echo.address().port, '127.0.0.1')
  });
  t.after(() => proxy.close());
  for (const target of ['REGISTRY.npmjs.org.:443', 'files.pythonhosted.org.:443', 'xn--bcher-kva.example:443']) {
    const ok = await tunnel(proxy.url, target);
    assert.equal(ok.status, 200, target);
    ok.socket.destroy();
  }
  for (const [target, reason] of [['pythonhosted.org:443', 'not-allowlisted'], ['evilpythonhosted.org:443', 'not-allowlisted'],
    ['xn--80ak6aa92e.pythonhosted.org:443', 'idn-not-allowlisted'], ['registry.npmjs.org..:443', 'invalid-target'],
    ['GitHub.com.:443', 'github-via-broker'], ['objects.githubusercontent.com:443', 'github-via-broker'], ['avatars.githubassets.com:443', 'github-via-broker'],
    ['pages.github.io:443', 'github-via-broker'], ['2130706433:443', 'ip-literal'], ['[::1]:443', 'ip-literal']]) {
    const denied = await tunnel(proxy.url, target);
    assert.ok([400, 403].includes(denied.status), target);
    denied.socket.destroy();
    assert.equal(events.at(-1).reason, reason, target);
  }
});

test('proxy rejects non-CONNECT methods and never logs payloads', async (t) => {
  const events = [];
  const proxy = await startEgressProxy({ allow: ['registry.npmjs.org:443'], port: 0, host: '127.0.0.1', audit: (event) => events.push(event) });
  t.after(() => proxy.close());
  const response = await fetch(`${proxy.url}/http://registry.npmjs.org/`);
  assert.equal(response.status, 405);
  await response.text();
  assert.deepEqual(events, []);
});

test('invalid allow entries fail closed at startup', async () => {
  for (const allow of [['registry.npmjs.org'], ['*.org:443'], ['*:443'], ['10.0.0.1:443'], ['host.example:0'], ['host.example:99999'], ['bad host:443'], 'x']) {
    await assert.rejects(startEgressProxy({ allow, port: 0, host: '127.0.0.1' }), /egress/i, JSON.stringify(allow));
  }
});

test('byte quota closes a live tunnel mid-stream and denies new tunnels for that client and host', async (t) => {
  const echo = await echoServer(t);
  const events = [];
  const proxy = await startEgressProxy({
    allow: ['registry.npmjs.org:443'], port: 0, host: '127.0.0.1', maxBytesPerHost: 64 * 1024, audit: (event) => events.push(event),
    resolve: async () => ['104.16.0.1'], connect: () => connect(echo.address().port, '127.0.0.1')
  });
  t.after(() => proxy.close());
  const ok = await tunnel(proxy.url, 'registry.npmjs.org:443');
  assert.equal(ok.status, 200);
  ok.socket.on('error', () => {});
  const closed = once(ok.socket, 'close');
  const chunk = Buffer.alloc(8 * 1024, 1);
  const pump = setInterval(() => { if (!ok.socket.destroyed) ok.socket.write(chunk); }, 5);
  await closed;
  clearInterval(pump);
  await new Promise((resolve) => setImmediate(resolve));
  const finished = events.find((event) => event.decision === 'allow');
  assert.equal(finished.reason, 'quota-exceeded');
  assert.ok(finished.bytesUp + finished.bytesDown < 64 * 1024 + 4 * chunk.length);
  const denied = await tunnel(proxy.url, 'registry.npmjs.org:443');
  assert.equal(denied.status, 403);
  denied.socket.destroy();
  assert.equal(events.at(-1).reason, 'quota-exceeded');
});

test('idle tunnels close after the idle timeout', async (t) => {
  const echo = await echoServer(t);
  const events = [];
  const proxy = await startEgressProxy({
    allow: ['registry.npmjs.org:443'], port: 0, host: '127.0.0.1', idleTimeoutMs: 150, audit: (event) => events.push(event),
    resolve: async () => ['104.16.0.1'], connect: () => connect(echo.address().port, '127.0.0.1')
  });
  t.after(() => proxy.close());
  const ok = await tunnel(proxy.url, 'registry.npmjs.org:443');
  const started = Date.now();
  await once(ok.socket, 'close');
  assert.ok(Date.now() - started >= 100);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(events.at(-1).reason, 'idle-timeout');
});

test('concurrent tunnels per client are capped and slow CONNECT headers time out', async (t) => {
  const echo = await echoServer(t);
  const events = [];
  const proxy = await startEgressProxy({
    allow: ['registry.npmjs.org:443'], port: 0, host: '127.0.0.1', maxTunnelsPerClient: 2, headerTimeoutMs: 200, audit: (event) => events.push(event),
    resolve: async () => ['104.16.0.1'], connect: () => connect(echo.address().port, '127.0.0.1')
  });
  t.after(() => proxy.close());
  const first = await tunnel(proxy.url, 'registry.npmjs.org:443');
  const second = await tunnel(proxy.url, 'registry.npmjs.org:443');
  const third = await tunnel(proxy.url, 'registry.npmjs.org:443');
  assert.deepEqual([first.status, second.status, third.status], [200, 200, 429]);
  assert.equal(events.at(-1).reason, 'too-many-tunnels');
  for (const { socket } of [first, second, third]) socket.destroy();

  const { hostname, port } = new URL(proxy.url);
  const slow = connect(Number(port), hostname, () => slow.write('CONNECT registry.npmjs.org:443 HTTP/1.1\r\n'));
  slow.on('error', () => {});
  slow.on('data', () => {});
  const started = Date.now();
  await once(slow, 'close');
  assert.ok(Date.now() - started < 5000);

  const long = await tunnel(proxy.url, `${'a'.repeat(300)}.example.com:443`);
  assert.equal(long.status, 400);
  long.socket.destroy();
});

test('a wildcard rule shares one byte quota across every subdomain it matches', async (t) => {
  const echo = await echoServer(t);
  const events = [];
  const proxy = await startEgressProxy({
    allow: ['*.pythonhosted.org:443'], port: 0, host: '127.0.0.1', maxBytesPerHost: 16 * 1024, audit: (event) => events.push(event),
    resolve: async () => ['151.101.0.223'], connect: () => connect(echo.address().port, '127.0.0.1')
  });
  t.after(() => proxy.close());
  const ok = await tunnel(proxy.url, 'a.pythonhosted.org:443');
  assert.equal(ok.status, 200);
  ok.socket.on('error', () => {});
  const closed = once(ok.socket, 'close');
  const pump = setInterval(() => { if (!ok.socket.destroyed) ok.socket.write(Buffer.alloc(4096, 1)); }, 5);
  await closed;
  clearInterval(pump);
  await new Promise((resolve) => setImmediate(resolve));
  const other = await tunnel(proxy.url, 'b.pythonhosted.org:443');
  assert.equal(other.status, 403);
  other.socket.destroy();
  assert.equal(events.at(-1).reason, 'quota-exceeded');
});

test('the connect timeout is one deadline across all resolved addresses', async (t) => {
  const events = [];
  const attempts = [];
  const proxy = await startEgressProxy({
    allow: ['registry.npmjs.org:443'], port: 0, host: '127.0.0.1', connectTimeoutMs: 150, audit: (event) => events.push(event),
    resolve: async () => ['104.16.0.1', '104.16.0.2', '104.16.0.3', '104.16.0.4', '104.16.0.5'],
    // Sockets that never connect.
    connect: (_port, address) => { attempts.push(address); const socket = new (class extends EventEmitter { connecting = true; destroyed = false; destroy() { this.destroyed = true; } on() { return super.on(...arguments); } })(); return socket; }
  });
  t.after(() => proxy.close());
  const started = Date.now();
  const result = await tunnel(proxy.url, 'registry.npmjs.org:443');
  assert.equal(result.status, 502);
  result.socket.destroy();
  assert.ok(Date.now() - started < 500, `took ${Date.now() - started} ms`);
  assert.ok(attempts.length < 5);
});

test('proxy attributes tunnels and quotas to a verified runtime from proxy credentials, and refuses forged ones', async (t) => {
  const { generateKeyPairSync } = await import('node:crypto');
  const { issueAssertion } = await import('../src/assertion.js');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const other = generateKeyPairSync('ed25519');
  const echo = await echoServer(t);
  const events = [];
  const start = (identity) => startEgressProxy({
    allow: ['echo.test:' + echo.address().port], port: 0, audit: (event) => events.push(event), maxBytesPerHost: 8,
    resolve: async () => ['93.184.216.34'], connect: () => connect(echo.address().port, '127.0.0.1'),
    identity: { audience: 'agentgate:acme', issuers: [{ kid: 'k1', publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) }], ...identity }
  });
  const proxy = await start({});
  t.after(() => proxy.close());
  const issue = (sub, key = privateKey) => issueAssertion({ iss: 'issuer', aud: 'agentgate:acme', sub, human: 'dev@example.com', agent: 'cursor', team: 'payments', mode: 'build' }, { privateKey: key, kid: 'k1', ttlSeconds: 600, clientToken: 'workspace-token-unknown-to-the-proxy-0123456' });
  const credential = (assertion) => `Basic ${Buffer.from(`runtime:${assertion}`).toString('base64')}`;
  const open = (proxyUrl, target, headers = {}) => new Promise((resolve, reject) => {
    const { hostname, port } = new URL(proxyUrl);
    const extra = Object.entries(headers).map(([key, value]) => `${key}: ${value}\r\n`).join('');
    const socket = connect(Number(port), hostname, () => socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${extra}\r\n`));
    let data = '';
    socket.on('data', (chunk) => { data += chunk; if (data.includes('\r\n\r\n')) resolve({ status: Number(data.split(' ')[1]), socket, head: data }); });
    socket.on('error', reject);
  });
  const target = `echo.test:${echo.address().port}`;
  const a = issue('rt-a');
  const b = issue('rt-b');
  const first = await open(proxy.url, target, { 'proxy-authorization': credential(a) });
  assert.equal(first.status, 200);
  first.socket.write('12345678');
  await once(first.socket, 'close');
  const allowed = events.find((event) => event.decision === 'allow' && event.runtime?.runtimeId === 'rt-a');
  assert.ok(allowed, 'the tunnel is attributed to the runtime');
  assert.equal(allowed.runtime.human, 'dev@example.com');
  assert.ok(!JSON.stringify(events).includes(a.split('.')[2]), 'the assertion is never audited');
  const exhausted = await open(proxy.url, target, { 'proxy-authorization': credential(a) });
  assert.equal(exhausted.status, 403, 'runtime A spent its own quota');
  const second = await open(proxy.url, target, { 'proxy-authorization': credential(b) });
  assert.equal(second.status, 200, 'runtime B at the same address has its own quota');
  second.socket.destroy();
  await once(second.socket, 'close');
  const anonymous = await open(proxy.url, target);
  assert.equal(anonymous.status, 200, 'no credentials: attributed to the address, which has its own quota');
  anonymous.socket.destroy();
  await once(anonymous.socket, 'close');
  // Allow events are emitted when a tunnel closes; the last one is the anonymous tunnel's.
  await new Promise((resolve) => setTimeout(resolve, 50));
  const lastAllow = events.filter((event) => event.decision === 'allow').at(-1);
  assert.equal(lastAllow.runtime, undefined);
  const forged = await open(proxy.url, target, { 'proxy-authorization': credential(issue('rt-x', other.privateKey)) });
  assert.equal(forged.status, 407);
  assert.match(forged.head, /proxy-authenticate: Basic/i);
  assert.equal(events.at(-1).reason, 'assertion-invalid');
  assert.equal((await open(proxy.url, target, { 'proxy-authorization': 'Basic ' + Buffer.from('someone:else').toString('base64') })).status, 407, 'other users are refused');
  const strict = await start({ required: true });
  t.after(() => strict.close());
  assert.equal((await open(strict.url, target)).status, 407);
  assert.equal(events.at(-1).reason, 'assertion-required');
  const strictOk = await open(strict.url, target, { 'proxy-authorization': credential(b) });
  assert.equal(strictOk.status, 200);
  strictOk.socket.destroy();
});

// A real CONNECT proxy standing in for the company's: records what it was asked for, optionally
// demands credentials, and pipes the tunnel to the echo server.
async function corporateProxy(t, echo, { authorization, refuse = false, greeting = '' } = {}) {
  const seen = [];
  const server = createServer((socket) => {
    socket.on('error', () => {});
    let head = '';
    const onData = (chunk) => {
      head += chunk.toString('latin1');
      if (!head.includes('\r\n\r\n')) return;
      socket.off('data', onData);
      seen.push({ line: head.split('\r\n')[0], authorization: /^proxy-authorization: (.*)$/im.exec(head)?.[1] });
      if (refuse) return socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
      if (authorization && seen.at(-1).authorization !== authorization) return socket.end('HTTP/1.1 407 Proxy Authentication Required\r\n\r\n');
      const upstream = connect(echo.address().port, '127.0.0.1', () => { socket.write(`HTTP/1.1 200 Connection established\r\n\r\n${greeting}`); socket.pipe(upstream); upstream.pipe(socket); });
      upstream.on('error', () => socket.destroy());
    };
    socket.on('data', onData);
  }).listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());
  return { seen, url: (credentials = '') => `http://${credentials}127.0.0.1:${server.address().port}` };
}

test('allowed tunnels are chained through a corporate proxy, with its credentials, and every local decision still applies', async (t) => {
  const echo = await echoServer(t);
  const corporate = await corporateProxy(t, echo, { authorization: `Basic ${Buffer.from('svc-agentbox:p@ss:word').toString('base64')}`, greeting: 'early' });
  const events = [];
  const resolved = [];
  const proxy = await startEgressProxy({
    allow: ['registry.npmjs.org:443', 'unresolvable.example.com:443', 'rebind.example.com:443'], port: 0, audit: (event) => events.push(event),
    upstreamProxy: corporate.url('svc-agentbox:p%40ss%3Aword@'),
    // The local resolver sees internal names only, as on a locked-down corporate network.
    resolve: async (hostname) => { resolved.push(hostname); if (hostname === 'rebind.example.com') return ['10.0.0.5']; if (hostname === 'registry.npmjs.org') return ['104.16.0.1']; throw new Error('ENOTFOUND'); }
  });
  t.after(() => proxy.close());

  const ok = await tunnel(proxy.url, 'registry.npmjs.org:443');
  assert.equal(ok.status, 200);
  let received = ok.rest;
  ok.socket.on('data', (chunk) => { received += chunk; });
  ok.socket.write('ping');
  await new Promise((resolve) => { const poll = setInterval(() => { if (received === 'earlyping') { clearInterval(poll); resolve(); } }, 5); });
  ok.socket.destroy();
  assert.equal(corporate.seen[0].line, 'CONNECT registry.npmjs.org:443 HTTP/1.1', 'the corporate proxy is asked for the name, never a locally resolved address');

  const unresolved = await tunnel(proxy.url, 'unresolvable.example.com:443');
  assert.equal(unresolved.status, 200, 'a name only the corporate proxy can resolve still tunnels');
  unresolved.socket.destroy();

  for (const [target, reason] of [['evil.example.com:443', 'not-allowlisted'], ['rebind.example.com:443', 'private-address'], ['10.0.0.5:443', 'ip-literal'], ['api.github.com:443', 'github-via-broker']]) {
    const denied = await tunnel(proxy.url, target);
    assert.equal(denied.status, 403, target);
    denied.socket.destroy();
    assert.equal(events.findLast((event) => event.host === target.split(':')[0])?.reason, reason, target);
  }
  assert.equal(corporate.seen.length, 2, 'denied targets never reach the corporate proxy');
  await new Promise((resolve) => setTimeout(resolve, 20));
  const allowed = events.find((event) => event.decision === 'allow' && event.host === 'registry.npmjs.org');
  assert.equal(allowed.bytesDown, 'earlyping'.length, 'bytes the corporate proxy sent with its response count toward the quota');
});

test('a corporate proxy that refuses, or is unreachable, fails the tunnel with a reason that names it', async (t) => {
  const echo = await echoServer(t);
  const refusing = await corporateProxy(t, echo, { refuse: true });
  for (const [upstreamProxy, reason] of [[refusing.url(), 'upstream-proxy-refused'], ['http://127.0.0.1:1', 'upstream-proxy-unreachable'], ['http://proxy.invalid:8080', 'upstream-proxy-unreachable']]) {
    const events = [];
    const proxy = await startEgressProxy({ allow: ['registry.npmjs.org:443'], port: 0, audit: (event) => events.push(event), upstreamProxy, connectTimeoutMs: 2000,
      resolve: async (hostname) => { if (hostname === 'registry.npmjs.org') return ['104.16.0.1']; throw new Error('ENOTFOUND'); } });
    const result = await tunnel(proxy.url, 'registry.npmjs.org:443');
    assert.equal(result.status, 502, upstreamProxy);
    assert.equal(events.at(-1).reason, reason, upstreamProxy);
    result.socket.destroy();
    await proxy.close();
  }
});

test('the corporate proxy setting is validated at startup', () => {
  assert.equal(parseUpstreamProxy(''), undefined);
  assert.deepEqual(parseUpstreamProxy('http://proxy.example.com:8080'), { host: 'proxy.example.com', port: 8080, authorization: undefined });
  assert.equal(parseUpstreamProxy('http://proxy.example.com').port, 80);
  for (const bad of ['proxy.example.com:8080', 'https://proxy.example.com:8080', 'socks5://proxy:1080', 'http://proxy.example.com:8080/path', 'http://proxy.example.com:8080/?x=1']) assert.throws(() => parseUpstreamProxy(bad), /Invalid egress upstream proxy/, bad);
});
