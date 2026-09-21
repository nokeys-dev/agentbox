import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Mirror } from '../src/mirror.js';
import { MAX_SECRET_SCAN_BYTES, pathAllowed, pathBlocked, scanPush } from '../src/scan.js';
import { validateConfig } from '../src/config.js';
import { exampleConfig, fixture, packet } from '../scripts/support/fixture.js';

// Obviously fake secrets, assembled at runtime so this file itself never matches the scanner.
const fakeAws = () => ['AK', 'IA', 'ABCDEFGHIJKLMNOP'].join('');
const fakeGithub = () => ['gh', 's_'].join('') + 'a'.repeat(36);
const fakeKeyHeader = () => ['-----BEGIN ', 'PRIVATE KEY-----'].join('');

let counter = 0;
async function cloneWith(f, files, branch = `agent/scan-${counter++}`) {
  const clone = join(f.directory, `c-${Math.random().toString(16).slice(2)}`);
  await f.git(f.directory, 'clone', f.remote, clone);
  await f.git(clone, 'config', 'user.name', 'T');
  await f.git(clone, 'config', 'user.email', 't@example.com');
  await f.git(clone, 'switch', '-c', branch);
  await commitFiles(f, clone, files);
  return { clone, branch };
}

async function commitFiles(f, clone, files, message = 'scan me') {
  for (const [path, content] of Object.entries(files)) {
    await mkdir(join(clone, path, '..'), { recursive: true });
    await writeFile(join(clone, path), content);
  }
  await f.git(clone, 'add', '.');
  await f.git(clone, 'commit', '-m', message);
}

// Returns 'pushed', or git's stderr when the broker answered with an HTTP error status. Anything
// else (git could not run, timed out, or failed without a broker response) is thrown with its full
// output, so an infrastructure failure never passes as an expected rejection.
async function push(f, clone, branch) {
  try { await f.git(clone, 'push', 'origin', `HEAD:refs/heads/${branch}`); return 'pushed'; } catch (error) {
    if (typeof error.stderr === 'string' && /returned error: [45]\d\d/.test(error.stderr)) return error.stderr;
    throw new Error(`git push failed without a broker HTTP response: ${error.message}\nstderr: ${error.stderr ?? ''}`);
  }
}

async function pushResult(f, files) {
  const { clone, branch } = await cloneWith(f, files);
  return push(f, clone, branch);
}

async function scanned(t, settings) {
  const config = exampleConfig();
  config.repositories[0].scan = settings;
  const f = await fixture({ config, scan: true });
  t.after(() => f.close());
  const forwarded = () => f.calls.filter((call) => call.service === 'git-receive-pack' && !call.discovery).length;
  const audit = async () => (await readFile(join(f.directory, 'state', 'audit.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  return { f, forwarded, audit };
}

test('blocks secrets, blocked paths, and oversized blobs before forwarding; allowlist is path-scoped', async (t) => {
  const { f, forwarded, audit } = await scanned(t, { secrets: true, blockedPaths: ['.github/workflows/', '*.pem'], maxBlobBytes: 1024, allowlist: [{ rule: 'aws-access-key', path: 'docs/example.md' }] });

  assert.equal(await pushResult(f, { 'docs/example.md': `key ${fakeAws()}\n` }), 'pushed');
  const before = forwarded();
  assert.notEqual(await pushResult(f, { 'src/config.js': `const t = "${fakeGithub()}";\n` }), 'pushed');
  assert.notEqual(await pushResult(f, { '.github/workflows/ci.yml': 'on: push\n' }), 'pushed');
  assert.notEqual(await pushResult(f, { 'big.txt': 'x'.repeat(2048) }), 'pushed');
  // The allowlist entry does not cover the same value at another path.
  assert.notEqual(await pushResult(f, { 'docs/other.md': `key ${fakeAws()}\n` }), 'pushed');
  assert.equal(forwarded(), before);
  const records = await audit();
  const blocked = records.filter((event) => event.decision === 'content-blocked');
  assert.equal(blocked.length, 4);
  assert.deepEqual(blocked.map((event) => event.findings.map(({ kind, rule, path }) => `${kind}:${rule}:${path}`)), [
    ['secret:github-token:src/config.js'], ['path:blocked-path:.github/workflows/ci.yml'], ['size:max-blob-bytes:big.txt'], ['secret:aws-access-key:docs/other.md']
  ]);
  assert(blocked.every((event) => event.findings.every((finding) => /^[0-9a-f]{12}$/.test(finding.commit))));
  const serialized = JSON.stringify(records);
  assert(!serialized.includes('a'.repeat(36)) && !serialized.includes('ABCDEFGHIJKLMNOP'), 'secret values must not be audited');
  // Quarantines are always removed.
  assert.deepEqual((await readdir(join(f.directory, 'mirrors'))).filter((name) => name.startsWith('quarantine-')), []);
});

test('the 403 response lists findings without values and nothing is forwarded', async (t) => {
  const { f, forwarded } = await scanned(t, { secrets: true });
  const { clone, branch } = await cloneWith(f, { 'key.txt': `${fakeKeyHeader()}\n` });
  const output = await push(f, clone, branch);
  assert.match(output, /CONTENT_BLOCKED|403/);
  assert.equal(forwarded(), 0);
});

test('scans blobs introduced by earlier commits, merges, and binary content', async (t) => {
  const { f, forwarded } = await scanned(t, { secrets: true });
  // Secret added then removed in the same push: history still contains it.
  const first = await cloneWith(f, { 'a.txt': `${fakeGithub()}\n` });
  await commitFiles(f, first.clone, { 'a.txt': 'clean\n' }, 'remove');
  assert.notEqual(await push(f, first.clone, first.branch), 'pushed');

  // Secret arrives through a side branch merged into the pushed branch.
  const second = await cloneWith(f, { 'base.txt': 'base\n' });
  await f.git(second.clone, 'switch', '-c', 'side', 'main');
  await commitFiles(f, second.clone, { 'side/creds.bin': Buffer.concat([Buffer.from([0, 255, 1]), Buffer.from(fakeAws()), Buffer.from([0])]) }, 'side');
  await f.git(second.clone, 'switch', second.branch);
  await f.git(second.clone, 'merge', '--no-edit', 'side');
  assert.notEqual(await push(f, second.clone, second.branch), 'pushed');
  assert.equal(forwarded(), 0);

  // A clean push is forwarded byte for byte from quarantine.
  assert.equal(await pushResult(f, { 'ok.txt': 'fine\n' }), 'pushed');
  assert.equal(forwarded(), 1);
});

test('repositories without scan keep the streaming path', async (t) => {
  const f = await fixture({ scan: true });
  t.after(() => f.close());
  assert.equal(await pushResult(f, { 'x.txt': `${fakeGithub()}\n` }), 'pushed');
  assert.equal(f.calls.find((call) => call.service === 'git-receive-pack' && !call.discovery).streamed, true);
});

test('scan configured without a mirror fails closed', async (t) => {
  const config = exampleConfig();
  config.repositories[0].scan = { secrets: true };
  const f = await fixture({ config });
  t.after(() => f.close());
  assert.notEqual(await pushResult(f, { 'x.txt': 'x\n' }), 'pushed');
  assert.equal(f.calls.filter((call) => call.service === 'git-receive-pack' && !call.discovery).length, 0);
});

test('scanPush reports findings without values', async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const mirror = new Mirror({ root: join(f.directory, 'm'), allowedProtocols: ['file'], fetchRemote: async () => ({ url: f.bare }) });
  const repository = { name: 'acme/demo', id: 1, installationId: 2 };
  await mirror.sync(repository);
  const head = await f.git(f.bare, 'rev-parse', 'refs/heads/main');
  const findings = await scanPush({ mirror, repository, env: {}, changes: [{ ref: 'refs/heads/main', oldOid: '0'.repeat(40), newOid: head, operation: 'create' }], settings: { secrets: true }, commits: [head] });
  assert.deepEqual(findings, []);
});

test('pathBlocked semantics: case-insensitive, basename, directory, and suffix patterns', () => {
  // "dir/" is a directory prefix from the root.
  assert(pathBlocked(['.github/workflows/'], '.github/workflows/ci.yml'));
  assert(pathBlocked(['.github/workflows/'], '.GitHub/Workflows/CI.yml'));
  assert(!pathBlocked(['secrets/'], 'src/secrets/x'));
  // "*.ext" matches a basename suffix at any depth, case-insensitively.
  assert(pathBlocked(['*.pem'], 'a/b/key.pem'));
  assert(pathBlocked(['*.pem'], 'KEY.PEM'));
  assert(!pathBlocked(['*.pem'], 'a/pem'));
  assert(!pathBlocked(['*.pem'], 'a.pem/readme'));
  // A bare name matches that basename at any depth, and the exact path.
  assert(pathBlocked(['.env'], '.env'));
  assert(pathBlocked(['.env'], 'config/.env'));
  assert(pathBlocked(['.env'], 'config/.ENV'));
  assert(!pathBlocked(['.env'], 'config/.env.example'));
  // A path with "/" matches exactly or as a directory, not as a string prefix.
  assert(pathBlocked(['deploy/prod'], 'deploy/prod'));
  assert(pathBlocked(['deploy/prod'], 'Deploy/Prod/keys.txt'));
  assert(!pathBlocked(['deploy/prod'], 'deploy/production.txt'));
  // Patterns are never regexes.
  assert(!pathBlocked(['(a+)+$'], 'aaaaaaaaaaaaaaaaaaaaaaaaaaaa!'));
});

test('pathAllowed covers an exact path or a directory, case-insensitively', () => {
  assert(pathAllowed('docs/example.md', 'docs/example.md'));
  assert(pathAllowed('docs/example.md', 'DOCS/Example.md'));
  assert(pathAllowed('docs', 'docs/a/b.md'));
  assert(pathAllowed('docs/', 'docs/a/b.md'));
  assert(!pathAllowed('docs', 'docsX/a.md'));
  assert(!pathAllowed('docs/example.md', 'other/docs/example.md'));
});

test('scan settings are validated strictly', () => {
  const withScan = (scan) => { const config = exampleConfig(); config.repositories[0].scan = scan; return () => validateConfig(config); };
  withScan({ secrets: true, blockedPaths: ['*.pem', 'dir/'], maxBlobBytes: 10, allowlist: [{ rule: 'blocked-path', path: 'dir/x' }] })();
  assert.throws(withScan({ secret: true }), /Unknown/);
  assert.throws(withScan({ secrets: 'yes' }), /boolean/);
  assert.throws(withScan({ maxBlobBytes: 0 }), /positive/);
  assert.throws(withScan({ maxBlobBytes: 1.5 }), /positive/);
  assert.throws(withScan({ blockedPaths: 'x' }), /blockedPaths/);
  assert.throws(withScan({ blockedPaths: ['a*b'] }), /blockedPaths/);
  for (const bad of ['', '/etc', './x', 'a/../b', '..', '*.', '*.a/b', '*.p*']) assert.throws(withScan({ blockedPaths: [bad] }), /blockedPaths/, bad);
  for (const bad of ['/x', './x', 'a/..', 'a*']) assert.throws(withScan({ allowlist: [{ rule: 'blocked-path', path: bad }] }), /allowlist path/, bad);
  withScan({ secrets: true, maxBlobBytes: MAX_SECRET_SCAN_BYTES })();
  withScan({ secrets: false, maxBlobBytes: MAX_SECRET_SCAN_BYTES + 1 })();
  assert.throws(withScan({ secrets: true, maxBlobBytes: MAX_SECRET_SCAN_BYTES + 1 }), /at most/);
  assert.throws(withScan({ blockedPaths: Array(101).fill('a') }), /blockedPaths/);
  assert.throws(withScan({ allowlist: [{ rule: 'nope', path: 'x' }] }), /allowlist rule/);
  assert.throws(withScan({ allowlist: [{ rule: 'aws-access-key', path: '' }] }), /allowlist path/);
  assert.throws(withScan({ allowlist: [{ rule: 'aws-access-key', path: 'x', extra: 1 }] }), /Unknown/);
  assert.throws(withScan([]), /object/);
});

test('blocked paths and allowlist apply case-insensitively through the push path', async (t) => {
  const { f, forwarded } = await scanned(t, { secrets: true, blockedPaths: ['.env'], allowlist: [{ rule: 'aws-access-key', path: 'fixtures' }] });
  assert.notEqual(await pushResult(f, { 'config/.ENV': 'X=1\n' }), 'pushed');
  assert.equal(forwarded(), 0);
  assert.equal(await pushResult(f, { 'Fixtures/aws.txt': `${fakeAws()}\n` }), 'pushed');
});

test('with secrets on, a blob larger than the secret scan limit is blocked even without maxBlobBytes', async (t) => {
  const { f, forwarded, audit } = await scanned(t, { secrets: true });
  assert.notEqual(await pushResult(f, { 'huge.bin': Buffer.alloc(MAX_SECRET_SCAN_BYTES + 1, 0x61) }), 'pushed');
  assert.equal(forwarded(), 0);
  const blocked = (await audit()).filter((event) => event.decision === 'content-blocked');
  assert.deepEqual(blocked.map((event) => event.findings.map(({ kind, rule, path }) => `${kind}:${rule}:${path}`)), [['size:max-blob-bytes:huge.bin']]);
});

async function rawPush(f, clone, { ref, oldOid, newOid, base, extra = [], thin = false }) {
  const pack = join(f.directory, `p-${Math.random().toString(16).slice(2)}.pack`);
  const revs = `${newOid}\n^${base}\n`;
  const listed = (await f.git(clone, 'rev-list', '--objects', newOid, `^${base}`)).split('\n').map((line) => line.slice(0, 40));
  if (thin) await f.git(clone, 'pack-objects', '--stdout', '--thin', '--revs', { input: revs, output: pack });
  else await f.git(clone, 'pack-objects', '--stdout', { input: `${[...listed, ...extra].join('\n')}\n`, output: pack });
  const body = Buffer.concat([packet(`${oldOid} ${newOid} ${ref}\0report-status`), Buffer.from('0000'), await readFile(pack)]);
  const response = await fetch(`${f.gate.url}/acme/demo.git/git-receive-pack`, { method: 'POST', body,
    headers: { ...f.authHeaders, 'content-type': 'application/x-git-receive-pack-request' } });
  return { status: response.status, text: await response.text() };
}

test('a pack carrying an unreferenced object is refused and nothing is forwarded', async (t) => {
  const { f, forwarded } = await scanned(t, { secrets: true });
  const { clone } = await cloneWith(f, { 'clean.txt': 'clean\n' });
  await writeFile(join(clone, 'hidden.txt'), `${fakeGithub()}\n`);
  const hidden = await f.git(clone, 'hash-object', '-w', 'hidden.txt');
  const main = await f.git(clone, 'rev-parse', 'origin/main');
  const head = await f.git(clone, 'rev-parse', 'HEAD');
  const result = await rawPush(f, clone, { ref: 'refs/heads/agent/raw', oldOid: '0'.repeat(40), newOid: head, base: main, extra: [hidden] });
  assert.equal(result.status, 403);
  assert.match(result.text, /UNSCANNABLE_OBJECT/);
  assert(!result.text.includes('a'.repeat(36)));
  assert.equal(forwarded(), 0);
  // The same push without the extra object, sent as a thin pack against main, is forwarded.
  const thin = await rawPush(f, clone, { ref: 'refs/heads/agent/raw', oldOid: '0'.repeat(40), newOid: head, base: main, thin: true });
  assert.equal(thin.status, 200, thin.text);
  assert.equal(forwarded(), 1);
  assert.equal(await f.git(f.bare, 'rev-parse', 'refs/heads/agent/raw'), head);
});

test('thin-pack bases fixed into the quarantine are not treated as unreferenced objects', async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const { execFile } = await import('node:child_process');
  const { Readable } = await import('node:stream');
  const repository = { name: 'acme/demo', id: 1, installationId: 2 };
  const clone = join(f.directory, 'thin');
  await f.git(f.directory, 'clone', f.bare, clone);
  await f.git(clone, 'config', 'user.name', 'T');
  await f.git(clone, 'config', 'user.email', 't@example.com');
  const large = Array.from({ length: 4000 }, (_, index) => `line ${index} of a delta base\n`).join('');
  await commitFiles(f, clone, { 'base.txt': large }, 'base');
  await f.git(clone, 'push', 'origin', 'HEAD:refs/heads/main');
  const mirror = new Mirror({ root: join(f.directory, 'm'), allowedProtocols: ['file'], fetchRemote: async () => ({ url: f.bare }) });
  await mirror.sync(repository);
  await commitFiles(f, clone, { 'base.txt': `${large}one more line\n` }, 'delta');
  const oldOid = await f.git(clone, 'rev-parse', 'origin/main');
  const newOid = await f.git(clone, 'rev-parse', 'HEAD');
  const packPath = join(f.directory, 'thin.pack');
  await f.git(clone, 'pack-objects', '--thin', '--stdout', '--revs', '--quiet', { input: `${newOid}\n^${oldOid}\n`, output: packPath });
  const commands = Buffer.concat([packet(`${oldOid} ${newOid} refs/heads/main\0report-status`), Buffer.from('0000')]);
  const quarantine = await mirror.quarantine(repository, Readable.from([commands, await readFile(packPath)]), { maxBytes: 10 * 1024 * 1024 });
  t.after(() => quarantine.cleanup());
  const env = { ...mirror.env({ GIT_OBJECT_DIRECTORY: quarantine.objectsDir }) };
  const all = await new Promise((done, reject) => execFile('git', ['cat-file', '--batch-all-objects', '--batch-check=%(objectname)'], { cwd: mirror.path(repository), env },
    (error, stdout) => error ? reject(error) : done(stdout.trim().split('\n'))));
  // The pack was thin: index-pack --fix-thin copied the old base blob into the quarantine.
  assert(all.includes(await f.git(clone, 'rev-parse', `${oldOid}:base.txt`)));
  assert.deepEqual(await mirror.quarantinedObjects(repository, quarantine.objectsDir).then((oids) => oids.length), 3);
  const changes = [{ ref: 'refs/heads/main', oldOid, newOid, operation: 'update' }];
  assert.deepEqual(await scanPush({ mirror, repository, env: quarantine.env, objectsDir: quarantine.objectsDir, changes, settings: { secrets: true } }), []);
});

test('scan path patterns reject "." and empty segments that could never match a Git path', async () => {
  const { validScanPath } = await import('../src/scan.js');
  for (const bad of ['.', 'a/./b', 'dir/.', 'dir/./', 'a//b', '//', '*./x', './a']) assert.equal(validScanPath(bad, { glob: true }), false, bad);
  for (const good of ['.github/workflows/', 'a/b', 'secrets.env', '*.pem', 'dir/']) assert.equal(validScanPath(good, { glob: true }), true, good);
});

test('a mirror sync failure does not spend an approval grant for a scanned push', async (t) => {
  const { adminRequest } = await import('../src/admin-client.js');
  const { pushBody } = await import('../scripts/support/fixture.js');
  const { GateError } = await import('../src/errors.js');
  const config = exampleConfig();
  config.repositories[0].scan = { secrets: true };
  let syncs = 0;
  let failSync = true;
  const mirror = { sync: async () => { syncs++; if (failSync) throw new GateError(502, 'MIRROR_FAILED', 'upstream unreachable'); },
    quarantine: async () => { throw new GateError(400, 'INVALID_PUSH', 'stop after sync'); } };
  const f = await fixture({ config, mirror });
  t.after(() => f.close());
  const push = () => fetch(`${f.remote}/git-receive-pack`, { method: 'POST', headers: { ...f.authHeaders, 'content-type': 'application/x-git-receive-pack-request' }, body: pushBody() });
  const first = await push();
  assert.equal((await first.json()).code, 'REQUIRE_APPROVAL');
  assert.equal(syncs, 0, 'no sync while no grant exists');
  const [pending] = f.gate.state.list();
  await adminRequest(f.gate.adminSocket, 'POST', `/approvals/${pending.id}/approve`, { reviewer: 'local:reviewer' });
  const failed = await push();
  assert.equal(failed.status, 502);
  await failed.arrayBuffer();
  assert.equal(syncs, 1);
  assert.equal(f.gate.state.list()[0].status, 'approved', 'grant stays unspent after a sync failure');
  failSync = false;
  const retried = await push();
  assert.equal(retried.status, 400);
  await retried.arrayBuffer();
  assert.equal(syncs, 2, 'the scan path does not sync twice');
  assert.equal(f.gate.state.list()[0].status, 'consumed');
});
