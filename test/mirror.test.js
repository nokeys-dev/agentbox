import test from 'node:test';
import assert from 'node:assert/strict';
import { createReadStream } from 'node:fs';
import { readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { Mirror, mirrorDirectory } from '../src/mirror.js';
import { fixture, packet } from '../scripts/support/fixture.js';

const repository = { name: 'acme/demo', id: 1, installationId: 2 };
const zero = '0'.repeat(40);

async function setup(t, options = {}) {
  const f = await fixture();
  t.after(() => f.close());
  const root = join(f.directory, 'mirrors');
  const mirror = new Mirror({ root, allowedProtocols: ['file'], fetchRemote: async () => ({ url: f.bare }), ...options });
  return { f, root, mirror };
}

test('quarantines a real push pack against a mirror and lists only new commits', async (t) => {
  const { f, mirror } = await setup(t);
  const path = await mirror.sync(repository);
  assert.equal(await f.git(path, 'rev-parse', 'refs/heads/main'), await f.git(f.bare, 'rev-parse', 'refs/heads/main'));
  assert.equal((await stat(join(f.directory, 'mirrors'))).mode & 0o777, 0o700);

  const clone = join(f.directory, 'work');
  await f.git(f.directory, 'clone', f.bare, clone);
  await f.git(clone, 'config', 'user.name', 'T');
  await f.git(clone, 'config', 'user.email', 't@example.com');
  await writeFile(join(clone, 'a.txt'), 'a\n');
  await f.git(clone, 'add', '.');
  await f.git(clone, 'commit', '-m', 'one');
  await writeFile(join(clone, 'b.txt'), 'b\n');
  await f.git(clone, 'add', '.');
  await f.git(clone, 'commit', '-m', 'two');
  const oldOid = await f.git(clone, 'rev-parse', 'origin/main');
  const newOid = await f.git(clone, 'rev-parse', 'HEAD');
  const packPath = join(f.directory, 'thin.pack');
  await f.git(clone, '-c', 'pack.window=0', 'pack-objects', '--thin', '--stdout', '--revs', '--quiet', { input: `${newOid}\n^${oldOid}\n`, output: packPath });
  const commands = Buffer.concat([packet(`${oldOid} ${newOid} refs/heads/main\0report-status`), Buffer.from('0000')]);
  const body = Readable.from([commands, await readFile(packPath)]);

  const quarantine = await mirror.quarantine(repository, body, { maxBytes: 10 * 1024 * 1024 });
  t.after(() => quarantine.cleanup());
  assert.equal((await stat(quarantine.pack)).mode & 0o777, 0o600);
  assert.deepEqual(Buffer.concat(await Array.fromAsync(createReadStream(quarantine.pack))), Buffer.concat([commands, await readFile(packPath)]));
  const commits = await mirror.newCommits(repository, quarantine.env, [{ ref: 'refs/heads/main', oldOid, newOid, operation: 'update' }]);
  assert.equal(commits.length, 2);
  assert.equal(commits[0], newOid);
  assert.deepEqual(await mirror.newCommits(repository, quarantine.env, [{ ref: 'refs/heads/main', oldOid, newOid: zero, operation: 'delete' }]), []);
  await assert.rejects(mirror.newCommits(repository, quarantine.env, [{ ref: 'refs/heads/x', oldOid, newOid: '--all', operation: 'update' }]), /Invalid object id/);
  await assert.rejects(f.git(path, 'cat-file', '-e', newOid), 'quarantined objects are not in the mirror');
  await quarantine.cleanup();
  await assert.rejects(stat(quarantine.objectsDir));
});

test('delete-only pushes need no pack, oversized pushes fail closed and clean up', async (t) => {
  const { f, root, mirror } = await setup(t);
  await mirror.sync(repository);
  const oid = await f.git(f.bare, 'rev-parse', 'refs/heads/main');
  const commands = Buffer.concat([packet(`${oid} ${zero} refs/heads/main\0report-status delete-refs`), Buffer.from('0000')]);
  const quarantine = await mirror.quarantine(repository, Readable.from([commands]), { maxBytes: 1024 });
  await quarantine.cleanup();

  await assert.rejects(mirror.quarantine(repository, Readable.from([commands, Buffer.alloc(2048)]), { maxBytes: 1024 }), { code: 'BODY_TOO_LARGE' });
  await assert.rejects(mirror.quarantine(repository, Readable.from([commands, Buffer.from('JUNKJUNK')]), { maxBytes: 1024 }), { code: 'INVALID_PUSH' });
  await assert.rejects(mirror.quarantine(repository, Readable.from([commands, Buffer.from('PACK\0\0\0\x02garbage')]), { maxBytes: 1024 }), { code: 'QUARANTINE_FAILED' });
  const aborted = Readable.from((async function* () { yield commands; throw new Error('client went away'); })());
  await assert.rejects(mirror.quarantine(repository, aborted, { maxBytes: 1024 }), /client went away/);
  assert.deepEqual((await readdir(root)).filter((name) => name.startsWith('quarantine-')), []);
});

test('refuses unsafe ids and disallowed protocols, and never stores the header', async (t) => {
  const { f } = await setup(t);
  const root = join(f.directory, 'mirrors');
  const secret = 'Authorization: Basic c2VjcmV0LXRva2Vu';
  const strict = new Mirror({ root, fetchRemote: async () => ({ url: f.bare, extraHeader: secret }) });
  await assert.rejects(strict.sync(repository), /protocol file is not allowed/);
  await assert.rejects(strict.sync({ ...repository, id: '../x' }), { code: 'INVALID_REPOSITORY' });
  const credentialed = new Mirror({ root, fetchRemote: async () => ({ url: 'https://user:pw@example.invalid/x.git' }) });
  await assert.rejects(credentialed.sync(repository), /must not embed credentials/);

  const allowed = new Mirror({ root, allowedProtocols: ['file'], fetchRemote: async () => ({ url: f.bare, extraHeader: secret }) });
  const [first, second] = await Promise.all([allowed.sync(repository), allowed.sync(repository)]);
  assert.equal(first, second);
  const config = await readFile(join(first, 'config'), 'utf8');
  assert.ok(!config.includes('c2VjcmV0') && !config.includes(f.bare));

  const failing = new Mirror({ root, allowedProtocols: ['file'], fetchRemote: async () => ({ url: join(f.directory, 'missing.git'), extraHeader: secret }) });
  await assert.rejects(failing.sync(repository), (error) => error.code === 'MIRROR_FAILED' && !error.message.includes('c2VjcmV0'));
});

test('fails closed on objects a commit scan cannot cover and on data after the pack', async (t) => {
  const { f, root, mirror } = await setup(t);
  await mirror.sync(repository);
  const clone = join(f.directory, 'work');
  await f.git(f.directory, 'clone', f.bare, clone);
  await f.git(clone, 'config', 'user.name', 'T');
  await f.git(clone, 'config', 'user.email', 't@example.com');
  await writeFile(join(clone, 'secret.txt'), 'new blob content\n');
  await f.git(clone, 'add', '.');
  await f.git(clone, 'commit', '-m', 'blob');
  const base = await f.git(clone, 'rev-parse', 'origin/main');
  const commit = await f.git(clone, 'rev-parse', 'HEAD');
  const blob = await f.git(clone, 'rev-parse', 'HEAD:secret.txt');
  const tree = await f.git(clone, 'rev-parse', 'HEAD^{tree}');
  await f.git(clone, 'tag', '-a', '-m', 'release', 'v1', commit);
  await f.git(clone, 'tag', '-a', '-m', 'tree', 'vtree', tree);
  const tagCommit = await f.git(clone, 'rev-parse', 'v1');
  const tagTree = await f.git(clone, 'rev-parse', 'vtree');
  const packPath = join(f.directory, 'all.pack');
  await f.git(clone, 'pack-objects', '--stdout', '--revs', '--quiet', { input: `${commit}\n${tagCommit}\n${tagTree}\n^${base}\n`, output: packPath });
  const packBytes = await readFile(packPath);
  const push = (lines) => Buffer.concat([...lines.map((line, index) => packet(index ? line : `${line}\0report-status`)), Buffer.from('0000')]);
  const change = (ref, newOid) => ({ ref, oldOid: zero, newOid, operation: 'create' });

  const quarantine = await mirror.quarantine(repository, Readable.from([push([`${zero} ${commit} refs/heads/x`]), packBytes]), { maxBytes: 1 << 20 });
  t.after(() => quarantine.cleanup());
  const { env } = quarantine;
  assert.deepEqual(await mirror.newCommits(repository, env, [change('refs/tags/v1', tagCommit)]), [commit]);
  assert.ok((await mirror.newObjects(repository, env, [change('refs/heads/x', commit)])).includes(blob));
  await assert.rejects(mirror.newCommits(repository, env, [change('refs/heads/x', 'a'.repeat(40))]), { status: 403, code: 'UNSCANNABLE_OBJECT' });
  await assert.rejects(mirror.newCommits(repository, env, [change('refs/heads/b', blob)]), { status: 403, code: 'UNSCANNABLE_OBJECT' });
  await assert.rejects(mirror.newObjects(repository, env, [change('refs/tags/vtree', tagTree)]), { status: 403, code: 'UNSCANNABLE_OBJECT' });

  await assert.rejects(mirror.quarantine(repository, Readable.from([push([`${zero} ${commit} refs/heads/x`]), packBytes, Buffer.from('0000')]), { maxBytes: 1 << 20 }),
    { status: 400, code: 'INVALID_PUSH' });
  const small = new Mirror({ root, allowedProtocols: ['file'], fetchRemote: async () => ({ url: f.bare }), maxObjects: 2 });
  await assert.rejects(small.newObjects(repository, env, [change('refs/heads/x', commit)]), { code: 'QUARANTINE_FAILED' });
});

test('sweeps stale quarantine directories on first use', async (t) => {
  const { root, mirror } = await setup(t);
  await mirror.sync(repository);
  const { mkdir, utimes } = await import('node:fs/promises');
  await mkdir(join(root, 'quarantine-old'));
  await mkdir(join(root, 'quarantine-new'));
  const old = new Date(Date.now() - 2 * 60 * 60_000);
  await utimes(join(root, 'quarantine-old'), old, old);
  // A symlink named like a quarantine is never followed or removed.
  const { symlink } = await import('node:fs/promises');
  await mkdir(join(root, 'outside'));
  await utimes(join(root, 'outside'), old, old);
  await symlink(join(root, 'outside'), join(root, 'quarantine-link'));
  const fresh = new Mirror({ root, allowedProtocols: ['file'], fetchRemote: mirror.fetchRemote });
  await fresh.sync(repository);
  assert.deepEqual((await readdir(root)).filter((name) => name.startsWith('quarantine-')).sort(), ['quarantine-link', 'quarantine-new']);
  assert.ok((await stat(join(root, 'outside'))).isDirectory());
  assert.throws(() => new Mirror({ root, fetchRemote: mirror.fetchRemote, timeoutMs: 60_000, staleMs: 60_000 }), /staleMs must be greater than timeoutMs/);
});

test('mirror directory honours AGENTGATE_MIRROR_DIR and defaults under the state directory', () => {
  assert.equal(mirrorDirectory({ AGENTGATE_MIRROR_DIR: '/var/lib/agentgate-mirrors', AGENTGATE_STATE_DIR: '/state' }), '/var/lib/agentgate-mirrors');
  assert.equal(mirrorDirectory({ AGENTGATE_STATE_DIR: '/state' }), '/state/mirrors');
  assert.equal(mirrorDirectory({}), resolve('.agentgate', 'mirrors'));
});

test('compose mounts the mirror volume only into agentd', async () => {
  const compose = await readFile(new URL('../compose.yaml', import.meta.url), 'utf8');
  const services = compose.split('\nnetworks:\n')[0].split(/\n  (?=[a-z0-9-]+:\n)/);
  const mounting = services.filter((block) => /broker-mirrors:/.test(block)).map((block) => block.split(':')[0].trim());
  assert.deepEqual(mounting, ['agentd']);
  assert.match(compose, /AGENTGATE_MIRROR_DIR: \/var\/lib\/agentgate-mirrors/);
  const dockerfile = await readFile(new URL('../Dockerfile', import.meta.url), 'utf8');
  assert.match(dockerfile, /apt-get install -y --no-install-recommends git ca-certificates/);
  assert.match(dockerfile, /chmod 700 [^\n]*\/var\/lib\/agentgate-mirrors/);
});
