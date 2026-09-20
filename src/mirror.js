import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { lstat, mkdir, mkdtemp, open, readdir, rm, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { GateError } from './errors.js';
import { createCommandSectionScanner } from './git-protocol.js';

const hex = /^[0-9a-f]{40}$/;
const zero = '0'.repeat(40);
const protocolName = /^[a-z][a-z0-9+.-]{0,31}$/;

// Mirror location. Mirrors hold full repository contents, so in Compose they live on a volume
// mounted only into agentd (AGENTGATE_MIRROR_DIR), never on the state volume the audit forwarder
// and approval UI mount. Locally they default to <AGENTGATE_STATE_DIR>/mirrors.
export function mirrorDirectory(env = process.env) {
  if (env.AGENTGATE_MIRROR_DIR) return resolve(env.AGENTGATE_MIRROR_DIR);
  return resolve(env.AGENTGATE_STATE_DIR || '.agentgate', 'mirrors');
}

const failed = (code, message) => new GateError(422, code, message);

// Credentials, when present, arrive only as a header value handed to git through GIT_CONFIG_* env,
// so they never reach argv, the mirror's config, or a stored remote URL. Error text is built from
// the first stderr line with that value removed, never from the environment.
function run(git, args, { cwd, env, input, stdin, secret, timeoutMs, code = 'MIRROR_FAILED', maxLines = Infinity, maxBytes = Infinity, raw = false }) {
  return new Promise((done, reject) => {
    const child = spawn(git, args, { cwd, env, stdio: ['pipe', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    let errBytes = 0;
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
        stdin?.destroy();
        reject(error);
      } else done(value);
    };
    const timer = setTimeout(() => finish(failed(code, `git ${args[0]} timed out`)), timeoutMs);
    let lines = 0;
    let bytes = 0;
    child.stdout.on('data', (chunk) => {
      out.push(chunk);
      bytes += chunk.length;
      if (bytes > maxBytes) return finish(failed(code, `git ${args[0]} output exceeds ${maxBytes} bytes`));
      for (const byte of chunk) if (byte === 10) lines += 1;
      // Output that exceeds the cap fails closed instead of being truncated.
      if (lines > maxLines) finish(failed(code, `git ${args[0]} output exceeds ${maxLines} entries`));
    });
    child.stderr.on('data', (chunk) => { if (errBytes < 65536) { err.push(chunk); errBytes += chunk.length; } });
    child.on('error', () => finish(failed(code, `git ${args[0]} could not start`)));
    child.stdin.on('error', () => {});
    child.on('close', (status) => {
      if (status === 0) return finish(null, raw ? Buffer.concat(out) : Buffer.concat(out).toString('utf8').trim());
      let detail = Buffer.concat(err).toString('utf8').split('\n').find((line) => line.trim()) ?? '';
      if (secret) detail = detail.split(secret).join('[redacted]');
      finish(failed(code, `git ${args[0]} failed: ${detail.replace(/[^\x20-\x7e]/g, '?').slice(0, 200)}`));
    });
    if (stdin) {
      stdin.on('error', (error) => finish(error));
      stdin.pipe(child.stdin);
    } else child.stdin.end(input);
  });
}

export class Mirror {
  constructor({ root, git = 'git', fetchRemote, allowedProtocols = ['https'], timeoutMs = 10 * 60_000, maxCommits = 10_000, maxObjects = 100_000, staleMs = 60 * 60_000 }) {
    if (typeof root !== 'string' || !root || root.includes(':')) throw new Error('Mirror root must be a path without ":"');
    if (typeof fetchRemote !== 'function') throw new Error('fetchRemote is required');
    if (!Array.isArray(allowedProtocols) || !allowedProtocols.every((name) => protocolName.test(name))) throw new Error('Invalid allowedProtocols');
    // The startup sweep deletes quarantines older than staleMs; a live one can be up to timeoutMs
    // old per git step, so staleMs must exceed it or a sweep could delete a quarantine in use.
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || !Number.isSafeInteger(staleMs) || staleMs <= timeoutMs) throw new Error('Mirror staleMs must be greater than timeoutMs');
    Object.assign(this, { root: resolve(root), git, fetchRemote, allowedProtocols: [...allowedProtocols], timeoutMs, maxCommits, maxObjects, staleMs, locks: new Map(), swept: null });
  }

  path(repository) {
    const id = repository?.id;
    if (!Number.isSafeInteger(id) || id <= 0) throw new GateError(400, 'INVALID_REPOSITORY', 'Repository id must be a positive integer');
    return join(this.root, `${id}.git`);
  }

  // Minimal, fully controlled environment: nothing inherited except PATH, no system/global config,
  // an empty HOME, no prompts, no hooks, fsmonitor or auto-gc, and only allowlisted transports.
  env(extra = {}, header) {
    const config = [
      ['protocol.allow', 'never'],
      ...this.allowedProtocols.map((name) => [`protocol.${name}.allow`, 'always']),
      ['core.hooksPath', '/dev/null'],
      ['core.fsmonitor', 'false'],
      ['credential.helper', ''],
      ['gc.auto', '0'],
      ['maintenance.auto', 'false'],
      ['http.followRedirects', 'false'],
      ...(header ? [['http.extraHeader', header]] : [])
    ];
    const env = { PATH: process.env.PATH ?? '/usr/bin:/bin', LC_ALL: 'C', HOME: join(this.root, '.home'), XDG_CONFIG_HOME: join(this.root, '.home'),
      GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: '', SSH_ASKPASS: '',
      GIT_CONFIG_COUNT: String(config.length) };
    config.forEach(([key, value], index) => { env[`GIT_CONFIG_KEY_${index}`] = key; env[`GIT_CONFIG_VALUE_${index}`] = value; });
    return { ...env, ...extra };
  }

  async prepare() {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    await mkdir(join(this.root, '.home'), { mode: 0o700 }).catch((error) => { if (error.code !== 'EEXIST') throw error; });
    this.swept ??= this.sweep();
    await this.swept;
  }

  // Removes quarantine directories left behind by a crashed process. Runs once per instance; only
  // directories older than staleMs are touched so live quarantines of another process survive.
  async sweep() {
    const cutoff = Date.now() - this.staleMs;
    for (const name of await readdir(this.root).catch(() => [])) {
      if (!name.startsWith('quarantine-')) continue;
      const path = join(this.root, name);
      // lstat: a symlink named quarantine-* is never followed, only left alone.
      const info = await lstat(path).catch(() => null);
      if (info?.isDirectory() && info.mtimeMs < cutoff) await rm(path, { recursive: true, force: true }).catch(() => {});
    }
  }

  serialize(repository, work) {
    const key = repository.id;
    const next = (this.locks.get(key) ?? Promise.resolve()).catch(() => {}).then(work);
    const tail = next.catch(() => {});
    this.locks.set(key, tail);
    tail.then(() => { if (this.locks.get(key) === tail) this.locks.delete(key); });
    return next;
  }

  async sync(repository) {
    const path = this.path(repository);
    return this.serialize(repository, async () => {
      await this.prepare();
      const remote = await this.fetchRemote(repository);
      const url = remote?.url;
      if (typeof url !== 'string' || !url || url.startsWith('-')) throw failed('MIRROR_FAILED', 'Invalid mirror remote');
      const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(url)?.[1]?.toLowerCase() ?? 'file';
      if (!this.allowedProtocols.includes(scheme)) throw failed('MIRROR_FAILED', `Mirror remote protocol ${scheme} is not allowed`);
      if (scheme !== 'file' && /^[a-z][a-z0-9+.-]*:\/\/[^/]*@/i.test(url)) throw failed('MIRROR_FAILED', 'Mirror remote URL must not embed credentials');
      const header = remote.extraHeader;
      if (header !== undefined && (typeof header !== 'string' || /[\r\n\0]/.test(header))) throw failed('MIRROR_FAILED', 'Invalid mirror header');
      const options = { env: this.env({}, header), secret: header, timeoutMs: this.timeoutMs };
      const exists = await stat(join(path, 'objects')).then(() => true, () => false);
      if (!exists) await run(this.git, ['init', '--bare', '--quiet', '--', path], { ...options, cwd: this.root });
      // The URL is passed on the command line, never saved as a configured remote.
      await run(this.git, ['fetch', '--prune', '--quiet', '--no-tags', '--no-write-fetch-head', '--end-of-options', url,
        '+refs/heads/*:refs/heads/*', '+refs/tags/*:refs/tags/*'], { ...options, cwd: path });
      return path;
    });
  }

  async quarantine(repository, body, { maxBytes }) {
    if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) throw new Error('maxBytes must be a positive integer');
    const mirrorPath = this.path(repository);
    try {
      await this.prepare();
    } catch (error) { body.destroy?.(); throw error; }
    let directory;
    try {
      directory = await mkdtemp(join(this.root, 'quarantine-'));
    } catch (error) { body.destroy?.(); throw error; }
    const cleanup = () => rm(directory, { recursive: true, force: true });
    try {
      const objectsDir = join(directory, 'objects');
      await mkdir(join(objectsDir, 'pack'), { recursive: true, mode: 0o700 });
      const pack = join(directory, 'push.raw');
      let size = 0;
      const limit = new Transform({ transform(chunk, _encoding, callback) {
        size += chunk.length;
        callback(size > maxBytes ? new GateError(413, 'BODY_TOO_LARGE', 'Push exceeds scan limit') : null, chunk);
      } });
      await pipeline(body, limit, createWriteStream(pack, { mode: 0o600, flags: 'wx' }));
      const packOffset = await sectionEnd(pack, size);
      const env = this.env({ GIT_OBJECT_DIRECTORY: objectsDir, GIT_ALTERNATE_OBJECT_DIRECTORIES: join(mirrorPath, 'objects') });
      // Indexing runs under the repository lock so a concurrent sync (init or fetch) never changes
      // the alternate object store underneath index-pack.
      await this.serialize(repository, async () => {
        if (!await stat(join(mirrorPath, 'objects')).then(() => true, () => false)) throw failed('QUARANTINE_FAILED', 'Repository mirror has not been synced');
        // Delete-only pushes and probes carry no pack.
        if (packOffset >= size) return;
        const handle = await open(pack, 'r');
        const signature = Buffer.alloc(4);
        try { await handle.read(signature, 0, 4, packOffset); } finally { await handle.close(); }
        if (signature.toString('latin1') !== 'PACK') throw new GateError(400, 'INVALID_PUSH', 'Expected a pack after the command section');
        const output = await run(this.git, ['index-pack', '--stdin', '--fix-thin', '--strict'],
          { cwd: mirrorPath, env, stdin: createReadStream(pack, { start: packOffset }), timeoutMs: this.timeoutMs, code: 'QUARANTINE_FAILED' });
        // index-pack prints exactly one "pack\t<hash>" (or "keep\t<hash>") line. Anything else, or a
        // pack trailer that does not hash the bytes before it, means data follows the pack: GitHub
        // would see bytes the scan never indexed, so refuse the push.
        if (!/^(pack|keep)\t[0-9a-f]{40}$/.test(output)) throw new GateError(400, 'INVALID_PUSH', 'Unexpected data after the pack');
        if (!await trailerMatches(pack, packOffset, size)) throw new GateError(400, 'INVALID_PUSH', 'Unexpected data after the pack');
      });
      return { pack, objectsDir, env, cleanup };
    } catch (error) {
      body.destroy?.();
      await cleanup();
      throw error;
    }
  }

  // Validates every pushed tip and returns the distinct non-zero ones. A tip must peel to a commit:
  // a ref pointing at a tree or blob (directly or through tags) has no commit to scan, and a missing
  // object cannot be inspected, so both fail closed.
  async tips(repository, env, changes) {
    const tips = new Set();
    for (const change of changes) {
      if (!hex.test(change?.newOid ?? '')) throw new GateError(400, 'INVALID_PUSH', 'Invalid object id');
      if (change.newOid !== zero && change.operation !== 'delete') tips.add(change.newOid);
    }
    if (!tips.size) return [];
    const list = [...tips];
    const output = await run(this.git, ['cat-file', '--batch-check=%(objecttype)'],
      { cwd: this.path(repository), env, input: list.map((oid) => `${oid}^{}\n`).join(''), timeoutMs: this.timeoutMs, code: 'QUARANTINE_FAILED' });
    const types = output.split('\n');
    list.forEach((oid, index) => {
      const type = types[index] ?? '';
      if (type.endsWith(' missing') || type === '') throw new GateError(403, 'UNSCANNABLE_OBJECT', `Pushed object ${oid} is missing`);
      if (type !== 'commit') throw new GateError(403, 'UNSCANNABLE_OBJECT', `Pushed object ${oid} does not resolve to a commit`);
    });
    return list;
  }

  // Revisions come from stdin (oids only, never options). "--stdin --not --all" is given on argv:
  // git reads stdin at the --stdin position, so the tips are positive and --not applies to --all
  // only. This does not depend on the pseudo-option-on-stdin support added in git 2.42.
  async revList(repository, env, tips, args, maxLines) {
    return run(this.git, ['rev-list', ...args, '--stdin', '--not', '--all'],
      { cwd: this.path(repository), env, input: `${tips.join('\n')}\n`, timeoutMs: this.timeoutMs, code: 'QUARANTINE_FAILED', maxLines });
  }

  // Runs under the repository lock so a concurrent sync cannot move the mirror refs `--not --all`
  // is computed against.
  async newCommits(repository, env, changes) {
    return this.serialize(repository, async () => {
      const tips = await this.tips(repository, env, changes);
      if (!tips.length) return [];
      const output = await this.revList(repository, env, tips, [`--max-count=${this.maxCommits + 1}`], this.maxCommits);
      const commits = output ? output.split('\n') : [];
      if (commits.length > this.maxCommits) throw failed('QUARANTINE_FAILED', `Push introduces more than ${this.maxCommits} commits`);
      return commits;
    });
  }

  // Every object (commits, trees, blobs, tags) reachable from the pushed tips but not from any mirror
  // ref. Objects in the pack that no pushed ref reaches are not listed: receive-pack upstream never
  // references them from a ref, so they are not reachable content of the repository.
  async newObjects(repository, env, changes) {
    return this.serialize(repository, async () => {
      const tips = await this.tips(repository, env, changes);
      if (!tips.length) return [];
      const output = await this.revList(repository, env, tips, ['--objects'], this.maxObjects);
      const objects = output ? output.split('\n').map((line) => line.slice(0, 40)) : [];
      if (objects.length > this.maxObjects) throw failed('QUARANTINE_FAILED', `Push introduces more than ${this.maxObjects} objects`);
      return objects;
    });
  }

  // Every object physically present in the quarantine (not the mirror: no alternates), minus those
  // the mirror already has (index-pack --fix-thin copies thin-pack bases into the quarantine).
  async quarantinedObjects(repository, objectsDir) {
    const env = this.env({ GIT_OBJECT_DIRECTORY: objectsDir });
    delete env.GIT_ALTERNATE_OBJECT_DIRECTORIES;
    const output = await run(this.git, ['cat-file', '--batch-all-objects', '--batch-check=%(objectname)'],
      { cwd: this.path(repository), env, timeoutMs: this.timeoutMs, code: 'QUARANTINE_FAILED', maxLines: this.maxObjects });
    const oids = output ? output.split('\n') : [];
    if (oids.length > this.maxObjects) throw failed('QUARANTINE_FAILED', `Push carries more than ${this.maxObjects} objects`);
    if (!oids.length) return [];
    const present = await run(this.git, ['cat-file', '--batch-check=%(objectname)'],
      { cwd: this.path(repository), env: this.env(), input: `${oids.join('\n')}\n`, timeoutMs: this.timeoutMs, code: 'QUARANTINE_FAILED' });
    const lines = present.split('\n');
    return oids.filter((oid, index) => lines[index] !== oid);
  }

  // Added, modified, and type-changed tree entries of each commit, parents included for merges (-m)
  // and the empty tree for root commits (--root). Commits come from stdin; -z keeps any path intact.
  // Returns [{ commit, mode, oid, path }]; deletions carry no content and are excluded.
  async changedEntries(repository, env, commits, { maxBytes = 256 * 1024 * 1024 } = {}) {
    if (!commits.length) return [];
    for (const oid of commits) if (!hex.test(oid)) throw new GateError(400, 'INVALID_PUSH', 'Invalid object id');
    const output = await run(this.git, ['diff-tree', '--stdin', '-r', '-m', '--root', '-z', '--no-renames', '--no-ext-diff', '--diff-filter=d'],
      { cwd: this.path(repository), env: this.env(env), input: `${commits.join('\n')}\n`, timeoutMs: this.timeoutMs, code: 'QUARANTINE_FAILED', maxBytes, raw: true });
    const fields = output.toString('utf8').split('\0');
    const entries = [];
    let commit;
    for (let index = 0; index < fields.length; index++) {
      const field = fields[index];
      if (field.startsWith(':')) {
        const [, mode, , oid] = field.slice(1).split(' ');
        const path = fields[++index];
        if (commit === undefined || path === undefined || !hex.test(oid ?? '')) throw failed('QUARANTINE_FAILED', 'Unexpected diff-tree output');
        entries.push({ commit, mode, oid, path });
      } else if (/^[0-9a-f]{40}/.test(field)) commit = field.slice(0, 40);
      else if (field.trim()) throw failed('QUARANTINE_FAILED', 'Unexpected diff-tree output');
    }
    return entries;
  }

  // Type and size of each object, in input order.
  async objectInfo(repository, env, oids) {
    if (!oids.length) return [];
    for (const oid of oids) if (!hex.test(oid)) throw new GateError(400, 'INVALID_PUSH', 'Invalid object id');
    const output = await run(this.git, ['cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)'],
      { cwd: this.path(repository), env: this.env(env), input: `${oids.join('\n')}\n`, timeoutMs: this.timeoutMs, code: 'QUARANTINE_FAILED' });
    const lines = output.split('\n');
    return oids.map((oid, index) => {
      const [name, type, size] = (lines[index] ?? '').split(' ');
      if (name !== oid || type === 'missing' || !/^\d+$/.test(size ?? '')) throw new GateError(403, 'UNSCANNABLE_OBJECT', `Object ${oid} cannot be inspected`);
      return { oid, type, size: Number(size) };
    });
  }

  // Streams blob contents through one `git cat-file --batch`. Only one object is held in memory at a
  // time, and none larger than maxObjectBytes (callers must pre-filter by size).
  readBlobs(repository, env, oids, onBlob, { maxObjectBytes }) {
    for (const oid of oids) if (!hex.test(oid)) throw new GateError(400, 'INVALID_PUSH', 'Invalid object id');
    if (!oids.length) return Promise.resolve();
    return new Promise((done, reject) => {
      const child = spawn(this.git, ['cat-file', '--batch'], { cwd: this.path(repository), env: this.env(env), stdio: ['pipe', 'pipe', 'ignore'] });
      let settled = false;
      const finish = (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) {
          if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
          reject(error);
        } else done();
      };
      const timer = setTimeout(() => finish(failed('QUARANTINE_FAILED', 'git cat-file timed out')), this.timeoutMs);
      // Header bytes are tiny and kept in one buffer; body chunks are collected and concatenated once
      // per object, so parsing stays linear in the output size.
      let header = Buffer.alloc(0);
      let current = null;
      let parts = [];
      let collected = 0;
      let next = 0;
      child.stdout.on('data', (chunk) => {
        if (settled) return;
        try {
          while (chunk.length) {
            if (!current) {
              const newline = chunk.indexOf(10);
              if (newline < 0) {
                header = Buffer.concat([header, chunk]);
                if (header.length > 256) throw failed('QUARANTINE_FAILED', 'Unexpected cat-file output');
                return;
              }
              const line = Buffer.concat([header, chunk.subarray(0, newline)]);
              header = Buffer.alloc(0);
              chunk = chunk.subarray(newline + 1);
              const [oid, type, size] = line.toString('latin1').split(' ');
              if (oid !== oids[next] || type !== 'blob' || !/^\d+$/.test(size ?? '') || Number(size) > maxObjectBytes) {
                throw new GateError(403, 'UNSCANNABLE_OBJECT', `Object ${oids[next]} cannot be scanned`);
              }
              // +1 for the newline that terminates each object's content.
              current = { oid, size: Number(size), need: Number(size) + 1 };
              parts = [];
              collected = 0;
            }
            const take = Math.min(chunk.length, current.need - collected);
            parts.push(chunk.subarray(0, take));
            collected += take;
            chunk = chunk.subarray(take);
            if (collected < current.need) return;
            const content = Buffer.concat(parts, collected).subarray(0, current.size);
            parts = [];
            const { oid } = current;
            current = null;
            next += 1;
            onBlob(oid, content);
          }
        } catch (error) { finish(error); }
      });
      child.on('error', () => finish(failed('QUARANTINE_FAILED', 'git cat-file could not start')));
      child.stdin.on('error', () => {});
      child.on('close', (status) => {
        if (status !== 0 || next !== oids.length) return finish(failed('QUARANTINE_FAILED', 'git cat-file did not return every object'));
        finish();
      });
      child.stdin.end(`${oids.join('\n')}\n`);
    });
  }

}

async function sectionEnd(path, size) {
  const scan = createCommandSectionScanner();
  const limit = Math.min(size, 1024 * 1024 + 4);
  const handle = await open(path, 'r');
  try {
    const head = Buffer.alloc(limit);
    let read = 0;
    while (read < limit) {
      const { bytesRead } = await handle.read(head, read, Math.min(65536, limit - read), read);
      if (!bytesRead) break;
      read += bytesRead;
      const end = scan(head.subarray(0, read));
      if (end >= 0) return end;
    }
  } finally { await handle.close(); }
  throw new GateError(400, 'INVALID_PUSH', 'Command section not found');
}

// A pack ends with the SHA-1 of everything before it; checking that the last 20 bytes of the request
// are exactly that trailer proves no bytes follow the pack.
async function trailerMatches(path, start, size) {
  if (size - start < 32) return false;
  const hash = createHash('sha1');
  for await (const chunk of createReadStream(path, { start, end: size - 21 })) hash.update(chunk);
  const trailer = Buffer.alloc(20);
  const handle = await open(path, 'r');
  try { await handle.read(trailer, 0, 20, size - 20); } finally { await handle.close(); }
  return hash.digest().equals(trailer);
}
