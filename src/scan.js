import { GateError } from './errors.js';

// Pre-forward content scanning of pushed packs: secrets, blocked paths, and oversized blobs.
// Findings carry only kind, rule, commit, and path; the matched value or surrounding content is
// never stored, logged, audited, or returned. Git LFS objects are not part of the pack and are not
// scanned here.

// Every pattern is linear: no nested quantifiers or overlapping alternations.
export const SECRET_RULES = [
  ['private-key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/],
  ['github-token', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{80,255}\b/],
  ['aws-access-key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
  ['anthropic-key', /\bsk-ant-[A-Za-z0-9_-]{20,}\b/],
  ['openai-key', /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/],
  ['slack-token', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  ['gcp-service-account', /"type":\s*"service_account"/]
];

export const SCAN_RULE_IDS = [...SECRET_RULES.map(([id]) => id), 'blocked-path', 'max-blob-bytes'];

// Largest blob the secret rules read; with secrets on, anything larger is a max-blob-bytes finding.
export const MAX_SECRET_SCAN_BYTES = 10 * 1024 * 1024;

const GITLINK = '160000';

// ASCII-only case fold: never locale- or Unicode-dependent.
const fold = (value) => value.replace(/[A-Z]/g, (letter) => letter.toLowerCase());
const basename = (path) => path.slice(path.lastIndexOf('/') + 1);

// Pattern and path strings are compared with ===/startsWith/endsWith after an ASCII case fold; they
// are never compiled to a regex. Semantics (see docs/policy.md "Content scanning"):
//   "*.ext"   basename ends with ".ext", at any depth
//   "dir/"    everything below dir (from the repository root)
//   "name"    (no "/") that exact path, or that basename at any depth
//   "a/b"     that exact path, or everything below a/b/ (not a/bX)
export function pathBlocked(patterns, path) {
  const target = fold(path);
  return patterns.some((raw) => {
    const pattern = fold(raw);
    if (pattern.startsWith('*.')) return basename(target).endsWith(pattern.slice(1));
    if (pattern.endsWith('/')) return target.startsWith(pattern);
    if (!pattern.includes('/')) return target === pattern || basename(target) === pattern;
    return target === pattern || target.startsWith(`${pattern}/`);
  });
}

// Allowlist paths cover that exact path or the directory below it, case-insensitively.
export function pathAllowed(entryPath, path) {
  const pattern = fold(entryPath);
  const target = fold(path);
  return target === pattern || target.startsWith(pattern.endsWith('/') ? pattern : `${pattern}/`);
}

// Shared by config validation: no empty, absolute, "./"-relative, or ".." patterns, and no "." or
// empty segments anywhere (Git paths never contain them, so such a pattern would silently match
// nothing). A single trailing "/" (directory pattern) is allowed.
export function validScanPath(value, { glob }) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 4096 || /[\0\r\n]/.test(value)) return false;
  if (value.startsWith('/') || value.startsWith('./') || value.includes('..')) return false;
  const segments = (value.endsWith('/') ? value.slice(0, -1) : value).split('/');
  if (segments.some((segment) => segment === '' || segment === '.')) return false;
  if (!glob) return !value.includes('*');
  return value.startsWith('*.') ? value.length > 2 && !/[*/]/.test(value.slice(2)) : !value.includes('*');
}

export async function scanPush({ mirror, repository, env: extra, changes, settings, commits, objectsDir }) {
  const env = mirror.env(extra);
  // Objects the pack carries that no pushed ref reaches would be stored upstream without being
  // scanned, so they are refused rather than scanned.
  if (objectsDir) {
    const carried = await mirror.quarantinedObjects(repository, objectsDir);
    if (carried.length) {
      const reachable = new Set(await mirror.newObjects(repository, env, changes));
      const stray = carried.find((oid) => !reachable.has(oid));
      if (stray) throw new GateError(403, 'UNSCANNABLE_OBJECT', `Push carries object ${stray.slice(0, 12)} that no pushed ref references`);
    }
  }
  const list = commits ?? await mirror.newCommits(repository, env, changes);
  if (!list.length) return [];
  const allowlist = settings.allowlist ?? [];
  const allowed = (rule, path) => allowlist.some((entry) => entry.rule === rule && pathAllowed(entry.path, path));
  const findings = [];
  const reported = new Set();
  const report = (kind, rule, commit, path) => {
    const key = `${kind}\0${rule}\0${path}`;
    if (reported.has(key) || allowed(rule, path)) return;
    reported.add(key);
    findings.push({ kind, rule, commit, path });
  };

  // Every path each blob appears at in a new commit (merges against each parent, roots against the
  // empty tree), so path-scoped rules and allowlist entries are evaluated at all of them.
  const occurrences = new Map();
  for (const entry of await mirror.changedEntries(repository, env, list)) {
    if (settings.blockedPaths?.length && pathBlocked(settings.blockedPaths, entry.path)) report('path', 'blocked-path', entry.commit, entry.path);
    if (entry.mode === GITLINK) continue;
    if (!occurrences.has(entry.oid)) occurrences.set(entry.oid, []);
    const places = occurrences.get(entry.oid);
    if (!places.some((place) => place.path === entry.path)) places.push({ commit: entry.commit, path: entry.path });
  }

  // Defense in depth: any new blob reachable from the pushed tips that no diff attributed to a path
  // is still scanned, reported at an empty path against the first new commit.
  if (changes) {
    const reachable = await mirror.newObjects(repository, env, changes);
    const unseen = reachable.filter((oid) => !occurrences.has(oid));
    for (const info of await mirror.objectInfo(repository, env, unseen)) {
      if (info.type === 'blob') occurrences.set(info.oid, [{ commit: list[0], path: '' }]);
    }
  }

  const oids = [...occurrences.keys()];
  const toRead = [];
  for (const info of await mirror.objectInfo(repository, env, oids)) {
    if (info.type !== 'blob') continue;
    const places = occurrences.get(info.oid);
    // With secrets on, a blob too large to scan fails closed as a size finding.
    if ((settings.maxBlobBytes && info.size > settings.maxBlobBytes) || (settings.secrets && info.size > MAX_SECRET_SCAN_BYTES)) {
      for (const { commit, path } of places) report('size', 'max-blob-bytes', commit, path);
      continue;
    }
    if (settings.secrets) toRead.push(info.oid);
  }

  await mirror.readBlobs(repository, env, toRead, (oid, content) => {
    // latin1 maps every byte to one code unit, so binary content is scanned without decoding errors.
    const text = content.toString('latin1');
    for (const [rule, pattern] of SECRET_RULES) {
      if (!pattern.test(text)) continue;
      for (const { commit, path } of occurrences.get(oid)) report('secret', rule, commit, path);
    }
  }, { maxObjectBytes: MAX_SECRET_SCAN_BYTES });
  return findings;
}

export function publicFindings(findings) {
  return findings.map(({ kind, rule, path, commit }) => ({ kind, rule, path, commit: commit.slice(0, 12) }));
}
