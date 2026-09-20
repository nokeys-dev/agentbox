// Deterministic fuzzing of the wire-facing parsers: git-protocol's parsePush and
// github-api's routeApi/pullRequestPayload. Every generated input is derived from a
// seeded PRNG so a failure is reproducible: FUZZ_SEED=<n> FUZZ_ITERATIONS=<n> node --test test/fuzz.test.js
//
// FUZZ_SEED defaults to a FIXED value (not Date.now()) so that a plain `npm test` run
// stays deterministic: a failure in CI or locally always reproduces with the same seed.
// The nightly `test:fuzz` job (and any exploratory run) should pass FUZZ_SEED explicitly.
//
// Each generator below is grammar-based: it builds a mostly-valid input first (so the
// suite actually exercises the accepting paths, not just the 4xx-rejection paths), then
// optionally mutates it (structural corruption, byte-level corruption, or both) so the
// invalid paths stay well exercised too. Every property test asserts BOTH `accepted > 0`
// and `rejected > 0` so a degenerate generator (one that only ever produces one outcome)
// fails the suite instead of silently testing nothing.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { GateError } from '../src/errors.js';
import { parsePush, parsePushRequest } from '../src/git-protocol.js';
import { pullRequestPayload, forkHead, routeApi, commentPayload, reviewPayload, mergePayload } from '../src/github-api.js';
import { packet } from './support/fixture.js';
import { prng } from './support/prng.js';

const iterations = Number(process.env.FUZZ_ITERATIONS || 300);
const seed = Number(process.env.FUZZ_SEED || 1);
const hex = '0123456789abcdef';
const oid = (r) => Array.from({ length: 40 }, () => r.pick([...hex])).join('');

// ---- parsePush: grammar-based ref generator --------------------------------------------
// Builds a structurally valid ref (safe-character path components under refs/heads/) and
// then, about half the time, injects one clearly-invalid token (a forbidden character or a
// forbidden sequence like '..', '.lock', '@{') at a random position. This keeps a healthy
// fraction of generated refs fully valid (so `parsePush` actually reaches its accepting
// path) while still exercising every rejection rule. A flat per-character random alphabet
// (mixing valid and invalid characters uniformly) was tried first but drove the valid-ref
// probability toward zero as ref length grew, which is exactly the failure mode this
// generator needs to avoid (see task-8-report.md's fix-report addendum).
const refSafeChars = [...'abcAZ09_-'];
const refInvalidTokens = ['~', '^', ':', '?', '*', '[', '\\', 'é', ' ', '\t', '\u0000', '..', '.lock', '@{'];

function buildValidRef(r) {
  const parts = Array.from({ length: 1 + r.int(3) }, () => Array.from({ length: 1 + r.int(8) }, () => r.pick(refSafeChars)).join(''));
  return `refs/heads/${parts.join('/')}`;
}

function mutateRef(ref, r) {
  if (!r.chance(0.5)) return ref;
  const token = r.pick(refInvalidTokens);
  const at = 11 + r.int(Math.max(1, ref.length - 11)); // never corrupt the "refs/heads/" prefix
  return ref.slice(0, at) + token + ref.slice(at);
}

// A hang would otherwise block CI indefinitely with no indication of which seed caused it.
// The timeout scales with FUZZ_ITERATIONS (capped) so the default run stays snappy while
// FUZZ_ITERATIONS=20000 (test:fuzz, and the nightly job) still gets enough headroom above
// its observed ~2s real runtime per test to absorb slower CI hardware.
const timeout = Math.min(180_000, Math.max(30_000, iterations * 40));

function expectGateOrValue(fn, label) {
  try { return { value: fn() }; } catch (error) {
    assert(error instanceof GateError, `${label}: non-GateError ${error?.constructor?.name}: ${error?.message} (FUZZ_SEED=${seed})`);
    assert(error.status >= 400 && error.status < 500, `${label}: status ${error.status} (FUZZ_SEED=${seed})`);
    return { error };
  }
}

function gitAccepts(ref) {
  try { execFileSync('git', ['check-ref-format', ref], { stdio: 'ignore' }); return true; } catch { return false; }
}

test(`parsePush survives random and mutated input (seed ${seed})`, { timeout }, () => {
  const r = prng(seed);
  const hasGit = (() => { try { execFileSync('git', ['--version'], { stdio: 'ignore' }); return true; } catch { return false; } })();
  let accepted = 0;
  let rejected = 0;
  for (let i = 0; i < iterations; i++) {
    const count = 1 + r.int(4);
    const refs = Array.from({ length: count }, () => mutateRef(buildValidRef(r), r));
    const commands = refs.map((ref, index) => packet(`${r.chance(0.1) ? '0'.repeat(40) : oid(r)} ${r.chance(0.1) ? '0'.repeat(40) : oid(r)} ${ref}${index === 0 ? `\0${r.pick(['report-status', 'report-status side-band-64k', 'push-cert=1', 'atomic ofs-delta', ''])}` : ''}`));
    let body = Buffer.concat([...commands, Buffer.from('0000'), r.chance(0.3) ? Buffer.concat([Buffer.from('PACK'), r.bytes(r.int(32))]) : Buffer.alloc(0)]);
    if (r.chance(0.4)) {
      body = Buffer.from(body);
      for (let m = 0; m < 1 + r.int(4); m++) {
        const at = r.int(body.length);
        const op = r.int(3);
        if (op === 0) body[at] = r.int(256);
        else if (op === 1) body = Buffer.concat([body.subarray(0, at), body.subarray(at + 1 + r.int(8))]);
        else body = Buffer.concat([body.subarray(0, at), r.bytes(1 + r.int(8)), body.subarray(at)]);
      }
    }
    const result = expectGateOrValue(() => parsePush(body), `parsePush #${i}`);
    if (result.value) {
      accepted++;
      for (const change of result.value) {
        assert.match(change.oldOid, /^[0-9a-f]{40}$/);
        assert.match(change.newOid, /^[0-9a-f]{40}$/);
        assert(['create', 'update', 'delete'].includes(change.operation));
        // Sampled rather than exhaustive: spawning `git check-ref-format` for every accepted
        // ref would run thousands of child processes at FUZZ_ITERATIONS=20000. A 20% sample
        // still gives strong coverage across many seeds while keeping the default run fast.
        if (hasGit && r.chance(0.2)) assert(gitAccepts(change.ref), `accepted ref Git rejects: ${JSON.stringify(change.ref)} (FUZZ_SEED=${seed})`);
      }
    } else {
      rejected++;
    }
  }
  assert(accepted > 0, `generator produced no valid pushes (FUZZ_SEED=${seed})`);
  assert(rejected > 0, `generator produced no rejected pushes (FUZZ_SEED=${seed})`);
});

test(`valid pushes round-trip exactly (seed ${seed})`, { timeout }, () => {
  const r = prng(seed + 1);
  for (let i = 0; i < iterations; i++) {
    const changes = Array.from({ length: 1 + r.int(5) }, (_, index) => ({ ref: `refs/heads/agent/b${i}-${index}`, oldOid: oid(r), newOid: oid(r) }));
    const body = Buffer.concat([...changes.map((change, index) => packet(`${change.oldOid} ${change.newOid} ${change.ref}${index === 0 ? '\0report-status' : ''}\n`)), Buffer.from('0000')]);
    assert.deepEqual(parsePush(body).map(({ ref, oldOid, newOid }) => ({ ref, oldOid, newOid })), changes);
  }
});

// ---- parsePushRequest with allowUnicode:true: NFC refs plus spoofing-character mutations ----
// parsePush itself always calls parsePushRequest with the default allowUnicode:false (per the
// git-protocol/fuzz contract: it stays a protocol-only parser with no repository context), so
// this generator drives parsePushRequest directly with allowUnicode:true to exercise the
// Unicode-ref path: a mostly-valid multibyte ref half the time gets one spoofing character
// (a combining accent that breaks NFC, a bidi override, a zero-width space, NBSP, BOM, the
// replacement character, a noncharacter, a C1 control) injected at a random position, so both
// the accepting and rejecting branches of validateRef's Unicode rules stay exercised. About a
// third of iterations also flip a random byte of the encoded pkt-line, which can turn a valid
// multibyte ref into invalid UTF-8 -- this must be rejected cleanly by the strict decoder, never
// silently accepted as a replacement character or thrown as a non-GateError.
const unicodeSafeChars = [...'abcAZ09_-', 'é', 'ü', 'ñ', '日', '本', 'а', 'ω'];
const cp = (point) => String.fromCodePoint(point);
// Combining acute accent (breaks NFC), RIGHT-TO-LEFT OVERRIDE, ZERO WIDTH SPACE, NO-BREAK
// SPACE, BOM, the replacement character, a noncharacter (U+FFFE), a C1 control (NEL), and
// the Arabic Letter Mark -- built with String.fromCodePoint rather than embedded literally so
// this file does not itself contain the invisible/bidi characters it generates for testing.
const unicodeInvalidTokens = [cp(0x0301), cp(0x202e), cp(0x200b), cp(0x00a0), cp(0xfeff), cp(0xfffd), cp(0xfffe), cp(0x0085), cp(0x061c)];

function buildValidUnicodeRef(r) {
  const parts = Array.from({ length: 1 + r.int(3) }, () => Array.from({ length: 1 + r.int(6) }, () => r.pick(unicodeSafeChars)).join(''));
  return `refs/heads/agent/${parts.join('/')}`;
}

const unicodeRefPrefixLength = 'refs/heads/agent/'.length;

function mutateUnicodeRef(ref, r) {
  if (!r.chance(0.5)) return ref;
  const token = r.pick(unicodeInvalidTokens);
  const at = unicodeRefPrefixLength + r.int(Math.max(1, ref.length - unicodeRefPrefixLength));
  return ref.slice(0, at) + token + ref.slice(at);
}

test(`parsePushRequest with allowUnicode survives random and mutated Unicode refs (seed ${seed})`, { timeout }, () => {
  const r = prng(seed + 10);
  let accepted = 0;
  let rejected = 0;
  for (let i = 0; i < iterations; i++) {
    const ref = mutateUnicodeRef(buildValidUnicodeRef(r), r);
    let body = Buffer.concat([packet(`${oid(r)} ${oid(r)} ${ref}\0report-status`), Buffer.from('0000')]);
    if (r.chance(0.3)) {
      body = Buffer.from(body);
      const at = 4 + r.int(Math.max(1, body.length - 8));
      body[at] = r.int(256);
    }
    const result = expectGateOrValue(() => parsePushRequest(body, { allowUnicode: true }), `parsePushRequest(allowUnicode) #${i}`);
    if (result.value) accepted++; else rejected++;
  }
  assert(accepted > 0, `generator produced no accepted Unicode pushes (FUZZ_SEED=${seed})`);
  assert(rejected > 0, `generator produced no rejected Unicode pushes (FUZZ_SEED=${seed})`);
});

// ---- routeApi: grammar-based generator -------------------------------------------------
// Builds a request against one of the templates routeApi's own allowlist regex actually
// recognizes (read from src/github-api.js: pulls, pulls/:id, pulls/:id/comments,
// pulls/:id/reviews, issues/:id/comments, actions/runs, actions/runs/:id,
// actions/runs/:id/jobs, actions/jobs/:id/logs), with a valid method and a plausible mix of
// valid/invalid query values, then optionally applies a structural mutation (path traversal
// tokens, doubled slashes, encoded slashes, NUL, a flipped method, or a duplicated query
// parameter).

const identChars = [...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'];
const ident = (r, extra = [], min = 1, max = 8) =>
  Array.from({ length: min + r.int(max - min + 1) }, () => r.pick([...identChars, ...extra])).join('');

function routeApiBranchValue(r, valid) {
  if (!valid) return r.pick(['a/../b', '%2e%2e', 'a#b', 'a%2fb', '-leading', 'trailing.', '..', '', 'a b', 'a\u0000b']);
  return Array.from({ length: 1 + r.int(2) }, () => ident(r)).join('/');
}

function buildRouteApiInput(r) {
  const owner = ident(r, ['-']);
  const repo = ident(r, ['-', '_', '.']);
  const kind = r.pick(['pulls', 'pulls-item', 'actions-runs', 'actions-runs-item', 'actions-runs-jobs', 'actions-jobs-logs', 'pulls-comments', 'pulls-reviews', 'pulls-merge', 'issues-comments']);
  const resource = kind === 'pulls' ? 'pulls'
    : kind === 'pulls-item' ? `pulls/${1 + r.int(1000)}`
      : kind === 'actions-runs' ? 'actions/runs'
        : kind === 'actions-runs-item' ? `actions/runs/${1 + r.int(1000)}`
          : kind === 'actions-runs-jobs' ? `actions/runs/${1 + r.int(1000)}/jobs`
            : kind === 'actions-jobs-logs' ? `actions/jobs/${1 + r.int(1000)}/logs`
              : kind === 'pulls-comments' ? `pulls/${1 + r.int(1000)}/comments`
                : kind === 'pulls-reviews' ? `pulls/${1 + r.int(1000)}/reviews`
                  : kind === 'pulls-merge' ? `pulls/${1 + r.int(1000)}/merge`
                  : `issues/${1 + r.int(1000)}/comments`;
  // pulls-reviews is POST-only; issues-comments (like pulls itself) supports both GET and
  // POST, so it randomly creates like pulls does; pulls-comments and actions-jobs-logs are
  // GET-only, and actions-jobs-logs is a single resource (never a list, so it never gets
  // page/per_page/etc query params).
  const create = kind === 'pulls' || kind === 'issues-comments' ? r.chance(0.4) : kind === 'pulls-reviews' || kind === 'pulls-merge';
  const list = (['pulls', 'actions/runs'].includes(resource) || resource.endsWith('/jobs') || resource.endsWith('/comments')) && !create && kind !== 'actions-jobs-logs';
  const validMethod = kind === 'pulls-merge' ? 'PUT' : create ? 'POST' : 'GET';
  const method = r.chance(0.85) ? validMethod : r.pick(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']);
  const allowedKeys = create || !list ? [] : ['page', 'per_page', ...(resource === 'pulls' ? ['state'] : resource === 'actions/runs' ? ['branch'] : [])];
  const params = [];
  if (allowedKeys.length && r.chance(0.7)) {
    for (const key of allowedKeys) {
      if (!r.chance(0.6)) continue;
      const invalid = r.chance(0.25);
      let value;
      if (key === 'page') value = invalid ? r.pick(['0', '-1', 'abc', '01', '']) : String(1 + r.int(50));
      else if (key === 'per_page') value = invalid ? r.pick(['0', '101', '1000', 'abc', '']) : String(1 + r.int(100));
      else if (key === 'state') value = invalid ? r.pick(['bogus', 'OPEN', '']) : r.pick(['open', 'closed', 'all']);
      else value = routeApiBranchValue(r, !invalid);
      params.push([key, value]);
      if (r.chance(0.1)) params.push([key, value]);
    }
  }
  const query = params.map(([k, v]) => `${k}=${v}`).join('&');
  const url = `/api/repos/${owner}/${repo}/${resource}${query ? `?${query}` : ''}`;
  return { url, method };
}

function insertAt(str, r, token) {
  const at = r.int(str.length + 1);
  return str.slice(0, at) + token + str.slice(at);
}

function mutateRouteApiInput({ url, method }, r) {
  let u = url;
  let m = method;
  if (r.chance(0.35)) u = insertAt(u, r, '..');
  if (r.chance(0.25)) u = insertAt(u, r, '//');
  if (r.chance(0.25)) u = insertAt(u, r, '%2f');
  if (r.chance(0.15)) u = insertAt(u, r, '\u0000');
  if (r.chance(0.3)) m = r.pick(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']);
  if (r.chance(0.25) && u.includes('=')) {
    const qi = u.indexOf('?');
    if (qi >= 0) {
      const first = u.slice(qi + 1).split('&')[0];
      u = `${u}&${first}`;
    }
  }
  return { url: u, method: m };
}

test(`routeApi only accepts allowlisted normalized paths (seed ${seed})`, { timeout }, () => {
  const r = prng(seed + 2);
  let mergeAccepted = 0;
  let accepted = 0;
  let rejected = 0;
  for (let i = 0; i < iterations * 3; i++) {
    let input = buildRouteApiInput(r);
    if (r.chance(0.4)) input = mutateRouteApiInput(input, r);
    const result = expectGateOrValue(() => routeApi(input), `routeApi ${JSON.stringify(input.url)}`);
    if (result.value) {
      accepted++;
      // NOTE ON THIS INVARIANT (see task-8-report.md for the full explanation): the brief's
      // original regex forbade a literal '%' anywhere in `path`, but routeApi legitimately
      // produces one whenever a validated `branch` value contains '/' — URLSearchParams.toString()
      // percent-encodes it to '%2F', which is correct, safe query-string encoding, not a defect.
      // The real invariants that must hold are: (1) the resource segment (before '?', which is
      // built only from the fixed allowlist match and validated numeric ids) never contains '..'
      // or '//', and (2) the query string, which URLSearchParams always serializes correctly,
      // never contains a raw '#' or a '%' that isn't a well-formed percent-escape.
      const [resourcePart, queryPart = ''] = result.value.path.split(/\?(.*)/s);
      assert.match(resourcePart, /^(pulls(\/\d+(\/(?:comments|reviews|merge))?)?|issues\/\d+\/comments|actions\/runs(\/\d+(\/jobs)?)?|actions\/jobs\/\d+\/logs)$/, `unexpected resource ${resourcePart} (FUZZ_SEED=${seed})`);
      assert(!/\.\.|\/\//.test(resourcePart), `resource contains traversal-like sequence: ${resourcePart} (FUZZ_SEED=${seed})`);
      if (queryPart) {
        assert.match(queryPart, /^[a-z_]+=(?:[A-Za-z0-9_.-]|%[0-9A-Fa-f]{2})+(&[a-z_]+=(?:[A-Za-z0-9_.-]|%[0-9A-Fa-f]{2})+)*$/, `unexpected query ${queryPart} (FUZZ_SEED=${seed})`);
        assert(!/#/.test(queryPart), `query contains raw '#': ${queryPart} (FUZZ_SEED=${seed})`);
        assert(!/%(?![0-9A-Fa-f]{2})/.test(queryPart), `query contains a malformed '%' escape: ${queryPart} (FUZZ_SEED=${seed})`);
      }
      if (result.value.kind === 'merge') {
        mergeAccepted++;
        assert.equal(input.method, 'PUT');
        assert.deepEqual(result.value.permissions, { contents: 'write' });
        assert.equal(queryPart, '', `merge route accepted a query (FUZZ_SEED=${seed})`);
      }
    } else {
      rejected++;
    }
  }
  assert(mergeAccepted > 0, `generator produced no accepted merge routes (FUZZ_SEED=${seed})`);
  assert(accepted > 0, `generator produced no accepted routeApi calls (FUZZ_SEED=${seed})`);
  assert(rejected > 0, `generator produced no rejected routeApi calls (FUZZ_SEED=${seed})`);
});

// ---- pullRequestPayload: grammar-based generator ---------------------------------------
// Builds a valid-ish { title, head, base, body, draft } object, applies zero or more
// structural mutations (dropped/extra/prototype-pollution-style keys, wrong types, huge or
// NUL-containing strings, invalid branch characters, head === base), serializes it, and
// sometimes corrupts the serialized bytes directly (mirroring parsePush's byte-mutation
// style) so plain "not JSON at all" inputs stay well covered too.

function prTitle(r) {
  const text = Array.from({ length: 1 + r.int(20) }, () => r.pick([...'abcdefghijklmnopqrstuvwxyz ABCXYZ0123456789-_'])).join('').trim();
  return text || 'x';
}

function prBranch(r) {
  return Array.from({ length: 1 + r.int(2) }, () => ident(r)).join('/');
}

function prBody(r) {
  return Array.from({ length: r.int(40) }, () => r.pick([...'abcdefg \n-_.'])).join('');
}

// Configured forks for the fuzzed target: 'twin' is deliberately ambiguous (two forks share it).
const fuzzForks = [{ owner: 'agent-bot', name: 'agent-bot/demo' }, { owner: 'twin', name: 'twin/a' }, { owner: 'twin', name: 'twin/b' }];
const fuzzForkOwners = ['agent-bot', 'Agent-Bot', 'someone', 'twin'];

function buildPullRequestObject(r) {
  const head = prBranch(r);
  let base = prBranch(r);
  while (base === head) base = prBranch(r);
  const obj = { title: prTitle(r), head, base };
  if (r.chance(0.7)) obj.body = prBody(r);
  if (r.chance(0.7)) obj.draft = r.chance(0.5);
  return obj;
}

function mutatePullRequestObject(obj, r) {
  if (r.chance(0.15) && Object.keys(obj).length) delete obj[r.pick(Object.keys(obj))];
  if (r.chance(0.15)) obj[r.pick(['extra', 'foo', '__proto__', 'constructor'])] = r.pick(['x', 1, true]);
  if (r.chance(0.1)) obj.title = r.pick([123, null, [], {}, '', '   ']);
  if (r.chance(0.1)) obj.title = 'x'.repeat(300);
  if (r.chance(0.1)) obj.title = 'bad\u0000title';
  if (r.chance(0.1)) obj.head = r.pick(['a..b', '-lead', 'trail.', 'a b', '../x', '', 123, null]);
  if (r.chance(0.2)) obj.head = `${r.pick(fuzzForkOwners)}:${typeof obj.head === 'string' ? obj.head : prBranch(r)}`;
  if (r.chance(0.05)) obj.head = r.pick(['agent-bot:a:b', ':x', 'agent-bot:', 'agent_bot:x', `${'a'.repeat(40)}:x`, 'agent-bot:../x', 'twin:x']);
  if (r.chance(0.1)) obj.base = obj.head;
  if (r.chance(0.1)) obj.draft = r.pick(['yes', 1, 'true']);
  if (r.chance(0.05)) obj.body = 'x'.repeat(60001);
  if (r.chance(0.05)) obj.body = 'has\u0000nul';
  return obj;
}

function corruptBytes(body, r) {
  let bytes = body;
  for (let m = 0; m < 1 + r.int(3); m++) {
    if (bytes.length === 0) { bytes = r.bytes(1 + r.int(4)); continue; }
    const at = r.int(bytes.length);
    const op = r.int(3);
    if (op === 0) bytes[at] = r.int(256);
    else if (op === 1) bytes = Buffer.concat([bytes.subarray(0, at), bytes.subarray(Math.min(at + 1 + r.int(4), bytes.length))]);
    else bytes = Buffer.concat([bytes.subarray(0, at), r.bytes(1 + r.int(4)), bytes.subarray(at)]);
  }
  return bytes;
}

function buildPullRequestPayload(r) {
  const obj = mutatePullRequestObject(buildPullRequestObject(r), r);
  let body = Buffer.from(JSON.stringify(obj), 'utf8');
  if (r.chance(0.2)) body = corruptBytes(Buffer.from(body), r);
  return body;
}

test(`pullRequestPayload rejects malformed JSON without crashing (seed ${seed})`, { timeout }, () => {
  const r = prng(seed + 3);
  let accepted = 0;
  let rejected = 0;
  let forkAccepted = 0;
  for (let i = 0; i < iterations * 3; i++) {
    const body = buildPullRequestPayload(r);
    const result = expectGateOrValue(() => pullRequestPayload(body, { forks: fuzzForks }), `pullRequestPayload ${JSON.stringify(body.toString('utf8').slice(0, 200))}`);
    if (result.value) {
      accepted++;
      assert.deepEqual(Object.keys(result.value).sort(), ['base', 'body', 'draft', 'head', 'title']);
      if (result.value.head.includes(':')) {
        forkAccepted++;
        assert.equal(forkHead(result.value.head, fuzzForks).name, 'agent-bot/demo');
      }
    }
    else rejected++;
  }
  assert(accepted > 0, `generator produced no accepted PR payloads (FUZZ_SEED=${seed})`);
  assert(rejected > 0, `generator produced no rejected PR payloads (FUZZ_SEED=${seed})`);
  assert(forkAccepted > 0, `generator produced no accepted fork-head PR payloads (FUZZ_SEED=${seed})`);
});

// ---- commentPayload / reviewPayload: grammar-based generator ---------------------------
// Builds a valid-ish { body } (and, for reviews, { body, event: 'COMMENT' }) object, applies
// structural mutations (dropped/extra keys, wrong types, empty/huge/NUL-containing bodies, and
// for reviews a non-COMMENT event), serializes it, and sometimes corrupts the serialized bytes
// directly so malformed-JSON inputs stay covered too.

function fuzzCommentBody(r) {
  return Array.from({ length: r.int(80) }, () => r.pick([...'abcdefg \n-_.é😀'])).join('');
}

function buildCommentObject(r) {
  return { body: fuzzCommentBody(r) || 'x' };
}

function mutateCommentObject(obj, r) {
  if (r.chance(0.15)) obj.extra = r.pick(['x', 1, true]);
  if (r.chance(0.15)) delete obj.body;
  if (r.chance(0.1)) obj.body = r.pick([123, null, [], {}, '', '   ']);
  if (r.chance(0.1)) obj.body = 'x'.repeat(70000);
  if (r.chance(0.1)) obj.body = 'has nul';
  return obj;
}

function buildCommentPayload(r) {
  const obj = mutateCommentObject(buildCommentObject(r), r);
  let body = Buffer.from(JSON.stringify(obj), 'utf8');
  if (r.chance(0.2)) body = corruptBytes(Buffer.from(body), r);
  return body;
}

test(`commentPayload rejects malformed JSON without crashing (seed ${seed})`, { timeout }, () => {
  const r = prng(seed + 4);
  let accepted = 0;
  let rejected = 0;
  for (let i = 0; i < iterations * 3; i++) {
    const body = buildCommentPayload(r);
    const result = expectGateOrValue(() => commentPayload(body), `commentPayload ${JSON.stringify(body.toString('utf8').slice(0, 200))}`);
    if (result.value) {
      accepted++;
      assert.deepEqual(Object.keys(result.value), ['body']);
      assert(result.value.body.length >= 1 && result.value.body.length <= 65536, `accepted body length out of range (FUZZ_SEED=${seed})`);
    } else rejected++;
  }
  assert(accepted > 0, `generator produced no accepted comment payloads (FUZZ_SEED=${seed})`);
  assert(rejected > 0, `generator produced no rejected comment payloads (FUZZ_SEED=${seed})`);
});

function buildReviewObject(r) {
  return { body: fuzzCommentBody(r) || 'x', event: 'COMMENT' };
}

function mutateReviewObject(obj, r) {
  mutateCommentObject(obj, r);
  if (r.chance(0.3)) obj.event = r.pick(['APPROVE', 'REQUEST_CHANGES', 'COMMENT', 'bogus', '', null, 123]);
  if (r.chance(0.1)) delete obj.event;
  return obj;
}

function buildReviewPayload(r) {
  const obj = mutateReviewObject(buildReviewObject(r), r);
  let body = Buffer.from(JSON.stringify(obj), 'utf8');
  if (r.chance(0.2)) body = corruptBytes(Buffer.from(body), r);
  return body;
}

test(`reviewPayload rejects malformed JSON and non-COMMENT events without crashing (seed ${seed})`, { timeout }, () => {
  const r = prng(seed + 5);
  let accepted = 0;
  let rejected = 0;
  for (let i = 0; i < iterations * 3; i++) {
    const body = buildReviewPayload(r);
    const result = expectGateOrValue(() => reviewPayload(body), `reviewPayload ${JSON.stringify(body.toString('utf8').slice(0, 200))}`);
    if (result.value) {
      accepted++;
      assert.equal(result.value.event, 'COMMENT');
      assert(typeof result.value.body === 'string' && result.value.body.length >= 1 && result.value.body.length <= 65536);
    } else rejected++;
  }
  assert(accepted > 0, `generator produced no accepted review payloads (FUZZ_SEED=${seed})`);
  assert(rejected > 0, `generator produced no rejected review payloads (FUZZ_SEED=${seed})`);
});

// ---- mergePayload: grammar-based generator ---------------------------------------------
// Builds a valid { sha, merge_method }, then mutates it (short/uppercase/non-hex sha, unknown
// methods, extra keys such as commit_title/commit_message, wrong types) and sometimes corrupts
// the serialized bytes.
test(`mergePayload accepts only a full sha and a known method (seed ${seed})`, { timeout }, () => {
  const r = prng(seed + 6);
  let accepted = 0;
  let rejected = 0;
  for (let i = 0; i < iterations * 3; i++) {
    const obj = { sha: oid(r), merge_method: r.pick(['merge', 'squash', 'rebase']) };
    if (r.chance(0.15)) obj.sha = r.pick([obj.sha.slice(0, 39), obj.sha.toUpperCase(), `${obj.sha}0`, 'g'.repeat(40), '', 123, null]);
    if (r.chance(0.15)) obj.merge_method = r.pick(['MERGE', 'fast-forward', '', null, 1, 'squash ']);
    if (r.chance(0.1)) obj[r.pick(['commit_title', 'commit_message', '__proto__', 'sha2'])] = 'x';
    if (r.chance(0.05)) delete obj.sha;
    let body = Buffer.from(JSON.stringify(r.chance(0.03) ? [obj] : obj), 'utf8');
    if (r.chance(0.2)) body = corruptBytes(Buffer.from(body), r);
    const result = expectGateOrValue(() => mergePayload(body), `mergePayload ${JSON.stringify(body.toString('utf8').slice(0, 200))}`);
    if (result.value) {
      accepted++;
      assert.deepEqual(Object.keys(result.value), ['sha', 'merge_method']);
      assert.match(result.value.sha, /^[0-9a-f]{40}$/);
      assert(['merge', 'squash', 'rebase'].includes(result.value.merge_method));
    } else rejected++;
  }
  assert(accepted > 0, `generator produced no accepted merge payloads (FUZZ_SEED=${seed})`);
  assert(rejected > 0, `generator produced no rejected merge payloads (FUZZ_SEED=${seed})`);
});

// ---- runtime assertions: mutation-based ------------------------------------------------
// Start from a valid signed token and apply random corruptions: byte flips in any segment,
// dropped or duplicated segments, injected or duplicated JSON members, case flips of known
// member names, non-canonical base64url. The verifier must either accept the unmodified
// token or throw ASSERTION_INVALID; any other error type is a parser bug. strictJson must
// never throw anything but ASSERTION_INVALID or a SyntaxError for arbitrary JSON-shaped text.
test('runtime assertion verification never throws anything but ASSERTION_INVALID under mutation', { timeout }, async () => {
  const { generateKeyPairSync } = await import('node:crypto');
  const { issueAssertion, strictJson, verifyAssertion } = await import('../src/assertion.js');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const r = prng(seed + 7);
  const now = () => 1_800_000_000_000;
  const clientToken = 'fuzz-client-token-0123456789abcdefghijk';
  const options = { keys: { k1: publicKey }, audience: 'agentgate:fuzz', clientToken, now };
  const base = issueAssertion({ iss: 'fuzz', aud: 'agentgate:fuzz', sub: 'rt-fuzz', human: 'dev@example.com', agent: 'cursor', team: 'payments', mode: 'build', task: { system: 'jira', id: 'PAY-1' } }, { privateKey, kid: 'k1', now, ttlSeconds: 600, clientToken });
  assert.equal(verifyAssertion(base, options).sub, 'rt-fuzz');
  const members = ['exp', 'iat', 'sub', 'cnf', 'alg', 'kid', 'typ', 'human', 'mode', 'jti', 'tokenSha256'];
  const junk = ['{', '}', '"', ',', ':', String.fromCharCode(92), String.fromCharCode(0), String.fromCharCode(233), String.fromCharCode(10)];
  const mutateJson = (text) => {
    const kind = r.int(5);
    if (kind === 0) return text.replace(/}$/, `,"${r.pick(members)}":${r.int(3)}}`);
    if (kind === 1) { const m = r.pick(members); return text.replace(`"${m}"`, `"${m[0].toUpperCase()}${m.slice(1)}"`); }
    if (kind === 2) { const at = r.int(text.length); return text.slice(0, at) + r.pick(junk) + text.slice(at); }
    if (kind === 3) return text.replace(/}$/, `,"x":{"${r.pick(members)}":1,"${r.pick(members)}":2}}`);
    return text.slice(0, r.int(text.length));
  };
  const b64 = (text) => Buffer.from(text).toString('base64url');
  for (let i = 0; i < iterations; i++) {
    const parts = base.split('.');
    const mode = r.int(6);
    let token;
    if (mode === 0) { const idx = r.int(3); const bytes = Buffer.from(parts[idx]); bytes[r.int(bytes.length)] ^= 1 << r.int(8); parts[idx] = bytes.toString('latin1'); token = parts.join('.'); }
    else if (mode === 1) { parts.splice(r.int(3), 1); token = parts.join('.'); }
    else if (mode === 2) { parts.push(parts[r.int(3)]); token = parts.join('.'); }
    else if (mode === 3) { parts[1] = b64(mutateJson(Buffer.from(parts[1], 'base64url').toString('utf8'))); token = parts.join('.'); }
    else if (mode === 4) { parts[0] = b64(mutateJson(Buffer.from(parts[0], 'base64url').toString('utf8'))); token = parts.join('.'); }
    else { token = base + r.pick(['=', '==', 'A', '.', String.fromCharCode(10)]); }
    const outcome = expectGateOrValue(() => verifyAssertion(token, options), `assertion mutation ${mode}`);
    if (outcome.value) assert.equal(token, base, 'only the unmodified token may verify');
    else assert.equal(outcome.error.code, 'ASSERTION_INVALID', `mode ${mode}: ${outcome.error.message}`);
    const text = mutateJson(Buffer.from(parts[1] ?? '', 'base64url').toString('utf8'));
    try { strictJson(text); } catch (error) {
      assert.ok(error instanceof GateError || error instanceof SyntaxError, `strictJson threw ${error.constructor.name}: ${error.message}`);
    }
  }
});
