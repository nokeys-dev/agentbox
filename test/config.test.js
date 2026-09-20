import test from 'node:test';
import assert from 'node:assert/strict';
import { validateConfig } from '../src/config.js';

const base = () => ({
  runtime: { human: 'h', agent: 'a', runtimeId: 'r', task: 't' },
  repositories: [{ name: 'acme/demo', id: 1, installationId: 2 }],
  rules: []
});

test('protectedBranches accepts branch names and rejects junk', () => {
  const ok = base();
  ok.repositories[0].protectedBranches = ['main', 'release/v1'];
  assert.doesNotThrow(() => validateConfig(ok));
  for (const value of ['main', ['refs/heads/main'], ['..'], [''], Array(21).fill('x')]) {
    const bad = base();
    bad.repositories[0].protectedBranches = value;
    assert.throws(() => validateConfig(bad), /protectedBranches/);
  }
});

test('allowedPushOptions accepts exact strings, prefix* wildcards and a bare *, and rejects a "*" anywhere else', () => {
  const ok = base();
  ok.repositories[0].allowedPushOptions = ['ci.skip', 'merge_request.*', '*'];
  assert.doesNotThrow(() => validateConfig(ok));
  for (const value of [
    'a*b', // '*' in the middle
    '*b', // '*' as a non-final leading character (not the bare-wildcard case, which is exactly "*")
    '**', // doubled '*'
    'ci.skip**', // more than one trailing '*'
    'ci.skip*extra', // trailing '*' not actually final
    '', // empty string
    Array(33).fill('ci.skip'), // over the 32-entry cap
    'a'.repeat(257) // over the per-entry length cap
  ]) {
    const bad = base();
    bad.repositories[0].allowedPushOptions = Array.isArray(value) ? value : [value];
    assert.throws(() => validateConfig(bad), /allowedPushOptions/, `expected rejection for ${JSON.stringify(value)}`);
  }
});

test('forkOf must reference another configured repository with a different owner', () => {
  const config = base();
  config.repositories.push({ name: 'agent-bot/demo', id: 9, installationId: 3, forkOf: 'acme/demo' });
  assert.doesNotThrow(() => validateConfig(config));
  const self = base();
  self.repositories[0].forkOf = 'acme/demo';
  assert.throws(() => validateConfig(self), /forkOf/);
  const missing = base();
  missing.repositories.push({ name: 'agent-bot/demo', id: 9, installationId: 3, forkOf: 'acme/nope' });
  assert.throws(() => validateConfig(missing), /forkOf/);
});

test('forkOf rejects same-owner forks, fork-of-fork chains, and non-strings; headRepository is pr.create-only', () => {
  const sameOwner = base();
  sameOwner.repositories.push({ name: 'acme/demo-fork', id: 9, installationId: 3, forkOf: 'acme/demo' });
  assert.throws(() => validateConfig(sameOwner), /forkOf/);
  const chain = base();
  chain.repositories.push({ name: 'agent-bot/demo', id: 9, installationId: 3, forkOf: 'acme/demo' },
    { name: 'other/demo', id: 10, installationId: 3, forkOf: 'agent-bot/demo' });
  assert.throws(() => validateConfig(chain), /forkOf/);
  const typed = base();
  typed.repositories.push({ name: 'agent-bot/demo', id: 9, installationId: 3, forkOf: 7 });
  assert.throws(() => validateConfig(typed), /forkOf/);
  const upper = base();
  upper.repositories.push({ name: 'agent-bot/demo', id: 9, installationId: 3, forkOf: 'ACME/Demo' });
  assert.equal(validateConfig(upper).repositories[1].forkOf, 'acme/demo');
  const rule = (extra) => { const c = base(); c.repositories.push({ name: 'agent-bot/demo', id: 9, installationId: 3, forkOf: 'acme/demo' }); c.rules.push({ id: 'r', repository: 'acme/demo', effect: 'allow', ...extra }); return c; };
  assert.doesNotThrow(() => validateConfig(rule({ action: 'github.pr.create', ref: 'refs/heads/*', headRepository: '*' })));
  assert.equal(validateConfig(rule({ action: 'github.pr.create', ref: 'refs/heads/*', headRepository: 'Agent-Bot/Demo' })).rules[0].headRepository, 'agent-bot/demo');
  assert.throws(() => validateConfig(rule({ action: 'github.pr.create', ref: 'refs/heads/*', headRepository: 'nobody/demo' })), /headRepository/);
  assert.throws(() => validateConfig(rule({ action: 'git.push', ref: 'refs/heads/*', headRepository: '*' })), /headRepository/);
});

test('an invalid repository name is reported by name, and the shipped example config validates', async () => {
  const { readFile } = await import('node:fs/promises');
  const { resolve } = await import('node:path');
  const example = JSON.parse(await readFile(resolve('examples/config.json'), 'utf8'));
  assert.doesNotThrow(() => validateConfig(structuredClone(example)));
  example.repositories[0].name = 'YOUR_ORG/YOUR_REPO';
  for (const rule of example.rules) if (rule.repository === 'YOUR-ORG/YOUR-REPO') rule.repository = 'YOUR_ORG/YOUR_REPO';
  assert.throws(() => validateConfig(example), /OWNER\/REPO.*"YOUR_ORG\/YOUR_REPO"/);
});
