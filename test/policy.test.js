import test from 'node:test';
import assert from 'node:assert/strict';
import { validateConfig } from '../src/config.js';
import { decide, decidePush } from '../src/policy.js';
import { exampleConfig } from './support/fixture.js';

test('policy defaults to deny and constrains repository and branch access', () => {
  const config = validateConfig(exampleConfig());
  assert.equal(decide(config, 'git.read', 'acme/demo').effect, 'allow');
  assert.equal(decide(config, 'git.read', 'acme/other').effect, 'deny');
  assert.equal(decide(config, 'git.push', 'acme/demo', { ref: 'refs/heads/agent/demo', operation: 'create' }).effect, 'allow');
  assert.equal(decide(config, 'git.push', 'acme/demo', { ref: 'refs/heads/main', operation: 'update' }).effect, 'approval');
  assert.equal(decide(config, 'git.push', 'acme/demo', { ref: 'refs/heads/agentish', operation: 'create' }).effect, 'deny');
  assert.equal(decide(config, 'git.push', 'acme/demo', { ref: 'refs/heads/agent/demo', operation: 'delete' }).effect, 'deny');
});

test('deny overrides approval and allow regardless of rule order, across the entire push', () => {
  const config = exampleConfig();
  config.rules.unshift({ id: 'broad', action: 'git.push', repository: '*', ref: '*', effect: 'allow' });
  const changes = [{ ref: 'refs/heads/main', operation: 'update' }, { ref: 'refs/tags/v1', operation: 'create' }];
  assert.equal(decidePush(config, 'acme/demo', changes).effect, 'deny');
  assert.equal(decidePush(config, 'acme/demo', changes.slice(0, 1)).effect, 'approval');
  config.rules.reverse();
  assert.equal(decidePush(config, 'acme/demo', changes).effect, 'deny');
});

test('configuration rejects typos, unscoped permissions and duplicate resources', () => {
  for (const mutate of [
    (config) => { config.rules[0].effect = 'alow'; },
    (config) => { config.rules[0].efffect = 'allow'; },
    (config) => { config.repositories[0].id = '1'; },
    (config) => { config.repositories.push({ ...config.repositories[0] }); },
    (config) => { config.rules[1].ref = 'refs/*/main'; },
    (config) => { config.rules[0].repository = 'other/repo'; },
    (config) => { config.runtime.task = ''; },
    (config) => { config.rules[0].effect = 'approval'; },
    (config) => { config.repositories[0].allowWorkflowWrites = 'true'; },
    (config) => { config.rules.push({ id: 'bad-pr', action: 'github.pr.create', repository: '*', effect: 'allow' }); },
    (config) => { config.rules.push({ id: 'bad-api', action: 'github.actions.read', repository: '*', effect: 'approval' }); }
  ]) {
    const config = exampleConfig();
    mutate(config);
    assert.throws(() => validateConfig(config));
  }
});

test('approval rules carry required approval counts and pushes take the maximum', () => {
  const config = validateConfig({
    runtime: { human: 'h', agent: 'a', runtimeId: 'r', task: 't' },
    repositories: [{ name: 'acme/demo', id: 1, installationId: 2 }],
    rules: [
      { id: 'main', action: 'git.push', repository: 'acme/demo', ref: 'refs/heads/main', effect: 'approval', approvals: 2 },
      { id: 'release', action: 'git.push', repository: 'acme/demo', ref: 'refs/heads/release', effect: 'approval' }
    ]
  });
  const change = (ref) => ({ ref, oldOid: '1'.repeat(40), newOid: '2'.repeat(40), operation: 'update' });
  assert.equal(decidePush(config, 'acme/demo', [change('refs/heads/release')]).requiredApprovals, 1);
  assert.equal(decidePush(config, 'acme/demo', [change('refs/heads/release'), change('refs/heads/main')]).requiredApprovals, 2);
  assert.throws(() => validateConfig({ ...config, rules: [{ id: 'x', action: 'git.push', repository: 'acme/demo', ref: '*', effect: 'allow', approvals: 2 }] }), /approvals/);
  assert.throws(() => validateConfig({ ...config, rules: [{ id: 'x', action: 'git.push', repository: 'acme/demo', ref: '*', effect: 'approval', approvals: 6 }] }), /approvals/);
});
