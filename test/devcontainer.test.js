import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { loadEgressConfig, startEgressProxy } from '../src/egress-proxy.js';

const devcontainerPath = resolve('.devcontainer/devcontainer.json');

test('devcontainer attaches the IDE to the Compose workspace without widening its privileges', () => {
  const devcontainer = JSON.parse(readFileSync(devcontainerPath, 'utf8'));
  const composeFiles = [].concat(devcontainer.dockerComposeFile);
  assert.deepEqual(composeFiles, ['../compose.yaml']);
  for (const file of composeFiles) assert.ok(existsSync(resolve(dirname(devcontainerPath), file)), `${file} exists`);
  assert.equal(devcontainer.service, 'workspace');
  assert.equal(devcontainer.workspaceFolder, '/workspace');
  assert.equal(devcontainer.remoteUser, 'node');
  // The workspace entrypoint must keep running: it writes the managed gitconfig and exports the
  // model-gateway token. Overriding the command would skip both.
  assert.equal(devcontainer.overrideCommand, false);
  // Only the workspace is started/attached; the IDE must not be able to widen the topology.
  assert.deepEqual(devcontainer.runServices, ['workspace']);
  assert.equal(devcontainer.shutdownAction, 'none');
  for (const key of ['image', 'build', 'dockerFile', 'runArgs', 'privileged', 'capAdd', 'securityOpt', 'mounts', 'containerEnv', 'remoteEnv', 'features', 'initializeCommand', 'onCreateCommand', 'postCreateCommand', 'postStartCommand', 'postAttachCommand', 'forwardPorts', 'appPort']) {
    assert.equal(devcontainer[key], undefined, `${key} must not be set: the Compose service definition is the only source of workspace privileges`);
  }
});

test('IDE egress allowlist is a strict superset of the default one, valid, and never opens GitHub', async () => {
  const base = loadEgressConfig(resolve('examples/egress.json'));
  const ide = loadEgressConfig(resolve('examples/egress.ide.json'));
  for (const rule of base.allow) assert.ok(ide.allow.includes(rule), `${rule} kept from examples/egress.json`);
  assert.ok(ide.allow.length > base.allow.length);
  assert.equal(new Set(ide.allow).size, ide.allow.length, 'no duplicate rules');
  for (const rule of ide.allow) {
    assert.match(rule, /:443$/, `${rule} is HTTPS only`);
    assert.doesNotMatch(rule, /github/i, `${rule} must go through the broker, not the proxy`);
  }
  const proxy = await startEgressProxy({ allow: ide.allow, deny: ide.deny ?? [], host: '127.0.0.1', port: 0, maxBytesPerHost: ide.maxBytesPerHost });
  await proxy.close();
});
