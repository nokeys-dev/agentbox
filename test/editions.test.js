import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { edition, requireEdition } from '../src/extensions.js';
import { validateConfig } from '../src/config.js';
import { exampleConfig } from '../scripts/support/fixture.js';
import { baseEnv, makeTokenFile, spawnDaemon, tempDir } from './support/daemon-harness.js';

// This file runs in both trees. The open-source tree has no enterprise/ directory; the commercial
// tree does. Each half asserts what its edition must do.
const commercial = existsSync(resolve('enterprise/src/index.js'));

test('the edition that loads matches the tree', () => {
  assert.equal(Boolean(edition), commercial);
  if (commercial) assert.deepEqual(edition.entitlementKeys, ['jira', 'servicenow', 'okta', 'entra']);
  else assert.throws(() => requireEdition('this feature'), /this feature requires the AgentBox commercial edition/);
});

test('open source: commercial entitlement settings are refused by name, never ignored', { skip: commercial }, () => {
  for (const [key, settings] of Object.entries({
    okta: { baseUrl: 'https://acme.okta.com', tokenFile: '/run/secrets/okta', groups: ['eng'] },
    entra: { tenantId: 'acme', clientId: 'id', clientSecretFile: '/run/secrets/entra', groups: ['eng'] },
    jira: { baseUrl: 'https://acme.atlassian.net', tokenFile: '/run/secrets/jira' },
    servicenow: { baseUrl: 'https://acme.service-now.com', credentialFile: '/run/secrets/now' }
  })) {
    const config = exampleConfig();
    config.entitlements = { [key]: settings };
    assert.throws(() => validateConfig(config), new RegExp(`entitlements\\.${key} requires the AgentBox commercial edition`), key);
  }
  const open = exampleConfig();
  open.entitlements = { static: { path: '/etc/agentgate/directory.json' } };
  assert.doesNotThrow(() => validateConfig(open), 'the static source is open source');
});

test('open source: control-plane mode is refused at startup with the reason', { skip: commercial, timeout: 15_000 }, async (t) => {
  const dir = tempDir('agentgate-edition-');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const daemon = spawnDaemon(baseEnv(dir, { AGENTGATE_CLIENT_TOKEN_FILE: makeTokenFile(dir), AGENTGATE_CONTROL_URL: 'https://control.example', AGENTGATE_BROKER_ID: 'b1' }));
  const code = await daemon.waitForExit();
  assert.notEqual(code, 0);
  assert.match(daemon.stderr() + daemon.stdout(), /control-plane mode\) requires the AgentBox commercial edition/);
});
