import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const core = readFileSync(resolve('compose.yaml'), 'utf8');
const required = (text) => [...text.matchAll(/\$\{([A-Z0-9_]+):\?/g)].map((match) => match[1]).sort();
const services = (text) => [...text.split('\nnetworks:\n')[0].matchAll(/^  ([a-z0-9-]+):\n/gm)].map((match) => match[1]);

test('the core stack starts with only its own variables: no SIEM or OIDC setting is required', () => {
  assert.deepEqual(services(core), ['agentd', 'workspace', 'egress-proxy', 'model-gateway']);
  assert.deepEqual(required(core), ['AGENTGATE_CA_PATH', 'AGENTGATE_CLIENT_TOKEN_PATH', 'AGENTGATE_MODEL_GATEWAY_CLIENT_TOKEN_PATH', 'AGENTGATE_TLS_CERT_PATH', 'AGENTGATE_TLS_KEY_PATH', 'ANTHROPIC_API_KEY_PATH', 'GITHUB_APP_ID', 'GITHUB_PRIVATE_KEY_PATH']);
  for (const name of ['approval_web_admin_secret', 'audit_sink_token', 'oauth2_proxy', 'approval-egress']) assert.ok(!core.includes(name), `${name} belongs to the commercial edition's Compose file`);
});

// A company that only runs verified, mirrored images must be able to clear every build. A service
// added later with `build: .` and no entry here would quietly be built from source again.
test('the broker image overrides cover every service built from the broker Dockerfile, and nothing else', () => {
  const builtFromBroker = (text) => services(text).filter((name) => /^    build: \.$/m.test(text.split(`\n  ${name}:\n`)[1].split(/\n  [a-z0-9-]+:\n/)[0]));
  const overridden = (file) => { const text = readFileSync(resolve(file), 'utf8'); return { text, names: services(`${text}\nnetworks:\n`) }; };
  const coreOverride = overridden('compose.broker-image.yaml');
  assert.deepEqual(coreOverride.names.sort(), builtFromBroker(core).sort());
  for (const { text, names } of [coreOverride]) {
    assert.equal(text.match(/^    build: !reset null$/gm).length, names.length, 'build is cleared so up --build cannot rebuild under the verified name');
    assert.equal(text.match(/^    image: \$\{AGENTGATE_IMAGE:\?/gm).length, names.length);
    const keys = new Set([...text.matchAll(/^    ([a-z_]+):/gm)].map((match) => match[1]));
    assert.deepEqual([...keys].sort(), ['build', 'image'], 'an image override must not touch networks, secrets, or hardening');
  }
});

// Behind a mandatory forward proxy every service that calls out must be pointed at it; the
// workspace must never be, because its only route out is egress-proxy.
test('the corporate proxy and CA overrides cover the services that call out and never touch the workspace', () => {
  const read = (file) => readFileSync(resolve(file), 'utf8');
  const named = (text) => services(text.split('\nsecrets:\n')[0] + '\nnetworks:\n');
  const proxy = read('compose.corporate-proxy.yaml');
  const ca = read('compose.corporate-ca.yaml');
  assert.deepEqual(named(proxy), ['agentd', 'model-gateway', 'egress-proxy']);
  assert.deepEqual(named(ca), ['agentd', 'model-gateway', 'workspace']);
  assert.match(ca.split('\n  workspace:\n')[1], /AGENTGATE_CORPORATE_CA_FILE: \/run\/secrets\/corporate_ca/);
  assert.match(proxy.split('\n  egress-proxy:\n')[1], /^ {6}AGENTGATE_EGRESS_UPSTREAM_PROXY: \$\{AGENTGATE_CORPORATE_PROXY:\?/m);
  assert.ok(!proxy.split('\n  egress-proxy:\n')[1].includes('HTTPS_PROXY'), 'egress-proxy chains tunnels itself; it must not also read a proxy from the environment');
  for (const text of [proxy]) {
    const blocks = text.split(/\n  [a-z0-9-]+:\n/).slice(1).filter((block) => block.includes('NODE_USE_ENV_PROXY'));
    for (const block of blocks) {
      assert.match(block, /NO_PROXY: agentd,model-gateway,egress-proxy,/, 'service names are dialled directly');
      const keys = [...block.matchAll(/^    ([a-z_]+):/gm)].map((match) => match[1]);
      assert.deepEqual(keys, ['environment']);
    }
  }
  const forwardProxy = read('compose.corporate-proxy.audit-forward.yaml');
  assert.deepEqual(named(forwardProxy), ['audit-forwarder'], 'the forwarder calls the SIEM through the proxy too');
  assert.match(forwardProxy, /NO_PROXY: agentd,model-gateway,egress-proxy,/);
  for (const text of [proxy, forwardProxy]) assert.ok(!/^  workspace:/m.test(text), 'the workspace is never pointed at the corporate proxy');
  assert.match(core.split('\n  workspace:\n')[1].split('\n  egress-proxy:\n')[0], /NODE_USE_ENV_PROXY: "1"/, 'Node tools in the workspace read the egress proxy from the environment');
});

// Audit forwarding is part of the open-source edition: shipping the hash-chained log to a SIEM must
// not need the commercial Compose file. The forwarder reads the broker's state read-only, because
// it is the one core service on the internet-facing network.
test('the audit forwarder is an open-source override that only reads the broker state', () => {
  const forward = readFileSync(resolve('compose.audit-forward.yaml'), 'utf8');
  assert.deepEqual(services(`${forward.split('\nvolumes:\n')[0]}\nnetworks:\n`), ['agentd', 'audit-forwarder']);
  const forwarder = forward.split('\n  audit-forwarder:\n')[1].split(/\n[a-z]+:\n/)[0];
  assert.match(forwarder, /^ {4}build: \.$/m, 'the open-source image, never a commercial one');
  assert.match(forwarder, /- broker-state:\/var\/lib\/agentgate:ro/, 'the broker state is read-only to the forwarder');
  assert.match(forwarder, /networks:\n {6}- upstream/);
  for (const setting of ['read_only: true', 'cap_drop:', 'no-new-privileges:true', 'mem_limit:']) assert.ok(forwarder.includes(setting), setting);
  assert.deepEqual(required(forward), ['AGENTGATE_AUDIT_SINK_TOKEN_PATH', 'AGENTGATE_AUDIT_SINK_URL']);
  const agentd = forward.split('\n  agentd:\n')[1].split(/\n  [a-z0-9-]+:\n/)[0];
  assert.match(agentd, /audit-forward-state:\/var\/lib\/agentgate-forward:ro/, 'agentd only reads the checkpoint');
  assert.ok(!core.includes('AGENTGATE_AUDIT_SINK_URL'), 'the core stack needs none of it');
});
