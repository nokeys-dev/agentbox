import { existsSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { loadRevocationsFile } from '../../src/revocations.js';
import { exampleConfig, fixture } from '../../scripts/support/fixture.js';

// Credential-free upstream for the Docker smoke tests, never a deployment entrypoint.
const config = exampleConfig();
config.rules.push(
  { id: 'pr-read', action: 'github.pr.read', repository: 'acme/demo', effect: 'allow' },
  { id: 'pr-create', action: 'github.pr.create', repository: 'acme/demo', ref: 'refs/heads/agent/*', effect: 'allow' },
  { id: 'ci-read', action: 'github.actions.read', repository: 'acme/demo', effect: 'allow' }
);
// Fleet smoke (scripts/fleet-smoke.js): assertion identity, no shared workspace token, and a
// revocation file re-read on every request so the script can revoke without a signal.
const fleet = process.env.AGENTGATE_SMOKE_FLEET === '1';
if (fleet) {
  delete config.runtime;
  config.identity = { mode: 'assertion', audience: 'agentgate:smoke', issuers: [{ kid: 'smoke', publicKeyPem: process.env.AGENTGATE_SMOKE_ISSUER_PUBLIC_KEY }] };
}
const revocationsPath = process.env.AGENTGATE_SMOKE_REVOCATIONS_FILE;
const f = await fixture({ config, host: '0.0.0.0', port: 7432, clientToken: undefined,
  ...(fleet ? { clientAuth: 'assertion', revocations: () => (revocationsPath && existsSync(revocationsPath) ? loadRevocationsFile(revocationsPath) : new Set()) } : {}) });
await writeFile('/tmp/agentgate-broker-only', 'test-only marker');
f.provider.api = async ({ operation, payload }) => {
  if (operation.resource === 'actions/runs') return Response.json({ total_count: 1, workflow_runs: [{ id: 1, status: 'completed', conclusion: 'success' }] });
  const pull = { number: 1, title: payload?.title ?? 'Smoke PR', draft: true, head: { ref: 'agent/smoke' }, base: { ref: 'main' } };
  return Response.json(operation.create ? pull : [pull], { status: operation.create ? 201 : 200 });
};
console.log(`Docker smoke broker ready${fleet ? ' (fleet mode)' : ''}`);
process.on('SIGTERM', async () => { await f.close(); });
