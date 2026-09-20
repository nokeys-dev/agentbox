// Issues a signed runtime assertion for one workspace. Runs on the trusted issuing host; the issuer
// private key never goes to the broker or the workspace. Bind with --client-token-file when the
// issuer created the token, or with --client-token-sha256 (from `agentgate fingerprint` in the
// workspace) so the developer never sends the token itself to the issuer.
import { createPrivateKey } from 'node:crypto';
import { chmodSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { issueAssertion } from '../src/assertion.js';

try {
  const { values } = parseArgs({ options: {
    key: { type: 'string' }, kid: { type: 'string' }, 'client-token-file': { type: 'string' }, 'client-token-sha256': { type: 'string' }, out: { type: 'string' },
    audience: { type: 'string' }, issuer: { type: 'string', default: 'host-launcher' }, 'runtime-id': { type: 'string' },
    human: { type: 'string' }, agent: { type: 'string' }, team: { type: 'string' }, mode: { type: 'string', default: 'build' },
    application: { type: 'string' }, task: { type: 'string' }, 'gh-login': { type: 'string' }, ttl: { type: 'string', default: '28800' }
  } });
  for (const name of ['key', 'kid', 'out', 'audience', 'runtime-id', 'human', 'agent', 'team']) {
    if (!values[name]) throw new Error(`--${name} is required`);
  }
  if (values['client-token-file'] && values['client-token-sha256']) throw new Error('Give --client-token-file or --client-token-sha256, not both');
  if (!values['client-token-file'] && !values['client-token-sha256']) throw new Error('--client-token-file or --client-token-sha256 is required');
  const binding = values['client-token-sha256'] ? { clientTokenSha256: values['client-token-sha256'] } : { clientToken: readFileSync(values['client-token-file'], 'utf8').trim() };
  const ttl = Number(values.ttl);
  if (!Number.isSafeInteger(ttl) || ttl < 60 || ttl > 86400) throw new Error('--ttl must be between 60 and 86400 seconds');
  let task;
  if (values.task) {
    const separator = values.task.indexOf(':');
    if (separator < 1) throw new Error('--task must be SYSTEM:ID (jira, servicenow, or pagerduty)');
    task = { system: values.task.slice(0, separator), id: values.task.slice(separator + 1) };
  }
  const token = issueAssertion({
    iss: values.issuer, aud: values.audience, sub: values['runtime-id'], human: values.human, agent: values.agent, team: values.team, mode: values.mode,
    ...(values.application ? { application: values.application } : {}), ...(task ? { task } : {}), ...(values['gh-login'] ? { ghLogin: values['gh-login'] } : {})
  }, { privateKey: createPrivateKey(readFileSync(values.key)), kid: values.kid, ttlSeconds: ttl, ...binding });
  const temporary = `${values.out}.${process.pid}.tmp`;
  writeFileSync(temporary, `${token}\n`, { mode: 0o600 });
  chmodSync(temporary, 0o600);
  renameSync(temporary, values.out);
  console.log(`Wrote runtime assertion for ${values['runtime-id']} to ${values.out}`);
} catch (error) {
  console.error(`issue-runtime: ${error.message}`);
  process.exitCode = 1;
}
