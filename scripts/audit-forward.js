import { readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { forwardOnce, httpSink } from '../src/audit-forward.js';
import { createLogger } from '../src/log.js';

// warn/error go to stderr, matching the prior console.error behavior, so tests and operators
// reading stderr for failures keep working unchanged.
const logger = createLogger({ base: { service: 'agentgate-audit-forwarder' }, errorStream: process.stderr });

const directory = resolve(process.env.AGENTGATE_STATE_DIR || '.agentgate');
const url = process.env.AGENTGATE_AUDIT_SINK_URL;
if (!url) { logger.error('audit.forward.failed', { code: 'CONFIG_ERROR', message: 'AGENTGATE_AUDIT_SINK_URL is required' }); process.exit(1); }
const tokenPath = process.env.AGENTGATE_AUDIT_SINK_TOKEN_FILE;
let token;
if (tokenPath) {
  const mode = statSync(tokenPath).mode;
  if ((mode & 0o077) !== 0) { logger.error('audit.forward.failed', { code: 'CONFIG_ERROR', message: `AGENTGATE_AUDIT_SINK_TOKEN_FILE (${tokenPath}) must be owner-only (chmod 600)` }); process.exit(1); }
  token = readFileSync(tokenPath, 'utf8').trim();
  if (!token) { logger.error('audit.forward.failed', { code: 'CONFIG_ERROR', message: `AGENTGATE_AUDIT_SINK_TOKEN_FILE (${tokenPath}) must not be empty` }); process.exit(1); }
}
// Broker state is mounted read-only here (the forwarder never writes to it); the checkpoint
// lives in its own read-write location so a compromised forwarder cannot touch approvals.json
// or the audit files themselves. AGENTGATE_STATE_DIR stays the default when unset, so local,
// non-Compose runs (broker and forwarder sharing one state directory) keep working unchanged.
const checkpointPath = resolve(process.env.AGENTGATE_AUDIT_CHECKPOINT_PATH || join(directory, 'audit-forward.json'));
const intervalMs = Number(process.env.AGENTGATE_AUDIT_FORWARD_INTERVAL_MS || 5000);
const send = httpSink({ url, token });
let stopping = false;
process.on('SIGTERM', () => { stopping = true; });
process.on('SIGINT', () => { stopping = true; });
while (!stopping) {
  try {
    const result = await forwardOnce({ directory, checkpointPath, send });
    logger.info('audit.forward', { sent: result.sent, headSeq: result.head.seq, headHash: result.head.hash });
  } catch (error) {
    // CHAIN_BROKEN and AUDIT_GAP are security events: keep retrying so alerts stay visible, never skip ahead.
    logger.error('audit.forward.failed', { code: error.code ?? 'SEND_FAILED', message: error.message });
  }
  await setTimeout(intervalMs);
}
