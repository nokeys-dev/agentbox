import { resolve, join } from 'node:path';
import { userInfo } from 'node:os';
import { adminRequest } from './admin-client.js';

try {
  const [command, prefix, ...extra] = process.argv.slice(2);
  if (!['list', 'approve', 'deny'].includes(command) || extra.length || (command === 'list' ? prefix !== undefined : !/^[0-9a-f-]{8,36}$/.test(prefix || ''))) {
    throw new Error('Usage: node src/cli.js list | approve <id-prefix> | deny <id-prefix>');
  }
  const socket = join(resolve(process.env.AGENTGATE_STATE_DIR || '.agentgate'), 'admin.sock');
  let body;
  if (command !== 'list') {
    let reviewer = process.env.AGENTGATE_REVIEWER;
    if (!reviewer) {
      try { reviewer = `local:${userInfo().username}`; } catch { throw new Error('Could not determine the local username; set AGENTGATE_REVIEWER to a reviewer identity like local:alice'); }
    }
    if (reviewer.startsWith('oidc:')) {
      throw new Error('AGENTGATE_REVIEWER cannot be an oidc: identity: oidc: reviewers are accepted only from the approval web UI behind oauth2-proxy. Use local:<name> for CLI reviews');
    }
    if (!/^local:[A-Za-z0-9._@+-]{1,200}$/.test(reviewer)) {
      throw new Error(`Reviewer identity "${reviewer}" is not a valid local: identity; set AGENTGATE_REVIEWER to one like local:alice`);
    }
    body = { reviewer };
  }
  const result = await adminRequest(socket, command === 'list' ? 'GET' : 'POST', command === 'list' ? '/approvals' : `/approvals/${prefix}/${command}`, body);
  console.log(JSON.stringify(result, null, 2));
} catch (error) {
  console.error(`AgentBox: ${error.message}`);
  process.exitCode = 1;
}
