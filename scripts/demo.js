import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fixture } from './support/fixture.js';
import { adminRequest } from '../src/admin-client.js';

const f = await fixture();
try {
  const workspace = join(f.directory, 'workspace');
  await f.git(f.directory, 'clone', f.remote, workspace);
  console.log('1. Cloned through AgentBox without a provider credential.');
  await f.git(workspace, 'config', 'user.name', 'Demo Agent');
  await f.git(workspace, 'config', 'user.email', 'agent@example.com');
  await f.git(workspace, 'checkout', '-b', 'agent/demo');
  await writeFile(join(workspace, 'hello.txt'), 'Hello from the agent workspace.\n');
  await f.git(workspace, 'add', 'hello.txt');
  await f.git(workspace, 'commit', '-m', 'Agent contribution');
  await f.git(workspace, 'push', 'origin', 'HEAD:refs/heads/agent/demo');
  console.log('2. Policy allowed a push to agent/demo.');
  try {
    await f.git(workspace, 'push', 'origin', 'HEAD:refs/heads/main');
    throw new Error('Expected main to require approval');
  } catch (error) {
    if (!error.stderr) throw error;
  }
  const pending = (await adminRequest(f.gate.adminSocket, 'GET', '/approvals')).find((item) => item.status === 'pending');
  if (!pending) throw new Error('Expected a pending approval');
  console.log(`3. Push to main blocked. Approval: ${pending.id}`);
  // Demo only: simulate the separate human approval step via the host socket.
  await adminRequest(f.gate.adminSocket, 'POST', `/approvals/${pending.id}/approve`, { reviewer: 'local:reviewer' });
  await f.git(workspace, 'push', 'origin', 'HEAD:refs/heads/main');
  console.log('4. Host approval granted; the retried push reached main.');
  console.log('5. Approval consumed. Audit events recorded. Temporary demo data will be removed.');
} finally { await f.close(); }
