// A broker with a local Git remote and a temporary state directory, used both by `npm run demo`
// (so it ships in the package) and by the test suite. It starts the real server and speaks real
// Git over HTTP; nothing here is a stub.
import { execFile, spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { startGate } from '../../src/server.js';
import { Mirror } from '../../src/mirror.js';

const execute = promisify(execFile);

export function exampleConfig() {
  return {
    runtime: { human: 'test@example.com', agent: 'test-agent', runtimeId: 'test-runtime', task: 'test-task' },
    repositories: [{ name: 'acme/demo', id: 1, installationId: 2 }],
    rules: [
      { id: 'read', action: 'git.read', repository: 'acme/demo', effect: 'allow' },
      { id: 'feature', action: 'git.push', repository: 'acme/demo', ref: 'refs/heads/agent/*', effect: 'allow' },
      { id: 'main', action: 'git.push', repository: 'acme/demo', ref: 'refs/heads/main', effect: 'approval' },
      { id: 'tags', action: 'git.push', repository: '*', ref: 'refs/tags/*', effect: 'deny' },
      { id: 'deletions', action: 'git.push', repository: '*', ref: '*', operation: 'delete', effect: 'deny' }
    ]
  };
}

export function packet(value) {
  const bytes = Buffer.from(value);
  return Buffer.concat([Buffer.from((bytes.length + 4).toString(16).padStart(4, '0')), bytes]);
}

export function pushBody(ref = 'refs/heads/main', oldOid = '1'.repeat(40), newOid = '2'.repeat(40)) {
  return Buffer.concat([packet(`${oldOid} ${newOid} ${ref}\0report-status`), Buffer.from('0000')]);
}

export async function fixture(options = {}) {
  // '' and undefined both mean "disable auth"; only an explicit clientToken key opts out of the
  // default test token, so callers that never mention clientToken keep auth on by default. The
  // key is destructured out of `rest` so a later `...rest` spread cannot re-introduce it.
  const hasRequestedToken = Object.hasOwn(options, 'clientToken');
  const { clientToken: requestedToken, scan, ...rest } = options;
  const clientToken = hasRequestedToken ? (requestedToken || undefined) : 'test-client-token-0123456789abcdef';
  const authHeaders = clientToken ? { authorization: `Bearer ${clientToken}` } : {};
  const directory = await mkdtemp(join(tmpdir(), 'agentgate-'));
  const env = { PATH: process.env.PATH, HOME: directory, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0',
    ...(clientToken ? { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'http.extraHeader', GIT_CONFIG_VALUE_0: `Authorization: Bearer ${clientToken}` } : {}) };
  // An optional trailing { input, output } object pipes input to stdin and writes stdout to output.
  const git = async (cwd, ...args) => {
    const options = typeof args.at(-1) === 'object' ? args.pop() : {};
    if (options.input === undefined) return (await execute('git', args, { cwd, env, maxBuffer: 8 * 1024 * 1024 })).stdout.trim();
    return new Promise((resolve, reject) => {
      const child = spawn('git', args, { cwd, env, stdio: ['pipe', options.output ? 'pipe' : 'inherit', 'inherit'] });
      const done = options.output ? new Promise((ok) => child.stdout.pipe(createWriteStream(options.output)).on('finish', ok)) : Promise.resolve();
      child.on('error', reject);
      child.on('close', (code) => code === 0 ? done.then(() => resolve('')) : reject(new Error(`git ${args[0]} exited ${code}`)));
      child.stdin.end(options.input);
    });
  };
  const upstreamRoot = join(directory, 'upstream');
  const bare = join(upstreamRoot, 'acme', 'demo.git');
  const seed = join(directory, 'seed');
  await mkdir(join(upstreamRoot, 'acme'), { recursive: true });
  await mkdir(seed);
  await git(directory, 'init', '--bare', '--initial-branch=main', bare);
  await git(bare, 'config', 'http.receivepack', 'true');
  await git(seed, 'init', '--initial-branch=main');
  await git(seed, 'config', 'user.name', 'AgentBox Demo');
  await git(seed, 'config', 'user.email', 'demo@example.com');
  await writeFile(join(seed, 'README.md'), '# Demo repository\n');
  await git(seed, 'add', 'README.md');
  await git(seed, 'commit', '-m', 'Initial commit');
  await git(seed, 'push', bare, 'main');
  const calls = [];
  const provider = {
    async forward({ repository, service, discovery, body, protocol }) {
      calls.push({ repository, service, discovery, streamed: Boolean(body?.pipe) });
      const suffix = discovery ? 'info/refs' : service;
      return new Promise((resolve, reject) => {
        const child = spawn('git', ['http-backend'], {
          env: { ...env, GIT_PROJECT_ROOT: upstreamRoot, GIT_HTTP_EXPORT_ALL: '1', GIT_PROTOCOL: protocol || '',
            REQUEST_METHOD: discovery ? 'GET' : 'POST', PATH_INFO: `/${repository.name}.git/${suffix}`,
            QUERY_STRING: discovery ? `service=${service}` : '', REMOTE_USER: 'demo', REMOTE_ADDR: '127.0.0.1',
            CONTENT_TYPE: `application/x-${service}-request`,
            // Streamed bodies omit CONTENT_LENGTH: git http-backend (>= 2.35) then reads until EOF.
            ...(body?.pipe ? {} : { CONTENT_LENGTH: String(body?.length || 0) }) },
          stdio: ['pipe', 'pipe', 'pipe']
        });
        const chunks = [];
        const errors = [];
        child.stdout.on('data', (chunk) => chunks.push(chunk));
        child.stderr.on('data', (chunk) => errors.push(chunk));
        child.on('error', reject);
        child.stdin.on('error', reject);
        child.on('close', (code) => {
          if (code !== 0) return reject(new Error(Buffer.concat(errors).toString()));
          const output = Buffer.concat(chunks);
          const split = output.indexOf('\r\n\r\n');
          if (split < 0) return reject(new Error('Malformed Git CGI response'));
          const headers = new Headers();
          let status = 200;
          for (const line of output.subarray(0, split).toString().split('\r\n')) {
            const colon = line.indexOf(':');
            const name = line.slice(0, colon);
            const value = line.slice(colon + 1).trim();
            if (name.toLowerCase() === 'status') status = Number.parseInt(value, 10);
            else headers.set(name, value);
          }
          resolve(new Response(output.subarray(split + 4), { status, headers }));
        });
        if (body?.pipe) {
          body.on('error', (error) => { child.stdin.destroy(); child.kill(); reject(error); });
          body.pipe(child.stdin);
        } else child.stdin.end(body);
      });
    }
  };
  let gate;
  try {
    // scan: a mirror that syncs from the local upstream bare repository over the file protocol.
    if (scan) rest.mirror = new Mirror({ root: join(directory, 'mirrors'), allowedProtocols: ['file'], fetchRemote: async () => ({ url: bare }) });
    gate = await startGate({ config: exampleConfig(), provider, stateDirectory: join(directory, 'state'), port: 0, clientToken, ...rest });
  } catch (error) { await rm(directory, { recursive: true, force: true }); throw error; }
  return { directory, seed, bare, upstreamRoot, provider, calls, git, gate, clientToken, authHeaders, remote: `${gate.url}/acme/demo.git`, close: async () => {
    await gate.close();
    await rm(directory, { recursive: true, force: true });
  } };
}
