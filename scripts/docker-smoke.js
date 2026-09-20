import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { join, resolve } from 'node:path';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { setTimeout } from 'node:timers/promises';

const execute = promisify(execFile);
const image = process.env.AGENTGATE_WORKSPACE_IMAGE || 'agentgate-workspace:local';
// The agentd runtime image (Dockerfile at the repository root), e.g. `docker build -t agentgate:local .`.
const brokerImage = process.env.AGENTGATE_IMAGE || 'agentgate:local';
// Floor is the Debian bookworm package (2.39.5): the mirror and scan suites pass on it and on 2.48.1.
const MIN_GIT = [2, 39];
const id = `agentgate-smoke-${randomUUID().slice(0, 8)}`;
const network = `${id}-network`;
const broker = `${id}-broker`;
const upstreamNetwork = `${id}-upstream`;
const proxy = `${id}-egress-proxy`;
const gateway = `${id}-model-gateway`;
const proxyUrl = 'http://egress-proxy:3128';
const homeVolume = `${id}-home`;
const dataVolume = `${id}-data`;
const created = [];
const docker = async (...args) => (await execute('docker', args, { maxBuffer: 4 * 1024 * 1024, timeout: 90_000 })).stdout.trim();
// Container logs go to stderr for structured error records; a failure message must show them.
const logs = async (name) => { const { stdout, stderr } = await execute('docker', ['logs', name], { maxBuffer: 4 * 1024 * 1024, timeout: 30_000 }); return `${stdout}${stderr}`.trim(); };

async function workspace(identity, script) {
  // Same egress posture as compose.yaml: no external DNS, all other egress via the proxy.
  return docker('run', '--rm', '--init', '--network', network, '--dns', '127.0.0.1',
    ...['HTTPS_PROXY', 'HTTP_PROXY', 'https_proxy', 'http_proxy'].flatMap((name) => ['--env', `${name}=${proxyUrl}`]),
    '--env', 'NO_PROXY=agentd,model-gateway', '--env', 'no_proxy=agentd,model-gateway',
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
    '--mount', `type=volume,source=${homeVolume},target=/home/node`,
    '--mount', `type=volume,source=${dataVolume},target=/workspace`,
    ...(identity ? ['--env', 'AGENTGATE_GIT_NAME=Smoke Developer', '--env', 'AGENTGATE_GIT_EMAIL=smoke@example.com'] : []),
    image, 'sh', '-eu', '-c', script);
}

try {
  await docker('image', 'inspect', image);
  await docker('image', 'inspect', brokerImage);
  // Content scanning shells out to git inside agentd; the image must ship a recent enough one.
  const gitVersion = await docker('run', '--rm', '--network', 'none', '--entrypoint', 'git', brokerImage, '--version');
  const [major, minor] = (/git version (\d+)\.(\d+)/.exec(gitVersion) ?? []).slice(1).map(Number);
  if (!(major > MIN_GIT[0] || (major === MIN_GIT[0] && minor >= MIN_GIT[1]))) throw new Error(`agentd image needs git >= ${MIN_GIT.join('.')}, found: ${gitVersion}`);
  console.log(`agentd image ships ${gitVersion}.`);
  await docker('network', 'create', '--internal', network);
  created.push(['network', 'rm', network]);
  for (const volume of [homeVolume, dataVolume]) {
    await docker('volume', 'create', volume);
    created.push(['volume', 'rm', volume]);
  }
  await docker('run', '-d', '--name', broker, '--init', '--network', network, '--network-alias', 'agentd',
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
    '--mount', `type=bind,source=${resolve('src')},target=/app/src,readonly`,
    '--mount', `type=bind,source=${resolve('test')},target=/app/test,readonly`,
    '--mount', `type=bind,source=${resolve('package.json')},target=/app/package.json,readonly`,
    '--entrypoint', 'node', image, '/app/test/support/docker-broker.js');
  created.push(['rm', '-f', broker]);
  let ready = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    try { await docker('exec', broker, 'node', '-e', "fetch('http://127.0.0.1:7432/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"); ready = true; break; }
    catch { await setTimeout(200); }
  }
  if (!ready) throw new Error(`Smoke broker failed to start: ${await logs(broker)}`);
  // The egress proxy is the only container on both the internal network and a routed one, as in
  // compose.yaml. The allowlisted-registry probe in agentgate-egress-check needs internet access.
  await docker('network', 'create', upstreamNetwork);
  created.push(['network', 'rm', upstreamNetwork]);
  await docker('run', '-d', '--name', proxy, '--init', '--network', network, '--network-alias', 'egress-proxy',
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--read-only',
    '--mount', `type=bind,source=${resolve('src')},target=/app/src,readonly`,
    '--mount', `type=bind,source=${resolve('examples/egress.json')},target=/etc/agentgate/egress.json,readonly`,
    '--entrypoint', 'node', image, '/app/src/egress-proxy.js');
  created.push(['rm', '-f', proxy]);
  await docker('network', 'connect', upstreamNetwork, proxy);
  ready = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    try { await docker('exec', proxy, 'node', '-e', "require('node:net').connect(3128,'127.0.0.1').on('connect',()=>process.exit(0)).on('error',()=>process.exit(1))"); ready = true; break; }
    catch { await setTimeout(200); }
  }
  if (!ready) throw new Error(`Smoke egress proxy failed to start: ${await logs(proxy)}`);
  // Model gateway: started like compose.yaml (own client token, read-only, no capabilities). Only
  // local refusals are exercised, so no provider key or upstream call is involved.
  const gatewayDir = mkdtempSync(join(tmpdir(), 'agentgate-smoke-gateway-'));
  created.push(['__rm', gatewayDir]);
  const gatewayToken = randomUUID().replaceAll('-', '');
  writeFileSync(join(gatewayDir, 'token'), gatewayToken, { mode: 0o600 });
  writeFileSync(join(gatewayDir, 'key'), 'placeholder-not-a-real-key', { mode: 0o600 });
  writeFileSync(join(gatewayDir, 'model-gateway.json'), JSON.stringify({ routes: [{ prefix: '/anthropic', upstream: 'https://api.anthropic.com',
    allowPaths: ['^/v1/messages$'], inject: { header: 'x-api-key', valueFile: '/etc/agentgate/key' } }] }), { mode: 0o600 });
  chmodSync(gatewayDir, 0o755);
  // The token file is owner-only (loadClientToken insists), so the gateway must run as the uid
  // that created it: on CI the runner is not uid 1000 (the image's `node`), so pass the host uid.
  await docker('run', '-d', '--name', gateway, '--init', '--network', network, '--network-alias', 'model-gateway', '--user', String(process.getuid()),
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--read-only',
    '--mount', `type=bind,source=${resolve('src')},target=/app/src,readonly`,
    '--mount', `type=bind,source=${gatewayDir},target=/etc/agentgate,readonly`,
    '--env', 'AGENTGATE_MODEL_GATEWAY_CONFIG=/etc/agentgate/model-gateway.json',
    '--env', 'AGENTGATE_MODEL_GATEWAY_CLIENT_TOKEN_FILE=/etc/agentgate/token',
    '--entrypoint', 'node', image, '/app/src/model-gateway.js');
  created.push(['rm', '-f', gateway]);
  const probe = `const t=${JSON.stringify(gatewayToken)};const g=(p,h)=>fetch('http://127.0.0.1:7434'+p,{headers:h}).then(r=>r.status);`
    + "Promise.all([g('/anthropic/v1/messages',{}),g('/anthropic/v1/admin',{authorization:'Bearer '+t})]).then(s=>{console.log(s.join(','));process.exit(s.join()==='401,404'?0:1)}).catch(()=>process.exit(1))";
  ready = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    try { await docker('exec', gateway, 'node', '-e', probe); ready = true; break; }
    catch { await setTimeout(200); }
  }
  if (!ready) throw new Error(`Smoke model gateway failed its refusal checks: ${await logs(gateway)}`);
  console.log('Model gateway refuses unauthenticated and non-allowlisted requests.');
  console.log('Docker broker is ready on an internal network.');
  await workspace(true, `
    test "$(id -u)" = 1000
    for tool in git git-lfs gh ssh gpg node npm python3 pip3 gcc make rg jq curl nano tmux; do command -v "$tool" >/dev/null; done
    test ! -e /tmp/agentgate-broker-only
    test ! -e /app/src/github.js
    test ! -e /var/run/docker.sock
    test -z "\${GITHUB_TOKEN:-}\${GH_TOKEN:-}\${GITHUB_PRIVATE_KEY_PATH:-}"
    agentgate doctor
    git clone https://github.com/acme/demo repo
    cd repo
    git switch -c agent/smoke
    echo smoke > smoke.txt
    git add smoke.txt
    git commit -m 'Docker smoke commit'
    git push -u origin HEAD
    if git push origin HEAD:main; then exit 1; fi
    agentgate pr create --title 'Smoke PR' --base main > /tmp/pr.json
    jq -e '.number == 1 and .draft == true' /tmp/pr.json
    agentgate ci list | jq -e '.workflow_runs[0].conclusion == "success"'
    git config --global alias.st 'status --short'
    agentgate-egress-check
  `);
  console.log('Verified installed tools, clone/commit/push, policy denial, PR/CI commands, blocked direct HTTPS and DNS, and allowlisted egress via the proxy.');
  const persisted = await workspace(false, `
    test "$(git config user.name)" = 'Smoke Developer'
    test "$(git config user.email)" = 'smoke@example.com'
    test "$(git config alias.st)" = 'status --short'
    cd repo
    test "$(git branch --show-current)" = 'agent/smoke'
    test "$(git config --global --get-all include.path | wc -l)" = 1
    git fetch
    agentgate pr list | jq -e '.[0].number == 1' >/dev/null
    echo persisted
  `);
  assert.equal(persisted, 'persisted');
  console.log('Verified developer home and repository survive container recreation.');
} catch (error) {
  if (error.stdout) console.error(error.stdout);
  console.error(error.stderr || error.message);
  process.exitCode = 1;
} finally {
  for (const args of created.reverse()) {
    try { if (args[0] === '__rm') rmSync(args[1], { recursive: true, force: true }); else await docker(...args); } catch (error) { console.error(`Could not clean up ${args.at(-1)}: ${error.message}`); process.exitCode = 1; }
  }
}
