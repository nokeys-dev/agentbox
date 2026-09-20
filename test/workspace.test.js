import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fixture, exampleConfig } from './support/fixture.js';

const execute = promisify(execFile);
const setup = resolve('src/workspace-setup.js');

async function workspace(f) {
  const directory = join(f.directory, 'developer-home');
  await mkdir(directory);
  const tokenFile = join(f.directory, 'client-token');
  await writeFile(tokenFile, f.clientToken, { mode: 0o600 });
  const env = {
    PATH: process.env.PATH, HOME: directory, GIT_CONFIG_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0', AGENTGATE_URL: f.gate.url, AGENTGATE_CLIENT_TOKEN_FILE: tokenFile,
    AGENTGATE_GIT_NAME: 'Workspace Developer', AGENTGATE_GIT_EMAIL: 'dev@example.com'
  };
  const git = async (cwd, ...args) => (await execute('git', args, { cwd, env })).stdout.trim();
  const init = async () => execute(process.execPath, [setup], { cwd: directory, env });
  await init();
  return { directory, env, git, init };
}

test('workspace startup preserves preferences, persists identity, and refreshes routing without duplicate includes', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const w = await workspace(f);
  await w.git(w.directory, 'config', '--global', 'init.defaultBranch', 'trunk');
  await w.git(w.directory, 'config', '--global', 'alias.st', 'status --short');
  delete w.env.AGENTGATE_GIT_NAME;
  delete w.env.AGENTGATE_GIT_EMAIL;
  w.env.AGENTGATE_URL = 'http://localhost:9999';
  await w.init();
  await w.init();
  assert.equal(await w.git(w.directory, 'config', 'user.name'), 'Workspace Developer');
  assert.equal(await w.git(w.directory, 'config', 'user.email'), 'dev@example.com');
  assert.equal(await w.git(w.directory, 'config', 'init.defaultBranch'), 'trunk');
  assert.equal(await w.git(w.directory, 'config', 'alias.st'), 'status --short');
  assert.equal((await w.git(w.directory, 'config', '--global', '--get-all', 'include.path')).split('\n').length, 1);
  assert.equal(await w.git(w.directory, 'ls-remote', '--get-url', 'git@github.com:acme/demo'), 'http://localhost:9999/acme/demo');
  await assert.rejects(w.git(w.directory, 'config', '--get-regexp', `^url\\.${f.gate.url}/`));
});

test('normal GitHub URL forms clone through the broker and commit/push without manual Git setup', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const w = await workspace(f);
  const urls = ['https://github.com/acme/demo', 'https://github.com/acme/demo.git', 'git@github.com:acme/demo.git', 'ssh://git@github.com/acme/demo.git', 'ssh://git@github.com:22/acme/demo.git', 'ssh://git@ssh.github.com:443/acme/demo.git'];
  for (const [index, url] of urls.entries()) {
    const clone = join(w.directory, `clone-${index}`);
    await w.git(w.directory, 'clone', url, clone);
    assert.equal(await w.git(clone, 'show', 'HEAD:README.md'), '# Demo repository');
  }
  const clone = join(w.directory, 'clone-0');
  await w.git(clone, 'switch', '-c', 'agent/workspace');
  await writeFile(join(clone, 'work.txt'), 'workspace change\n');
  await w.git(clone, 'add', 'work.txt');
  await w.git(clone, 'commit', '-m', 'Workspace commit');
  assert.equal(await w.git(clone, 'show', '-s', '--format=%an <%ae>'), 'Workspace Developer <dev@example.com>');
  await w.git(clone, 'push', '-u', 'origin', 'HEAD');
  assert.equal(await f.git(f.bare, 'rev-parse', 'refs/heads/agent/workspace'), await w.git(clone, 'rev-parse', 'HEAD'));
  await assert.rejects(w.git(w.directory, 'ls-remote', 'https://github.com/acme/unauthorized'));
});

test('recursive submodules route relative and SSH URLs and deny unconfigured repositories', async (t) => {
  const config = exampleConfig();
  config.repositories.push({ name: 'acme/dependency', id: 3, installationId: 2 });
  config.rules.push({ id: 'read-dependency', action: 'git.read', repository: 'acme/dependency', effect: 'allow' });
  const f = await fixture({ config });
  t.after(f.close);
  const dependency = join(f.upstreamRoot, 'acme', 'dependency.git');
  const hidden = join(f.upstreamRoot, 'acme', 'hidden.git');
  await f.git(f.directory, 'clone', '--bare', f.seed, dependency);
  await f.git(f.directory, 'clone', '--bare', f.seed, hidden);
  const commit = await f.git(f.seed, 'rev-parse', 'HEAD');
  await writeFile(join(f.seed, '.gitmodules'), '[submodule "relative"]\n path = deps/relative\n url = ../dependency.git\n[submodule "ssh"]\n path = deps/ssh\n url = git@github.com:acme/dependency.git\n');
  await f.git(f.seed, 'add', '.gitmodules');
  for (const path of ['deps/relative', 'deps/ssh']) await f.git(f.seed, 'update-index', '--add', '--cacheinfo', `160000,${commit},${path}`);
  await f.git(f.seed, 'commit', '-m', 'Add submodules');
  await f.git(f.seed, 'push', f.bare, 'main');
  const w = await workspace(f);
  const clone = join(w.directory, 'recursive');
  await w.git(w.directory, 'clone', '--recurse-submodules', 'https://github.com/acme/demo.git', clone);
  assert.equal(await w.git(join(clone, 'deps/ssh'), 'rev-parse', 'HEAD'), commit);
  assert.equal(await w.git(join(clone, 'deps/relative'), 'rev-parse', 'HEAD'), commit);
  await assert.rejects(w.git(w.directory, 'clone', 'git@github.com:acme/hidden.git', join(w.directory, 'hidden')));
});

// Behind a proxy that inspects TLS: the workspace builds a bundle of the public roots plus the
// company CA, points Git at it for every host except the broker, and the shell environment points
// the other tools at it. Removing the setting removes the bundle and the Git setting.
test('a company root CA becomes a trust bundle for Git and the shell tools, and the broker keeps its own CA', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const w = await workspace(f);
  const tls = join(f.directory, 'corp');
  await mkdir(tls);
  await execute('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=Example Corp Root CA', '-keyout', join(tls, 'ca.key'), '-out', join(tls, 'ca.crt')]);
  const system = join(tls, 'system.crt');
  await writeFile(system, '# public roots stand-in\n');
  const brokerCa = join(tls, 'broker-ca.crt');
  await writeFile(brokerCa, 'unused');
  const env = { ...w.env, AGENTGATE_CORPORATE_CA_FILE: join(tls, 'ca.crt'), AGENTGATE_SYSTEM_CA_BUNDLE: system, AGENTGATE_CA_FILE: brokerCa };
  await execute(process.execPath, [setup], { cwd: w.directory, env });
  const bundle = join(w.directory, '.config', 'agentgate', 'ca-bundle.crt');
  const { readFile: read } = await import('node:fs/promises');
  const written = await read(bundle, 'utf8');
  assert.ok(written.startsWith('# public roots stand-in\n-----BEGIN CERTIFICATE-----'), 'public roots first, then the company CA');
  assert.equal(await w.git(w.directory, 'config', '--global', '--includes', '--get-urlmatch', 'http.sslCAInfo', 'https://registry.npmjs.org/'), bundle);
  assert.equal(await w.git(w.directory, 'config', '--global', '--includes', '--get-urlmatch', 'http.sslCAInfo', `${f.gate.url}/acme/demo.git`), brokerCa, 'the broker URL keeps its own CA');

  const shell = async (extra) => (await execute('sh', ['-c', `. ${resolve('scripts/agentgate-env.sh')}; printf '%s|%s|%s|%s' "\${SSL_CERT_FILE:-}" "\${CURL_CA_BUNDLE:-}" "\${REQUESTS_CA_BUNDLE:-}" "\${NODE_EXTRA_CA_CERTS:-}"`], { env: { PATH: process.env.PATH, HOME: w.directory, ...extra } })).stdout;
  assert.equal(await shell({ AGENTGATE_CORPORATE_CA_FILE: join(tls, 'ca.crt') }), `${bundle}|${bundle}|${bundle}|${join(tls, 'ca.crt')}`);
  assert.equal(await shell({}), '|||', 'nothing is exported without the setting');

  await writeFile(join(tls, 'not-a-cert.crt'), 'hello');
  const invalid = await execute(process.execPath, [setup], { cwd: w.directory, env: { ...env, AGENTGATE_CORPORATE_CA_FILE: join(tls, 'not-a-cert.crt') } }).then(() => null, (error) => error);
  assert.match(invalid.stderr, /AGENTGATE_CORPORATE_CA_FILE is not a PEM certificate/);

  await w.init();
  await assert.rejects(read(bundle), /ENOENT/, 'the bundle is removed with the setting');
  assert.equal(await w.git(w.directory, 'config', '--global', '--includes', '--get-urlmatch', 'http.sslCAInfo', 'https://registry.npmjs.org/').catch(() => ''), '');
});
