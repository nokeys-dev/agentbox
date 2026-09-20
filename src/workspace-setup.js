import { spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, rmSync, chmodSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { brokerUrl, clientAuthHeader, providerHost, runtimeHeader } from './workspace-config.js';

function git(...args) {
  const result = spawnSync('git', ['config', ...args], { encoding: 'utf8' });
  if (result.error || ![0, 1].includes(result.status)) throw new Error(result.error?.message || result.stderr.trim() || 'Could not configure Git');
  return { status: result.status, value: result.stdout.trim() };
}

try {
  const broker = brokerUrl();
  const directory = join(homedir(), '.config', 'agentgate');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const managed = join(directory, 'gitconfig');
  const temporary = `${managed}.${process.pid}.tmp`;
  writeFileSync(temporary, '', { mode: 0o600 });
  const host = providerHost();
  const prefixes = [`https://${host}/`, `http://${host}/`, `git@${host}:`, `ssh://git@${host}/`, `ssh://git@${host}:22/`, ...(host === 'github.com' ? ['ssh://git@ssh.github.com:443/'] : [])];
  for (const prefix of prefixes) {
    git('--file', temporary, '--add', `url.${broker}/.insteadOf`, prefix);
  }
  git('--file', temporary, `credential.${broker}.helper`, '');
  git('--file', temporary, `http.${broker}/.followRedirects`, 'false');
  const auth = clientAuthHeader();
  if (auth.authorization) git('--file', temporary, '--add', `http.${broker}/.extraHeader`, `Authorization: ${auth.authorization}`);
  // Git sends every http.<url>.extraHeader value; the assertion rides alongside the bearer token.
  // Git cannot re-read a file per request, so a renewed assertion needs this setup to run again.
  const runtime = runtimeHeader();
  if (runtime['x-agentgate-runtime']) git('--file', temporary, '--add', `http.${broker}/.extraHeader`, `x-agentgate-runtime: ${runtime['x-agentgate-runtime']}`);
  if (process.env.AGENTGATE_CA_FILE) git('--file', temporary, `http.${broker}/.sslCAInfo`, process.env.AGENTGATE_CA_FILE);
  // Behind a proxy that inspects TLS, every tool in the workspace sees certificates signed by the
  // company root CA. The bundle is the image's public roots plus that CA; agentgate-env.sh points
  // curl, Python, and OpenSSL-based tools at it, and Git is pointed at it here because Debian's Git
  // ignores SSL_CERT_FILE. The broker URL keeps its own sslCAInfo above, which is more specific.
  const bundle = join(directory, 'ca-bundle.crt');
  if (process.env.AGENTGATE_CORPORATE_CA_FILE) {
    const corporate = readFileSync(process.env.AGENTGATE_CORPORATE_CA_FILE, 'utf8');
    try { new X509Certificate(corporate); } catch { throw new Error('AGENTGATE_CORPORATE_CA_FILE is not a PEM certificate'); }
    const system = readFileSync(process.env.AGENTGATE_SYSTEM_CA_BUNDLE || '/etc/ssl/certs/ca-certificates.crt', 'utf8');
    writeFileSync(`${bundle}.${process.pid}.tmp`, `${system.trimEnd()}\n${corporate.trimEnd()}\n`, { mode: 0o644 });
    renameSync(`${bundle}.${process.pid}.tmp`, bundle);
    git('--file', temporary, 'http.sslCAInfo', bundle);
  } else rmSync(bundle, { force: true });
  chmodSync(temporary, 0o600);
  renameSync(temporary, managed);
  const includes = git('--global', '--get-all', 'include.path').value.split('\n');
  if (!includes.includes(managed)) git('--global', '--add', 'include.path', managed);
  for (const [key, value] of Object.entries({ 'user.useConfigOnly': 'true', 'init.defaultBranch': 'main', 'fetch.prune': 'true', 'push.default': 'simple' })) {
    if (git('--global', '--includes', '--get', key).status === 1) git('--global', key, value);
  }
  for (const [key, value] of [['user.name', process.env.AGENTGATE_GIT_NAME], ['user.email', process.env.AGENTGATE_GIT_EMAIL]]) {
    if (value) {
      if (!value.trim() || /[\r\n\0]/.test(value)) throw new Error(`Invalid ${key}`);
      git('--global', key, value);
    }
    if (!git('--global', '--includes', '--get', key).value) console.error(`AgentBox: set ${key} with git config --global before committing.`);
  }
} catch (error) {
  console.error(`AgentBox workspace setup: ${error.message}`);
  process.exitCode = 1;
}
