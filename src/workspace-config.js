import { readFileSync } from 'node:fs';

export function brokerUrl(value = process.env.AGENTGATE_URL || 'http://agentd:7432') {
  let url;
  try { url = new URL(value); } catch { throw new Error('AGENTGATE_URL must be an HTTP(S) origin'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('AGENTGATE_URL must be an HTTP(S) origin without credentials, a path, or query');
  }
  return url.origin;
}

// The Git host the broker fronts: github.com unless the deployment sets AGENTGATE_PROVIDER_HOST
// (a GitLab instance). Only used to recognise remotes and rewrite URLs in the workspace.
export function providerHost(env = process.env) {
  const host = (env.AGENTGATE_PROVIDER_HOST || 'github.com').toLowerCase();
  if (!/^[a-z0-9.-]{1,253}$/.test(host) || host.includes('..')) throw new Error('AGENTGATE_PROVIDER_HOST must be a hostname');
  return host;
}

export function repositoryName(value) {
  // OWNER/REPO, or a nested GitLab path (group/subgroup/project); never traversal or a scheme.
  if (!/^[\w.-]+(\/[\w.-]+)+$/.test(value || '') || value.length > 255) throw new Error('Repository must be OWNER/REPO');
  const name = value.replace(/\.git$/, '');
  if (name.split('/').some((part) => ['.', '..', ''].includes(part))) throw new Error('Invalid repository name');
  return name.toLowerCase();
}

export function repositoryFromRemote(remote, broker, env = process.env) {
  const host = providerHost(env);
  if (remote.startsWith(`git@${host}:`)) return repositoryName(remote.slice(`git@${host}:`.length));
  let url;
  try { url = new URL(remote); } catch { throw new Error('Use --repo OWNER/REPO or configure a provider origin remote'); }
  const hosts = [host, ...(host === 'github.com' ? ['ssh.github.com'] : [])];
  if (!hosts.includes(url.hostname) && url.origin !== broker) throw new Error('Origin is not the provider host or the configured broker; use --repo OWNER/REPO');
  return repositoryName(url.pathname.slice(1));
}

export function clientAuthHeader(env = process.env) {
  if (!env.AGENTGATE_CLIENT_TOKEN_FILE) return {};
  const token = readFileSync(env.AGENTGATE_CLIENT_TOKEN_FILE, 'utf8').trim();
  if (!/^[\x21-\x7e]{32,512}$/.test(token)) throw new Error('AGENTGATE_CLIENT_TOKEN_FILE does not contain a valid token');
  return { authorization: `Bearer ${token}` };
}

// The signed runtime assertion (identity.mode "assertion" on the broker). Re-read on every call so
// a renewed assertion file takes effect without restarting; Git itself only sees it through the
// managed gitconfig, so renewal also re-runs workspace setup (`agentgate renew`).
export function runtimeHeader(env = process.env) {
  if (!env.AGENTGATE_RUNTIME_ASSERTION_FILE) return {};
  const token = readFileSync(env.AGENTGATE_RUNTIME_ASSERTION_FILE, 'utf8').trim();
  // Empty means "not issued" (Compose mounts /dev/null for static-identity deployments). The
  // broker still rejects every request without a valid assertion when it requires one.
  if (!token) return {};
  if (token.length > 8192 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) {
    throw new Error('AGENTGATE_RUNTIME_ASSERTION_FILE does not contain a valid runtime assertion');
  }
  return { 'x-agentgate-runtime': token };
}
