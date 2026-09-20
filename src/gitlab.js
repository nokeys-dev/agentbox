// GitLab provider adapter: Git smart HTTP, merge requests, pipelines, and job traces behind the
// same broker paths GitHub uses. The root credential is an OAuth refresh token held only by the
// broker (owner-only file): it is exchanged for a short-lived access token at <base>/oauth/token,
// cached until 60 seconds before expiry, and the rotated refresh token GitLab returns is written
// back atomically. The base URL is fixed at startup, https only, and never taken from a request.
// OAuth tokens are user-scoped, so `permission` cannot narrow them the way GitHub App tokens can;
// policy is the least-privilege boundary here (see docs/providers/gitlab.md, section 3).
import { chmodSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { GateError, assert } from './errors.js';

export function gitlabBaseUrl(value = 'https://gitlab.com') {
  let url;
  try { url = new URL(value); } catch { throw new Error('AGENTGATE_GITLAB_URL must be an https origin'); }
  assert(url.protocol === 'https:' && !url.username && !url.password && url.pathname === '/' && !url.search && !url.hash, 'AGENTGATE_GITLAB_URL must be a bare https origin without credentials, path, query, or fragment');
  return url.origin;
}

function ownerOnly(path, label) {
  assert((statSync(path).mode & 0o077) === 0, `${label} must be owner-only (chmod 600)`);
  const value = readFileSync(path, 'utf8').trim();
  assert(/^[\x21-\x7e]{8,512}$/.test(value), `${label} must hold a printable token`);
  return value;
}

export class GitLab {
  constructor({ baseUrl, clientId, clientSecret, refreshTokenFile, fetchImpl = fetch, now = Date.now }) {
    this.base = gitlabBaseUrl(baseUrl);
    assert(typeof clientId === 'string' && /^[A-Za-z0-9_.-]{1,256}$/.test(clientId), 'GitLab OAuth client id is required');
    assert(typeof clientSecret === 'string' && /^[\x21-\x7e]{8,512}$/.test(clientSecret), 'GitLab OAuth client secret is required');
    assert(typeof refreshTokenFile === 'string' && refreshTokenFile, 'AGENTGATE_GITLAB_REFRESH_TOKEN_FILE is required');
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.refreshTokenFile = refreshTokenFile;
    this.refreshToken = ownerOnly(refreshTokenFile, 'AGENTGATE_GITLAB_REFRESH_TOKEN_FILE');
    this.fetch = fetchImpl;
    this.now = now;
    this.access = undefined;
    this.exchange = undefined;
  }

  get kind() { return 'gitlab'; }

  // One token serves every repository and permission. A concurrent burst of first requests shares
  // one in-flight exchange: refresh tokens are single use, so parallel exchanges would race.
  async token() {
    if (this.access && this.access.expiresAt > this.now() + 60_000) return this.access.token;
    if (!this.exchange) this.exchange = this.exchangeRefreshToken().finally(() => { this.exchange = undefined; });
    return this.exchange;
  }

  async exchangeRefreshToken() {
    const response = await this.fetch(`${this.base}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json', 'user-agent': 'AgentBox/0.1' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: this.refreshToken, client_id: this.clientId, client_secret: this.clientSecret }).toString(),
      redirect: 'error', signal: AbortSignal.timeout(15_000)
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new GateError(502, 'TOKEN_FAILED', `GitLab token exchange failed (${response.status})`);
    }
    let data;
    try { data = await response.json(); } catch { throw new GateError(502, 'TOKEN_FAILED', 'GitLab returned an invalid token response'); }
    const lifetime = Number(data.expires_in);
    const issuedAt = Number.isSafeInteger(data.created_at) ? data.created_at * 1000 : this.now();
    const expiresAt = issuedAt + lifetime * 1000;
    if (typeof data.access_token !== 'string' || !/^[\x21-\x7e]{8,4096}$/.test(data.access_token) || !Number.isFinite(lifetime) || expiresAt <= this.now() + 60_000) {
      throw new GateError(502, 'TOKEN_FAILED', 'GitLab returned an invalid access token');
    }
    // GitLab rotates the refresh token on every exchange: persist the new one before using the
    // access token, or a restart would present the spent one and lock the broker out.
    if (typeof data.refresh_token === 'string' && data.refresh_token && data.refresh_token !== this.refreshToken) {
      const temporary = `${this.refreshTokenFile}.${process.pid}.tmp`;
      writeFileSync(temporary, `${data.refresh_token}\n`, { mode: 0o600 });
      chmodSync(temporary, 0o600);
      renameSync(temporary, this.refreshTokenFile);
      this.refreshToken = data.refresh_token;
    }
    this.access = { token: data.access_token, expiresAt };
    return data.access_token;
  }

  invalidate() { this.access = undefined; }

  // The content-scanning mirror fetches over https from the same host with the same token.
  async mirrorRemote(repository) {
    return { url: `${this.base}/${repository.name}.git`, extraHeader: `Authorization: Basic ${Buffer.from(`oauth2:${await this.token()}`).toString('base64')}` };
  }

  async forward({ repository, service, discovery, body, protocol, signal }) {
    const token = await this.token();
    const suffix = discovery ? `info/refs?service=${service}` : service;
    const headers = {
      authorization: `Basic ${Buffer.from(`oauth2:${token}`).toString('base64')}`,
      'user-agent': 'AgentBox/0.1',
      accept: `application/x-${service}-${discovery ? 'advertisement' : 'result'}`
    };
    if (protocol) headers['git-protocol'] = protocol;
    if (!discovery) headers['content-type'] = `application/x-${service}-request`;
    const streamed = Boolean(body) && typeof body.pipe === 'function';
    // repository.name is validated by config.js (group/project, no traversal); never client input.
    const response = await this.fetch(`${this.base}/${repository.name}.git/${suffix}`, {
      method: discovery ? 'GET' : 'POST', headers, body, redirect: 'error',
      ...(streamed ? { duplex: 'half' } : {}),
      signal: AbortSignal.any([signal, AbortSignal.timeout(streamed ? 30 * 60_000 : 120_000)])
    });
    if (response.status === 401) this.invalidate();
    return response;
  }

  // REST API v4, project-scoped. operation.path is built by gitlab-api.js from validated values.
  async api({ repository, operation, payload, signal }) {
    const token = await this.token();
    const response = await this.fetch(`${this.base}/api/v4/projects/${repository.projectId}/${operation.path}`, {
      method: operation.method,
      headers: { authorization: `Bearer ${token}`, accept: 'application/json', 'content-type': 'application/json', 'user-agent': 'AgentBox/0.1' },
      body: payload === undefined ? undefined : JSON.stringify(payload),
      redirect: 'error', signal: AbortSignal.any([signal, AbortSignal.timeout(30_000)])
    });
    if (response.status === 401) this.invalidate();
    return response;
  }

  // Job traces come back in the body. A redirect is surfaced, never followed with the token.
  async apiRaw({ repository, operation, signal }) {
    const token = await this.token();
    const response = await this.fetch(`${this.base}/api/v4/projects/${repository.projectId}/${operation.path}`, {
      method: 'GET', headers: { authorization: `Bearer ${token}`, accept: 'text/plain', 'user-agent': 'AgentBox/0.1' },
      redirect: 'manual', signal: AbortSignal.any([signal, AbortSignal.timeout(120_000)])
    });
    if (response.status === 401) this.invalidate();
    return response;
  }

  // Unauthenticated fetch of an allowlisted storage URL; unused by GitLab's trace route today.
  fetchLog(url, options) {
    return this.fetch(url, options);
  }
}
