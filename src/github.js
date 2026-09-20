import { GateError, assert } from './errors.js';
import { localSigner } from './signer.js';
import { isVerifyHref } from './lfs.js';

export class GitHub {
  constructor({ appId, signer, privateKey, fetchImpl = fetch, now = Date.now }) {
    assert(typeof appId === 'string' && /^[A-Za-z0-9_.-]+$/.test(appId), 'GITHUB_APP_ID is required');
    assert(signer || privateKey, 'GitHub requires a signer or privateKey');
    this.appId = appId;
    this.signer = signer ?? localSigner(privateKey);
    this.fetch = fetchImpl;
    this.now = now;
    this.tokens = new Map();
  }

  async jwt() {
    const now = Math.floor(this.now() / 1000);
    const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const unsigned = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({ iat: now - 60, exp: now + 540, iss: this.appId })}`;
    return `${unsigned}.${(await this.signer.sign(Buffer.from(unsigned))).toString('base64url')}`;
  }

  permissions(repository, permission) {
    if (typeof permission !== 'string') return permission;
    return { contents: permission, ...(permission === 'write' && repository.allowWorkflowWrites ? { workflows: 'write' } : {}) };
  }

  tokenKey(repository, permission) {
    return `${repository.installationId}:${repository.id}:${JSON.stringify(Object.entries(this.permissions(repository, permission)).sort())}`;
  }

  async token(repository, permission) {
    return this.requestToken(this.tokenKey(repository, permission), repository.installationId,
      { repository_ids: [repository.id], permissions: this.permissions(repository, permission) });
  }

  // Organization-scoped installation token (no repository_ids), used only for org endpoints such as
  // team membership. Cached separately from repository tokens so the two can never be confused.
  orgTokenKey(installationId, permissions) {
    return `org:${installationId}:${JSON.stringify(permissions)}`;
  }

  async orgToken(installationId, permissions) {
    assert(Number.isSafeInteger(installationId) && installationId > 0, 'installationId must be a positive integer');
    assert(permissions && typeof permissions === 'object' && Object.keys(permissions).length > 0, 'orgToken requires permissions');
    return this.requestToken(this.orgTokenKey(installationId, permissions), installationId, { permissions });
  }

  async requestToken(cacheKey, installationId, body) {
    const cached = this.tokens.get(cacheKey);
    if (cached && cached.expiresAt > this.now() + 60_000) return cached.token;
    const response = await this.fetch(`https://api.github.com/app/installations/${installationId}/access_tokens`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${await this.jwt()}`,
        accept: 'application/vnd.github+json',
        'content-type': 'application/json',
        'x-github-api-version': '2026-03-10',
        'user-agent': 'AgentBox/0.1'
      },
      body: JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.timeout(15_000)
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new GateError(502, 'TOKEN_FAILED', `GitHub token request failed (${response.status})`);
    }
    const data = await response.json();
    const expiresAt = Date.parse(data.expires_at);
    if (typeof data.token !== 'string' || !data.token || !Number.isFinite(expiresAt) || expiresAt <= this.now() + 60_000) {
      throw new GateError(502, 'TOKEN_FAILED', 'GitHub returned an invalid installation token');
    }
    this.tokens.set(cacheKey, { token: data.token, expiresAt });
    return data.token;
  }

  // GET an organization endpoint (path relative to api.github.com, built by the caller from
  // validated org/team/login values) with an org-scoped token. Never follows redirects.
  async apiOrg({ installationId, path, permissions }) {
    assert(typeof path === 'string' && /^orgs\/[A-Za-z0-9-]+\/[A-Za-z0-9_./%-]+$/.test(path) && !path.includes('..'), 'apiOrg path must be an orgs/ path');
    const token = await this.orgToken(installationId, permissions);
    const response = await this.fetch(`https://api.github.com/${path}`, {
      method: 'GET', headers: { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2026-03-10', 'user-agent': 'AgentBox/0.1' },
      redirect: 'error', signal: AbortSignal.timeout(15_000)
    });
    if (response.status === 401) this.tokens.delete(this.orgTokenKey(installationId, permissions));
    return response;
  }

  async forward({ repository, service, discovery, body, protocol, signal }) {
    const token = await this.token(repository, service === 'git-upload-pack' ? 'read' : 'write');
    const suffix = discovery ? `info/refs?service=${service}` : service;
    const headers = {
      authorization: `Basic ${Buffer.from(`x-access-token:${token}`).toString('base64')}`,
      'user-agent': 'AgentBox/0.1',
      accept: `application/x-${service}-${discovery ? 'advertisement' : 'result'}`
    };
    if (protocol) headers['git-protocol'] = protocol;
    if (!discovery) headers['content-type'] = `application/x-${service}-request`;
    // Never follow redirects with credentials or forward client-supplied headers.
    // A Readable push body streams upstream; large pushes get a longer timeout, and the caller's
    // signal still cancels on client disconnect or a mid-stream byte-cap failure.
    const streamed = Boolean(body) && typeof body.pipe === 'function';
    const response = await this.fetch(`https://github.com/${repository.name}.git/${suffix}`, {
      method: discovery ? 'GET' : 'POST', headers, body, redirect: 'error',
      ...(streamed ? { duplex: 'half' } : {}),
      signal: AbortSignal.any([signal, AbortSignal.timeout(streamed ? 30 * 60_000 : 120_000)])
    });
    if (response.status === 401) this.tokens.delete(this.tokenKey(repository, service === 'git-upload-pack' ? 'read' : 'write'));
    return response;
  }

  // Git LFS batch API. Download uses a Contents read token, upload a Contents write token. The token
  // only ever goes to github.com; storage hrefs in the response are handled by the broker without it.
  async lfsBatch({ repository, operation, payload, signal }) {
    const permission = operation === 'upload' ? 'write' : 'read';
    const token = await this.token(repository, { contents: permission });
    const response = await this.fetch(`https://github.com/${repository.name}.git/info/lfs/objects/batch`, {
      method: 'POST',
      headers: {
        authorization: `Basic ${Buffer.from(`x-access-token:${token}`).toString('base64')}`,
        accept: 'application/vnd.git-lfs+json', 'content-type': 'application/vnd.git-lfs+json', 'user-agent': 'AgentBox/0.1'
      },
      body: JSON.stringify({ operation, transfers: ['basic'], objects: payload.objects }),
      redirect: 'error', signal: AbortSignal.any([signal, AbortSignal.timeout(30_000)])
    });
    if (response.status === 401) this.tokens.delete(this.tokenKey(repository, { contents: permission }));
    return response;
  }

  // Git LFS verify action. The href comes from GitHub's own batch response and is re-checked to be
  // an https github.com LFS endpoint for this repository before a Contents write token is attached;
  // tokens are never sent to storage hosts. Only 2xx counts as verified.
  async lfsVerify({ repository, oid, size, href, header = {}, signal }) {
    if (!isVerifyHref(href, repository.name)) throw new GateError(502, 'LFS_UNTRUSTED_HOST', 'LFS verify endpoint is not trusted');
    const token = await this.token(repository, { contents: 'write' });
    const headers = Object.fromEntries(Object.entries(header).filter(([key]) => !['authorization', 'content-type', 'accept', 'user-agent', 'host', 'content-length'].includes(key.toLowerCase())));
    const response = await this.fetch(href, {
      method: 'POST',
      headers: { ...headers, authorization: `Basic ${Buffer.from(`x-access-token:${token}`).toString('base64')}`, accept: 'application/vnd.git-lfs+json', 'content-type': 'application/vnd.git-lfs+json', 'user-agent': 'AgentBox/0.1' },
      body: JSON.stringify({ oid, size }), redirect: 'error', signal: AbortSignal.any([...(signal ? [signal] : []), AbortSignal.timeout(30_000)])
    });
    await response.body?.cancel().catch(() => {});
    if (response.status === 401) this.tokens.delete(this.tokenKey(repository, { contents: 'write' }));
    if (response.status < 200 || response.status > 299) throw new GateError(502, 'UPSTREAM_FAILED', `GitHub LFS verify failed (${response.status})`);
  }

  async api({ repository, operation, payload, signal }) {
    const token = await this.token(repository, operation.permissions);
    const response = await this.fetch(`https://api.github.com/repos/${repository.name}/${operation.path}`, {
      method: operation.method,
      headers: {
        authorization: `Bearer ${token}`, accept: 'application/vnd.github+json',
        'content-type': 'application/json', 'x-github-api-version': '2026-03-10', 'user-agent': 'AgentBox/0.1'
      },
      body: payload === undefined ? undefined : JSON.stringify(payload),
      redirect: 'error', signal: AbortSignal.any([signal, AbortSignal.timeout(30_000)])
    });
    if (response.status === 401) this.tokens.delete(this.tokenKey(repository, operation.permissions));
    return response;
  }

  // Same request shape as api(), but with a manual redirect: GitHub answers a job-logs request
  // with a 302 to a short-lived, presigned storage URL. That redirect (and its Location) is
  // never followed with the GitHub token attached; the caller (handleApi) fetches the storage
  // URL itself, with no credentials at all, via fetchLog below.
  async apiRaw({ repository, operation, signal }) {
    const token = await this.token(repository, operation.permissions);
    return this.fetch(`https://api.github.com/repos/${repository.name}/${operation.path}`, {
      method: 'GET',
      headers: { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2026-03-10', 'user-agent': 'AgentBox/0.1' },
      redirect: 'manual', signal: AbortSignal.any([signal, AbortSignal.timeout(30_000)])
    });
  }

  // Fetches an allowlisted log-storage URL. Never attaches any GitHub or client credential;
  // the URL itself carries the storage host's own short-lived signature.
  fetchLog(url, options) {
    return this.fetch(url, options);
  }
}
