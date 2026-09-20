// The provider interface a broker adapter must implement to sit behind AgentBox's request
// handling, LFS transfer, API proxy, and log-fetch code paths. `src/github.js` (`GitHub`) is the
// only implementation today; this module exists so a future adapter (GitLab, a cloud IAM
// provider, an internal Git host, ...) can be added without server.js/daemon.js/github-api.js
// depending on GitHub specifics. See docs/provider-adapter-plan-template.md for what a new
// adapter's plan must cover, and test/provider-contract.test.js for the reusable contract test.
//
// `apiOrg`/`orgToken` (org-scoped installation tokens for GitHub Team membership checks, used
// only by the optional `githubTeams` entitlement source in src/entitlements.js) are deliberately
// left out of this interface: they are a GitHub App concept (installation-wide, not
// repository-scoped) with no obvious equivalent across providers, the feature is opt-in
// (entitlements.js feature-detects `provider.apiOrg` itself and throws a clear, contained error
// only when a config actually enables `githubTeams`), and no core broker path (git, LFS, PR/API
// proxy, Actions logs) depends on it. An adapter that wants that entitlement source implements
// `apiOrg` on top of the required interface; adapters that don't simply can't offer it.
import assert from 'node:assert/strict';

// Method groups behind each capability an adapter can advertise. 'git' covers the raw Git
// smart-HTTP proxy (git-protocol.js/server.js) plus the token minting every other capability also
// needs; 'api' covers the PR/issue/Actions-metadata proxy (github-api.js, rulesets.js); 'lfs'
// covers the Git LFS batch/verify flow (lfs.js/server.js); 'logs' covers the Actions job-log
// download (github-api.js), which is split from 'api' because it uses a manual-redirect request
// (apiRaw) followed by an unauthenticated fetch of the redirect target (fetchLog).
const REQUIRED = {
  git: ['forward', 'token'],
  api: ['api', 'apiRaw'],
  lfs: ['lfsBatch', 'lfsVerify'],
  logs: ['fetchLog']
};

// The full set of methods any capability can require, in the order a broker calls them across a
// request lifecycle: mint/attach a token and proxy Git (forward), proxy the REST API (api),
// fetch API resources with redirects surfaced rather than followed (apiRaw), fetch an
// already-redirected storage URL with no provider credential (fetchLog), the LFS batch and verify
// calls, and the token minting all of the above share.
export const PROVIDER_METHODS = ['forward', 'api', 'apiRaw', 'fetchLog', 'lfsBatch', 'lfsVerify', 'token'];

// Fails closed: throws naming every missing method for the requested capabilities, rather than
// letting a broker start against a provider that will only fail once a client hits the gap.
// Call this once, at startup, after constructing the provider.
export function assertProvider(provider, { capabilities }) {
  const missing = capabilities.flatMap((capability) => REQUIRED[capability]).filter((method) => typeof provider?.[method] !== 'function');
  if (missing.length) throw new Error(`Provider is missing methods: ${[...new Set(missing)].join(', ')}`);
}

// Reports what a provider can do so callers (healthz) never have to hard-code per-adapter
// booleans. `pullRequests` and `actionsRead` are both surfaced from the same underlying methods
// today (GitHub's REST API and Actions-log endpoints share `api`/`apiRaw`/`fetchLog`); a future
// adapter without one of them would need finer-grained methods to distinguish, which is out of
// scope for this refactor since GitHub -- the only provider -- always has both together.
export function providerCapabilities(provider) {
  const has = (capability) => REQUIRED[capability].every((method) => typeof provider?.[method] === 'function');
  return { git: typeof provider?.forward === 'function', pullRequests: has('api'), actionsRead: has('api') && has('logs'), lfs: has('lfs') };
}

// Reusable contract test, runnable against any adapter with a mocked `fetchImpl` (no network).
// `makeProvider(fetchImpl)` must return a provider constructed with that fetch implementation.
// Verifies the security properties every adapter must preserve:
//   - redirects are always rejected (`redirect: 'error'`) on every upstream call `forward` makes;
//   - upstream calls use https;
//   - `forward` returns the raw upstream Response (status included) rather than throwing on a
//     non-2xx, so the broker -- not the provider -- decides what the client sees;
//   - tokens are cached per repository *and* permission, so a `read` and a `write` request never
//     share a cache entry and a cached token is reused rather than re-minted on every call.
// It deliberately does not assert that error bodies are never exposed to the client: that is a
// server.js/broker property (bodies are discarded on non-200), not something every provider
// implementation can enforce on its own -- see test/github.test.js's "upstream token error bodies
// are never exposed" for that coverage, and require an equivalent test in any adapter's plan.
// `isTokenCall`/`tokenResponse` describe the adapter's token-minting call (GitHub defaults);
// `perPermissionTokens: false` is for adapters whose credential cannot be narrowed per permission
// (a user-scoped OAuth token), where one cached token serves read and write alike.
export async function runProviderContract(makeProvider, { isTokenCall = (url) => url.includes('access_tokens'),
  tokenResponse = () => Response.json({ token: 'contract-secret-token-value', expires_at: new Date(Date.now() + 3600_000).toISOString() }), perPermissionTokens = true } = {}) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    if (isTokenCall(url)) return tokenResponse();
    return new Response('upstream says no: contract-secret-token-value', { status: 500 });
  };
  const provider = makeProvider(fetchImpl);
  const repository = { name: 'acme/demo', id: 1, installationId: 2 };
  const response = await provider.forward({ repository, service: 'git-upload-pack', discovery: true, signal: new AbortController().signal });
  assert.equal(response.status, 500, 'provider returns upstream status for the broker to handle');
  await response.body?.cancel();
  for (const call of calls) assert.equal(call.options.redirect, 'error', `redirects must be rejected: ${call.url}`);
  const upstreamCalls = calls.filter((call) => !isTokenCall(call.url));
  assert(upstreamCalls.every((call) => /^https:\/\//.test(call.url)), 'upstream calls use https');
  await provider.token(repository, 'read');
  await provider.token(repository, 'read');
  assert.equal(calls.filter((call) => isTokenCall(call.url)).length, 1, 'tokens are cached per repository and permission');
  await provider.token(repository, 'write');
  assert.equal(calls.filter((call) => isTokenCall(call.url)).length, perPermissionTokens ? 2 : 1, perPermissionTokens ? 'different permissions get different tokens' : 'one token serves every permission');
}
