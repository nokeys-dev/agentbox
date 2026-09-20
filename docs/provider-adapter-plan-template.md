# Provider adapter plan template

Required outline for each ROADMAP Milestone 4 adapter plan (GitLab, AWS STS, Azure workload
identity, Kubernetes impersonation, internal HTTP APIs, ...). Copy this file, fill in every
section for the specific provider, and keep it alongside the adapter's code review. An adapter is
not ready to enable in production until every section has concrete answers — "TBD" is not
acceptable in a plan submitted for review.

The interface an adapter must implement is `PROVIDER_METHODS` in `src/providers/index.js`
(`forward`, `api`, `apiRaw`, `fetchLog`, `lfsBatch`, `lfsVerify`, `token`), grouped into the
capabilities `assertProvider`/`providerCapabilities` check (`git`, `api`, `lfs`, `logs`). An
adapter need not implement every capability — `assertProvider(provider, { capabilities })` is
called with only the capabilities the deployment actually uses — but every method behind a
capability it does claim must be present and behave per `src/github.js` (`GitHub`), the reference
implementation.

## 1. Credential model

- How are short-lived credentials minted? (e.g. GitHub: a JWT signed with the App's private key
  exchanged for an installation access token; must describe the equivalent exchange for this
  provider.)
- What is the scoping unit? (repository, project, resource group, namespace, ...) Map it to the
  `repository` object (`name`, `id`, `installationId`, ...) the broker passes to every provider
  method, or specify the new/extended shape needed.
- What is the maximum credential lifetime, and how is expiry checked before use? (GitHub:
  `expiresAt > now + 60_000`, i.e. a 60-second safety margin before use, not just before
  caching.)
- Where does the root credential (the thing that mints short-lived ones) live? It must never enter
  the workspace. It must be one of:
  - the `Signer`/KMS pattern from Phase 1 Task 1 (a private key held by a signer that never
    exposes raw key material to the broker process), or
  - the provider's own workload identity federation (e.g. AWS STS `AssumeRoleWithWebIdentity`,
    Azure workload identity federation, Kubernetes service account token projection) with no
    long-lived secret material on the broker host at all.
  Name which one, and where the trust anchor (public key, OIDC issuer, federation config) is
  configured and rotated.

## 2. Resource naming and config fields

- What fields does this provider add to `repositories[]` in `config.local.json` (or to a new
  top-level resource list, if the provider's resources are not repository-shaped)? List every
  field, its type, and whether it is required.
- Validation rules for each field (`src/config.js` is the model: an allowlist pattern anchored
  with `^...$`, a bound on length/count, and a `disallow ..`/traversal check for anything
  path-like). A resource identifier the broker will interpolate into a URL or path must be
  validated the same way `repository.name` is (`^[\w.-]+/[\w.-]+$`-style, no `..`, no scheme).
- Whether this provider's resources can coexist with GitHub repositories in the same config, or
  require a separate top-level list and a separate route prefix.

## 3. Policy actions

For each policy action this provider introduces (or maps an existing action like `git.read`,
`git.push`, `github.pr.*`, `github.actions.read` onto):

- The action name (config `rules[].action` value).
- The least-privilege scope/permission requested when minting a credential for it (e.g. GitHub:
  `{ contents: 'read' }` vs `{ contents: 'write', workflows: 'write' }`  — never a broader grant
  than the action needs).
- Whether `effect: 'approval'` is meaningful for it (i.e. whether the action can be held for human
  review before the provider call is made) or whether the provider's own request shape makes that
  impossible (e.g. a streamed, long-running operation that cannot be paused mid-flight).

## 4. Request routing

- Which broker HTTP paths does this provider serve? (New paths, or the existing
  `/info/refs`, `/git-upload-pack`, `/git-receive-pack`, `/info/lfs/objects/batch`,
  `/lfs-transfer/*`, `/api/*` set, reused with a different provider behind them?)
- Which upstream hosts does it call, and are they fixed, allowlisted constants in the adapter code
  (never derived from client input, a config field the workspace can influence, or a redirect
  target)? List every upstream hostname pattern the adapter's `fetch` calls can reach. Per the
  `GitHub` reference: `api.github.com` and `github.com` are the only hosts `github.js` itself
  calls; LFS `verify` hrefs are checked against `isLfsHost`/`isVerifyHref` (`src/lfs.js`) before a
  token is attached, and Actions log redirects are followed by `fetchLog` with **no** provider
  credential attached, only after the redirect target passed a hostname allowlist
  (`LOG_HOST_PATTERN` in `src/github-api.js`). Do the same: allowlist every redirect target by
  pattern before attaching any credential to it.

## 5. Response projection

- An explicit field list this adapter returns to the broker/client for every operation — never a
  raw provider API object passed through unfiltered. (`src/github-api.js`'s `PR_FIELDS`/
  equivalent per-endpoint projections are the model.)
- Confirm no field in that list can carry a credential, an internal-only identifier, or an
  upstream error body verbatim (error bodies can carry secrets — see the security invariants
  below).

## 6. Contract test

- Run `runProviderContract(makeProvider)` from `src/providers/index.js` against this adapter with
  a mocked `fetchImpl` — no network. It verifies, without needing anything provider-specific:
  - every upstream call sets `redirect: 'error'`;
  - every upstream call target is `https://`;
  - `forward` returns the raw upstream `Response` (including non-2xx) rather than throwing, so the
    broker decides what the client sees;
  - `token(repository, permission)` caches per `(repository, permission)` pair and re-mints on a
    different permission.
- In addition, write provider-specific tests (see `test/github.test.js` for the shape) covering:
  - **redirect rejection** on every method that talks to this provider, not just `forward`;
  - **error body suppression**: an upstream 4xx/5xx body containing a substring that must never
    reach a client or log (a fake secret token, an internal path, ...) is never present in the
    broker's response, logs, or audit trail (`test/github.test.js`'s "upstream token error bodies
    are never exposed" is the reference test);
  - **token scoping**: two different scopes/permissions/resources never share a cached credential,
    and a 401 from upstream evicts the cached credential rather than reusing it forever.

## 7. Live smoke test

- A disposable account, project, or subscription used only for this smoke test — never a
  production credential or resource.
- Setup: what has to exist before the smoke test runs (a test repo/project, a service
  account/App/role, IAM bindings) and how it is provisioned (script or documented manual steps).
- The smoke test itself: one read operation and one write operation (or the closest safe
  equivalent) exercised through the real broker against the real provider, with the response
  compared against the plan's response-projection field list.
- Cleanup: how the disposable resource created (if any) during the write step is torn down, and
  confirmation that no credential from the smoke test outlives it (cached tokens expire, any
  file-based key used for setup is deleted).

## 8. Threat model delta

- New assets introduced (the root credential/workload identity, any new cached token shape, any
  new config field that becomes sensitive).
- New trust boundaries (a new upstream host the broker now talks to; a new identity federation
  endpoint; a new class of client-supplied input that reaches this provider, e.g. a project ID
  instead of a GitHub repo name).
- New exfiltration channels to rule out: can a response field, error body, log line, or audit
  record from this provider carry the root credential, a minted token, or another tenant's data?
  Walk every response-projection field from section 5 and every error path from section 6 and
  state explicitly why each is safe.

## 9. Egress

- Every upstream hostname from section 4 must be added to the egress proxy's allowlist
  (`src/egress-proxy.js`) so the provider is reachable **only** via the broker process, never
  directly from the workspace network. List the exact hostnames (or hostname patterns) to add.
- Confirm `agentgate-egress-check` (or the equivalent check for this deployment) is updated to
  assert these hosts are reachable through the proxy and unreachable via direct DNS/egress from
  the workspace, and that removing them from the allowlist is covered by the same check failing
  closed.
