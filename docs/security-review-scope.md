# AgentBox security review scope

## System under review
Commit: <fill in the release tag at engagement start>. Components: `agentd` (src/server.js, src/github.js, src/github-api.js, src/git-protocol.js, src/policy.js, src/state.js, src/signer.js, src/client-auth.js, src/rulesets.js, src/reload.js, src/limits.js, src/log.js, src/metrics.js), approval web (enterprise/src/approval-web.js, src/admin-client.js, src/admin-auth.js), runtime identity issuer (enterprise/src/issuer-web.js, src/assertion.js, scripts/issue-runtime.js), fleet-mode client authentication (src/client-auth.js, src/assertion.js per-call binding), KMS signing (src/aws-kms.js, src/signer.js), entitlement sources (src/entitlements.js: static, GitHub teams, Jira, ServiceNow, Okta, Entra), runtime attribution in the model gateway and egress proxy (src/model-gateway.js and src/egress-proxy.js `identity`, unbound assertion verification), the issuer's runtime inventory endpoint (/api/runtimes) and its oauth2-proxy front end (enterprise/examples/oauth2-proxy.cfg, enterprise/examples/oauth2-proxy.alpha.yaml), audit forwarder (src/audit-chain.js, src/audit-forward.js, scripts/audit-forward.js), Slack notifier (src/notify.js), admin CLI (src/cli.js), workspace image (examples/workspace.Dockerfile, scripts/workspace-entrypoint.sh, scripts/egress-check.sh, src/workspace-cli.js, src/workspace-config.js, src/workspace-setup.js), compose deployment (compose.yaml, compose.kms.yaml), and the CI/release pipeline (.github/workflows/ci.yml, .github/workflows/release.yml) including image signing, SBOM, and provenance.

## Attacker models (in priority order)
1. Malicious agent with code execution in the workspace container, holding the client token.
2. Other host on the broker network without the client token.
3. Malicious repository content, issue text, or PR data returned by GitHub.
4. Compromised reviewer browser session (CSRF, clickjacking) against the approval UI.
4a. Host user with access to the admin socket (`admin.sock`) but not the approval-web admin secret, attempting to submit `oidc:` reviews or otherwise pass a `reviewerSources: ["oidc"]` rule. (A compromised approval-web process holds that secret and can approve as any `oidc:` reviewer by design; report any way to widen that, e.g. reaching the secret from another container.)
5. Attacker able to influence the CI/release pipeline (compromised CI credentials, a malicious pull request, or a dependency) attempting to publish or ship an unsigned, unscanned, or backdoored image.

## Objectives (report each as achieved / not achieved with evidence)
- O1 Obtain a GitHub installation token, App JWT, or private key material from the workspace.
- O2 Push to a ref denied by policy, or to an approval-gated ref without a matching consumed approval.
- O3 Reuse, replay, or widen an approval (different OIDs, refs, repository, runtime, or policy hash).
- O4 Reach a GitHub API endpoint or repository outside the allowlist/configuration.
- O5 Approve a request without a valid OIDC identity, as the delegating human, or twice as the same reviewer.
- O5a Get an `oidc:` reviewer accepted on the admin socket without a valid HMAC from approval-web (forged, replayed outside the ±60 s window, or re-targeted to another path/body), get a review counted from a source a rule's `reviewerSources` excludes, or review a superseded approval.
- O6 Modify or drop audit records without `audit:verify` or the forwarder detecting it.
- O7 Egress data from the workspace by any channel other than an allowed push (document each channel found).
- O8 Deny service to the broker from the workspace despite rate limits and quotas.
- O9 Escape the workspace container or reach the Docker API, broker state volume, or host.
- O10 Forge or replay an approval through the web UI, by CSRF or by proxy-header spoofing (e.g. `X-Forwarded-Email`) against oauth2-proxy or approval-web; approve as another reviewer; or bypass a `approvals: 2` two-person rule on a protected ref.
- O11 Leak GitHub tokens, the App private key, approval reviewer identities, or other secrets through `/metrics`, application logs, or Slack notifications.
- O12 Inject content via agent-controlled fields (PR titles, branch names, ref names, runtime identity) into Slack notifications or the approval web UI to spoof a reviewer, forge a channel mention, or otherwise mislead the approver.
- O13 Subvert the CI or release pipeline to publish or deploy an agentd or workspace image that is unsigned, lacks an SBOM, or has known-vulnerable dependencies that should have failed the scan gate.

## Out of scope
GitHub.com itself; the KMS provider; the OIDC provider; physical host access.

## Environment provided
Disposable GitHub org and App, compose deployment with production settings, approval UI behind the real OIDC proxy, read access to audit sink.

## Deliverables
Findings with severity (CVSS 4.0), reproduction, and fix guidance; retest after fixes.
