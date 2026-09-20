# Changelog

All notable changes to AgentBox. Format follows Keep a Changelog; versions follow semver once
1.0 is tagged. Dates are UTC.

## Unreleased

### Changed
- The codebase is split into an open-source edition (everything outside `enterprise/`) and a
  commercial edition (`enterprise/`: control plane and signed bundles, central approvals, issuing
  service, hosted agents, approval UI, and the Okta, Entra ID, Jira, and ServiceNow entitlement
  sources). A commercial setting in the open-source edition is refused by name.

## 0.2.0 - 2026-09-19

### Added
- Product renamed to AgentBox (daemon `agentd`, CLI `agentgate`, and `AGENTGATE_*` kept).
- Dev Container attach for VS Code, Cursor, and Windsurf; IDE egress allowlist; Claude Code
  workspace profile with managed deny settings; `npm run bootstrap`; onboarding runbook.
- Fleet mode: one broker serves many workspaces by assertion-bound tokens
  (`AGENTGATE_CLIENT_AUTH=assertion`); per-runtime rate limits.
- Issuing service with identity-provider login, dashboard, revocation, and runtime inventory
  (`src/issuer-web.js`); `agentgate fingerprint`; `--client-token-sha256` for the script.
- Delegation bound at issuance (directory export, Okta, Entra) and at verification
  (`identity.delegation`).
- Entitlement sources: Okta groups, Entra ID groups (Graph), ServiceNow change/incident.
- Built-in AWS KMS signing with SigV4 and Pod Identity/IRSA credentials.
- Runtime attribution and budgets at the model gateway (request header) and egress proxy
  (proxy credentials).
- Revocation file polling (`AGENTGATE_REVOCATIONS_POLL_MS`).
- GitLab provider: Git, merge requests, pipelines, job logs, protected-branch verification.
- Hosted-agent coverage: webhook service and required check run for vendor-hosted agents.
- Cross-broker central approvals at the control plane with signed review documents.
- `npm run demo:identity`, `npm run test:fleet`, Compose split into core and enterprise files,
  prebuilt-image override, security policy, contribution rules, security review plan.
- Installable package: the `agentbox` command (`init`, `up`, `down`, `compose`, `doctor`,
  `daemon`, `demo`, ...) published to npm as `@nokeys/agentbox`; the release workflow also builds single-file
  executables for Linux, macOS, and Windows, a Debian package, and Homebrew and winget manifests.
  The package runs Compose from its own directory against the project's `.env`. Each project
  directory is its own Compose project with a generated `.devcontainer` for editor attach.
- `agentbox check`: a host preflight (Docker, Compose version, every setting, secret file
  permissions, config placeholders) that `agentbox up` runs first.
- Development certificates are renewed by a bootstrap rerun when under a week is left, and
  `agentbox check` reports a certificate that has expired or is about to.
- Corporate forward proxy: `compose.corporate-proxy.yaml` routes `agentd` and `model-gateway`
  through it and chains allowed egress tunnels through it (`AGENTGATE_EGRESS_UPSTREAM_PROXY`);
  `compose.corporate-ca.yaml` trusts a TLS-inspecting proxy's root CA in the broker services and,
  through a generated bundle, in every tool inside the workspace.
- Node's built-in `fetch` in the workspace now goes through the egress proxy (`NODE_USE_ENV_PROXY`).
- `agentbox assertion FILE` installs or renews a runtime assertion by overwriting it in place (a
  moved file is never seen through the single-file mount) and confirms the workspace reads it.
- The release publishes to npm by trusted publishing (repository variable
  `NPM_TRUSTED_PUBLISHING=true`) or with an `NPM_TOKEN` secret, which now reaches only the publish step.
- Release images are built, scanned, and signed for `linux/amd64` and `linux/arm64`.
- `AGENTGATE_KMS_KEY_ID` and `AGENTBOX_ENTERPRISE=1` in a project's `.env` select the KMS and
  enterprise Compose files for every `agentbox` command and for the generated `.devcontainer`.
- Prebuilt broker images: `compose.broker-image.yaml` and `compose.broker-image.enterprise.yaml`
  run a verified digest for every broker service instead of building; `AGENTGATE_IMAGE` and
  `AGENTGATE_WORKSPACE_IMAGE` in `.env` select the overrides for the `agentbox` command.

### Changed
- README restructured into a front page plus topic docs under `docs/`.
- Example config placeholder is `YOUR-ORG/YOUR-REPO` (a valid owner name); invalid repository
  names are reported by name.
- Enterprise services (audit forwarder, approval UI, issuer, hosted agents, oauth2-proxy) live in
  `compose.enterprise.yaml`; the core stack needs only its own settings.

### Fixed
- Push quarantine is removed before the client hears the verdict.
- `docker compose exec` and IDE shells receive the model-gateway token.
- Assertions with duplicate or case-variant JSON members are rejected.
- Issuer state directory exists in the image; agentd starts after the issuer.
- CI Docker job used a different broker image name than the smoke script.

### Security
- Apache 2.0 license; open-core statement. No external security review yet; see
  `docs/security-review-plan.md`.

## 0.1.0

Initial prototype: Git smart-HTTP broker for GitHub with policy, approvals, audit chain,
isolated Docker workspace, egress proxy, model gateway, content scanning, and control-plane
bundles.
