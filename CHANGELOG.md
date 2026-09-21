# Changelog

All notable changes to AgentBox. Format follows Keep a Changelog; versions follow semver once
1.0 is tagged. Dates are UTC.

## Unreleased

## 0.2.2 - 2026-09-21

### Fixed
- `agentbox demo` failed from the installed package with `ERR_MODULE_NOT_FOUND`: it imported its
  harness from `test/`, which the package deliberately does not ship. The harness now lives in
  `scripts/support/fixture.js`, which does ship, and the package test runs the demo from an
  installed copy so this cannot pass unnoticed again. The demo is the first thing a new user runs.

## 0.2.1 - 2026-09-21

### Fixed
- The Windows single-file executable was never built. `npx` is `npx.cmd` there, which cannot be
  spawned without a shell, so the release failed before `postject` ran and took the macOS
  executable and the release assets down with it. The build now runs npx's own JavaScript entry
  point with the node binary, on every platform and without a shell. 0.2.0 shipped on npm and as
  container images; this release adds the executables, the Debian package, and the manifests.

### Changed
- CI builds and runs the single-file executable on Linux, macOS, and Windows, so a
  platform-specific break in that build surfaces on the change that causes it rather than at a
  release. One platform's failure no longer cancels the others.
- A release re-run skips the npm publish when the version is already on the registry, instead of
  failing the whole run.

## 0.2.0 - 2026-09-19

AgentBox is open core from this release. This changelog covers the open-source edition; entries
marked *commercial edition* are features of the commercial edition, listed so the history is
complete. Asking for one of them here fails with a message naming it, never silently.

### Added
- Product renamed to AgentBox (daemon `agentd`, CLI `agentgate`, and `AGENTGATE_*` kept).
- Dev Container attach for VS Code, Cursor, and Windsurf; IDE egress allowlist; Claude Code
  workspace profile with managed deny settings; `npm run bootstrap`; onboarding runbook.
- Fleet mode: one broker serves many workspaces by assertion-bound tokens
  (`AGENTGATE_CLIENT_AUTH=assertion`); per-runtime rate limits.
- `agentgate fingerprint`; `--client-token-sha256` for the issuing script. Issuing service with
  identity-provider login, dashboard, revocation, and runtime inventory: *commercial edition*.
- Delegation bound at issuance (directory export) and at verification (`identity.delegation`).
- Entitlement sources: a static directory export and GitHub team membership. Okta groups, Entra ID
  groups (Graph), and Jira and ServiceNow elevation: *commercial edition*.
- Built-in AWS KMS signing with SigV4 and Pod Identity/IRSA credentials.
- Runtime attribution and budgets at the model gateway (request header) and egress proxy
  (proxy credentials).
- Revocation file polling (`AGENTGATE_REVOCATIONS_POLL_MS`).
- GitLab provider: Git, merge requests, pipelines, job logs, protected-branch verification.
- Hosted-agent coverage (webhook service and required check run), and cross-broker central
  approvals at the control plane with signed review documents: *commercial edition*.
- `npm run test:fleet`, Compose split into a core file and layered overrides, prebuilt-image override,
  security policy, contribution rules, security review plan.
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
- `AGENTGATE_KMS_KEY_ID` in a project's `.env` selects the KMS Compose file for every `agentbox`
  command and for the generated `.devcontainer` (`AGENTBOX_ENTERPRISE=1` does the same for the
  commercial services).
- Prebuilt broker images: `compose.broker-image.yaml` runs a verified digest for every broker
  service instead of building; `AGENTGATE_IMAGE` and `AGENTGATE_WORKSPACE_IMAGE` in `.env` select
  the overrides for the `agentbox` command.

### Changed
- Off-host audit forwarding runs as a service from `compose.audit-forward.yaml`, selected by
  `AGENTGATE_AUDIT_SINK_URL` in the project's `.env`; it no longer needs the commercial Compose file.
- README restructured into a front page plus topic docs under `docs/`.
- Example config placeholder is `YOUR-ORG/YOUR-REPO` (a valid owner name); invalid repository
  names are reported by name.
- The audit forwarder, approval UI, issuer, hosted agents, and oauth2-proxy are layered on by a
  separate Compose file; the core stack needs only its own settings.

### Fixed
- Push quarantine is removed before the client hears the verdict.
- `docker compose exec` and IDE shells receive the model-gateway token.
- Assertions with duplicate or case-variant JSON members are rejected.
- CI Docker job used a different broker image name than the smoke script.

### Security
- Apache-2.0 license. No external security review yet; see
  `docs/security-review-plan.md`.

## 0.1.0

Initial prototype: Git smart-HTTP broker for GitHub with policy, approvals, audit chain,
isolated Docker workspace, egress proxy, model gateway, content scanning, and control-plane
bundles.
