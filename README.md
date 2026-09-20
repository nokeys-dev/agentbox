# AgentBox

**Identity and access for AI agents.**

Every enterprise already has AI agents at work, and nearly all of them authenticate
with a developer's personal access token or API key pasted into a local file. The
agent *is* the developer: same scope, same audit trail, no separate off switch, and
a secret sitting where any package script or prompt-injected instruction can read it.

AgentBox gives each agent runtime an identity of its own: a signed, revocable
assertion delegated from a developer, governed by the enterprise's existing
machinery (directory groups, team membership, change tickets, human approval), and
never backed by a credential the agent can read. A trusted broker holds every
credential, decides each request, asks a human when policy says so, and records
the decision with the verified identity in a hash-chained audit log.

**The delegation principle: an agent's authority is at most the developer's, and
usually less.** Entitlements resolve from the issuing human's own groups, teams,
and tickets, so an agent can never be granted something its developer lacks. Work
mode, a single task, and repository, ref, and operation scopes then narrow it
further. Its identity, approvals, and revocation are its own; cutting it off never
touches the developer's credentials.

The broker daemon is `agentd`, the workspace command is `agentgate`, and settings
are `AGENTGATE_*`; those names predate the product name and are kept for
compatibility.

AgentBox is open source under the [Apache 2.0 license](LICENSE), open core: the
broker, workspace, policy engine, entitlement sources, issuer, gateway, proxy, and
the single-fleet control plane in this repository are and will stay open. NoKeys
sells the multi-fleet control plane (cross-broker approvals and inventory,
directory-driven revocation, analytics) and support.

## What it governs

| Access | How AgentBox handles it | Status |
| --- | --- | --- |
| GitHub over Git (clone, fetch, push, LFS) | The workspace's Git talks to the broker; the broker mints short-lived GitHub App tokens, applies default-deny policy per repository, ref, and operation, and asks for approval when a rule says so | shipped |
| Pull requests and CI | `agentgate pr` and `agentgate ci` call the broker, never GitHub; merges always need a human | shipped |
| Model APIs | A gateway on the workspace network injects the provider key, allowlists paths, and enforces budgets | shipped |
| Everything else on the network | An allowlisting CONNECT proxy is the workspace's only route out; GitHub direct is always denied | shipped |
| Who the developer is and what they are working on | Directory exports and GitHub teams compile into an envelope rules can require; Okta, Entra ID, Jira, and ServiceNow in the commercial edition | shipped |
| GitLab over Git, merge requests, pipelines | The same broker paths and CLI, with an OAuth refresh token the broker rotates in place; no LFS yet | shipped |
| Vendor-hosted agents (Copilot coding agent, Cursor background agents) | Webhooks plus a required check run: policy and human approval gate their merges, pushes are audited | commercial edition |
| AWS, Azure, Kubernetes, internal APIs | Provider-native short-lived credentials behind the same identity | roadmap |

No MCP or agent-specific integration is required. Cursor, Copilot, Claude Code,
Codex, and whatever comes next work unmodified, because the boundary is Git and
the network, not the agent.

```text
Developer ── issues signed identity ──> Agent workspace ── Git HTTP + identity ──> agentd ──> GitHub
                                             │                                       │
                                model gateway · egress proxy      entitlements · policy · approvals · audit
                                                                                     │
                                            AD/Entra · Okta · GitHub teams · Jira · ServiceNow ── approvals
```

**Status.** Pilot-ready for a platform team that reads
[THREAT_MODEL.md](THREAT_MODEL.md), which says what this does and does not
protect against. It has not had an external security review, and the control
plane is still partial. [ROADMAP.md](ROADMAP.md) lists what is shipped versus
planned.

## Editions

AgentBox is open core. This repository is the open-source edition under Apache-2.0, and it is
complete on its own: the broker, policy and approvals from the host, runtime identity, the isolated
workspace, the egress proxy, the model gateway, audit with SIEM forwarding, GitHub and GitLab, and
the `agentbox` command. It is what a developer, or a team running its own brokers, needs.

The commercial edition adds what an organisation running AgentBox across many teams needs: the
control plane (signed policy and revocation bundles, broker inventory, central approvals), the
issuing service and dashboard, the approval UI behind your single sign-on, coverage for
vendor-hosted agents, and entitlement sources backed by Okta, Entra ID, Jira, and ServiceNow. It is
the same code plus an `enterprise/` directory; paths under `enterprise/` in these docs refer to it.
A commercial setting in the open-source edition is refused by name, never silently ignored. Contact
hello@nokeys.dev.

## Five-minute start

Requires Docker with Compose, Node 22.14 or newer, and Git. There are no npm
dependencies. You need a GitHub App from your platform team (App ID and key, or a
KMS key) and a model provider key file; everything else is generated for you.

```bash
npm ci
npm run bootstrap                                   # per-machine secrets and TLS, wired into .env
# add GITHUB_APP_ID, GITHUB_PRIVATE_KEY_PATH (or KMS), ANTHROPIC_API_KEY_PATH,
# AGENTGATE_GIT_NAME, AGENTGATE_GIT_EMAIL to .env; edit config.local.json
docker compose up -d --build
docker compose exec workspace agentgate doctor       # every check must be ok
docker compose exec workspace agentgate fingerprint  # send this to whoever issues your identity
```

Then open the checkout in VS Code, Cursor, or Windsurf and choose *Reopen in
Container*. The editor's terminal, Git, and agent commands run inside the
isolated workspace; see [docs/workspace.md](docs/workspace.md#using-an-ide-with-the-workspace).

### From an installed package

The same flow without a checkout, once a release is published: `npm install -g @nokeys/agentbox`, or the
Homebrew formula, winget manifest, `.deb`, or single-file executable attached to each
[release](https://github.com/rvasqz86/agentbox/releases) (the executables need no Node).

```bash
mkdir my-agent && cd my-agent
agentbox init          # secrets, .env, config.local.json, and .devcontainer for this project
# fill in the platform-team settings as above
agentbox check         # Docker, Compose version, and every setting, reported at once
agentbox up            # runs the same check first
agentbox doctor
agentbox fingerprint   # send to whoever issues your identity
agentbox assertion ~/Downloads/runtime-assertion   # install what they send back; same command to renew
```

The project's `.env` decides which Compose files every command uses: `AGENTGATE_KMS_KEY_ID` adds
KMS signing, `AGENTBOX_ENTERPRISE=1` the enterprise services, and the image, proxy, and CA settings
their overrides (docs/workspace.md). `--kms` and `--enterprise` on `up` add them for one run.

Open the project directory in your editor and choose *Reopen in Container*. Each project directory
is its own Compose project (`COMPOSE_PROJECT_NAME` in its `.env`), so several can run side by side.
Rerun `agentbox init` after upgrading the package; it keeps existing secrets and settings, and
renews the 30-day development certificates when they have under a week left (`agentbox check`
tells you when). On Windows, run `agentbox` inside WSL 2 or from Git Bash: `init` needs `sh` and
`openssl`.

For the two-role rollout at a company (what the platform team does once, what a
developer does per machine), read [docs/onboarding.md](docs/onboarding.md).

## Run the credential-free demo

Requires Linux or macOS, Node **22.14+**, and Git. No GitHub account is needed.

```bash
npm ci
npm run check
npm test
npm run demo
```

The demo creates a temporary local Git server, clones through AgentBox, pushes
an allowed `agent/demo` branch, blocks a push to `main`, simulates approval from
the host, and retries. It removes its temporary repositories and audit files on
exit. It exercises real Git transport and policy enforcement without contacting
GitHub. It does not demonstrate container isolation or live App authentication.

`npm --prefix enterprise run demo:identity` tells the whole identity story the same way: an issuer
refuses a team the developer does not hold and then mints a runtime identity bound
to the workspace's token fingerprint, a fleet-mode broker serves the workspace
with no credential of its own, policy blocks a push to `main`, the delegating
developer cannot approve it but another human can, a dashboard revocation cuts the
workspace off, and every audit decision names the runtime and the human. The
identity-provider login is simulated with the headers oauth2-proxy would inject.

## Start here

| I want to… | Read |
| --- | --- |
| Broker a real repository | [Connect a GitHub repository](docs/github.md#connect-a-github-repository) |
| Give an agent its own identity | [Runtime identity](docs/identity.md) |
| Let developers issue identities themselves, with a login | [Issuing service](docs/identity.md#issuing-service-with-a-login) |
| Serve many workspaces from one broker | [Fleet mode](docs/identity.md#fleet-mode-one-broker-many-workspaces) |
| Gate on teams, groups, and tickets | [Entitlements](docs/entitlements.md) |
| Write rules and require approvals | [Policy and approvals](docs/policy.md#policy-and-approvals) |
| Block secrets before they reach GitHub | [Content scanning](docs/policy.md#content-scanning) |
| Run agents in an isolated container | [Isolated Docker example](docs/workspace.md#isolated-docker-example) |
| Open the workspace in Cursor, VS Code, or Windsurf | [Using an IDE with the workspace](docs/workspace.md#using-an-ide-with-the-workspace) |
| Install Claude Code or other tools in the workspace | [Workspace profiles](docs/workspace.md#workspace-profiles) |
| Sign with AWS KMS instead of a key file | [KMS signing](docs/workspace.md#signing-with-aws-kms-instead-of-a-key-file) |
| Run a fleet of brokers with signed policy | Control plane (commercial edition) |
| Ship audit records to a SIEM and alert on them | [Operations](docs/operations.md#audit-forwarding), [Detections](docs/detections.md) |
| Roll this out to developers at a company | [Onboarding](docs/onboarding.md) |
| Understand what this does not protect against | [THREAT_MODEL.md](THREAT_MODEL.md) |

## Documentation

| Page | Covers |
| --- | --- |
| [docs/github.md](docs/github.md) | Connecting a repository through a GitHub App, pull request and CI commands, merges, fork PRs, Git LFS, the live smoke test |
| [docs/providers/gitlab.md](docs/providers/gitlab.md) | GitLab: OAuth credential model, merge request and pipeline actions, protected branches, what is deferred |
| [docs/policy.md](docs/policy.md) | Policy rules, approvals from the CLI and the OIDC web UI, multi-reviewer rules, content scanning |
| [docs/identity.md](docs/identity.md) | Runtime assertions, the issuing service and dashboard, the fingerprint flow, fleet mode, renewal, revocation |
| [docs/entitlements.md](docs/entitlements.md) | Directory exports, GitHub teams, Okta, Entra ID, Jira, ServiceNow, and how rules require them |
| Control plane (commercial edition) | Signed policy and revocation bundles, broker inventory, heartbeats, audit-head anchoring |
| [docs/workspace.md](docs/workspace.md) | The Compose stack, workspace image profiles, IDE attach, image verification, the deployment-host check, the egress proxy, the model gateway, KMS signing |
| [docs/operations.md](docs/operations.md) | Environment variable reference, source map, audit forwarding, monitoring |
| [docs/onboarding.md](docs/onboarding.md) | Rolling out to a company: platform team once, developer per machine |
| [docs/detections.md](docs/detections.md) | SIEM detections over the forwarded audit stream |
| [docs/security-review-scope.md](docs/security-review-scope.md) | Scope, attacker models, and objectives for an external review |
| [docs/provider-adapter-plan-template.md](docs/provider-adapter-plan-template.md) | How a new provider (GitLab, AWS, ...) is added |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Protected assets, trust boundaries, implemented controls, limits |
| Hosted agents (commercial edition) | Governing vendor-hosted agents through webhooks and required checks |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability, scope, supported versions |
| [docs/security-review-plan.md](docs/security-review-plan.md) | How the external review gets done: firms, funding, preparation, publication |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Sign-off (DCO), no runtime dependencies, tests and documents with every change |
| [ROADMAP.md](ROADMAP.md) | Milestones and status |

## Development

```bash
npm run check        # syntax check every source, script, and test
npm test             # unit and integration tests against a local Git server
npm run test:docker  # builds the images and smoke-tests the isolated workspace
npm run test:live    # against a real GitHub App (see docs/github.md)
```

Source map, environment variables, audit forwarding, and monitoring are in
[docs/operations.md](docs/operations.md). Protocol references:
[Git smart HTTP](https://git-scm.com/docs/gitprotocol-http),
[Git receive-pack](https://git-scm.com/docs/gitprotocol-pack), and
[GitHub App authentication](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/about-authentication-with-a-github-app).
