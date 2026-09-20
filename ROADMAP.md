# Roadmap

## Where this is going

Every enterprise already has AI agents at work, and nearly all of them authenticate with a
developer's personal access token or API key pasted into a local file. The agent *is* the
developer: same scope, same audit trail, no separate off switch, and a secret sitting where any
package script or prompt-injected instruction can read it.

AgentBox's goal is to give each agent runtime an identity of its own — delegated from a
developer, governed by the enterprise's existing machinery (directory groups, team ownership,
change tickets, human approval), and never backed by a credential the agent can read.

### The delegation principle

An agent's authority is **at most the developer's, and usually less.**

- **Never more.** Entitlements resolve from the issuing human's own directory entry, provider
  login, and assigned tickets. Nothing in the system can grant an agent a team, group, or
  elevation its developer does not hold.
- **Usually less.** The identity carries a work mode (`readonly`, `build`, `operate`) and at most
  one task; policy scopes it further to a repository, ref pattern, and operation.
- **Always separate.** The agent has its own identity in every audit record, its own approvals,
  and its own revocation. Cutting it off never touches the developer's credentials.

Today this bound is *emergent*: it follows from entitlement sources being keyed to the human and
from default-deny policy. Making it an explicit, testable invariant is tracked in Milestone 2.

### Build order

Milestones are numbered in dependency order and referenced by number elsewhere (for example the
Milestone 4 adapter plan template). Status: **done**, **partial**, or **planned**.

| # | Milestone | Status |
|---|-----------|--------|
| 1 | Secretless Git runtime | done |
| 2 | Real workload identity | mostly done |
| 3 | Enterprise entitlement adapters | partial |
| 4 | Provider-native enforcement | planned |
| 5 | Controlled egress | done |
| 6 | Enterprise control plane | partial |
| 7 | Adoption surface | partial |

## Milestone 1 — Secretless Git runtime (done)

Exit criterion, met: an untrusted agent can clone/fetch/push an approved feature branch with no
GitHub credential present in its process environment or filesystem.

- [x] Git smart-HTTP broker with real local Git integration tests
- [x] GitHub App token minting adapter with mocked-provider tests; built-in AWS KMS signing
      (`AGENTGATE_KMS_KEY_ID`, SigV4, Pod Identity/IRSA credentials) and generic KMS/HSM signing
      via `AGENTGATE_SIGN_COMMAND`
- [x] Ref-level push policy with deny precedence; create/update/delete operation scoping
- [x] Durable one-time approval store, host CLI, OIDC approval web UI, Slack notifications
- [x] Multi-reviewer approvals (`approvals: N`, `reviewerSources`), self-approval and duplicate
      reviewer rejection
- [x] Hash-chained JSONL audit, rotation, `audit:verify`, off-host forwarding
- [x] Isolated Docker workspace: persistent home, URL routing, dev tools, egress check
- [x] Dev Container attach for VS Code, Cursor, and Windsurf (`.devcontainer/`), with editor
      credential injection disabled and an IDE egress allowlist
- [x] Brokered PR list/view/create/comment/review/merge and CI run/job/step/log inspection
- [x] Fork pull requests, workflow-file write opt-in, configurable push size limit
- [x] Git LFS batch/object transport with hash-verified transfers
- [x] Shallow pushes, allowlisted push options, opt-in NFC Unicode refs
- [x] Pre-forward content scanning (secrets, blocked paths, blob size) with quarantine mirror
- [x] Live GitHub App smoke test (`npm run test:live`, nightly workflow)
- [x] Rate limiting, concurrency caps, disk-low fail-closed, lock reclaim, protocol fuzzing
- [ ] Live GitHub coverage for PR/CI permission edge cases and workflow-file writes
- [x] Claude Code workspace profile (`examples/workspace-claude-code.Dockerfile`), pinned and
      gateway-routed; further tool profiles tracked in Milestone 7

Signed pushes (push certificates) and SHA-256 repositories are rejected by design because GitHub
does not support them; they are not roadmap items.

## Milestone 2 — Real workload identity (mostly done)

Replace config-file identity with a signed runtime assertion, minted outside the agent and
verified by `agentd` on every request, carrying the human delegator, agent type, runtime ID,
team/application ownership, work mode, optional task elevation, and issue/expiry time.

- [x] Ed25519 runtime assertions (`identity.mode: "assertion"`, `scripts/issue-runtime.js`),
      bound to the workspace client token, sent as `x-agentgate-runtime`, verified per request,
      used for audit records and approval contexts
- [x] Revocation by `jti` or runtime ID: local `AGENTGATE_REVOCATIONS_FILE` (re-read on SIGHUP)
      or signed control-plane bundles
- [x] `agentgate renew` and entrypoint renewal on container start
- [x] **Delegation invariant.** `identity.delegation: "enforce"` rejects at verification time
      an assertion whose `team` is not among the teams or groups the entitlement sources report
      for its `human` (403 `DELEGATION_MISMATCH`, 503 `DELEGATION_UNKNOWN` on source failure),
      audited; `audit` mode records only. `application` and `mode` are not yet checked.
- [x] Issuing service (`enterprise/src/issuer-web.js`) behind oauth2-proxy: the developer's OIDC login is the
      `human` claim, assertions bind to a token fingerprint, a dashboard lists and revokes
      runtimes, and revocations feed agentd's revocation file
- [x] Delegation bound at issuance: with a directory export configured, a developer can only
      delegate a team they hold (verification-time check on the broker still tracked below)
- [x] Per-runtime request budget on the broker (rate limit keyed by assertion `jti`)
- [x] Per-runtime identity at the model gateway: the workspace sends its assertion as
      `x-agentgate-runtime` (`ANTHROPIC_CUSTOM_HEADERS`), the gateway verifies it against the
      issuer keys, attributes each `model.request`, and budgets per runtime
- [x] Per-runtime identity at the egress proxy: the assertion travels as proxy credentials
      (`http://runtime:<assertion>@egress-proxy:3128`, sent as Proxy-Authorization by Git, curl,
      npm, pip, apt); tunnels are attributed and byte quotas kept per runtime
- [x] Multiple concurrent runtimes per broker (`AGENTGATE_CLIENT_AUTH=assertion`): each
      request's bearer must be the token its assertion is bound to; the broker holds no
      workspace token

## Milestone 3 — Enterprise entitlement adapters (partial)

Compile baseline (who the developer is) and elevation (what they are currently working on) into
one capability envelope that rules gate on with `requires`, failing closed on source errors.

Baseline sources:

- [x] Static directory export (AD/Entra groups, Backstage ownership) via `entitlements.static`
- [x] GitHub team membership via `entitlements.githubTeams` (org-scoped token, assertion `ghLogin`)
- [x] Live Entra ID group membership via Microsoft Graph (`entitlements.entra`)
- [x] Okta group membership (`entitlements.okta`)
- [ ] Backstage catalog lookups
- [ ] GitLab group membership

Elevation sources:

- [x] Jira work item (status in `allowedStatuses`, assignee equals the runtime's `human`)
- [x] ServiceNow change/incident via the Table API (`entitlements.servicenow`): allowed state
      and assignment to the runtime's human
- [ ] PagerDuty incident (same state as ServiceNow)

Envelope:

- [x] Per-request compilation, 5-minute positive cache, 30-second negative cache, SIGHUP flush
- [x] Envelope summary recorded in decision audit records and bound into approvals
- [ ] Entitlement expiry and revocation pushed from the control plane (see Milestone 6)

## Milestone 4 — Provider-native enforcement (planned)

Add providers without making MCP a requirement, preferring short-lived provider-native
credentials and policy over command interception. Every adapter follows
`docs/provider-adapter-plan-template.md` and must keep its root credential out of the workspace
(KMS signer or the provider's workload identity federation).

- [x] Provider interface and contract test (`src/providers/index.js`)
- [x] GitLab (Git, merge requests, pipelines, job traces, protected-branch verification) via an
      OAuth refresh token rotated by the broker; LFS and a live smoke test deferred
      (`docs/providers/gitlab.md`)
- [ ] AWS STS / workload identity
- [ ] Azure workload identity
- [ ] Kubernetes impersonation / scoped service accounts
- [ ] Internal HTTP APIs behind an allowlist, with the runtime identity forwarded as a header
- [x] GitHub provider-native enforcement for hosted agents: required check run driven by policy,
      ruleset verification of the requirement and of App bypass actors

## Milestone 5 — Controlled egress (done)

The workspace gets policy-based egress for package registries, docs, model APIs, and approved
enterprise endpoints. Direct privileged provider paths remain unavailable except through the
broker.

- [x] Allowlisting CONNECT egress proxy with SSRF-safe resolution, byte quotas, closed workspace
      DNS, and GitHub always denied direct
- [x] Model API access through a model gateway with its own client token, anchored path
      allowlists, and per-address plus global budgets
- [x] Runtime-attributed model budgets (`budget.maxRequestsPerHourPerRuntime`) and egress byte
      quotas (per runtime and rule when the tunnel carries an assertion)

## Milestone 6 — Enterprise control plane (partial)

- [x] Signed policy and revocation bundle distribution with persisted version high-water marks
- [x] Broker inventory, heartbeats, audit-head anchoring with rollback detection
- [x] SIEM detections D1–D7 over the forwarded audit stream, with a triage CLI
- [x] Central approvals across brokers: brokers publish pending approvals, reviewers decide in
      the control plane's UI, decisions return as signed `reviews` documents applied with every
      broker-side check (`enterprise/docs/control-plane.md`, "Central approvals")
- [ ] Entitlement expiry and revocation: push a developer's offboarding or team change to every
      broker as a revocation, rather than waiting for the 5-minute cache
- [x] Runtime inventory at the issuer (`GET /issuer/api/runtimes`, administrators): every identity, its
      status, who issued and who revoked it; cross-broker correlation is still the control plane's
- [ ] Risk analytics over the merged stream (per-runtime and per-developer views)
- [ ] Audit/forensics: cross-broker chain verification against anchored heads

## Milestone 7 — Adoption surface (partial)

The security model only matters if developers land in it by default. Every path below has to
work with whatever agent the developer already uses, with no agent-specific integration
(see Non-goals). Ordered by how many agent runs each one captures.

- [x] **Dev Container attach.** VS Code, Cursor, and Windsurf open the isolated workspace with
      *Reopen in Container*; the editor's terminal, Git, and agent tool calls are brokered
      unmodified. Editor Git credential injection is off; `examples/egress.ide.json` admits the
      IDE server and marketplace hosts.
- [ ] **Prebuilt workspace image with the IDE server baked in**, so attach works with the
      default allowlist and no marketplace egress at all.
- [x] **Claude Code workspace profile**: derived image, exact version pin, model traffic through
      the gateway, non-essential vendor traffic off, privilege posture enforced by test.
- [ ] **Further tool profiles** (Codex CLI, Aider, language toolchains) as derived-image recipes,
      each verified by the egress check, and a CI job that builds and smoke-tests every profile.
- [x] **One-command machine bootstrap** (`npm run bootstrap`): generates every per-machine
      secret and certificate the core stack needs, wires `.env`, and names the settings only the
      platform team can supply. `enterprise/compose.enterprise.yaml` keeps SIEM and OIDC settings off
      developer machines.
- [ ] **One-command trial** (`npx agentgate try`): local broker, demo repository, policy
      walkthrough, explicitly labelled as not an isolation boundary. Converts curiosity into a
      configured policy in under ten minutes; the Compose topology is the upgrade path.
- [ ] **IDE model traffic through the gateway.** Blocked on vendors: Cursor, Copilot, and
      Windsurf send prompts from the client to their own cloud. Track vendor support for a
      configurable model endpoint or an enterprise proxy setting; until then the docs and
      threat model state the gap plainly rather than paper over it.
- [x] **Hosted agent coverage** (`enterprise/src/hosted-agents.js`): Copilot coding agent, Cursor background
      agents, and any configured bot login are governed at merge through webhooks, the
      `github.pr.hosted` action, a required check run, and the existing approval store; pushes
      are audited and unexpected protected-branch pushes flagged; ruleset verification requires
      the check and refuses App bypass actors. Human attribution is best-effort (`humanSource`).
- [ ] Hosted agent attribution from the vendor's own task record (Copilot task, Cursor run) once
      vendors expose it, replacing the PR-derived human.
- [ ] **Remote development platforms.** Coder, GitHub Codespaces, Gitpod/Ona, and DevPod
      templates that stand up the broker beside the workspace, so platform teams can make
      AgentBox the default rather than an opt-in.
- [ ] **Fleet defaults.** A control-plane-distributed devcontainer and workspace image pin, so
      every developer in an org opens the same governed workspace.

## Non-goals

- Making the model the authorization authority. Deterministic policy and provider-native
  permissions are the enforcement boundary; the model is never consulted for a decision.
- Requiring MCP or any agent-specific integration. The runtime must stay useful with Cursor,
  Copilot, Claude Code, Codex, and whatever comes next, unmodified.
- Replacing provider-side protections. Branch rules, required reviews, and IAM policies remain
  the provider's to enforce; AgentBox narrows what reaches them.
