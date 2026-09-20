# AgentBox threat model

## Protected assets

- GitHub App private key and installation tokens
- Model API provider keys and entitlement source tokens (Jira, GitHub org)
- Repository write authority delegated to an agent
- The delegation bound: an agent never acting with more authority than its issuing developer
- Runtime identity, issuer keys, and policy configuration
- Approval decisions and audit history

## Delegation model

An agent runtime acts under an identity delegated from a human developer. The security claim is
that the agent's authority is **at most the developer's, and usually less**, and that the agent
is always distinguishable from the developer.

How the bound holds today:

- **Entitlements are keyed to the human, not the agent.** The `static` directory export is looked
  up by the assertion's `human` email; `githubTeams` by its `ghLogin`; `jira` elevation counts
  only when the ticket's assignee equals `human`. There is no path by which an agent gains a
  team, group, or elevation the developer does not hold in those sources.
- **Default deny narrows from there.** A rule with `requires` only participates as `allow` when
  every requirement is *satisfied*; a source outage makes requirements *unknown*, which cannot
  satisfy an allow rule but still lets `deny` and `approval` rules apply. Repository, ref pattern,
  and operation scopes, plus the assertion's `mode` and single `task`, cut the grant below the
  developer's.
- **Separation is structural.** The assertion's `jti` and `sub` (runtime ID) appear in every
  decision and approval record; approvals bind to the `jti`; the developer named in `human` cannot
  approve that runtime's requests; revocation is by `jti` or runtime ID and never touches a human
  credential.

Where the bound is weaker than the claim (also tracked in ROADMAP Milestone 2):

- **The bound is checked at issuance and, when enabled, at verification.** The issuing service
  refuses a `team` the developer does not hold in the configured directory export or live Okta
  or Entra groups, and always sets `human` to the authenticated login. With
  `identity.delegation: "enforce"` the broker also refuses, before any route, an assertion whose
  `team` is not among the teams or groups its own sources report for `human`, and fails closed
  when a source is down. Without it (the default), an assertion minted by the script, or by an
  issuer with no directory configured, carries whatever its operator typed, and a wrong `team`
  claim merely fails `requires`. `application` and `mode` are not checked against sources in
  either place. An operator who writes an `allow` rule without `requires` has opted out of the
  bound for that rule.
- **The issuer is trusted for the developer's identity.** With the issuing service, "developer X
  delegated to runtime Y" rests on the identity provider's login via oauth2-proxy and on the
  issuer's Ed25519 key, which lives on the issuer host as a file (KMS-backed Ed25519 is not
  offered by AWS KMS; an HSM-backed issuer key is future work). Whoever can run
  `issue-runtime.js` with that key can still mint any identity; keep the script's key separate
  from the service's, or off developer-reachable hosts entirely. Issuer administrators see and
  can revoke every runtime.
- **Revocation propagates within the poll interval.** The issuer writes `revocations.json`;
  agentd re-reads it when its modification time changes (polled every 5 seconds by default,
  `AGENTGATE_REVOCATIONS_POLL_MS`), on SIGHUP, or takes signed bundles from the control plane.
  A revoked assertion is therefore still accepted for up to one poll interval plus any
  verifier cache hit (revocation is re-checked on every request, so the cache does not extend
  it). A malformed rewrite keeps the previous list in force.
- **Directory data can be stale.** A `static` export written by a scheduled job, the 5-minute
  positive entitlement cache, and Entra or Okta group lookups that the sources cache mean a
  developer's offboarding or team removal can take effect late. Revoke the runtime explicitly
  when the developer's access changes. The Okta and Entra sources hold an API credential with
  read-only directory scope; a compromised broker can enumerate group membership of any user
  it names, nothing more.
- **Egress and model traffic are attributed to the runtime, but not bound to it.** Given the
  issuer keys, the egress proxy (assertion as proxy credentials) and the model gateway
  (assertion as a request header) verify the assertion a workspace sends and keep quotas and
  budgets per runtime, but neither can check the token binding, so a workspace that obtains
  another runtime's assertion can spend that runtime's egress quota and model budget under its
  name (never its Git authority). Workspaces that send no assertion are attributed by source
  address. The delegation bound does not extend to what those services allow, only to the
  broker's own decisions.

## Trust boundaries

The agent, its commands, repository contents, package scripts, prompts, and issue
text are untrusted. The broker process, host operator, configuration, state
directory, private key, and container/network administrator are trusted.

In static mode the daemon is dedicated to **one runtime identity** loaded from
host-controlled configuration; every client presenting the per-broker bearer token
receives that identity, so deploy one broker per isolated workspace. In fleet mode
(`AGENTGATE_CLIENT_AUTH=assertion`) the daemon holds no workspace token: a request
is accepted only when its bearer token hashes to the `cnf` binding inside a valid,
unrevoked assertion, so the issuer, not the broker, decides which token is which
runtime, and one broker can serve many workspaces. A workspace can still read its
own token and assertion, so the pair proves which workspace is calling but cannot
keep a secret from the agent; a stolen pair works until expiry or revocation, and
one workspace's pair never authenticates as another runtime. Requests cannot choose
their identity in either mode. Do not publish the listener to a shared or public
network. Localhost development alone does not isolate an agent running under the
broker's OS user.

## IDE attachment

`.devcontainer/devcontainer.json` attaches VS Code, Cursor, or Windsurf to the Compose
`workspace` service over `docker exec` (docs/workspace.md "Using an IDE with the workspace"). What that
does and does not change:

- **Agent tools are denied the secret files, but not prevented.** The Claude Code profile's
  managed settings deny the agent's Read and Bash tools the token, assertion, and gateway token
  paths and environment dumps. Any shell the agent runs can still read them, so this changes
  effort and visibility, not the boundary.
- **The editor's server is workspace code.** It runs as `node` inside the container with the
  same reach as the agent: it can read the workspace client token, the model-gateway token, and
  the runtime assertion, and so can every extension it installs. Nothing it does can exceed the
  workspace's own authority, because that authority is defined by the broker, the egress proxy,
  and the Compose service, not by the editor. The devcontainer sets no image, mounts, ports,
  capabilities, or lifecycle hooks; `test/devcontainer.test.js` enforces that.
- **The developer's machine is trusted, as it already was.** Whoever can run `docker exec`
  against the workspace is the container administrator. The devcontainer adds no new principal.
- **Editor credential injection is disabled, and denied anyway.** The devcontainer turns off the
  GitHub Authentication extension's Git credential provider and terminal askpass, so the
  developer's laptop GitHub login is never forwarded into container Git operations. Even if a
  user re-enables it, direct GitHub access from the workspace is denied by the egress proxy and
  external DNS is closed, so a forwarded token has nowhere to go.
- **The IDE's own model traffic is outside every control here.** Cursor, Copilot, and Windsurf
  send prompts from the client on the developer's machine to their vendor. The model gateway,
  its budgets, and its path allowlist never see that traffic; neither does the audit log. Prompt
  injection through repository content reaches the vendor model on the same path. Treat the IDE
  vendor as a trusted party for prompt confidentiality, exactly as the enterprise's existing IDE
  agreement already does.
- **Allowlisting IDE hosts widens egress.** `examples/egress.ide.json` admits the editor's server
  download, marketplace, and Open VSX hosts. Marketplaces accept uploads only with publisher
  credentials the workspace does not hold, but they are third-party code sources: an extension
  the developer installs runs with the agent's reach. Byte quotas still apply per rule.
- **Hosted agents are governed at merge, not at the credential.** Cursor background agents,
  the Copilot coding agent, and similar run with the vendor's own GitHub App credential and
  never touch the workspace or the broker. With `hostedAgents` configured, the `hosted-agents`
  service evaluates policy for their pull requests and a branch ruleset requires its check run
  before merge; their pushes are audited. See "Hosted agents" below for what that trusts.
- **Laptop mode is not a boundary.** Running `agentd` and workspace setup directly on the
  developer's machine brokers Git for whatever editor is in use, but the agent runs as the
  developer's OS user and can read the client token, the admin socket, and every other
  credential there, and can reach GitHub directly with any of them. It demonstrates policy and
  audit; it enforces nothing against a hostile agent.

## GitLab credential

With `AGENTGATE_PROVIDER=gitlab` the root credential is an OAuth refresh token (plus client id
and secret) held only by agentd. Access tokens are minted at the configured origin, live two
hours in memory, and the rotated refresh token is written back atomically to an owner-only file
that the broker alone can write. The token is a user-scoped credential and cannot be narrowed
per project or operation the way GitHub App tokens are: a broker bug that reached an
unconfigured project would succeed upstream. The mitigations are that project ids and paths
come only from validated configuration, policy is default deny, and the OAuth user must be a
dedicated bot with Developer role on the configured projects only. Revoke the OAuth application
to end the credential's life; deleting the file is not enough. The GitLab host must be added to
the egress deny list. `docs/providers/gitlab.md` section 8 has the full delta.

## Hosted agents

The `hosted-agents` service (`enterprise/src/hosted-agents.js`, enterprise/docs/hosted-agents.md) governs vendor-hosted
agents through GitHub itself, so its guarantees are GitHub's.

- **Trusts GitHub's webhook signature and delivery.** Events are accepted only with a valid
  `X-Hub-Signature-256` over the exact body and a fresh delivery id. A leaked webhook secret lets
  an attacker forge events: at worst a forged `pull_request` creates a pending approval or posts
  a failing check, never a success without policy saying so, and a forged push only writes an
  audit record. Rotate the secret on the App and in the secret file together.
- **Trusts the ruleset.** The check run is decorative unless every protected branch's ruleset
  requires it and no GitHub App is a bypass actor. Startup and hourly verification fail closed on
  both conditions; a hosted push that lands on a protected branch is audited as
  `hosted-push-unexpected` and logged as an error because it means the ruleset is wrong.
- **The human is best-effort.** Nothing signed says who asked the vendor's agent to work. The
  human is derived from the pull request (assignee, trailer, linked issue) and every record says
  how (`humanSource`). Self-approval rejection uses that derived human; a hosted run whose human
  is `unknown` can only be approved by someone else, which is the safe direction.
- **A compromised `hosted-agents` process** holds an App token with `checks: write` and
  `pull_requests: read`, the webhook secret, and the approval-web admin secret. It can post any
  check conclusion on any repository the App is installed on and create hosted approvals; it
  cannot mint contents tokens, read the workspace, approve anything, or alter the broker's
  audit chain (broker state is mounted read-only; it has its own chain).
- **Latency.** A reviewer's decision reaches the check within one poll interval (default 10 s).
  Until then the pull request is unmergeable, never mergeable.

## GitHub App signing key

With `GITHUB_PRIVATE_KEY_PATH` the RSA key is read by agentd alone from a file-backed secret.
With `AGENTGATE_KMS_KEY_ID` the key never exists on the broker host: agentd sends each JWT
signing input to AWS KMS over SigV4-signed HTTPS using credentials from the container
credential endpoint, STS web identity, or static keys, and receives only the signature. A
compromised broker can therefore sign App JWTs while it runs (it holds `kms:Sign`) but cannot
exfiltrate the key, and revoking the role's grant ends its ability instantly. Credentials and
KMS responses are never logged. The signer refuses to start with both a key file and a KMS
key configured. `AGENTGATE_SIGN_COMMAND` delegates the same operation to any program for other
HSMs and inherits that program's credential handling.

## Implemented controls

1. The GitHub adapter holds the key and tokens in the daemon and adds authentication
   only to fixed GitHub HTTPS endpoints. Redirects are rejected.
2. Tokens are requested for one numeric repository ID and read/write Contents
   permission. Client authorization headers are not forwarded.
3. Repository reads and every pushed ref are checked. Unknown resources and
   unmatched actions are denied; deny overrides approval and allow.
4. All pushed refs are checked before any receive-pack body is forwarded. Malformed
   packets and unsupported push extensions fail closed.
5. Approval binds repository, all refs and old/new object IDs, runtime context, and
   configuration digest. It expires after 15 minutes and is durably consumed once
   before an upstream attempt. Denied refs cannot be approved around policy.
6. Approval administration uses an owner-only Unix socket inside the owner-only
   state directory, separate from the workspace HTTP listener. CLI (`local:`) reviews
   are attributed to an unverified name typed by whoever can reach the socket.
   `oidc:` reviews are accepted on that socket only when HMAC-SHA256-signed (±60 s
   timestamp, constant-time compare) with the approval-web admin secret, which only
   agentd and approval-web hold; agentd records the verified source (`local`/`oidc`)
   on each review and audit record, and rules can require `reviewerSources: ["oidc"]`.
   Self-approval checks strip scheme, case, and email `+tag`, and treat
   `local:<name>` as the human when `<name>` is the local part of an email-form
   `runtime.human`.
7. Audit append failure prevents forwarding. State and audit files have owner-only
   permissions. The state directory permits one daemon process at a time.
8. Request sizes, concurrency, HTTP headers, and upstream waits are bounded.
   Browser-origin requests and unexpected HTTP Host values are rejected. The
   per-client token-bucket rate limit runs before the Host/Origin check and
   authentication (`/healthz` stays unlimited and unauthenticated), so a flood
   of disallowed-origin or unauthenticated requests is throttled rather than
   given unlimited rejection handling. `CLIENT_NOT_ALLOWED`, `UNAUTHENTICATED`,
   and `RATE_LIMITED` rejections are never written as a per-request audit
   record; they are tallied in memory and flushed as at most one `rejections`
   summary record per code per 60-second window (and on shutdown), so a client
   cannot force unbounded fsync'd audit writes just by sending disallowed or
   unauthenticated traffic.
9. The Compose example attaches the workspace only to an internal Docker network,
   keeps broker state and secrets out of its mounts, and drops container capabilities.
10. PR/CI access uses an allowlist of methods and paths, configured repository
    identities, and separate API policies in addition to repository read access.
    API tokens request only Pull requests or Actions permissions, except merges
    (Contents: write). Response fields
    are projected explicitly; nested repository objects and temporary clone tokens
    are never returned. Upstream error bodies and headers are not forwarded.
11. PR creation approval binds the exact normalized request parameters, runtime,
    and policy. Grants use the same durable consumption mechanism as Git pushes.
    Fork heads must name a configured `forkOf` fork and match a `headRepository`
    rule. Branch commits can change before PR creation, so this approval does not
    attest the PR's code or pin its head SHA.
12. PR merges (`github.pr.merge`) are never allowed without approval; config
    validation rejects `allow`. With a read-only token, the broker first checks
    that the PR is open, not a draft, and that its head equals the SHA the agent
    submitted. Policy is then decided on the PR's real base branch, its fork head
    repository, and an allowed merge method. The approval binds the PR number,
    head SHA, base, merge method, head repository, runtime, and policy. None of
    these checks consumes a grant. GitHub's `sha` parameter pins the head at
    merge time, and immediately before the merge PUT the broker re-reads the PR
    and aborts (`409 BASE_CHANGED` or `HEAD_MOVED`, audited, merge endpoint not
    called) if the base branch or head SHA no longer matches the approval. The
    grant is already consumed by then, so an abort needs a new approval. Residual
    risk: only the milliseconds between that re-read and the PUT remain, in
    which a base-branch edit could still race the merge. The agent cannot supply a commit title or
    message, and GitHub's response body is never relayed. The PR title is shown to
    reviewers but excluded from the approval key; it is author-controlled and
    escaped wherever it is displayed. Residual risk: a reviewer approves a SHA,
    not a diff, so they must inspect that commit on GitHub. Branch protection
    remains GitHub's to enforce. Operators should use `approvals` >= 2 and
    `reviewerSources: ["oidc"]` on merge rules.

## Limits and outstanding validation

- The tests cover real local Git operations and mocked GitHub authentication.
  Container smoke tests also check developer home persistence, tool availability,
  broker access and blocked direct GitHub HTTPS on a disposable internal network.
  They do not certify live GitHub behavior. `scripts/egress-check.sh`
  (installed in the workspace image as `agentgate-egress-check`) checks direct
  HTTPS/IPv4/IPv6 egress, cloud metadata endpoints, the host gateway (SSH and
  the Docker API), plain HTTP, DNS resolution, GitHub credential leakage into
  the workspace or PID 1 environment, broker key/state mounts, private key
  material anywhere on the filesystem (a content-based scan for
  `PRIVATE KEY-----`, not a filename pattern, so a key mounted or copied under
  any name is still caught), the Docker socket, effective capabilities, and
  broker reachability. Every probe fails closed: a `curl`, `ip`, or `getent`
  exit code that means the probe itself could not run (missing binary,
  malformed invocation, unsupported protocol) is reported as `FAIL`, not
  conflated with a genuine connection refusal, and an unreadable
  `/proc/1/environ` is a `FAIL` rather than a silent pass. It exits 0 when
  isolated (including external DNS blocked and allowlisted egress working
  through the egress proxy, which must refuse non-allowlisted hosts, GitHub
  and IP literals), or 1 on any failure, including a probe that could not run
  at all. It runs on every
  `npm run test:docker` invocation and can be run against a live deployment
  host; see docs/workspace.md "Validate a deployment host".
- The admin socket is a trust boundary with two callers: the host CLI (unauthenticated,
  `local:` only) and approval-web (HMAC-authenticated, `oidc:`). A compromised approval-web
  process, or anyone who reads `AGENTGATE_APPROVAL_WEB_ADMIN_SECRET_FILE` or the
  `broker-state` socket plus that secret, can approve as any `oidc:` reviewer and satisfy
  a two-person `reviewerSources: ["oidc"]` rule alone. The OIDC identity is only as strong
  as oauth2-proxy, the proxy secret, and the isolation of the `approval` network.
- A compromised host, broker, Docker daemon, or same-UID process can bypass controls.
  Fleet mode authenticates many workspaces to one broker by assertion-bound tokens, but
  those workspaces still share the broker's egress proxy and model gateway identity. The
  broker rate-limits per source address and, in assertion mode, per runtime `jti`, so one
  workspace cannot spend a neighbour's budget, but a flood from one address still throttles
  every workspace behind it.
- Runtime identity (`identity.mode: "assertion"`) is a host-issued Ed25519 assertion,
  verified by `agentd` on every request, bound to the workspace client token by
  SHA-256, time-limited (at most 24 hours), and revocable by `jti` or runtime ID.
  Approvals are bound to the assertion's `jti`. Limits: the issuer host and its
  private key are trusted (whoever holds the key can mint any identity); the
  binding proves possession of the client token, not the integrity of the
  workload; a stolen token plus assertion pair works until expiry or revocation;
  and in static mode the identity is still the root-owned config file.
- An allowed repository write can exfiltrate workspace data. Ref policy does not
  inspect commit ancestry or distinguish force pushes. File contents are inspected
  only for repositories with `scan` configured: every commit and blob the push
  adds is checked in quarantine against a mirror for built-in secret patterns,
  blocked paths, and oversized blobs before anything is forwarded, and findings
  cannot be approved around (an approval consumed by a blocked push stays spent).
  Packs carrying objects no pushed ref reaches are refused. Scanning is
  regex-based: encoded, encrypted, or split secrets pass; commit and tag
  messages and Git LFS objects are not scanned; with secret scanning on, blobs
  over 10 MiB are blocked rather than scanned; and data can still leave in
  innocuous-looking content. Finding paths (agent-chosen file names) are echoed
  verbatim in responses and audit records. Each scanned push syncs a mirror and
  writes the request to disk, so the state volume must be sized for it. It
  reduces accidental leaks and low-effort exfiltration; it does not stop a
  determined agent. The broker
  verifies at startup that each configured `protectedBranches` entry carries
  GitHub's `deletion`, `non_fast_forward`, and `pull_request` rules, and
  refuses to start otherwise; provider-side branch protections remain
  responsible for enforcement itself. The hourly recheck only logs an
  `AgentBox WARNING` on drift — it does not stop the broker or block
  requests, so fail-closed enforcement of this control happens solely at
  startup, and an operator must act on the warning to restore fail-closed
  behavior after GitHub-side rules change.
- An allowed read grants repository-level visibility; there is no branch-level
  read filtering. Git receive-pack advertisements use a write-scoped token, but
  actual ref updates still require a separate authorization decision.
- For repositories without `scan`, push packfiles are opaque after parsing the ref
  command list; upstream Git checks integrity and connectivity. For repositories with
  `scan`, the pack is indexed in quarantine against the mirror (`index-pack --strict`),
  trailing data after the pack is refused, and objects no pushed ref reaches are refused. Signed pushes (push certificates) and SHA-256 pushes
  are rejected because GitHub itself does not support either, not because the
  broker imposes an additional limit. Compressed requests and pushes over the body
  limit are rejected, and so are non-ASCII ref names unless the repository sets
  `allowUnicodeRefs: true` (see below). Shallow pushes are accepted. Push
  options are accepted only when listed in a repository's `allowedPushOptions`
  (exact string, a bare `*` allowing any value, or `prefix*`; `*` may only be a
  standalone entry or the single final character of a pattern; default: none, so
  every option is denied). Option values are never stored anywhere, not just
  never echoed: the approval context (which is written into the `approval.review`
  audit record, `approvals.json`, and the admin `GET /approvals` response read by
  the CLI and approval-web) holds only `pushOptionsCount` and a `pushOptionsDigest`
  (SHA-256 of the sorted values), and a denied option is audited only as the rule
  name `push-option-not-allowed`. The digest is still bound into the approval's
  fingerprint, so approving one set of options does not authorize a retry with a
  different set (or no options at all). The digest is an unkeyed SHA-256, so anyone
  who can read the forwarded audit stream or approvals can confirm guesses of short
  or predictable option values by hashing candidates; it hides values from casual
  disclosure, not from a guessing attacker.
- Shallow push lines (`shallow <oid>`) are accepted but are not bound into push
  approval fingerprints: an approval covers the ref updates, push options digest,
  runtime, and policy, not the shallow boundary the client declared.
- For repositories with `allowUnicodeRefs: true`, the broker requires NFC and rejects
  control, spacing, bidirectional, invisible, and known lookalike characters, but it does
  not detect cross-script homoglyphs (for example a Cyrillic `а` in place of a Latin
  `a`). Reviewer displays (approval page and Slack) show escaped code points for
  every non-ASCII ref, which mitigates but does not eliminate spoofing; reviewers must
  read the escaped form.
- Audit records form a SHA-256 hash chain (`seq`, `prevHash`, `hash`) that
  `npm run audit:verify` checks. A chain alone cannot stop a host that rewrites
  the entire log. Tamper evidence therefore depends on forwarding records
  off-host (Task 7) and comparing heads. It records transport outcomes, not
  parsed per-ref Git outcomes; an upstream mutation can occur even if later
  audit or response delivery fails.
- State and audit storage have no quotas or automatic retention. A reachable
  malicious client can consume disk or availability.
- Workspace egress: the workspace network is internal, external DNS is closed
  (`dns: ["127.0.0.1"]`), and all other egress goes through the allowlisting
  CONNECT proxy (`src/egress-proxy.js`). It denies GitHub (broker only) and IP
  literals, resolves names itself, refuses any name with a private, loopback,
  link-local, CGNAT, reserved, or embedded-IPv4 form of those among its
  addresses, and connects only to the vetted addresses (no DNS rebinding).
  Per-client, per-host byte quotas, idle timeouts, and tunnel caps bound
  volume. Remaining exfiltration channels are named: allowlisted hosts that
  accept user content (for example package publish endpoints; registries are
  allowed for reads, and publishing needs credentials the workspace does not
  have, but any allowlisted host that accepts anonymous uploads is a channel),
  TLS content to allowlisted hosts (the proxy does not inspect it), and
  allowed Git pushes and PR/API writes through the broker.
- Tokens expire at the provider and are cached in memory. Local policy changes take
  effect on SIGHUP reload; control-plane policy on the next accepted bundle.
  Assertions are revocable through signed control-plane revocation lists or, without
  a control plane, the local `AGENTGATE_REVOCATIONS_FILE` (re-read when it changes, and on SIGHUP). Without
  either, an assertion is valid until it expires.
- PR creation may trigger provider-side notifications and automation. App permissions
  and explicit API policy govern this separately from pushing commits. `allowWorkflowWrites`
  is a repository-level opt-in for Workflows: write on Git write tokens; it can permit
  changes to CI definitions and should match the authority intended for that runtime.
- The persisted workspace home is untrusted workspace data. Git URL rewrites and
  CLI validation are conveniences, not enforcement boundaries: an agent may change
  its own configuration. Network separation and broker policy enforce access.
- Git LFS transfers go through the broker. The batch response's storage hrefs and headers are
  kept server-side behind single-use, 15-minute, 256-bit transfer IDs bound to repository and
  operation; the route still requires workspace authentication, re-checks the live policy
  (repository configured, `git.read`, and `git.lfs.upload` for uploads) and consumes the ID even
  when denied. IDs, hrefs, query strings, and storage headers are never logged or audited (only oid
  and size). Storage hosts must be in `AGENTGATE_LFS_HOSTS`; storage requests carry no GitHub or
  client credentials and do not follow redirects, and storage response headers are not copied to
  the client. Every byte is counted and SHA-256 hashed against the requested oid/size, and the final
  byte is withheld until the object verifies: a mismatched download is cut off before completion,
  and a mismatched upload never delivers its last byte (so a presigned PUT with a declared
  `content-length` cannot complete) and returns `LFS_HASH_MISMATCH`. If a storage service accepted a
  short body anyway, the broker still returns 400 and skips verify, so GitHub does not link the
  object. A `verify` action is called only if GitHub's batch response supplied one, only for an
  https `github.com` LFS endpoint of the same repository (otherwise the batch fails with
  `LFS_UNTRUSTED_HOST`), with a Contents write token; tokens never go to storage hosts. Uploads
  require an exact `content-length` (chunked uploads are rejected) and use the body inactivity
  timeout; each transfer holds a slot in the separate LFS transfer pool (`AGENTGATE_LFS_MAX_TRANSFERS`,
  default 8) for up to 30 minutes, so LFS traffic cannot exhaust the main request pool.
- The `gh` client is installed but does not gain general provider access.
  No arbitrary (non-allowlisted) outbound proxy, MCP actions, PR approvals or
  change-request reviews, unapproved PR merges, or cloud/SaaS adapters are implemented yet.
- Scan mirrors hold full repository contents. They live under `AGENTGATE_MIRROR_DIR`; Compose
  puts them on the `broker-mirrors` volume mounted only into agentd, never on `broker-state`
  (which the audit forwarder and approval UI mount read-only).

## Model API gateway

- Provider keys exist only in the `model-gateway` container (owner-only files, re-read per
  request); the workspace never mounts them. The gateway strips client credentials, injects the
  key only for anchored allowlisted paths on fixed https upstreams, refuses redirects, and drops
  response headers that echo the key.
- The gateway authenticates the workspace with its own client token, distinct from the agentd
  workspace token, so a compromised gateway cannot call agentd. The workspace can read that token,
  so it proves "a workspace" and nothing more; every workspace sharing it looks the same.
- Budgets are per source address plus an optional global bucket and, with `identity`
  configured, per runtime assertion `jti`. The gateway verifies the assertion's signature,
  audience, lifetime, and claims but not its token binding, so runtime attribution there is
  as strong as the workspace's custody of its assertion file, not as strong as the broker's.
  Workspaces that send no assertion share the address bucket.
- A compromised gateway holds the provider keys and can spend or leak them. Prompts and responses
  pass through it in clear text (plain HTTP on the internal network) and are an exfiltration
  channel to the provider that volume budgets and detection D7 only bound, not close.

## Control plane

- Brokers authenticate to the control plane with per-broker bearer tokens; the control plane
  stores only SHA-256 hashes and compares in constant time. A separate admin token (hash only)
  publishes documents, reads inventory, clears a target's document, and resets rollback flags.
  Whoever holds the admin token can withhold or replace (validly signed) documents and can clear
  rollback flags, so it must be held like a deployment credential.
- The control plane never holds signing keys. Brokers verify every document's Ed25519 signature,
  kind, lifetime, and addressee, and keep a persisted version high-water mark. A compromised
  control plane without the signing key therefore cannot forge policy or revocations and cannot
  roll a broker back to an older document. It can withhold updates: brokers then keep the last
  good policy until it expires and fail closed (`503 POLICY_EXPIRED`, and `503
  REVOCATIONS_EXPIRED` for assertion mode once the revocation list expires).
- Documents are stored per addressed target (broker ID or `*`) with per-target version checks, so
  a document for one broker cannot shadow another's. A mistakenly published huge version can be
  cleared per target by the admin; brokers that already accepted it keep their own high-water mark.
- Central approvals add one key the control plane holds: the Ed25519 key that signs `reviews`
  documents. Whoever controls that key, or the control plane process, can approve or deny any
  approval that any broker has published, exactly as a reviewer in the UI could, and nothing
  more: it cannot mint runtime identities, read provider keys or tokens, change policy, or roll a
  broker back. Every broker-side check still applies to a central review: the approval's policy
  hash, the self-approval rule against the delegating human, duplicate reviewers, the rule's
  `reviewerSources`, and expiry. A rule that should never be satisfiable from the control plane
  says `reviewerSources: ["oidc"]`. Published approvals carry only what the approval UI displays
  (repository, action, runtime identity fields, refs and object IDs, request payloads); tokens,
  assertions, and entitlement envelopes never leave the broker. The reviewer's identity is the
  OIDC email oauth2-proxy verified in front of the control plane; the control plane cannot check
  that identity against a broker's directory, so a compromised control plane can attribute a
  decision to any email in the allowed domains. Keep the reviews key separate from the
  policy-signing key so a leaked reviews key never becomes a policy key.
- Audit anchoring: each heartbeat reports the broker's audit-chain head. A lower sequence, or the
  same sequence with a different hash, is flagged `rollbackDetected` (sticky) and the recorded
  high-water mark is kept. This detects a broker host that truncates or rewrites its log after
  reporting; it cannot detect tampering before the first heartbeat, between heartbeats that are
  then consistently extended, or by a host that stops sending heartbeats (visible only as
  `stale`). An admin reset re-baselines on the next heartbeat and should follow an investigation.

## Detections

- `scripts/detect.js` runs over the merged audit, egress-proxy, and model-gateway streams.
  Windowed detections alert once per burst and re-arm after the window drains below the
  threshold.
- Attribution limits: broker decisions carry the verified runtime; approval reviews carry it in
  their context; egress and model-gateway records carry only the client source address (no
  runtime assertion reaches those services, and workspaces behind one address are
  indistinguishable). Pre-authentication rejections (including invalid assertions) reach the audit
  stream only as identity-free per-code summaries flushed at most once per 60 seconds, so D6 is
  broker-wide and can lag by a window. Detections are heuristics over logs an attacker who controls
  the broker host could suppress; they rely on off-host forwarding.

The model is never the final authorization authority. Deterministic policy and
provider-native permissions remain the enforcement boundary.

## Review history

Scope for external reviews: `docs/security-review-scope.md`. Add a row after each engagement and link the report. Before external production use, open a tracking issue that blocks the release: an engagement against objectives O1–O13 has been completed, and every High or Critical finding has been fixed and retested. The next engagement should add an objective for the delegation model above: obtain, as a runtime, any team, group, elevation, or action that the assertion's `human` does not hold in the configured entitlement sources.

| Date | Reviewer | Scope | Commit | Result |
|------|----------|-------|--------|--------|
