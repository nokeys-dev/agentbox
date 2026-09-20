# Policy, approvals, and content scanning

Default-deny rules over repositories, refs, and operations; human approvals from the CLI or the OIDC web UI; and pre-forward content scanning.

Part of the [AgentBox documentation](../README.md#documentation).

## Policy and approvals

The example policy permits repository reads and writes to `refs/heads/agent/*`,
requires approval for `refs/heads/main`, and denies tags and deletions. Unmatched
actions are denied. Deny takes precedence over approval, which takes precedence
over allow. Repository reads are required for both fetch and push discovery.

Each push is inspected before forwarding. If **any** ref is denied, none of that
request is forwarded. Ref patterns support exact matches, a trailing `*` prefix
match, or `*` for all refs. An optional `operation` limits a rule to `create`,
`update`, or `delete`. List every sensitive branch in `protectedBranches`. The
broker refuses to start unless GitHub reports `deletion`, `non_fast_forward` and
`pull_request` rules on each one, because it cannot tell force pushes from
updates itself. `AGENTGATE_SKIP_RULESET_CHECK=1` is for offline demos only.

**Push options.** `git push -o <option>` is forwarded only when the option is
listed in that repository's `allowedPushOptions` (exact strings, or a
`prefix*` wildcard; up to 32 entries; default: none, so every option is
denied). A bare `*` entry allows **any** option value at all, effectively
disabling the allowlist for that repository — a `*` may only appear as a
standalone entry or as the single final character of another entry; it is
otherwise rejected as invalid configuration (`a*b`, `**`, and `*b` are not
allowed patterns). A push carrying a disallowed option is rejected with HTTP
403 `PUSH_OPTION_DENIED` before the pack is forwarded upstream. Option
*values* are free text an agent fully controls and may try to use to
exfiltrate data, so they are never stored or written anywhere: not in the
error message, a log line, the audit record, approvals.json, admin
`GET /approvals`, the approval web UI, or a Slack notification. Only a count
of options requested (`pushOptionsCount`) and a SHA-256 digest of the sorted
values (`pushOptionsDigest`) are kept, and only the count is ever rendered in
the approval web UI or a notification. The digest still binds the requested
options into the approval's fingerprint, so an approval only covers the exact
set of options that was reviewed; requesting a different set of options (or
none) always requires a new approval, even for the same ref updates. Shallow
pushes (from a `--depth`-limited clone) are accepted without any additional
configuration.

**Unicode ref names.** Ref names are ASCII-only by default. Setting
`allowUnicodeRefs: true` on a repository additionally accepts a ref name that
is NFC-normalized and contains no C0/C1 control characters, no Unicode
whitespace, no bidirectional-override or embedding characters (which could
otherwise make a ref display as something other than its actual bytes), and
no zero-width or invisible characters; a ref that fails any of those checks
is rejected even with the setting on. Ref patterns in `rules[].ref` and
`protectedBranches` stay ASCII-only regardless of this setting, so a Unicode
branch can never satisfy an exact protected-branch or rule match — it can
only match `*` or an ASCII prefix pattern such as `refs/heads/agent/*`.
A Unicode lookalike of a protected name (e.g. a Cyrillic homoglyph of `main`)
therefore always falls through to the prefix rules or the default deny,
never to the rule written for the real branch.

A blocked push returns HTTP 403. Git clients may only display the status code;
use the CLI on the trusted host to inspect the requested changes:

```bash
npm run approvals
npm run approve -- <request-id-or-at-least-8-character-prefix>
# Or reject it:
npm run deny -- <request-id-or-at-least-8-character-prefix>
```

An approval rule can require more than one distinct reviewer with `"approvals": N`
(1-5; defaults to 1). A push touching several approval-gated refs takes the
maximum `approvals` across the matching rules.

Every review carries a reviewer identity and a **source**, `local` or `oidc`,
which the broker decides and records on the review and in its `approval.review`
audit record; it is never taken from the client:

- `local:<name>` reviews come from the host CLI. `npm run approve`/`npm run deny`
  send `AGENTGATE_REVIEWER` (which must be `local:<name>`), otherwise
  `local:$(whoami)`. The name is unverified: it is whatever the caller types, so a
  `local:` reviewer is only as trustworthy as who can reach
  `.agentgate/admin.sock`, and anyone with socket access can approve as any
  `local:` name. The CLI refuses `oidc:` identities.
- `oidc:<email>` reviews come only from the [approval web UI](#approval-web-ui),
  where the email is asserted by your OIDC identity provider via oauth2-proxy.
  approval-web signs each admin-socket review with HMAC-SHA256 over
  `method\npath\nbody\ntimestamp` using the shared secret in
  `AGENTGATE_APPROVAL_WEB_ADMIN_SECRET_FILE`, mounted only into `agentd` and
  `approval-web`. agentd accepts an `oidc:` reviewer only when that signature
  verifies (constant-time) and the timestamp is within 60 seconds of its clock;
  otherwise it answers `403 REVIEWER_SOURCE_UNVERIFIED`. With no secret
  configured, agentd rejects every `oidc:` reviewer. The file must be owner-only
  (`chmod 600`), at least 32 characters, and contain no whitespace or trailing
  newline: `umask 077; openssl rand -hex 32 | tr -d '\n' > approval-web-admin-secret`.

An approval rule may restrict which sources count with
`"reviewerSources": ["oidc"]` (a nonempty subset of `local`/`oidc`/`control`, only on
`approval` rules; when several matching rules set it, only sources allowed by all
of them count). A review from any other source is rejected with
`403 REVIEWER_SOURCE_NOT_ALLOWED` and not counted. The allowed sources are bound
into the approval's context and key, so changing them creates a new approval.
The example configuration's `approvals: 2` rule on `main` uses
`reviewerSources: ["oidc"]`: without it, anyone with socket access could supply
both approvals as two made-up `local:` names. For `approvals > 1` and
self-approval prevention to be a security boundary, use
`reviewerSources: ["oidc"]` and restrict `.agentgate/admin.sock` (and the
`broker-state` volume) to the approval-web process and trusted operators.

`control` reviews come from the control plane's central approval UI (commercial
edition, `enterprise/docs/control-plane.md`, "Central approvals"): an `oidc`-verified reviewer there, whose
decision arrives at the broker as a signed `reviews` document and is applied with every check
below. They are identified as `control:<email>`.

The broker rejects a review from the push's delegating `runtime.human` as
`SELF_APPROVAL`: identities are compared without their `local:`/`oidc:` prefix,
case-insensitively, with any `+tag` removed from an email local part; in addition,
a `local:<name>` reviewer counts as the human when `<name>` equals the local part
of an email-form `runtime.human` (so `local:developer` cannot approve for
`developer@example.com`). A second review whose identity (same comparison)
already reviewed the request is rejected as `DUPLICATE_REVIEWER`, so
`oidc:dev+x@example.com` after `oidc:dev@example.com` is the same reviewer. The
web UI only ever produces `oidc:<email>` identities, so `local:alice` and
`oidc:alice@example.com` are *different* identities and would count as two
reviewers on a rule that accepts both sources; use `reviewerSources` to prevent
that. An approval reaches `approved`, and can be consumed, only once distinct
approving reviewers meet the rule's required count; any single deny closes the
request as `denied`.

Review the identity, repository, refs, and old/new object IDs, then retry the
push from the agent. A grant applies to those exact ref updates, runtime context,
and configuration. Grants expire 15 minutes after the request and are consumed
durably before forwarding, including when the upstream fails. Concurrent retries
cannot share a grant. A new commit or a configuration change needs a new approval.
Denial rejects that request; it does not create a permanent policy rule.

Set `AGENTGATE_APPROVAL_WEBHOOK_URL` (or, preferred, `AGENTGATE_APPROVAL_WEBHOOK_URL_FILE`
pointing at an owner-only file, like the other secret files) to have the broker post a
Slack-compatible message to that webhook once per new approval request — not on retries of a
request that is already pending. It must be `https://`. The URL is itself a bearer credential
(anyone who has it can post to your channel), so treat it like the client token or audit sink
token and never put it in plaintext config; it is never logged. The message includes the
approval ID, repository, action, agent/human identity, changed refs with short object IDs, the
approval count, expiry, and — when `AGENTGATE_APPROVAL_PUBLIC_URL` is set — a link to review it.
It never includes the PR body (free text an agent fully controls, so it could otherwise carry
prompt injection or exfiltrate data into the chat channel), and it escapes Slack mrkdwn
metacharacters (`&`, `<`, `>`) in every agent-controlled field it does include — the PR title,
head/base branches, refs, and the agent/human identity — so a malicious title or branch name
cannot forge an `@channel`/`@user` mention. A notifier failure (a non-2xx response, a network
error, or even a synchronous throw) is only logged; it never fails or delays the push/API
response. Leave both webhook variables unset to disable notifications.

The HTTP listener exposes Git, a small allowlist of GitHub API operations, and
`/healthz`. It does not expose arbitrary GitHub APIs or credentials. Administration uses
`.agentgate/admin.sock` with owner-only permissions. Approval state survives
restarts. Send `SIGHUP` (`docker compose kill -s HUP agentd`) to reload the
configuration. Invalid configs and new protected branches without GitHub rules
are rejected, and the previous policy keeps serving. A reload that changes the
policy invalidates outstanding approvals: pending ones are listed with
`"superseded": true` (`npm run approvals`) and shown in a separate, read-only
"Superseded" section of the web UI, and reviewing one returns
`409 APPROVAL_SUPERSEDED`; the agent retries to create a new approval. A single-writer lock
prevents two daemons from sharing state. After an unclean shutdown, the broker
reclaims its lock automatically, serializing concurrent reclaim attempts through
a short-lived `daemon.lock.reclaim` guard file, if the recorded process on the
same host has exited. A lock from a different hostname is never reclaimed unless
`AGENTGATE_FORCE_UNLOCK=1` is set after you confirm that broker has stopped.

### Hosted agents

`github.pr.hosted` rules govern pull requests opened by vendor-hosted agents (configured under
`hostedAgents`), matched on the base branch like `github.pr.merge`; `allow`, `deny`, and
`approval` map to the `agentbox/policy` check run's conclusion. Hosted-agent coverage is part of
the commercial edition (`enterprise/docs/hosted-agents.md`).

### Content scanning

A repository can opt in to scanning every push before any byte reaches GitHub:

```json
{ "name": "acme/demo", "id": 1, "installationId": 2,
  "scan": { "secrets": true, "blockedPaths": [".github/workflows/", "*.pem"], "maxBlobBytes": 5242880,
            "allowlist": [{ "rule": "aws-access-key", "path": "docs/example.md" }] } }
```

- `secrets` checks blob contents against built-in rules: `private-key`, `github-token`,
  `aws-access-key`, `anthropic-key`, `openai-key`, `slack-token`, `gcp-service-account`.
- `blockedPaths` (up to 100) blocks paths added or modified by the push. Entries are plain strings,
  never regexes. Matching is ASCII case-insensitive:
  - `*.ext` matches any file whose name ends in `.ext`, at any depth (`*.pem` blocks `a/KEY.PEM`).
  - `dir/` (trailing `/`) matches everything below `dir` at the repository root.
  - `name` (no `/`) matches that exact path and that file name at any depth (`.env` blocks
    `config/.env`, not `config/.env.example`).
  - `a/b` matches that exact path or anything below `a/b/`, not `a/bX`.
  Entries must not be empty, start with `/` or `./`, contain `..`, `.` or empty path segments
  (`a/./b`, `a//b`), or use `*` in any other way. Case folding is ASCII-only: `A`-`Z` match
  `a`-`z`, but non-ASCII letters (for example `É` and `é`) are compared exactly.
- `maxBlobBytes` blocks any new blob larger than the limit (rule `max-blob-bytes`). With `secrets`
  on, it must be at most 10 MiB (10485760), and any blob over 10 MiB is blocked even when
  `maxBlobBytes` is unset, because the secret rules cannot read it.
- `allowlist` (up to 100) exempts one rule (`blocked-path`, `max-blob-bytes`, or a secret rule id)
  at one path: that exact path or anything below it as a directory, ASCII case-insensitive, with the
  same restrictions as `blockedPaths` and no `*`. It is path-scoped: the same content at another path
  is still blocked.

Unknown keys or bad types make the config invalid. When `scan` is set, the broker syncs a bare
mirror of the repository under `AGENTGATE_MIRROR_DIR` (default `$AGENTGATE_STATE_DIR/mirrors`;
Compose uses `/var/lib/agentgate-mirrors` on the `broker-mirrors` volume, mounted only into agentd,
because mirrors hold full repository contents and `broker-state` is also mounted by the audit
forwarder and approval UI) (fetched with a read-only
installation token passed to git through its environment), writes the push into a quarantine
directory, indexes the pack against the mirror, and inspects every commit and blob the push adds,
including earlier commits, merges, and root commits. With no findings, the quarantined bytes are
forwarded; the quarantine is always deleted. Otherwise the push fails with `403 CONTENT_BLOCKED`,
and the response and audit record list each finding's `kind`, `rule`, `path`, and 12-character
`commit`. They never include the matched value. Findings cannot be approved around. If an approval
grant was consumed for the push, it stays spent. To proceed, rewrite history to remove the content,
or have an operator add a path-scoped `allowlist` entry in config. Repositories without `scan` keep
the streaming push path. If the gate has no mirror, a push to a scanned repository fails closed with
`503 SCAN_UNAVAILABLE`.

A pack that carries any object not reachable from the pushed refs (and not already in the mirror)
is refused with `403 UNSCANNABLE_OBJECT` rather than scanned, so no unreferenced data is stored
upstream.

Limits and operations:
- Only blob contents and paths are checked. Commit and tag messages, author fields, and ref names
  are not scanned. Git LFS objects are not in the pack and are not scanned.
- The rules are regexes, so encoded (for example base64), compressed, encrypted, or split secrets
  get through. Scanning reduces accidental leaks and low-effort exfiltration; it does not stop a
  determined agent.
- Finding paths are echoed verbatim in the 403 response and the audit log. A file name chosen by
  the agent can therefore appear there, but blob contents never do.
- Every scanned push first fetches the repository into its mirror, then writes the whole request
  (up to `AGENTGATE_MAX_BODY_MIB`) to disk. Size the state volume for one full clone per scanned
  repository, plus one push body per concurrent push (`AGENTGATE_MAX_CONCURRENT`). Expect extra
  latency on large repositories.
- Any approval consumed by a blocked push stays spent, so a fresh approval is needed after history
  is rewritten. The mirror is synced before a grant is consumed, so a failed sync (GitHub
  unreachable, token error) leaves the approval unspent for a retry.
- The broker shells out to `git` for mirroring and scanning. The agentd image installs Debian
  bookworm's `git` (2.39.5); the mirror and scan test suites pass on it and on git 2.48.1, and
  `npm run test:docker` fails if the agentd image ships anything older than 2.39.

## Approval web UI

`enterprise/src/approval-web.js` (`npm --prefix enterprise run approval-web`, Compose service `approval-web` in
`enterprise/compose.enterprise.yaml`) lists
pending approvals and lets reviewers approve or deny from a browser. It has no login
of its own and must only be reached through oauth2-proxy:

- It trusts `X-Forwarded-Email` only when `X-AgentBox-Proxy-Secret` matches the
  secret in `AGENTGATE_APPROVAL_PROXY_SECRET_FILE` (constant-time compare); otherwise 401.
  The email is lowercased and must match a strict ASCII pattern; the reviewer recorded
  is `oidc:<email>`. `AGENTGATE_APPROVAL_EMAIL_DOMAINS` optionally restricts domains (403).
  Configure the allowed domains in both places: oauth2-proxy's `email_domains` and
  `AGENTGATE_APPROVAL_EMAIL_DOMAINS`. Every user in an allowed domain sees all pending
  approvals, including repositories, refs, runtime identities, and PR titles and bodies.
- The proxy secret file must not contain whitespace or a trailing newline. oauth2-proxy
  sends a `fromFile` secret byte-for-byte, so approval-web refuses to start rather than
  trimming. Create it with `openssl rand -hex 32 | tr -d '\n' > approval-proxy-secret`,
  and create the cookie secret the same way (`openssl rand -hex 16 | tr -d '\n'`).
- Each form carries a CSRF token `HMAC(csrfKey, email:approvalId:action)`, so a token only
  works for that reviewer, request, and action (a deny token cannot approve). POSTs also require `application/x-www-form-urlencoded`
  and, when `AGENTGATE_APPROVAL_ORIGIN` is set (Compose requires it), an exact `Origin`.
  The CSRF key is random per process: restarting approval-web invalidates open pages;
  reload and resubmit.
- Responses carry `Content-Security-Policy: default-src 'none'`, `X-Frame-Options: DENY`,
  `no-store`, and `no-referrer`. Agent-authored text (including PR bodies, truncated to
  4000 characters) is HTML-escaped. The process never logs the proxy secret, CSRF key,
  cookies, or approval payloads.

Header injection decision: oauth2-proxy's alpha config
[`injectRequestHeaders`](https://oauth2-proxy.github.io/oauth2-proxy/configuration/alpha-config)
supports both a claim source (`email`) and a secret source (`fromFile`), and replaces any
client-supplied header of the same name (`preserveRequestValue` defaults to false), so no
extra reverse proxy (Caddy) is needed. Compose runs `quay.io/oauth2-proxy/oauth2-proxy:v7.15.4`
with `enterprise/examples/oauth2-proxy.alpha.yaml` (upstream, OIDC provider, injected headers) and
`enterprise/examples/oauth2-proxy.cfg` (email domains, cookie flags). Edit the issuer URL, client ID,
and domains, register `https://<your origin>/oauth2/callback` with your IdP, and put TLS in
front of the published port (`AGENTGATE_APPROVAL_PUBLISH_ADDR`, default loopback).

`approval-web` joins only the internal `approval` network shared with oauth2-proxy (only
oauth2-proxy also joins `approval-egress` to reach the IdP) and mounts
`broker-state` read-only: it only connects to `admin.sock`, and connecting to a Unix
socket through a read-only mount works (checked on Docker 28.4.0). It cannot write
`approvals.json`. Anyone who can reach port 7433 with the proxy secret can review as any
email, so keep the `approval` network free of other services.

approval-web also holds `AGENTGATE_APPROVAL_WEB_ADMIN_SECRET_FILE` (Compose secret
`approval_web_admin_secret`, from `AGENTGATE_APPROVAL_WEB_ADMIN_SECRET_PATH`), the key agentd
uses to accept `oidc:` reviewers (see [Policy and approvals](#policy-and-approvals)); it
refuses to start without it. A compromised approval-web process (or anyone who reads that
secret) can therefore approve as **any** `oidc:` reviewer, including enough distinct ones to
satisfy a two-person rule. Keep the secret out of the workspace and every other service, and
treat approval-web and its host as part of the approval trust boundary. Its HTTP server sets a
30 s request timeout and a 10 s headers timeout.
