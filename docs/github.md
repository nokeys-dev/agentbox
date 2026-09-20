# GitHub: repositories, pull requests, CI, LFS

How AgentBox brokers GitHub for an agent workspace: connecting a repository through a GitHub App, the pull request and CI commands, merges, fork PRs, Git LFS, and the live smoke test.

Part of the [AgentBox documentation](../README.md#documentation). For GitLab, see
[providers/gitlab.md](providers/gitlab.md): the same broker paths and workspace commands, a
different credential model.

## Connect a GitHub repository

1. Create a GitHub App with **Contents: read and write** and the automatically
   included **Metadata: read** permission. For the workspace PR/CI commands, also
   grant **Pull requests: read and write** and **Actions: read**. Install it on a
   disposable test repo. Git-only installations do not need the extra permissions.
   **Organization → Members: read** is required only for the GitHub teams
   entitlement source (see [Entitlements](entitlements.md#entitlements)).
2. Record its App ID, installation ID, and the numeric repository ID. Download
   the App private key to a location accessible only to the trusted broker.
3. Copy the example configuration:

   ```bash
   cp .env.example .env
   cp examples/config.json config.local.json
   ```

4. Edit `.env` with the App ID and absolute private key path. Edit
   `config.local.json` with your runtime identity, `OWNER/REPO`, repository ID,
   installation ID, and policy rules. Replace `YOUR-ORG/YOUR-REPO` in every rule.
   For production, set `AGENTGATE_KMS_KEY_ID` (built-in AWS KMS signing) or
   `AGENTGATE_SIGN_COMMAND` (any HSM or KMS program) instead of
   `GITHUB_PRIVATE_KEY_PATH`, so the key never exists on the broker host. Under
   Compose, use the `compose.kms.yaml` override instead of editing `compose.yaml`;
   see "Signing with AWS KMS instead of a key file" below.
5. Generate a workspace bearer token and point `AGENTGATE_CLIENT_TOKEN_FILE` at it:

   ```bash
   umask 077; openssl rand -hex 32 > ~/.agentgate-client-token
   echo "AGENTGATE_CLIENT_TOKEN_FILE=$HOME/.agentgate-client-token" >> .env
   ```

   Without `AGENTGATE_CLIENT_TOKEN_FILE`, the daemon refuses to start. The only
   override is `AGENTGATE_ALLOW_UNAUTHENTICATED=1`, which lets it run with no
   workspace bearer token at all — **local demos only**. Never set it in a shared
   or production deployment: any client that can reach the listener would act as
   the runtime identity, with no way to tell workspaces apart.

   Start the broker on the trusted host:

   ```bash
   npm start
   ```

   In another terminal:

   ```bash
   curl http://127.0.0.1:7432/healthz
   git -c credential.helper= -c http.extraHeader="Authorization: Bearer $(cat ~/.agentgate-client-token)" \
     clone http://127.0.0.1:7432/OWNER/REPO.git
   ```

6. **TLS on the workspace-to-broker hop.** The daemon serves plain HTTP only while
   `AGENTGATE_HOST` is loopback (`127.0.0.1`, `::1`, or `localhost`); listening on any other
   address requires TLS, or an explicit `AGENTGATE_ALLOW_PLAINTEXT=1` for local demos only.
   Generate a development CA and broker certificate for `127.0.0.1`, `localhost`, and `agentd`:

   ```bash
   sh scripts/make-dev-cert.sh ~/.agentgate-tls
   ```

   Set `AGENTGATE_TLS_CERT_FILE` and `AGENTGATE_TLS_KEY_FILE` on the broker to the generated
   `broker.crt`/`broker.key`, and `AGENTGATE_CA_FILE` in the workspace to `ca.crt` so Git and the
   `agentgate` CLI trust it. `AGENTGATE_URL` must then use `https://`. Production certificates
   come from your own PKI, not this development script.

The key is loaded only by `agentd`. Installation tokens are held in memory and
requested for one configured repository with read or write Contents permission.
The upstream is fixed to GitHub; redirects are rejected. The broker never offers
a token-returning endpoint.

**Local development is not an isolation boundary.** An agent running as the same
OS user can read that user's files and access the admin socket. Use a separate
runtime with trusted configuration and state outside its filesystem.

## Pull requests and CI from the workspace

After pushing a feature branch, run these commands inside its checkout:

```bash
agentgate pr list
agentgate pr view 42
agentgate pr create --title "Implement the feature" --base main --body-file description.md
agentgate pr comment 42 --body-file note.md
agentgate pr review 42 --body-file note.md
agentgate pr merge 42 --sha 0123456789abcdef0123456789abcdef01234567 --method squash
agentgate ci list --branch agent/my-feature
agentgate ci view 123456789
agentgate ci jobs 123456789
agentgate ci logs 987654321 --output job.log
```

Commands infer `OWNER/REPO` from `origin`, or accept `--repo OWNER/REPO`. Creation
uses the current branch unless `--head` is supplied. PRs are drafts by default;
`--ready` creates a ready-for-review PR. Output is JSON for both humans and agents,
except `ci logs`, which prints plain text. Lists accept `--page` and `--per-page`
(1–100); PR lists also accept `--state`. CI commands show run/job/step status and
conclusions; reruns are not implemented.

### Merging pull requests

`github.pr.merge` rules can only use `approval` or `deny`; `effect: "allow"` is a
config error, so every merge needs a human approval. A rule scopes the **base**
branch with `ref`, and `mergeMethods` (default `["squash"]`) lists the allowed
methods. Merges land code on protected branches, so use `approvals` of at least
2 and `reviewerSources: ["oidc"]` (this is recommended, not enforced):

```json
{ "id": "merge-main", "action": "github.pr.merge", "repository": "acme/demo",
  "ref": "refs/heads/main", "effect": "approval", "approvals": 2,
  "reviewerSources": ["oidc"], "mergeMethods": ["squash"] }
```

`agentgate pr merge NUMBER --sha HEAD_SHA [--method squash|merge|rebase]` needs
the full 40-character head SHA. Before any policy check, the broker reads the PR
with a read-only token. The PR must be open and not a draft, and its head must
equal `--sha`; otherwise the command fails with `PR_NOT_MERGEABLE` or
`HEAD_MOVED`. Policy is then decided on the PR's actual base branch and on its
head repository. A head in another repository must be a configured `forkOf` fork
matched by a `headRepository` rule; a head whose repository is gone is denied. A
disallowed method, base branch, draft PR, or moved head never uses up an
approval.

Each approval is bound to the repository, PR number, head SHA, base branch, merge
method, fork head repository, runtime identity, and policy. A new commit needs a
new approval. The approval page and Slack show the number, base, method, head
repository, short and full SHA, and the PR title. The title is display-only and
is **not** part of the approval key, because anyone can edit it while a request
waits. The broker sends GitHub only `{ sha, merge_method }` (never a commit title
or message from the agent), and GitHub's `sha` check refuses the merge if the
head moved after the broker's check. Immediately before the merge request, the
broker reads the PR again and aborts without merging if its base branch changed
(`409 BASE_CHANGED`) or its head moved (`409 HEAD_MOVED`). The approval is already
used up at that point, so the abort (which is audited) needs a new approval. A
failed PR read returns `404` for GitHub 403/404 and `502` otherwise. The merge token is **Contents: write** only,
which is what GitHub documents for this endpoint. A merge that changes
`.github/workflows` also needs Workflows: write, which the broker never grants
for merges, so GitHub rejects it. Branch protection, required checks, and
required reviews on GitHub still apply. A GitHub 405 (not mergeable) or 409 (head
changed) returns `409`, and a 422 returns `422`, without GitHub's response body.
The approval is used up once the merge reaches GitHub. The response is only
`{ merged, sha }`.

### Fork pull requests

To open a PR from a fork, configure the fork as its own repository with
`forkOf` naming the upstream, allow `git.read` on the fork, and add a
`github.pr.create` rule on the upstream with `headRepository`:

```json
{ "name": "agent-bot/demo", "id": 9, "installationId": 3, "forkOf": "acme/demo" }
{ "id": "fork-pr", "action": "github.pr.create", "repository": "acme/demo",
  "ref": "refs/heads/agent/*", "headRepository": "agent-bot/demo", "effect": "approval" }
```

From a checkout whose `origin` is the fork, run
`agentgate pr create --title ... --base main --upstream acme/demo`; the head is
sent as `agent-bot:<branch>`. `forkOf` must name another configured repository
with a different owner that is not itself a fork. The head must be exactly
`OWNER:BRANCH` where OWNER matches exactly one configured, readable fork of the
target (case-insensitive); anything else is rejected before policy. A rule
without `headRepository` matches same-repository heads only; `"*"` matches any
configured fork of the target. This applies to deny rules and approval rules as
well: a same-repository `github.pr.create` or `github.pr.merge` deny or approval
rule (no `headRepository`) does **not** apply to fork heads. Add fork rules
explicitly (for example a `deny` with `"headRepository": "*"`) for every
restriction that should also cover forks. Approvals bind the head repository, and the
approval page and Slack notification show it. The PR is created with the
upstream repository's installation token (`pull_requests: write`); no token is
requested for the fork, so GitHub only accepts the PR when the fork is reachable
by the same App installation.

`ci logs JOB_ID` downloads a completed job's log. GitHub answers the log request
with a redirect to its log storage; the broker follows that redirect itself,
without ever attaching the GitHub App token or any client credential to the
storage request, and only if the redirect target's host exactly matches the
Azure Blob shard family GitHub has been observed to use for logs (a bare
username/password or port in the redirect is rejected outright even when the
host matches) — any other host is rejected as `LOG_UNTRUSTED_HOST`. The log
streams to the client as plain text capped at 64 MiB; a larger log makes the
broker destroy the connection outright rather than end it cleanly, so a
truncated download is never mistaken for a short-but-complete one. `--output
FILE` writes the log to `FILE` with mode `0600` and refuses to overwrite an
existing file unless `--force` is also given; without `--output` the log goes
to stdout. If the download is interrupted (including by the size cap), the
command exits non-zero with a clear error and never writes `FILE` at all.

`pr comment` posts a conversation comment on a pull request (GitHub's issue-comments
endpoint); the broker first confirms the target number is actually a pull request and
never posts to a plain issue. `pr review` always submits a `COMMENT` review — agents
cannot approve a pull request or request changes on it through the broker; that needs a
human using GitHub directly. Neither command logs or audits the comment/review text
itself, only its length.

The example policy allows PR and CI reads and requires host approval to create a
PR from `agent/*`. Use the host approval commands above, then retry the exact
workspace command. Approval binds repository, head/base branch names, title,
body, draft status, runtime identity, and policy. It does **not** pin the head
branch's commit: GitHub creates a PR from the branch's current state. Approve Git
pushes separately when commit-specific review is required. An upstream failure
consumes the grant; inspect existing PRs before retrying after an uncertain result.

API actions default to deny and are separate from Git push authorization:

| Action | Policy scope | GitHub App permission |
| --- | --- | --- |
| `github.pr.read` | Repository; allow/deny | Pull requests: read |
| `github.pr.create` | Repository, head `ref` pattern, optional `headRepository` (forks); allow/deny/approval | Pull requests: write |
| `github.pr.comment` | Repository; allow/deny | Pull requests: write |
| `github.pr.merge` | Repository, base `ref` pattern, optional `headRepository`, `mergeMethods`; approval/deny only | Pull requests: read (pre-check), Contents: write (merge) |
| `github.actions.read` | Repository; allow/deny | Actions: read |

All API actions also require `git.read`. Tokens are minted for the individual
repository and operation, and API responses expose only selected fields. Existing
configs continue to work; add rules explicitly to enable the new commands.

To allow pushes that edit `.github/workflows`, grant the App **Workflows: write**
and set `allowWorkflowWrites: true` on that configured repository. This defaults
to false and applies only to Git write tokens; it does not authorize workflow
dispatch or other Actions mutations. See GitHub's [permission guidance](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app).

### Git LFS

The broker answers the Git LFS batch API at `/OWNER/REPO.git/info/lfs/objects/batch`,
after the same rate limit, Host/Origin check, and bearer authentication as Git. Downloads
follow `git.read`. Uploads also need an explicit `git.lfs.upload` rule (allow/deny only, no
`ref`), which defaults to deny:

```json
{ "id": "lfs-upload", "action": "git.lfs.upload", "repository": "acme/demo", "effect": "allow" }
```

The broker asks GitHub for the batch using a Contents read or write token, then rewrites each
storage href to a single-use, 15-minute `AGENTGATE_PUBLIC_URL/lfs-transfer/<id>` URL for the
object the client requested. It keeps upstream headers and `verify` actions server-side. LFS locking
returns 404, so `git-lfs` treats it as unsupported. The optional batch `ref` is validated with the
repository's push ref rules (non-ASCII names only with `allowUnicodeRefs: true`) but is
not used for policy or forwarded. Hrefs pointing to hosts outside
`AGENTGATE_LFS_HOSTS` fail with `LFS_UNTRUSTED_HOST`. The default is
`github-cloud.githubusercontent.com`, the download host observed on 2026-09-17. No upload
storage host has been confirmed, so uploads fail with `LFS_UNTRUSTED_HOST` until you confirm
one and add it. Set `AGENTGATE_PUBLIC_URL` to the origin workspaces use (`https://agentd:7432`
in Compose). It is required when `AGENTGATE_HOST` is not loopback.

`GET`/`PUT /lfs-transfer/<id>` (bearer auth required) proxies the object to or from storage
without GitHub credentials, counting and SHA-256-hashing every byte against the requested oid and
size. The final byte is withheld until it verifies, so a corrupt download is cut off and a corrupt
upload fails with `LFS_HASH_MISMATCH` without completing. Uploads need an exact `content-length`.
Each transfer re-checks the current policy, so a reload that removes the repository or the upload
rule denies pending transfers with 403. If GitHub's batch response includes a `verify` action (a
github.com endpoint for the same repository), the broker calls it with a write token after the
upload; otherwise verification is skipped. `AGENTGATE_LFS_MAX_OBJECT_MIB` (1–5120, default 5120)
caps object size. Object transfers use their own pool of `AGENTGATE_LFS_MAX_TRANSFERS` slots
(1–64, default 8, matching git-lfs's default `lfs.concurrenttransfers`), separate from the
`AGENTGATE_MAX_CONCURRENT` pool that Git, API, and LFS batch requests share; a full transfer pool
returns `503 LFS_BUSY` with `retry-after`. Storage downloads request `accept-encoding: identity`,
and a transfer requested with the wrong method (`PUT` on a download, `GET` on an upload) gets 405
without consuming the single-use URL. `/healthz` reports `lfs: true`.

`agentgate doctor` is the first thing to run in a workspace that misbehaves. It
checks Git/LFS installation, commit identity, broker reachability (via the
unauthenticated `/healthz`, so a bad token file cannot mask a down broker), the
client token file, the runtime assertion, the model gateway, and the egress proxy,
and exits 1 if any check AgentBox controls fails. For the assertion it reports
who the agent is acting as (`runtime`, `human`, `agent`, `team`, `mode`, `task`),
when it expires, and whether it is bound to the client token this workspace
holds; an expired or mis-bound assertion fails, and one expiring within the hour
warns to run `agentgate renew` after replacing the file. The gateway and proxy
are probed by TCP reachability (neither exposes a health route to the workspace),
and the gateway check fails when `ANTHROPIC_AUTH_TOKEN` was not exported. It never
prints a token or the assertion itself. It reports broker capabilities; it does
not prove the configured GitHub App permissions or repository rules allow a
particular operation.

## Testing against GitHub

`npm test` and `npm run test:docker` only exercise a mocked GitHub provider.
`npm run test:live` (`scripts/live-smoke.js`) drives a real GitHub App
installation end to end: it starts a real broker, clones through it, pushes an
allowed feature branch, confirms a push to `main` is denied and a push to an
approval-gated branch is held until approved through the admin socket, opens
and closes a draft PR, lists PRs and CI runs, and checks the audit log for
leaked installation tokens. It exits non-zero on the first failed assertion
and cleans up the branches and PR it created on exit, using the trusted
provider directly (the broker itself cannot delete refs or close PRs).

Required environment (put these in `.env.live`, which is git-ignored, or export
them directly):

| Variable | Purpose |
| --- | --- |
| `LIVE_GITHUB_APP_ID` | The GitHub App ID to authenticate as |
| `LIVE_GITHUB_PRIVATE_KEY_PATH` | Path to the App's PEM private key (or set `AGENTGATE_SIGN_COMMAND` instead) |
| `LIVE_REPO` | Disposable repository as `owner/name` |
| `LIVE_REPO_ID` | That repository's numeric GitHub ID |
| `LIVE_INSTALLATION_ID` | The App installation ID for that repository |

The disposable repository must have:

- A `main` branch with GitHub rules requiring deletion protection,
  non-fast-forward protection, and pull requests (the same rules
  `verifyProtectedBranches` checks at broker startup)
- A workflow that runs on `push` to `agent/**` so the smoke test's CI-run
  assertion has something to observe

Run `npm run test:live`. Every `live-smoke:` step should print, followed by
`live-smoke: PASS`, and the test branches and PR should no longer exist on
GitHub afterward. If it fails, treat it as a broker bug unless the failure
shows GitHub behavior that differs from the mocks in `test/github.test.js` or
`test/github-api.test.js`, in which case update the matching mock alongside
the fix.

`.github/workflows/live-smoke.yml` runs this nightly (and on manual dispatch)
against the `live-github` GitHub Environment, which supplies
`LIVE_GITHUB_APP_ID`, `LIVE_REPO`, `LIVE_REPO_ID`, and `LIVE_INSTALLATION_ID`
as environment variables and the App's private key as the
`LIVE_GITHUB_PRIVATE_KEY` secret.

Protocol references: [Git smart HTTP](https://git-scm.com/docs/gitprotocol-http),
[Git receive-pack](https://git-scm.com/docs/gitprotocol-pack), and
[GitHub App installation tokens](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app).
