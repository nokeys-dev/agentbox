# GitLab provider adapter

Answers every section of [the adapter plan template](../provider-adapter-plan-template.md) for
GitLab (gitlab.com or self-managed). Code: `src/gitlab.js` (adapter), `src/gitlab-api.js` (merge
request and pipeline proxy), `src/gitlab-rulesets.js` (protected-branch verification). Enable
with `AGENTGATE_PROVIDER=gitlab` and `"provider": "gitlab"` in the config; the daemon refuses to
start if the two disagree. `examples/config.gitlab.json` is a starting point.

Part of the [AgentBox documentation](../../README.md#documentation).

## 1. Credential model

- **Root credential:** an OAuth 2.0 refresh token for a GitLab application (confidential, scopes
  `api` for merge requests and pipelines, or `read_api` plus `write_repository` for Git only),
  held in an owner-only file named by `AGENTGATE_GITLAB_REFRESH_TOKEN_FILE`, together with the
  application's client id (`AGENTGATE_GITLAB_CLIENT_ID`) and client secret file
  (`AGENTGATE_GITLAB_CLIENT_SECRET_FILE`, owner-only). The workspace never mounts any of them.
- **Short-lived credential:** the broker exchanges the refresh token at `<base>/oauth/token`
  (`grant_type=refresh_token`, form-encoded, `redirect: 'error'`, 15 s timeout) for an access
  token. GitLab access tokens live two hours; the broker caches one until 60 seconds before
  `created_at + expires_in` and re-exchanges after that or after any upstream 401. Concurrent
  first requests share one in-flight exchange, because a refresh token is single use.
- **Rotation:** GitLab returns a new refresh token on every exchange and invalidates the old
  one. The adapter writes the new token to the refresh-token file atomically (temporary file,
  mode 0600, rename) before it uses the access token, so a restart after an exchange never
  presents a spent token. The file must therefore be writable by the broker (Compose: a named
  volume, not a read-only secret).
- **Scoping unit:** a GitLab project. Each `repositories[]` entry names the project path
  (`group/project`, nested groups allowed) and its numeric `projectId`, which is what the API
  calls use; the path is used only for Git smart HTTP and mirror URLs.
- **Where the token can go:** only the configured base origin (`AGENTGATE_GITLAB_URL`, default
  `https://gitlab.com`, https only, fixed at startup). Git requests carry it as
  `Basic oauth2:<token>`, API requests as `Bearer <token>`. Nothing else ever receives it.
- **Alternative not implemented:** project access tokens with an expiry, rotated through
  `POST /projects/:id/access_tokens/:token_id/rotate`. They scope to one project (better than a
  user token) but need one credential per project and a rotation job; the OAuth path was chosen
  because one refresh token covers a fleet's projects and rotates itself on use. A per-project
  token adapter can be added behind the same interface later.
- **Least privilege caveat:** an OAuth token carries the user's full scope on every project the
  user can reach. Unlike GitHub App installation tokens, it cannot be narrowed per request. The
  broker's default-deny policy is the boundary, and the OAuth user should be a dedicated bot
  account with Developer role only on the configured projects. This is the main threat-model
  difference from GitHub; see section 8.

## 2. Resource naming and config fields

| Field | Type | Required | Validation |
| --- | --- | --- | --- |
| `provider` (top level) | `"gitlab"` | yes for GitLab | must equal `AGENTGATE_PROVIDER` |
| `repositories[].name` | string | yes | `^[\w.-]+(/[\w.-]+)+$`, no `.`/`..` segments, no `-` prefix, no `.git`, at most 255 chars; lowercased |
| `repositories[].projectId` | positive integer | yes | numeric project id; also used as the duplicate and mirror key (`id`) |
| `protectedBranches`, `allowedPushOptions`, `allowUnicodeRefs`, `forkOf`, `scan` | as for GitHub | no | unchanged |

`id`, `installationId`, and `allowWorkflowWrites` are GitHub-only and refused. A GitLab config
cannot contain GitHub repositories or actions; one provider per broker.

## 3. Policy actions

| Action | Broker path | GitLab call | Approval |
| --- | --- | --- | --- |
| `git.read` | Git smart HTTP | `GET/POST <base>/<path>.git/...` | allow/deny |
| `git.push` | Git smart HTTP | receive-pack | allow/deny/approval |
| `gitlab.mr.read` | `pulls`, `pulls/:iid`, `pulls/:iid/comments`, `issues/:iid/comments` (GET) | `merge_requests`, `merge_requests/:iid`, `merge_requests/:iid/notes` | allow/deny |
| `gitlab.mr.create` | `pulls` (POST) | `POST merge_requests` (on the fork project for fork MRs) | allow/deny/approval, head ref pattern |
| `gitlab.mr.comment` | `issues/:iid/comments`, `pulls/:iid/reviews` (POST) | `POST merge_requests/:iid/notes` | allow/deny |
| `gitlab.mr.merge` | `pulls/:iid/merge` (PUT) | `PUT merge_requests/:iid/merge` with `sha` and `squash` | approval or deny only |
| `gitlab.pipelines.read` | `actions/runs`, `actions/runs/:id`, `actions/runs/:id/jobs`, `actions/jobs/:id/logs` | `pipelines`, `pipelines/:id`, `pipelines/:id/jobs`, `jobs/:id/trace` | allow/deny |

The token cannot be narrowed per action (section 1), so the "least-privilege scope" column of
the template is the policy action itself. `mergeMethods` accepts `merge` and `squash`; `rebase`
is a project setting in GitLab, not an accept-time option, and is refused. A review is a note:
GitLab has no comment-only review object, and approvals stay human-only exactly as for GitHub.

## 4. Request routing

The broker serves the same paths as for GitHub, so the workspace CLI is unchanged:
`/<group>/<project>.git/{info/refs,git-upload-pack,git-receive-pack}` (nested groups allowed)
and `/api/repos/<group>/<project>/{pulls...,issues/:n/comments,actions/...}`. Upstream hosts:
exactly one, the origin in `AGENTGATE_GITLAB_URL`, for OAuth, Git, and API v4. Job traces
return in the response body (`GET /jobs/:id/trace`) with `redirect: 'manual'`; a redirect is
reported as a failure and never followed, so no storage host is ever contacted. LFS is not
offered: `providerCapabilities` reports `lfs: false` and the broker answers 404 on the LFS batch
route. Git LFS through GitLab is a follow-up.

## 5. Response projection

Projected to the GitHub-shaped fields the CLI prints (`src/gitlab-api.js`):

- Merge request: `number` (iid), `title`, `body` (description), `state` (`opened` -> `open`,
  `merged` -> `closed`), `draft`, `html_url`, `created_at`, `updated_at`, `merged`,
  `mergeable` (from `detailed_merge_status`), `head.ref/sha`, `base.ref/sha`, `user.login`.
- Note: `id`, `body`, `created_at`, `updated_at`, `html_url` (null), `user.login`.
- Review: `id`, `state` (`COMMENTED`), `body`, `submitted_at`.
- Merge: `merged`, `sha` (merge or squash commit).
- Pipeline (`workflow_runs`): `id`, `name`, `head_branch`, `head_sha`, `event`, `status` and
  `conclusion` mapped from GitLab status, `html_url`, `created_at`, `updated_at`, `run_number`.
- Job: `id`, `name`, `status`, `conclusion`, `html_url`, `started_at`, `completed_at`, `steps: []`.

No field carries a credential; author emails, project objects, and pipeline variables are never
projected. Upstream error bodies and headers are dropped; only fixed messages with the status
reach the client.

## 6. Contract test

`test/gitlab.test.js` runs `runProviderContract` with the OAuth token call and
`perPermissionTokens: false` (one token serves every permission), and covers redirect rejection
on every method, error-body suppression on the token exchange, 401 eviction, refresh-token
rotation persistence, and the owner-only file rule. `test/gitlab-api.test.js` covers routing,
payloads, projection, protected-branch verification, and an integration run through the real
Git transport with a mocked v4 API: clone, push, blocked push, the full `agentgate pr`/`ci`
surface, a fork MR, and a merge approval bound to iid, sha, target, and method.

## 7. Live smoke test

Not yet automated. Manual procedure with a disposable project:

1. Create a bot user, a confidential OAuth application (`api` scope, redirect to
   `urn:ietf:wg:oauth:2.0:oob`), complete the authorization code flow once to obtain a refresh
   token, and store it with `umask 077`.
2. Protect `main` (allowed to push: No one; allow force push: off).
3. Set `AGENTGATE_PROVIDER=gitlab`, the four `AGENTGATE_GITLAB_*` variables, and the config;
   start the broker; from a workspace with `AGENTGATE_PROVIDER_HOST=<gitlab host>` run clone,
   push to `agent/*`, `agentgate pr create`, `agentgate ci list`, and a merge approval.
4. Tear down: revoke the OAuth application, delete the project, and delete the refresh-token
   file. A `test:live:gitlab` script mirroring `scripts/live-smoke.js` is a follow-up.

## 8. Threat model delta

- **New asset:** the OAuth refresh token and client secret. A leak grants the bot user's full
  API scope until the application is revoked; rotate by revoking the application, not by
  deleting the file. Access tokens live two hours in broker memory only.
- **Broader credential than GitHub's:** the token is not narrowed per repository or operation.
  A broker bug that forwarded a request to an unconfigured project would succeed upstream where
  a GitHub installation token would fail. Mitigations: the broker only ever interpolates
  `projectId` from configured entries and `name` from validated config; the bot user holds
  Developer on the configured projects only; policy is default deny. Treat the bot user's
  project membership as part of the policy.
- **New trust boundary:** the configured GitLab origin, fixed at startup. Self-managed
  instances must present a certificate the broker trusts.
- **Rotation persistence:** the refresh-token file is writable by the broker (a new writable
  path on the broker host). It is 0600 and never mounted into any other service.
- **Exfiltration walk:** projected fields (section 5) are scalars from the MR, note, pipeline,
  and job objects and the bot's own username; error paths return fixed strings; the audit trail
  records iid, sha, target, method, and byte counts, never bodies or tokens.

## 9. Egress

Add the GitLab host to the egress proxy `deny` list so the workspace can reach it only through
the broker (GitHub is denied by default; GitLab is not, because the host is deployment
specific): `{ "deny": ["gitlab.example.com"] }`. Set `AGENTGATE_PROVIDER_HOST` in the workspace
so URL rewriting and `agentgate pr` recognise the host. `agentgate-egress-check` still verifies
GitHub; extending it to a configurable provider host is a follow-up.

## Deferred

- Git LFS via GitLab (batch and verify against `<base>/<path>.git/info/lfs`).
- Automated live smoke test.
- Per-project access-token credential mode.
- Fork merge-request head detection relies on `source_project_id` matching a configured fork.
