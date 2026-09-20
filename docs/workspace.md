# The isolated workspace

Running agents in the isolated Docker workspace: the Compose stack, workspace image profiles, IDE attach, image verification, the deployment-host check, the egress proxy, the model gateway, and KMS signing.

Part of the [AgentBox documentation](../README.md#documentation).

## Isolated Docker example

`compose.yaml` is the core stack one developer runs: the broker, the isolated
workspace, the egress proxy, and the model gateway. It needs only its own eight
settings (GitHub App, key, client token, TLS files, gateway token, model key).
`enterprise/compose.enterprise.yaml` layers on the audit forwarder and the OIDC approval UI
with oauth2-proxy, and is where the SIEM and identity-provider settings are
required; use it as `docker compose -f compose.yaml -f enterprise/compose.enterprise.yaml`.
Without it, approvals come from the host CLI and rules that require
`reviewerSources: ["oidc"]` cannot be satisfied, because agentd holds no
approval-web admin secret.

The Compose workspace has an internal-only network. The broker also has an
upstream network and exposes no host port. Only the broker receives the private
key, configuration, state volume, and admin socket. Do not mount the Docker socket,
host credentials, or broker state into the workspace.

### Bootstrap in one command

`npm run bootstrap` (`scripts/bootstrap-dev.sh`)
generates the per-machine secrets the core stack needs (workspace client token,
model-gateway client token, development CA and broker certificate, all owner-only
under `~/.agentgate`), writes their paths into `.env` (replacing existing lines,
never duplicating them), copies `examples/config.json` to `config.local.json` if
absent, and prints exactly which settings still need your platform team: the App
ID and key or KMS settings, the model provider key file, and your commit identity.
Rerunning keeps existing secrets. The manual equivalents follow.

Compose serves the workspace-to-broker hop over TLS. Generate a development CA and
broker certificate, then point the three secret paths and `AGENTGATE_CA_PATH` at it in `.env`:

```bash
sh scripts/make-dev-cert.sh ~/.agentgate-tls
echo "AGENTGATE_TLS_CERT_PATH=$HOME/.agentgate-tls/broker.crt" >> .env
echo "AGENTGATE_TLS_KEY_PATH=$HOME/.agentgate-tls/broker.key" >> .env
echo "AGENTGATE_CA_PATH=$HOME/.agentgate-tls/ca.crt" >> .env
```

After configuring `.env` and `config.local.json`:

```bash
docker compose up --build -d
docker compose exec workspace agentgate doctor
docker compose exec workspace bash
# In the workspace:
git clone --recurse-submodules https://github.com/OWNER/REPO.git
exit
# On the trusted host:
docker compose exec agentd node src/cli.js list
docker compose exec agentd node src/cli.js approve <request-id>
docker compose down
```

The broker runs as UID 1000. Its key file must be readable by that UID inside the
container. Compose file-backed secrets preserve host file permissions. The
workspace uses named volumes for `/workspace` and `/home/node` instead of mounting
this trusted broker checkout. Both volumes survive `docker compose down` and
container recreation. `docker compose down -v` deletes their data.

### Signing with AWS KMS instead of a key file

`compose.yaml` above is the
file-key default (`GITHUB_PRIVATE_KEY_PATH` and the `github_app_key` secret).
The broker has a built-in KMS signer (`src/aws-kms.js`: SigV4 over HTTPS, no
AWS CLI or SDK in the image). Import the App's RSA key into KMS, or generate it
there and register its public key with GitHub, grant the broker's role `kms:Sign`
on that one key, set `AGENTGATE_KMS_KEY_ID` (an ARN infers the region; otherwise
set `AWS_REGION`), and layer `compose.kms.yaml` first:

```bash
docker compose -f compose.yaml -f compose.kms.yaml up -d --build agentd
docker compose -f compose.yaml -f compose.kms.yaml -f enterprise/compose.enterprise.yaml up -d --build
```

Credentials are resolved in order from EKS Pod Identity or an ECS task role
(`AWS_CONTAINER_CREDENTIALS_FULL_URI` and its token file), IRSA web identity
(`AWS_ROLE_ARN` with `AWS_WEB_IDENTITY_TOKEN_FILE`, mount the projected token),
then static keys, and cached until shortly before expiry. Credentials, request
bodies, and KMS responses are never logged; a failure is `SIGNER_FAILED`. agentd
refuses to start if `GITHUB_PRIVATE_KEY_PATH` and `AGENTGATE_KMS_KEY_ID` both
reach it, so the override replaces `agentd`'s environment and secrets entirely
(a Compose merge cannot delete one key), which is why it must come before
`enterprise/compose.enterprise.yaml` and why `GITHUB_PRIVATE_KEY_PATH` must still name an
existing placeholder such as `/dev/null` for `compose.yaml`'s own interpolation.
For another HSM or cloud KMS, `AGENTGATE_SIGN_COMMAND` still runs any program
that reads the signing input on stdin and writes a raw RSASSA-PKCS1-v1_5
SHA-256 signature; `examples/sign-with-aws-kms.sh` shows the shape. Verify the
merged configuration first with `docker compose -f compose.yaml -f
compose.kms.yaml config -q`.

Set `AGENTGATE_GIT_NAME` and `AGENTGATE_GIT_EMAIL` in `.env` before starting, or run
`git config --global user.name ...` and `git config --global user.email ...` inside
the workspace. Environment values, when nonempty, take precedence on startup.
With no supplied identity, startup prints setup instructions and Git requires an
explicit identity before committing. Existing aliases and preferences are kept.

Startup manages `~/.config/agentgate/gitconfig`, included from `~/.gitconfig`.
It rewrites normal GitHub HTTPS, SCP-style SSH, and SSH URLs to the broker. URLs
with and without `.git` work. Recursive submodules with relative or GitHub URLs
work when **every referenced repository** is configured and allowed by the broker.
SSH URL rewriting uses HTTP transport; no workspace SSH key is needed for GitHub.
For a broker outside Compose, set `AGENTGATE_URL` to its HTTP(S) origin.

The image includes Git, Git LFS, GitHub CLI, SSH, GnuPG, Node/npm, Python/pip/venv,
C/C++ build tools, ripgrep, jq, curl, wget, archive tools, nano, vi, and tmux.
Git LFS objects transfer through the broker (see [Git LFS](github.md#git-lfs)).
`gh` is available for separately configured deployments; in this isolated topology,
use `agentgate pr` and `agentgate ci`, which need no workspace GitHub credentials.
GnuPG/SSH are available for local signing, but signing keys are not provisioned.

The workspace defaults to a 4 GiB memory limit (override `WORKSPACE_MEMORY_LIMIT`)
and 512 processes. Language dependencies and AI tools are installed in a derived
image at build time, where registries are reachable; at run time only the egress
allowlist and the model gateway are. This base image is a Git development
foundation.

### Workspace profiles

`examples/workspace-claude-code.Dockerfile` is the first
derived image: the base workspace plus a pinned Claude Code, which honours the
`ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN` that Compose and the entrypoint
point at the model gateway, so its model traffic is key-injected, path-allowlisted,
and budgeted like any other. Its telemetry, error reporting, auto-updater, and
other non-essential traffic are disabled in the image because the egress proxy
would refuse those hosts anyway. Build it on top of the base and point Compose at
it:

```bash
docker build --tag agentgate-workspace:local --file examples/workspace.Dockerfile .
docker build --tag agentgate-workspace-claude:local --file examples/workspace-claude-code.Dockerfile .
```

To run it, name the image in `.env` and layer the `compose.workspace-image.yaml`
override, which swaps the workspace's `build:` for that `image:` and changes
nothing else about the service:

```bash
echo "AGENTGATE_WORKSPACE_IMAGE=agentgate-workspace-claude:local" >> .env
docker compose -f compose.yaml -f compose.workspace-image.yaml up -d
```

The same override runs a signed `ghcr.io` digest in production. To derive a
profile from a released base instead of a local build, pass
`--build-arg AGENTGATE_WORKSPACE_IMAGE=ghcr.io/OWNER/agentgate-workspace@sha256:...`.
CI builds every profile on each push, and each profile's Dockerfile ends by
running its tool as `node`, so a broken postinstall or version pin fails the build
rather than the developer's first session. The Claude Code profile also installs managed settings
(`examples/claude-code-managed-settings.json` at `/etc/claude-code/managed-settings.json`)
that deny Claude Code's own Read and Bash tools the token, assertion, and gateway
token files and the environment dump commands. This is defence in depth, not a
boundary: a shell can still read those files, and THREAT_MODEL.md says so. Its
value is that reaching a secret becomes a deliberate act rather than a casual file
read, and the denial shows up in Claude Code's own logs.
`test/workspace-profiles.test.js` checks every profile derives from
the workspace image, pins each tool to an exact release, ends as the `node` user,
bakes in no credential or endpoint, and uses no piped installer scripts. Add
further tools (Codex CLI, Aider, language toolchains) the same way, and rerun
`agentgate-egress-check` on the result: a tool that needs a host the allowlist
does not name will fail at run time, not silently reach it.

This topology illustrates credential and network separation. It still needs
deployment-specific egress testing and host hardening before handling untrusted
workloads. See [THREAT_MODEL.md](../THREAT_MODEL.md).

## Using an IDE with the workspace

AgentBox sits under Git, not under the editor. Any tool that runs `git` inside the
workspace is brokered unmodified, because startup writes a managed gitconfig that
routes every GitHub URL to the broker with the workspace token and runtime
assertion attached. So an IDE agent (Cursor, Copilot, Windsurf, Claude Code in
VS Code) is covered exactly to the extent that its terminal, Git, and tool calls
execute inside the workspace container. `.devcontainer/devcontainer.json` makes
that the default.

**Attach with Dev Containers.** VS Code, Cursor, and Windsurf all ship the Dev
Containers extension (Cursor and Windsurf are VS Code forks). Bring the stack up,
then open the checkout and choose *Reopen in Container*:

```bash
docker compose up -d --build
# then: Command Palette → "Dev Containers: Reopen in Container"
```

The editor UI stays on your machine. Its server, terminal, Git, and agent commands
run as `node` inside the `workspace` service, in `/workspace`, with the entrypoint
intact (it writes the managed gitconfig and exports the model-gateway token). The
devcontainer sets no image, mounts, ports, capabilities, or lifecycle commands: the
Compose service definition is the only source of workspace privileges, and
`test/devcontainer.test.js` fails if that changes. `shutdownAction` is `none`, so
closing the window leaves the broker and its audit trail running.

Shells the editor opens, like any `docker compose exec` session, do not pass
through the container entrypoint. The image therefore installs
`/etc/profile.d/agentgate.sh`, and the entrypoint adds it to `~/.bashrc`, so
login and interactive shells export the model-gateway token
(`ANTHROPIC_AUTH_TOKEN`) exactly as PID 1 has it. A bare non-interactive
`docker compose exec workspace claude ...` gets no profile; wrap it as
`bash -lc '...'`. `agentgate doctor` reports which case you are in.

The devcontainer also turns off the editor's own Git credential injection
(`github.gitAuthentication`, `git.terminalAuthentication`, integrated askpass).
Without that, the GitHub Authentication extension would forward the token from your
laptop's GitHub login into the container's Git operations, which is the exact
pattern AgentBox exists to remove. Direct GitHub access from the container is
denied by the egress proxy regardless, so this is defence in depth, not the
boundary.

**Let the IDE server download.** The editor installs its headless server into the
container on first attach and fetches extensions from its marketplace. The workspace
network has no route out, so those hosts must be allowlisted in the egress proxy.
`examples/egress.ide.json` is the default allowlist plus the VS Code server and
marketplace hosts, Cursor's server host, and Open VSX (Cursor's and Windsurf's
extension registry). Point the proxy at it in `.env`:

```bash
echo "AGENTGATE_EGRESS_CONFIG_PATH=./examples/egress.ide.json" >> .env
docker compose up -d --force-recreate egress-proxy
```

Vendor hosts change; if the attach fails with a download error, read the
`egress` deny line in the proxy log for the host it wanted and add it. For a
fully offline workspace, bake the server into a derived image instead and keep
the default allowlist. Extensions installed into the container are code that runs
as the workspace user with the same reach as the agent; treat them like any
other dependency.

**What the IDE cannot give you.** Two things fall outside the boundary, and both
are worth knowing before promising anyone "every agent action is governed":

- *The IDE's own model traffic bypasses the model gateway.* Cursor, Copilot, and
  Windsurf send prompts from the client on your machine to their vendor's cloud.
  The gateway's key injection, path allowlist, and budgets never see it. Only
  tools that honour `ANTHROPIC_BASE_URL` (Claude Code, the SDKs, scripts in the
  workspace) are covered. This is a vendor-side limitation, not a configuration
  gap; see ROADMAP.md Milestone 7, "Adoption surface".
- *Hosted agents run elsewhere.* Cursor background agents, the Copilot coding
  agent, and Codex cloud tasks execute in the vendor's infrastructure with a
  GitHub credential from the vendor's own App. AgentBox has no hook in that path
  today. Covering them is what Milestone 4's provider-native enforcement is for:
  policy the provider enforces no matter which client shows up.

**Approvals from the editor.** A push that policy routes to approval fails in the
IDE's Git output with the request ID. Approve it from the host CLI or the approval
web UI, then push again; the retry consumes the grant. Nothing in the container
can approve its own request. `agentgate pr` and `agentgate ci` work from the
integrated terminal and need no GitHub credential.

**Remote SSH is not supported into this topology, on purpose.** The workspace
network is `internal`, and Docker cannot publish a port from an internal-only
network, so there is nowhere for an SSH listener to be reached without adding a
second network that would also be a second egress path. Dev Containers attaches
over `docker exec` and needs no listener. If you must use Remote SSH, run the
editor on a jump host that itself attaches with Dev Containers.

**Running AgentBox on the laptop instead.** You can run `agentd` locally, run
`node src/workspace-setup.js` against your own home directory, and use Cursor
natively; Git then routes through the broker and you get policy, approvals, and
audit. You do not get isolation: the agent runs as your OS user, can read the
client token, the admin socket, and every other credential on the machine, and can
reach GitHub directly with any of them. Use this to try the policy model, never as
the enforcement boundary. THREAT_MODEL.md "IDE attachment" has the full list.

## Verifying images

Tagged releases (`v*`) publish `ghcr.io/OWNER/agentgate` and
`ghcr.io/OWNER/agentgate-workspace` images from `.github/workflows/release.yml`,
for `linux/amd64` and `linux/arm64` (Apple Silicon and Graviton run them natively), with an SPDX
SBOM, SLSA provenance attestation, and a keyless cosign signature bound to that workflow on the
index and on each architecture's manifest. Verify a release before deploying it:

```bash
cosign verify ghcr.io/OWNER/agentgate:vX.Y.Z \
  --certificate-identity-regexp '^https://github.com/OWNER/REPO/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
docker buildx imagetools inspect ghcr.io/OWNER/agentgate:vX.Y.Z --format '{{json .SBOM}}'
```

CI (`.github/workflows/ci.yml`) also runs a Trivy scan on every push and pull
request, failing on fixable HIGH/CRITICAL vulnerabilities. Release builds each
image once and pushes it by digest only, scans that exact digest from the registry,
once per architecture, with Trivy (failing the release on fixable HIGH/CRITICAL findings), and only then
points the `vX.Y.Z` tag at the same digest and signs it with cosign, so the tagged,
signed image is byte-for-byte the scanned one. Trivy exceptions live in
`examples/workspace.trivyignore` and apply only to the workspace image scans; the
broker image is scanned with no ignore file.

In production Compose, deploy by digest instead of `build: .`, so the running image matches
exactly what was scanned and signed. The override files do this without editing `compose.yaml`:
name the verified digests (or your registry's mirror of them) in `.env` and layer the overrides.
This is also the path for machines that cannot reach npm and the OS package mirrors during a build.

```bash
echo "AGENTGATE_IMAGE=registry.example.com/agentgate@sha256:..." >> .env
echo "AGENTGATE_WORKSPACE_IMAGE=registry.example.com/agentgate-workspace@sha256:..." >> .env
docker compose -f compose.yaml -f compose.broker-image.yaml -f compose.workspace-image.yaml up -d
# with the enterprise services: add -f enterprise/compose.enterprise.yaml -f enterprise/compose.broker-image.enterprise.yaml
```

With the installed `agentbox` command the two `.env` lines are enough: `agentbox up` and every
other command select the override files from them, and the generated `.devcontainer` names the
same files, so attaching an editor does not recreate the workspace. `agentbox up --broker-image`
and `--image` do the same for one run. Each override clears `build`, so `up --build` cannot
rebuild the Dockerfile under the verified image's name, and touches nothing else about a service.

## Validate a deployment host

Run the workspace egress and secret-isolation check on each deployment host
before trusting it with untrusted workloads:

```bash
docker compose run --rm workspace agentgate-egress-check
```

It checks that the workspace cannot reach GitHub or the internet directly
(HTTPS, IPv6, plain HTTP), cannot reach cloud metadata endpoints or the host
gateway (SSH, the Docker API), holds no GitHub credentials in its environment
or PID 1's environment, has no private key material anywhere on its
filesystem (a content-based scan for `PRIVATE KEY-----`, not just files named
after AgentBox), has no Docker socket and no effective capabilities, and can
reach the broker. Every probe fails closed: if a check cannot even run (curl,
`ip`, or `getent` missing, or `/proc/1/environ` unreadable), that counts as a
failure, never as "blocked."

It also requires that external DNS does not resolve (`getent hosts
example.com` must report "not found"), that an allowlisted registry
(`registry.npmjs.org`) is reachable through the egress proxy, and that the
proxy itself refuses (CONNECT status 403) a non-allowlisted host, GitHub, and
an IP literal. A proxy that is down counts as a failure, not as "refused."

Exit 0 means isolated. Exit 1 means a real isolation gap (or a probe that
could not run at all) and should block deployment; read the `FAIL` lines it
prints and fix Compose or the host before proceeding. There is no longer an
accepted-DNS exit 2 or `EGRESS_ALLOW_DNS` escape. If external DNS still
resolves on your host (verified closed with `dns: ["127.0.0.1"]` on Docker
28.4.0), give `agentd` and `egress-proxy` static addresses on a fixed-subnet
`workspace` network, add them to the workspace's `extra_hosts`, and set its
`dns` to `0.0.0.0`.

## Workspace egress proxy

The workspace network has no route out. Everything except the broker goes
through `egress-proxy` (`src/egress-proxy.js`), the only service on both the
`workspace` and `upstream` networks. Compose sets `HTTPS_PROXY`/`HTTP_PROXY`
(and lowercase forms) to `http://egress-proxy:3128` and `NO_PROXY` to
`agentd,model-gateway`, and sets the workspace `dns` to `127.0.0.1`: Docker's
embedded resolver still answers service names, but external names go nowhere,
which closes DNS as an exfiltration channel. The proxy resolves allowlisted
names itself.

The allowlist is `examples/egress.json` by default; point
`AGENTGATE_EGRESS_CONFIG_PATH` in `.env` at your own copy:

```json
{
  "allow": ["registry.npmjs.org:443", "*.pythonhosted.org:443"],
  "deny": ["uploads.example.com"],
  "maxBytesPerHost": 2147483648
}
```

- Only `CONNECT host:port` is supported; any other method gets 405, so there
  is no plaintext HTTP proxying. Tools that honor `HTTPS_PROXY` (curl, git,
  npm, pip, apt over HTTPS) work unchanged.
- `allow` entries are `host:port` or `*.suffix:port`. Matching is
  case-insensitive and ignores one trailing dot; `*.example.org` does not match
  `example.org` itself. Punycode (`xn--`) names are allowed only when listed
  exactly. IP literals, numeric hosts, and invalid entries are rejected (the
  proxy refuses to start on an invalid config).
- GitHub (`github.com`, `*.github.com`, `*.githubusercontent.com`,
  `*.githubassets.com`, `*.github.io`, `ghcr.io`) is always denied, whatever the
  allowlist says: GitHub access goes through the broker only. `deny` adds more
  hosts to that fixed list.
- The proxy resolves every address for the name and refuses the tunnel if
  any of them is loopback, private, link-local, CGNAT, documentation,
  benchmarking (including `3fff::/20`), multicast, reserved, unspecified, any
  IPv4-mapped address (`::ffff:0:0/96`, always refused), or a NAT64 or 6to4 form
  of those. The whole connect phase shares one 10-second deadline across all
  resolved addresses. It then connects only to those vetted addresses, trying
  each in order, and never re-resolves (no DNS rebinding).
- `maxBytesPerHost` (default 2 GiB) caps bytes in both directions per client
  address and matched allow rule for the proxy's lifetime (a `*.suffix` rule is
  one budget for all its subdomains; usage is tracked for at most 16384
  client/rule pairs, least recently used first out); a tunnel that would exceed it is
  closed mid-stream. Tunnels idle for 5 minutes are closed, each client may
  hold at most 32 tunnels, and CONNECT headers must arrive within 10 seconds.
- Each decision is logged as `{ type: 'egress', host, port, decision, reason,
  bytesUp, bytesDown }`. No payload is ever logged.

Model API hosts are not in the example allowlist; they go through the
[model gateway](#model-api-gateway). Allowlisted hosts that accept uploads (for example package publish
endpoints) remain an exfiltration channel; see THREAT_MODEL.md.

### Behind a corporate forward proxy

On a network where nothing reaches the internet directly, layer `compose.corporate-proxy.yaml`
(and `enterprise/compose.corporate-proxy.enterprise.yaml` with the enterprise services):

```bash
echo "AGENTGATE_CORPORATE_PROXY=http://proxy.example.com:8080" >> .env
echo "AGENTGATE_CORPORATE_NO_PROXY=.corp.example.com,ghe.example.com" >> .env   # optional
docker compose -f compose.yaml -f compose.corporate-proxy.yaml up -d
```

With the installed `agentbox` command the `.env` lines are enough; every command selects the
override files from them, and `agentbox check` validates the values.

- `agentd` and `model-gateway` make their provider and model calls through the proxy. Names in
  `NO_PROXY` (the stack's own services, plus `AGENTGATE_CORPORATE_NO_PROXY`) are dialled directly;
  list a self-hosted GitHub Enterprise or GitLab there if it is reachable without the proxy.
- `egress-proxy` chains each tunnel it has already allowed through the proxy
  (`AGENTGATE_EGRESS_UPSTREAM_PROXY`). The allow list, deny list, GitHub block, IP-literal block,
  and quotas are decided first, so the corporate proxy only sees what passed. It asks for the
  hostname, and the corporate proxy resolves it: the private-address check still applies to any
  name the local resolver can see, and cannot apply to names only the corporate proxy resolves.
  Audit events use `upstream-proxy-unreachable` and `upstream-proxy-refused` for its failures.
- The workspace is unchanged: its only route out is still `egress-proxy`.
- Only `http://` proxies are supported (the tunnels inside stay TLS end to end). Proxy
  credentials go in the URL; keep `.env` owner-only. NTLM and Kerberos proxies are not supported;
  put a local authenticating forwarder in front of them.

If the proxy inspects TLS, also layer `compose.corporate-ca.yaml` with
`AGENTGATE_CORPORATE_CA_PATH` set to the company root CA (PEM). Public roots stay trusted.

- `agentd` and `model-gateway` add the CA to Node's trust store.
- The workspace entrypoint builds a bundle of the image's public roots plus the CA
  (`~/.config/agentgate/ca-bundle.crt`) and points Git, curl, Python (`requests`, `pip`), and
  OpenSSL-based tools at it; Node and npm get the CA through `NODE_EXTRA_CA_CERTS`. Nothing has to
  be baked into the workspace image. The broker connection keeps its own CA.

Node's built-in `fetch` reads the egress proxy from the environment (`NODE_USE_ENV_PROXY` is set in
the workspace); on current Node 22 it prints a one-line experimental warning the first time.

### Attributing egress to a runtime

Give the proxy the issuer keys and it attributes each tunnel to the runtime whose
assertion arrives as proxy credentials:

```json
{ "allow": ["registry.npmjs.org:443"], "identity": { "audience": "agentgate:acme", "issuers": [{ "kid": "k1", "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n" }], "required": false } }
```

The workspace profile rewrites `HTTPS_PROXY` and friends to
`http://runtime:<assertion>@egress-proxy:3128` when a runtime assertion is
present; Git, curl, npm, pip, and apt send that as `Proxy-Authorization` on every
CONNECT. The proxy verifies the signature, audience, lifetime, and claims (not the
token binding, which it cannot see), records `runtime` on the `egress` event, and
keeps the byte quota per runtime and rule instead of per address. A credential
that fails verification, or a user other than `runtime`, is refused with 407; with
`"required": true` a tunnel without credentials is refused too. Tools that print
their proxy URL in error output will show the assertion; it names the developer
and task but grants nothing without the workspace token.


## Model API gateway

Model API keys never enter the workspace. `model-gateway`
(`src/model-gateway.js`) sits on the `workspace` and `upstream` networks, accepts
the workspace client token, and forwards allowlisted requests to the provider
with the real key injected. Compose sets `ANTHROPIC_BASE_URL` in the workspace to
`http://model-gateway:7434/anthropic`, and `workspace-entrypoint.sh` exports
`ANTHROPIC_AUTH_TOKEN` from `AGENTGATE_MODEL_GATEWAY_TOKEN_FILE`. That is a
model-gateway client token of its own (Compose secret `model_gateway_client_token`, from
`AGENTGATE_MODEL_GATEWAY_CLIENT_TOKEN_PATH`), not the agentd workspace token, so a
compromised gateway cannot call agentd. Generate it like the workspace token
(`umask 077; openssl rand -hex 32 > ~/.agentgate-model-gateway-token`). The Anthropic SDKs and Claude
Code send that value as `Authorization: Bearer`; the gateway checks it in constant
time, strips it, and injects `x-api-key`. Other SDKs work the same way: point their
base URL at `http://model-gateway:7434/<prefix>` and use the model-gateway client token as their
API token. The gateway accepts the client token only as a Bearer header.

SDKs must use `ANTHROPIC_AUTH_TOKEN` (sent as `Authorization: Bearer`). Do not set
`ANTHROPIC_API_KEY` in the workspace: it is sent as `x-api-key`, which the gateway
does not accept as the client token.

Upgrade note: `ANTHROPIC_API_KEY_PATH` is now required by `compose.yaml`; add it
to existing `.env` files. Point it at a file holding the provider key. The file must
be mode `600` (the gateway returns 503 if group or other can read it) and owned
by the uid the container runs as (the image's `node` user), because compose
file secrets keep host ownership and mode. Routes and budgets default to `examples/model-gateway.json`; set
`AGENTGATE_MODEL_GATEWAY_CONFIG_PATH` to use your own copy:

```json
{
  "routes": [
    { "prefix": "/anthropic", "upstream": "https://api.anthropic.com", "allowPaths": ["^/v1/messages$", "^/v1/messages/count_tokens$", "^/v1/models$"], "inject": { "header": "x-api-key", "valueFile": "/run/secrets/anthropic_api_key" } }
  ],
  "budget": { "maxRequestsPerHour": 600, "maxGlobalRequestsPerHour": 3000, "maxRequestBytes": 8388608 },
  "maxConcurrent": 8
}
```

- Only `GET` and `POST` to paths that match an anchored `allowPaths` regex are
  forwarded; everything else gets 404. The regex is matched against the raw path
  after the prefix and compiled as `^(?:...)$`; entries without both anchors or
  with top-level `|` (use a group: `^/v1/(messages|models)$`) are refused at
  startup. Paths with dot segments, `//`, backslashes, or encoded `/`,
  `\`, `.`, `%`, or NUL are refused outright. The query string is forwarded
  unchanged, but only after the path matches.
- Client `authorization`, `x-api-key`, `api-key`, `x-goog-api-key`, `cookie`,
  `x-agentgate-*`, forwarding headers, and hop-by-hop headers are stripped.
  Responses stream back unchanged (SSE works), minus `set-cookie`, hop-by-hop
  headers, and any header whose value contains the injected key. Redirects are
  refused (`redirect: 'error'`).
- The key file is re-read on every request, so rotating it needs no restart. A
  key file readable by group or other fails closed with 503.
- Every workspace presents the same client token, so the gateway cannot tell
  agents apart by credential. `budget.maxRequestsPerHour` is therefore a token
  bucket per client IP address: workspaces that share an address (NAT, one
  host network) share one bucket. The optional
  `budget.maxGlobalRequestsPerHour` is one bucket across all clients. Either
  returns 429 `RATE_LIMITED` with `Retry-After`. A token is taken only after the
  body has been read in full and is within budget, so refused requests cost
  nothing.
- `budget.maxRequestBytes` (default 8 MiB) caps each body (413; an invalid
  `Content-Length` gets 400). Bodies are buffered before forwarding, so
  `maxConcurrent` (default 8) caps in-flight requests and
  `budget.maxBufferedBytes` (default `maxConcurrent × maxRequestBytes`) caps
  total buffered bytes. Either limit returns 503 `GATEWAY_BUSY`. Peak memory is
  about twice the buffered bytes, which is why compose gives the service
  `mem_limit: 384m`. Raise it if you raise either limit.
- Each request logs `{ type: 'model.request', route, path, status, bytesUp,
  bytesDown }`. Bodies, headers, and keys are never logged. Upstream failures
  return a generic 502.
- Inside the container the gateway reads `AGENTGATE_MODEL_GATEWAY_CONFIG`,
  `AGENTGATE_MODEL_GATEWAY_HOST` (default `0.0.0.0`),
  `AGENTGATE_MODEL_GATEWAY_PORT` (default `7434`), and
  `AGENTGATE_MODEL_GATEWAY_CLIENT_TOKEN_FILE` (falls back to `AGENTGATE_CLIENT_TOKEN_FILE` for
  older deployments; do not share the agentd token). Compose sets all four.

Upgrade note: `compose.yaml` now requires `AGENTGATE_MODEL_GATEWAY_CLIENT_TOKEN_PATH` in `.env`.

The workspace-to-gateway hop is plain HTTP on the internal `workspace` network.
If the gateway runs on another host, put it behind TLS the same way as the
broker (see `AGENTGATE_TLS_CERT_FILE`). The client token then crosses the
network.

### Attributing model traffic to a runtime

Add the broker's issuer keys to the gateway config and it verifies the runtime
assertion a workspace sends, attributes the request to that runtime in its log,
and gives each runtime its own hourly bucket:

```json
"identity": { "audience": "agentgate:acme", "issuers": [{ "kid": "k1", "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n" }], "required": false },
"budget": { "maxRequestsPerHour": 600, "maxRequestsPerHourPerRuntime": 200 }
```

The workspace profile exports `ANTHROPIC_CUSTOM_HEADERS` with the assertion as
`x-agentgate-runtime`, which Claude Code and the Anthropic SDKs send on every
call; other tools can set the same header. The gateway checks the signature,
audience, lifetime, and claims, but cannot check the token binding (it never sees
the workspace token), so the assertion attributes the request rather than
authorising it: the gateway client token is still required, a present but invalid
header is refused (401), and a missing header is refused only with
`"required": true`. The header is stripped before the request reaches the
provider. `model.request` log records then carry `runtime` (runtime ID, human,
agent, team, jti), which the detections in `docs/detections.md` can key on. The
egress proxy still attributes by source address: CONNECT carries no per-request
header from Git or package managers.

