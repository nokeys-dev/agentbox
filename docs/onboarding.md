# Onboarding a developer

Who does what to get one developer's agent working under AgentBox, in an enterprise where
the platform team holds the keys and developers hold none. Two roles, in order. Every step
references the documentation page that explains it.

The shape: each developer runs the Compose stack on their own machine. Their workspace container
is the only place the agent runs. The broker beside it signs GitHub App requests with a key the
developer cannot read (KMS) and identifies the workspace by a signed assertion the platform team
issued. Nothing in the developer's checkout, home directory, or IDE holds a GitHub or model
credential.

## Platform team, once per organisation

1. **GitHub App.** Create it with Contents read/write, Metadata read, and, for `agentgate pr`
   and `agentgate ci`, Pull requests read/write and Actions read. Install it on the repositories
   agents may touch. Record the App ID and installation IDs. github.md "Connect a GitHub repository".
2. **Signing key in a KMS.** Put the App private key in AWS KMS (or your HSM) and grant each
   developer's role `kms:Sign` on it and nothing else. Developers' brokers sign with
   `AGENTGATE_KMS_KEY_ID` (built in) or `AGENTGATE_SIGN_COMMAND`; the PEM never exists on a
   laptop. workspace.md "Signing with AWS KMS instead of a key file".
3. **Issuer key.** Generate the Ed25519 issuer keypair on an issuing host the platform team
   controls. Only the public key goes into broker configuration; the private key goes to the issuing
   service. identity.md "Runtime identity assertions".
4. **Policy, entitlements, egress.** Write `config.json` with `identity.mode: "assertion"`, the
   issuer public key, the repositories, and rules that `requires` team membership or a ticket.
   Wire `entitlements` to your directory export, GitHub teams, or Jira. Choose an egress allowlist
   (`examples/egress.ide.json` if developers attach an IDE). policy.md "Policy and approvals",
   "Entitlements", "Workspace egress proxy".
5. **Model gateway.** Put the provider API key in the gateway's secret and set the budget.
   workspace.md "Model API gateway".
6. **Images.** Build and sign the broker image and the workspace profile your developers need
   (`examples/workspace-claude-code.Dockerfile` for Claude Code). Publish by digest.
   docs/workspace.md "Verifying images", "Workspace profiles".
7. **Approvals.** Stand up approval-web behind your OIDC provider so reviewers approve with a
   verified identity, and set `reviewerSources: ["oidc"]` on rules that matter.
   docs/policy.md "Approval web UI".
8. **Audit.** Point `audit:forward` at your SIEM and load the detections. `docs/detections.md`.
9. **Bundle it.** Give developers a repository containing `compose.yaml`, the pinned image
   digests, `config.json`, the egress allowlist, the gateway config, the CA for the
   workspace-to-broker hop, and a `.env.example` with everything but the per-developer values.
   Developers run the core `compose.yaml` only. The SIEM forwarder and the OIDC approval UI
   (`enterprise/compose.enterprise.yaml`) run wherever reviewers and the audit pipeline live, and their
   settings never need to be on a developer's machine. If reviewers must approve with a
   verified OIDC identity, that host needs the developer's broker state, so plan the broker
   placement (developer machine versus shared host) with that in mind.

   With the installed `agentbox` command the bundle shrinks to the configuration files and a
   `.env.example`: the Compose files and source come from the package, and these lines select
   the rest. Use absolute paths; `agentbox check` rejects relative ones because Compose runs
   from the package directory.

   ```bash
   AGENTGATE_IMAGE=registry.example.com/agentgate@sha256:...             # verified broker image
   AGENTGATE_WORKSPACE_IMAGE=registry.example.com/agentgate-workspace@sha256:...
   AGENTGATE_CONFIG=/opt/agentbox/config.json
   AGENTGATE_EGRESS_CONFIG_PATH=/opt/agentbox/egress.json
   AGENTGATE_MODEL_GATEWAY_CONFIG_PATH=/opt/agentbox/model-gateway.json
   AGENTGATE_CORPORATE_PROXY=http://proxy.example.com:8080               # if outbound needs it
   AGENTGATE_CORPORATE_CA_PATH=/etc/ssl/certs/corp-root.pem              # if the proxy inspects TLS
   ```

## Developer, once per machine

Time: about ten minutes if the platform team's bundle is in hand. Windows works through
Docker Desktop with WSL 2; run these commands in the WSL shell, which is also what the Dev
Containers extension uses.

With the installed command (`npm install -g @nokeys/agentbox`, or the `.deb`, winget, or executable from a
release) the same steps are: copy the bundle's `.env.example` to `.env` in an empty directory,
`agentbox init`, fill in your commit identity, `agentbox check`, `agentbox up`,
`agentbox fingerprint`, then `agentbox assertion FILE` with what the platform team returns, and
open that directory in your editor. The steps below are the checkout equivalents.

1. **Clone the bundle.**
2. **Bootstrap your machine's secrets.** This generates your workspace client token (it
   identifies your workspace to your broker and never leaves your machine), the model-gateway
   token, and a development CA, and writes their paths into `.env`:

   ```bash
   npm run bootstrap
   ```

   It ends by listing what is still missing. Fill in the App ID and key (or KMS) settings and
   the model key file path your platform team gave you.
3. **Set your commit identity** in `.env` (`AGENTGATE_GIT_NAME`, `AGENTGATE_GIT_EMAIL`).
4. **Bring the stack up and get your token's fingerprint.**

   ```bash
   docker compose up -d --build
   docker compose exec workspace agentgate fingerprint
   ```

   This prints the SHA-256 of your client token. Send that fingerprint, not the token, to the
   platform team with your runtime request: your email, the agent you use (`cursor`,
   `claude-code`, ...), your team, the work mode you need, and the ticket you are working.
5. **Install your runtime assertion.** The platform team returns a signed assertion file (see
   the next section). Save it and point `.env` at it, then renew:

   ```bash
   cp ~/Downloads/runtime-assertion ~/.agentgate-runtime-assertion
   echo "AGENTGATE_RUNTIME_ASSERTION_PATH=$HOME/.agentgate-runtime-assertion" >> .env
   docker compose up -d --force-recreate workspace   # Compose does not remount a secret whose path changed
   docker compose exec workspace agentgate doctor
   ```

   With the installed command this is one step, `agentbox assertion ~/Downloads/runtime-assertion`,
   which also confirms the workspace reads the new file.

   `doctor` shows who you are acting as, when the assertion expires, that it is bound to your
   token, and that the broker, gateway, and proxy are reachable. Every check must be `ok`.
6. **Open the workspace in your editor.** *Reopen in Container* from VS Code, Cursor, or
   Windsurf. workspace.md "Using an IDE with the workspace". Or use the terminal:

   ```bash
   docker compose exec workspace bash
   git clone https://github.com/YOUR-ORG/YOUR-REPO
   ```

7. **Work normally.** Clone, fetch, push, `agentgate pr create`, `agentgate ci list`. A push that
   policy sends to approval fails with a request ID; a reviewer approves in approval-web; push
   again.

## When something is wrong

`agentbox check` on the host and `agentgate doctor` in the workspace name most of these directly.

| Symptom | Cause | Fix |
| --- | --- | --- |
| Every Git and model call fails with a TLS or certificate error about a month after setup | The 30-day development CA and broker certificate expired | `agentbox init` (or `npm run bootstrap`) renews them, then `agentbox up --force-recreate` |
| `doctor` says the assertion has expired right after you renewed it | The new file was moved over the old name; the workspace mounts the old inode | `agentbox assertion FILE`, or overwrite in place with `cp` and run `agentgate renew` |
| The assertion is missing after you set `AGENTGATE_RUNTIME_ASSERTION_PATH` | Compose does not remount a secret whose path changed | `docker compose up -d --force-recreate workspace` (`agentbox assertion` does this) |
| Nothing reaches GitHub or the model provider; egress audit shows `upstream-unreachable` | Outbound traffic must use the company forward proxy | Set `AGENTGATE_CORPORATE_PROXY`; see workspace.md "Behind a corporate forward proxy" |
| `npm`, `pip`, `curl`, or Git in the workspace fail certificate verification | The company proxy inspects TLS | Set `AGENTGATE_CORPORATE_CA_PATH` |
| Egress audit shows `upstream-proxy-refused` | The company proxy rejected the tunnel (credentials, or its own allow list) | Put credentials in the proxy URL, or ask the network team to allow the host |
| `agentbox up` builds for minutes, or fails fetching packages | Images are being built from source | Set `AGENTGATE_IMAGE` and `AGENTGATE_WORKSPACE_IMAGE` to the verified digests |
| A file setting is ignored, or `check` calls it relative | Compose runs from the package directory | Use the absolute path `check` prints |
| *Reopen in Container* starts a second stack or rebuilds the workspace | `.devcontainer` predates a settings change | `agentbox up` regenerates it; reopen afterwards |
| A Node tool in the workspace cannot resolve an allowed host | It ignores the proxy variables | `compose.yaml` sets `NODE_USE_ENV_PROXY=1` for the workspace from 0.2.0; upgrade, then `agentbox up` |

## Platform team, per developer request

With the issuer service deployed (`enterprise/compose.enterprise.yaml`, reached at `/issuer/` behind the
approval proxy), there is no per-request work: the developer signs in, pastes their fingerprint,
and issues their own assertion. The human claim is their login, and the team is limited to what
the directory says they hold. Administrators see every runtime and can revoke any of them.

Without the service, on the issuing host, with the developer's fingerprint and their
entitlement details:

```bash
node scripts/issue-runtime.js --key issuer.pem --kid k1 --audience agentgate:acme \
  --client-token-sha256 <fingerprint from the developer> \
  --runtime-id rt-jane-laptop --human jane@example.com --agent cursor --team payments \
  --mode build --task jira:PAY-12 --gh-login jane-example --ttl 28800 --out runtime-assertion
```

Return the `runtime-assertion` file to the developer. It is not a secret on its own (it only
works with the token whose fingerprint it carries, on that developer's broker), but treat it
as one anyway: it names a person and a task.

Renewal is the same command with a new `--ttl`; the developer overwrites the file in place
(`cp new-assertion ~/.agentgate-runtime-assertion`, or `agentbox assertion new-assertion`) and
runs `agentgate renew`. Do not move a new file over the old name: see identity.md "Renewal". Revocation before expiry is by `jti` or runtime ID in the revocations file
or a signed control-plane bundle. identity.md "Runtime identity assertions".

## What the developer never has

- The GitHub App private key or any installation token (KMS signs; the broker holds tokens in
  memory only).
- The model provider key (the gateway injects it).
- The issuer private key (the platform team mints assertions; the developer cannot widen their
  own identity).
- A GitHub credential in the IDE's Git integration (the devcontainer disables it, and the egress
  proxy denies GitHub anyway).

## What still needs the platform team's judgement

- The Compose stack runs on the developer's machine, so the developer is that machine's
  container administrator: they can read their own client token and admin socket. The security
  claim is that the *agent* cannot exceed the delegated identity, not that the developer cannot.
  THREAT_MODEL.md "Trust boundaries", "IDE attachment".
- The IDE's own assistant (Cursor's, Copilot's) sends prompts to its vendor from the developer's
  machine; only tools that honour `ANTHROPIC_BASE_URL` go through the gateway. workspace.md "Using an IDE
  with the workspace".
- The issuing service authenticates the developer through the identity provider, but its
  Ed25519 key is a file on the issuer host. Turn on `identity.delegation: "enforce"` so the
  broker also re-checks the team claim on every request against its own sources.
  THREAT_MODEL.md "Delegation model".
