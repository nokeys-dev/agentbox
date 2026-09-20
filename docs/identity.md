# Runtime identity

How each agent runtime gets a signed, revocable identity delegated from a developer: assertions, the issuing service and dashboard, the fingerprint flow, fleet mode, renewal, and revocation.

Part of the [AgentBox documentation](../README.md#documentation).

## Runtime identity assertions

By default (`identity.mode: "static"`) the broker serves the single `runtime`
identity in its config file. In assertion mode, each workspace instead presents a
signed runtime assertion minted on the trusted host, and `agentgate` takes the
human, agent, runtime ID, team, work mode, and task from it on every request.

1. Create an issuer key on the trusted host. Only the public key goes to the broker;
   the private key never goes to the broker or any workspace:

   ```bash
   umask 077
   openssl genpkey -algorithm ed25519 -out issuer.pem
   openssl pkey -in issuer.pem -pubout -out issuer.pub.pem
   ```

2. Replace `runtime` in `config.local.json` with an `identity` section (`publicKeyPem`
   is the PEM text with `\n` line breaks; 1-10 issuers, unique `kid`s):

   ```json
   "identity": {
     "mode": "assertion",
     "audience": "agentgate:acme",
     "issuers": [{ "kid": "k1", "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n" }]
   }
   ```

3. Issue an assertion bound to that workspace's client token (at most 24 hours).
   When the issuer is on another host, the developer runs `agentgate fingerprint` in
   the workspace and sends the printed SHA-256 instead of the token; the issuer then
   passes `--client-token-sha256 <hex>` in place of `--client-token-file`, so the
   token never leaves the developer's machine (see `docs/onboarding.md`):

   ```bash
   node scripts/issue-runtime.js --key issuer.pem --kid k1 \
     --client-token-file ~/.agentgate-client-token --audience agentgate:acme \
     --runtime-id rt-42 --human dev@example.com --agent claude-code --team payments \
     --mode build --task jira:PAY-12 --ttl 28800 --out ~/.agentgate-runtime-assertion
   echo "AGENTGATE_RUNTIME_ASSERTION_PATH=$HOME/.agentgate-runtime-assertion" >> .env
   ```

The workspace sends it as the `x-agentgate-runtime` header next to the bearer
token: `agentgate` reads `AGENTGATE_RUNTIME_ASSERTION_FILE` on every call, and
workspace setup writes it into the managed gitconfig as a second
`http.<broker>/.extraHeader`. Requests without a valid assertion get 401
`ASSERTION_INVALID` (summarized, not audited per request). The broker checks the
signature, `kid`, `alg`/`typ`, audience, lifetime, client-token binding, claim
formats, and revocation (by `jti` or `sub:<runtimeId>`). Successful verifications
are cached by token hash until expiry; revocation is checked on every request.
Audit records carry the verified `runtime` (including `runtimeId` and `jti`),
never the raw assertion. Approvals are bound to the assertion's `jti`, so a renewed
assertion needs fresh approvals, and the assertion's `human` cannot approve its own
requests. Issuer changes apply on SIGHUP reload.

### Issuing service with a login

`enterprise/src/issuer-web.js` (`npm --prefix enterprise run issuer-web`, Compose
service `issuer-web` in `enterprise/compose.enterprise.yaml`, served by the same oauth2-proxy at
`/issuer/`) replaces the script for everyday use. A developer signs in through the
identity provider, enters a runtime ID, agent, team, mode, optional task, and the
fingerprint from `agentgate fingerprint`, and receives an assertion shown once. The
`human` claim is always the login email, never a form field, so the delegation is
authenticated. With `AGENTGATE_ISSUER_DIRECTORY_FILE` set to a directory export in
the `entitlements.static` format, the team must be one the developer holds, and a
directory failure issues nothing. The dashboard lists the developer's runtimes
(administrators in `AGENTGATE_ISSUER_ADMINS` see all) with status and a revoke
button; revoking writes `revocations.json`, which agentd mounts read-only as
`AGENTGATE_REVOCATIONS_FILE` and picks up changes automatically. Issuance and revocation are
recorded in an append-only `issued.jsonl` that never contains the assertion, only
its claims and the token fingerprint. The script remains for automation.

Administrators can also pull the whole inventory as JSON from `GET /issuer/api/runtimes`
(through the same proxy login): every issued runtime with its human, agent, team, mode,
task, issue and expiry times, status, and who revoked it. It never includes the assertion.
Point the control plane or a SIEM collector at it for the runtime inventory.

The team a developer may delegate can also be bounded by live directory data instead
of an export: point `AGENTGATE_ISSUER_ENTITLEMENTS_FILE` at a JSON file in the
broker's `entitlements` shape with any of `static`, `okta`, and `entra` (see
[entitlements.md](entitlements.md)); the union of teams and groups those sources
report for the login is what the developer may claim, resolved live on every
issuance, and a source outage issues nothing (503).

### Fleet mode: one broker, many workspaces

With `AGENTGATE_CLIENT_AUTH=assertion`
(and no `AGENTGATE_CLIENT_TOKEN_FILE`), the broker holds no workspace token at all.
Each request must carry a bearer token and an assertion whose `cnf` binding is the
SHA-256 of that exact token; the issuer decided which token belongs to which
runtime when it minted the assertion, so adding a workspace is issuing one
assertion, and removing it is a revocation. Requests with a token that does not
match their assertion, or without either, get 401. Approvals stay bound to the
assertion's `jti`, LFS transfers to the runtime, and every audit record names the
runtime, so nothing in the broker's state is shared between workspaces except the
repository mirrors. Static identity refuses fleet mode. The egress proxy and model
gateway still identify a workspace by source address and their own shared client
token; per-runtime attribution there is ROADMAP Milestone 2.

Each runtime also has its own request budget in assertion mode: a token bucket keyed
by the assertion `jti` (`AGENTGATE_RUNTIME_RATE_CAPACITY` and
`AGENTGATE_RUNTIME_RATE_REFILL_PER_SECOND`, defaulting to the per-address values),
so one workspace behind a shared address cannot spend its neighbours' budget.
`npm run test:fleet` exercises fleet mode in real containers: two workspaces with
their own tokens against one broker, cross-token rejection, and revocation.

### Delegation bound at verification

The issuer bounds the team at issuance. `identity.delegation` makes the broker
re-check it on every request against its own entitlement sources:

```json
"identity": { "mode": "assertion", "audience": "agentgate:acme", "issuers": [...], "delegation": "enforce" }
```

- `enforce`: a request whose assertion claims a team that is not among the teams or
  groups the sources report for its `human` gets 403 `DELEGATION_MISMATCH`, before
  any route, policy, LFS, or API handling. When membership cannot be established
  because a source failed, the request gets 503 `DELEGATION_UNKNOWN` (retryable)
  rather than a pass. Both are audited as `delegation-refused` with the claimed team.
- `audit`: the request proceeds and a `delegation-warning` record is written. Use it
  to find assertions minted with stale or hand-typed teams before turning on
  `enforce`.
- `off` (default): the check is skipped; the bound rests on the issuer alone.

`delegation` requires a membership source (`static`, `githubTeams`, `okta`, or
`entra`) and is only valid in assertion mode.

### Revocation without a control plane

agentd re-reads `AGENTGATE_REVOCATIONS_FILE` whenever its modification time, size, or
inode changes, polled every `AGENTGATE_REVOCATIONS_POLL_MS` milliseconds (default
5000; `0` disables polling and leaves SIGHUP as the only trigger). The issuer's
atomic rewrite is picked up within one interval with no operator action, and a
malformed rewrite is logged as `revocations.reload_rejected` while the previous list
stays enforced.

Set `AGENTGATE_REVOCATIONS_FILE` to an owner-only (chmod
600) JSON file `{ "jtis": [...], "runtimeIds": [...] }`. The broker refuses to start if the file is
unreadable or malformed, and re-reads it when it changes (or on SIGHUP): a bad file on reload is logged as
`revocations.reload_rejected` and the previous list stays enforced (`revocations.reloaded` on
success). Without this file (and without a control plane) nothing can revoke an assertion before
its expiry. The variable is refused in control-plane mode, where revocations come from signed
bundles.

### Renewal

Re-run `issue-runtime.js` before expiry, then run `agentgate renew` in
the workspace; it re-runs workspace setup so Git sends the new assertion. The
workspace entrypoint also does this on every container start.

Overwrite the assertion file in place (`cp new-assertion "$AGENTGATE_RUNTIME_ASSERTION_PATH"`).
The workspace mounts that one file, and a single-file mount follows the inode, not the path: a new
file moved over the old name (`mv`, a browser download, most editors' save) is never seen by the
running container, which keeps presenting the old assertion until it expires. `agentbox assertion
FILE` does the in-place overwrite, runs `agentgate renew`, and checks that the workspace reads the
new file; on a first install it sets `AGENTGATE_RUNTIME_ASSERTION_PATH` and recreates the workspace,
because Compose does not treat a secret's changed source path as a change to the service.
