# Security policy

AgentBox is a credential broker: a bug in it can expose repository write authority, provider
keys, or the audit trail. Reports are welcome and taken seriously.

## Reporting a vulnerability

- Use GitHub's [private vulnerability reporting](https://github.com/rvasqz86/agentbox/security/advisories/new)
  on this repository, or email security@nokeys.dev. Either way, include the commit or release, the
  component (`agentd`, workspace, issuer, gateway, proxy, approval UI, forwarder, control plane),
  steps to reproduce, and the impact against the attacker models in `docs/security-review-scope.md`.
- Do not open a public issue for anything that could let an agent exceed its delegated identity,
  reach a credential, bypass an approval, or alter the audit chain.
- You will get an acknowledgement within two business days and a fix or a mitigation plan within
  fourteen days for high and critical findings. We credit reporters in the changelog unless asked
  not to.

## Scope

In scope: everything under `src/`, `scripts/`, the Compose files, the workspace image and
profiles, and the deployment documentation's stated guarantees. `THREAT_MODEL.md` says what the
system claims to protect; a way to break a stated claim is a vulnerability, a limit it already
lists is not.

Out of scope: denial of service against upstream providers, attacks that require the broker
host, the Docker daemon, or the issuer key, and findings in third-party services (GitHub, the
identity provider, KMS) themselves.

## Supported versions

The `main` branch and the latest tagged release receive fixes. Releases are signed with cosign
and published by digest; verify before deploying (`docs/workspace.md`, "Verifying images").

## External review

No external security review has been completed yet. When one is, the report will be published
next to the threat model at nokeys.dev.
