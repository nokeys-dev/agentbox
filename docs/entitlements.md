# Entitlements

Compiling who the developer is (directory groups, GitHub teams, Okta, Entra) and what they are working on (Jira, ServiceNow) into an envelope that rules can require.

Part of the [AgentBox documentation](../README.md#documentation).

## Entitlements

Rules can require enterprise entitlements with an optional `requires` object. A
rule with `requires` matches only when **every** listed requirement is satisfied
(any one value within each list):

```json
{ "id": "team-write", "action": "git.push", "repository": "acme/payments-api", "ref": "refs/heads/agent/*",
  "effect": "allow", "requires": { "teams": ["payments"], "modes": ["build"] } },
{ "id": "hotfix", "action": "git.push", "repository": "acme/payments-api", "ref": "refs/heads/main",
  "effect": "approval", "approvals": 2, "requires": { "elevation": "jira" } }
```

`teams`, `groups`, and `owns` list 1-50 strings of at most 128 characters;
`elevation` is `jira`, `servicenow`, or `pagerduty` (`jira` and `servicenow` have sources
today); `modes` lists `build`, `operate`, or `readonly` (the assertion's `mode`;
static mode has no mode claim, so a `modes` requirement is unknown there).

Each requirement evaluates to satisfied, unsatisfied, or **unknown**. It is unknown
when a source that could supply its data failed (any `static` or `githubTeams`
failure makes `teams`/`groups`/`owns` unknown; a `jira` failure makes
`elevation: "jira"` unknown), when the identity input is missing (a `teams`
requirement while `githubTeams` is configured but the assertion has no `ghLogin`;
a `modes` requirement without a mode claim), or when no envelope exists. A rule is
unsatisfied if any requirement is unsatisfied, otherwise unknown if any is unknown.
**`allow` rules take part only when satisfied; `deny` and `approval` rules take part
unless unsatisfied**, so an outage can never lift a restriction or let a broader
allow through. Participating approval rules are merged as usual (highest
`approvals`, intersected `reviewerSources` and `mergeMethods`). A `requires.elevation`
of `servicenow` or `pagerduty` has no source yet: the broker logs
`entitlements.elevation_without_source` at load, and such rules never apply.

The broker compiles an envelope (`teams`, `groups`, `owns`, `elevation`, `mode`,
`errors`) once per request, only when some rule uses `requires`, from the optional
top-level `entitlements` sources (lazily, right before the request's first policy
decision; concurrent requests for the same runtime share one lookup):

```json
"entitlements": {
  "static": { "path": "/etc/agentgate/directory.json" },
  "githubTeams": { "org": "acme", "installationId": 1, "teams": ["payments"] },
  "jira": { "baseUrl": "https://acme.atlassian.net", "tokenFile": "/run/secrets/jira_token", "allowedStatuses": ["In Progress"] },
  "servicenow": { "baseUrl": "https://acme.service-now.com", "credentialFile": "/run/secrets/servicenow", "auth": "basic", "table": "change_request", "allowedStates": ["Implement"] },
  "okta": { "baseUrl": "https://acme.okta.com", "tokenFile": "/run/secrets/okta_token", "groups": ["eng", "payments-oncall"] },
  "entra": { "tenantId": "acme.onmicrosoft.com", "clientId": "00000000-0000-0000-0000-000000000000", "clientSecretFile": "/run/secrets/entra_client_secret", "groups": ["Engineering"] }
}
```

- `static` reads a JSON export (for example from AD/Entra or Backstage, written by
  a scheduled job) on each resolution:
  `{ "humans": { "dev@example.com": { "groups": [], "teams": [], "owns": [] } } }`.
  The human is matched case-insensitively.
- `githubTeams` checks `GET /orgs/{org}/teams/{slug}/memberships/{ghLogin}` for each
  listed slug with an org-scoped installation token (`members: read`, no
  repositories) and adds slugs whose membership is `active`. `ghLogin` comes only
  from a verified runtime assertion; without one, no teams are added.
- `jira` handles tasks of the form `jira:KEY-123`: it reads the issue's status and
  assignee over https (no redirects, 10 s timeout) and sets `elevation` when the
  status is in `allowedStatuses` (default `In Progress`) and the assignee's email
  equals the runtime's `human`. `tokenFile` must be owner-only (`chmod 600`); it is
  sent as a bearer token and read at startup and on every reload.

- `servicenow` handles tasks of the form `servicenow:CHG0030001` (or `INC…`,
  any 2-6 letter prefix and 5-12 digits): it reads the record from the Table API
  (`table` defaults to `change_request`; use `incident` for incidents) and grants
  `elevation: "servicenow"` only when the record's display state is in
  `allowedStates` (default `["Implement"]`) and `assigned_to.email` equals the
  runtime's `human`. `auth` is `basic` (credential file holds `user:password`) or
  `bearer` (an OAuth token). A record for a different number never counts.
- `okta` looks up `GET /api/v1/users/{email}/groups` with an SSWS token that has
  only `okta.users.read` and `okta.groups.read`, and supplies the configured
  `groups` the human belongs to. An unknown user holds none; an API failure makes
  `groups` unknown.
- `entra` uses Microsoft Graph with client credentials (`GroupMember.Read.All`
  application permission): `GET /users/{email}/memberOf/microsoft.graph.group`,
  matched by display name against the configured `groups`. The access token is
  cached until shortly before expiry and refreshed on 401. Live Entra group
  membership therefore needs no scheduled export; keep `static` for Backstage
  ownership or other catalogues.

Envelopes are cached per assertion `jti` (static mode: per `runtimeId`), up to
10,000 entries (expired first, then oldest evicted). **Positive results are cached
for 5 minutes**, so removing someone from a team or group, or reassigning or
closing a Jira issue, takes effect within that time (or immediately on SIGHUP
reload). Envelopes with a failed source are cached for 30 seconds. Failures
are logged as `entitlements.source_error` with the source name only and counted in
`agentgate_entitlement_source_errors_total{source}`; tokens and response bodies are
never logged. Decision audit records and approval contexts carry the envelope
summary so reviewers can see why a rule matched (an approval is also bound to it).
SIGHUP reload rebuilds all sources and drops cached envelopes.
