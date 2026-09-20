# Operations

Environment variable reference, source map, audit forwarding, and monitoring.

Part of the [AgentBox documentation](../README.md#documentation).

## Development

Environment variables not covered in the sections above:

| Variable | Read by | Meaning |
| --- | --- | --- |
| `GITHUB_APP_ID` | agentd | GitHub App ID used to sign App JWTs (required) |
| `AGENTGATE_PORT` | agentd | Broker listener port (default 7432) |
| `AGENTGATE_MIRROR_DIR` | agentd | Scan mirror directory (default `$AGENTGATE_STATE_DIR/mirrors`) |
| `AGENTGATE_REVOCATIONS_FILE` | agentd | Local assertion revocation list, re-read when it changes (`AGENTGATE_REVOCATIONS_POLL_MS`, default 5000) and on SIGHUP (static-config mode only) |
| `AGENTGATE_APPROVAL_HOST` / `AGENTGATE_APPROVAL_PORT` | approval-web | UI listener (default `127.0.0.1:7433`; Compose sets `0.0.0.0` on the `approval` network) |
| `AGENTGATE_AUDIT_SINK_TOKEN_FILE` | audit forwarder | Runtime path of the sink bearer token (Compose: `/run/secrets/audit_sink_token`, from `AGENTGATE_AUDIT_SINK_TOKEN_PATH`) |
| `AGENTGATE_MODEL_GATEWAY_CLIENT_TOKEN_FILE` | model-gateway | Gateway client token (Compose: from `AGENTGATE_MODEL_GATEWAY_CLIENT_TOKEN_PATH`) |
| `AGENTGATE_MODEL_GATEWAY_TOKEN_FILE` | workspace entrypoint | Exported as `ANTHROPIC_AUTH_TOKEN` |
| `AGENTGATE_IMAGE` | `npm run test:docker` | agentd image to check (default `agentgate:local`) |
| `AGENTGATE_PROTECTED_BRANCHES` | `scripts/detect.js` | Comma-separated branches for D5 when `--protected-branches` is not given |

| Path | Purpose |
| --- | --- |
| `src/server.js` | Git HTTP listener and separate admin socket |
| `src/git-protocol.js` | Strict receive-pack ref parser |
| `src/policy.js` | Default-deny authorization |
| `src/state.js` | Durable approvals and JSONL audit |
| `src/github.js` | GitHub App JWTs and scoped token cache |
| `src/github-api.js` | Allowlisted PR/CI routes, policy, and response filtering |
| `src/workspace-*.js` | Workspace Git setup and developer CLI |
| `src/log.js` | Structured JSON logging and credential redaction |
| `test/` | Policy, protocol, approval, provider, and real Git tests |

The broker, `npm run audit:forward`, and the daemon's own startup and ruleset
checks all log structured JSON lines (one object per line, with `time`,
`level`, and `msg` fields) via `src/log.js`. `AGENTGATE_LOG_LEVEL` (default
`info`; also `debug`, `warn`, `error`) controls verbosity. Any field whose key
matches token/authorization/secret/password/private/cookie/signature
(case-insensitive, checked recursively through nested objects and arrays) is
replaced with `[REDACTED]` before the line is written, so request URLs,
headers, and bodies are never logged — the broker logs one
`request.complete` line per request (route, method, status, duration,
repository, action) instead. `info`/`debug` write to stdout; `warn`/`error`
write to stderr for the daemon and audit-forwarder CLI.

Audit events are appended to `.agentgate/audit.jsonl` with runtime identity,
request ID, repository, decisions, ref updates, and upstream HTTP status. HTTP
200 means a response was received; Git's response body determines whether each
ref was actually updated. Upstream credentials and request headers are not
written to the audit stream. Audit write failure blocks forwarding.

Pushes stream: the broker buffers only the command section (at most 1 MiB), decides
on it, and only then streams the pack upstream. The default request limit is 2048 MiB
(`AGENTGATE_MAX_BODY_MIB` allows 1–4096 MiB) and counts every byte; exceeding it
mid-stream aborts the upstream request. A push may take up to 30 minutes, and a client
that sends no body data for 120 seconds is disconnected. Concurrency is limited to
`AGENTGATE_MAX_CONCURRENT` requests (1–64, default 4; beyond that, `503 BUSY`), so a few slow clients can hold every slot for up to the 30-minute timeout;
the per-client rate limit, the inactivity bound, and running one broker per workspace
limit the impact. Fetch negotiation bodies are buffered up to 32 MiB. Git downloads stream. API requests
are limited to 64 KiB and responses to 4 MiB.

Each client (identified by remote address) is limited to a token-bucket rate of
`AGENTGATE_RATE_CAPACITY` requests (default 60) refilling at
`AGENTGATE_RATE_REFILL_PER_SECOND` per second (default 2); in assertion mode a
second bucket per runtime `jti` uses `AGENTGATE_RUNTIME_RATE_CAPACITY` and
`AGENTGATE_RUNTIME_RATE_REFILL_PER_SECOND` (defaulting to the same values), see
[identity.md](identity.md#fleet-mode-one-broker-many-workspaces). Requests beyond the
budget get a `429 RATE_LIMITED` response with a `retry-after` header. The rate
limiter runs before the Host/Origin check and authentication (`/healthz` is
the only unlimited, unauthenticated route), so a flood of disallowed-origin or
unauthenticated requests is throttled rather than handled without limit.
`CLIENT_NOT_ALLOWED`, `UNAUTHENTICATED`, and `RATE_LIMITED` rejections are
never written as a per-request audit record — an unauthenticated or
disallowed client could otherwise force unlimited fsync'd audit writes just by
sending traffic. They are instead tallied in memory and flushed as at most one
`{ type: 'rejections', code, count, windowStart }` summary record per code per
60-second window (and once more on shutdown for a still-open window). Pending
approvals are capped (`maxPending`, default 50) to bound broker memory and
prevent a flood of push requests from exhausting the approval queue; once the
cap is hit, new approval requests fail with `429 TOO_MANY_PENDING` until an
approval is reviewed or expires. Approval history older than the retention
window (default 7 days) is pruned on save. The broker refuses to write new
approvals or audit events when the state volume's free space drops below
256 MiB (`503 DISK_LOW`), and fails closed rather than silently dropping audit
records.

The audit log rotates once `audit.jsonl` reaches `AGENTGATE_AUDIT_MAX_MIB`
(default 64 MiB) into a timestamped `audit-<epoch-ms>-<hrtime>.jsonl` file, and
keeps at most `AGENTGATE_AUDIT_MAX_FILES` (default 20) rotated files, deleting
the oldest first. Ship rotated audit files to durable storage before they age
out of that window; deleting them loses local evidence of broker decisions.

Each audit record is hash-chained: it carries a `seq`, the `prevHash` of the
previous record, and a `hash` covering both. `npm run audit:verify [directory]`
replays every rotated file (oldest first) and `audit.jsonl`, recomputing hashes
to detect edits, deletions, reordering, or rewritten history, and prints
`OK <n> records head <seq>:<hash>` or fails with `FAIL <file>:<line> <reason>`.
The broker itself refuses to start if its own audit tail fails this check. A
chain only proves the log is internally consistent since genesis (or since the
oldest file still on disk); it cannot stop a host that deletes or rewrites the
entire log, which is why rotated files should still be shipped off-host
promptly.

### Audit forwarding

`npm run audit:forward` (or the `audit-forwarder` service in `enterprise/compose.enterprise.yaml`) ships
chained audit records off-host over HTTPS so a compromised or wiped broker
host cannot erase the only copy of its own history. `forwardOnce` reads
`audit.jsonl` and any rotated files, verifies the pending records extend the
chain recorded in a local checkpoint (mode `0o600`, written atomically), and
posts them to the sink in `seq` order; the checkpoint only advances after the
sink accepts a batch, so a crash or a sink error can cause the same batch to
be resent (at-least-once delivery) and the receiving sink should dedupe on
each record's `hash`. Configure the sink with `AGENTGATE_AUDIT_SINK_URL`
(must be `https://`), `AGENTGATE_AUDIT_SINK_TOKEN_PATH` (a bearer token file
mounted into the container as a secret, checked owner-only and non-empty the
same way as the workspace client token), and `AGENTGATE_AUDIT_FORWARD_INTERVAL_MS`
(default 5000) between polls. The sink should write into WORM/object-lock storage
and alert on `audit.forward.failed` log lines: a `CHAIN_BROKEN` code means
local records were tampered with or corrupted, and an `AUDIT_GAP` code means
records were rotated out (see `AGENTGATE_AUDIT_MAX_FILES` above) before this
forwarder could ship them; both are treated as security events and the
forwarder keeps retrying rather than skipping ahead.

The `audit-forwarder` Compose service mounts the broker's state volume
**read-only** — the forwarder sits on the internet-facing upstream network, so
a compromised forwarder must never be able to write `approvals.json` or the
audit files themselves. Its checkpoint therefore lives in a separate,
forwarder-only read-write volume, at the path in `AGENTGATE_AUDIT_CHECKPOINT_PATH`
(Compose sets `/var/lib/agentgate-forward/audit-forward.json`). The broker
itself never writes or reads this checkpoint. Outside Compose, when unset it
defaults to `<AGENTGATE_STATE_DIR>/audit-forward.json`, so a local run where
the broker and forwarder share one state directory keeps working unchanged.

### Monitoring

The broker can expose Prometheus metrics on a second, unauthenticated HTTP
listener kept separate from the Git/API listener, so a monitoring scraper
never needs (and is never granted) the workspace bearer token. Set
`AGENTGATE_METRICS_PORT` to enable it (`AGENTGATE_METRICS_HOST` defaults to
`127.0.0.1`); the daemon logs the resulting `metricsUrl` at startup. The
metrics listener binds to exactly one address, so a host of `0.0.0.0` would
expose it on every network the container joins, including `workspace`. Compose
therefore gives the `monitoring` network a fixed subnet (`172.30.94.0/24`),
pins `agentd` to `172.30.94.10` on it, and sets `AGENTGATE_METRICS_HOST` to
that address: `/metrics` answers at `http://agentd:9464/metrics` from the
`monitoring` network, while a container on `workspace` gets a connection
refused on port 9464 (the main listener returns `404` for `/metrics`
regardless). If that subnet collides with an existing network, change the
subnet, `ipv4_address`, and `AGENTGATE_METRICS_HOST` together (in
`compose.kms.yaml` too). Point Prometheus's scrape config at the `monitoring`
network.

Metrics:

- `agentgate_requests_total{route,status}` and `agentgate_request_duration_seconds{route}`
  — HTTP traffic and latency by route (`healthz`, `git`, `api`, or `other`)
  and response status.
- `agentgate_decisions_total{action,decision}` — policy decisions
  (`allow`/`deny`/`approval`) by action (`git.read`/`git.push`).
- `agentgate_upstream_failures_total{action}` — GitHub rejected an already-approved request.
- `agentgate_entitlement_source_errors_total{source}` — entitlement source failures (`static`, `github-teams`, `jira`, `servicenow`, `okta`, `entra`).
- `agentgate_approval_reviews_total{decision}` — approvals reviewed through the admin CLI.
- `agentgate_approvals_pending` — approvals currently awaiting review.
- `agentgate_active_requests` — in-flight broker requests (compare against `AGENTGATE_MAX_CONCURRENT`).
- `agentgate_lfs_active_transfers` — in-flight Git LFS object transfers (compare against `AGENTGATE_LFS_MAX_TRANSFERS`).
- `agentgate_audit_head_seq` — latest audit chain sequence number.
- `agentgate_audit_forward_lag_records` — audit records not yet acknowledged by
  the off-host sink (`agentgate_audit_head_seq` minus the forwarder's
  checkpoint `seq`, read from `AGENTGATE_AUDIT_CHECKPOINT_PATH`); reports `-1`
  when the checkpoint is missing or unreadable (for example before the
  forwarder has run once), which is not the same as zero lag.
- `agentgate_errors_total{code}` — every error response returned to a client,
  by `GateError` code, including `UNAUTHENTICATED`, `CLIENT_NOT_ALLOWED`, and
  `RATE_LIMITED` (which never get a per-request audit record — see "Audit
  forwarding" above — but are still counted here from the rejection path).

All label values are bounded, broker-chosen enums (route names, policy
actions/decisions, `GateError` codes) — never repository names, ref names, or
anything else a client controls.

`examples/prometheus-alerts.yml` has example alerting rules for these
metrics: audit-forward lag, upstream failures, an approvals backlog, the
broker failing closed on low disk (`DISK_LOW`), a burst of unauthenticated
requests, and the broker being unreachable. Load it into Prometheus/Alertmanager
alongside a scrape job (`job: agentgate`) that targets the `monitoring`
network address.

This version accepts ordinary unsigned SHA-1 pushes, shallow pushes, push
options allowlisted per repository (see "Push options" below), and, opt-in
per repository, NFC-normalized Unicode ref names (see "Unicode ref names"
above); signed pushes (push certificates), SHA-256 pushes, compressed
requests, Git LFS locking, and APIs outside the PR/CI allowlist are unsupported and
rejected — GitHub itself does not support signed or SHA-256 pushes. Repositories
using the still-unsupported features need a later protocol implementation.
Signed push requests are distinct from signed commits, whose objects can pass
through.

CI runs syntax checks, tests, and the demo on Node 22 and 24, and builds and tests
the workspace image. To run the container check locally:

```bash
docker build --tag agentgate-workspace:local --file examples/workspace.Dockerfile .
npm run test:docker
```

Build the agentd image too (`docker build --tag agentgate:local .`, or set `AGENTGATE_IMAGE`):
the check fails unless it ships `git` 2.39 or newer. It also starts the model gateway and checks
that it refuses unauthenticated and non-allowlisted requests. The egress check inside it probes an
allowlisted registry through the proxy, so `npm run test:docker` needs internet access.

It creates disposable containers and volumes, verifies Git/PR/CI commands against
a local test broker, checks home persistence across recreation, and checks that
direct GitHub HTTPS is blocked on the test network. Test resources are removed
on completion. The tests use local repositories and mocked GitHub responses; the
live GitHub App smoke test below is still required for your installation. This
check does not certify all deployment egress paths or hostile-workload isolation.
