# SIEM detections over the forwarded audit stream

`scripts/detect.js` implements seven detections (`D1`–`D7`) over the record streams AgentBox
already produces. It is meant as a reference implementation an operator's real SIEM (Splunk,
Sentinel/KQL, Elastic, etc.) mirrors as scheduled searches or streaming rules; the detection IDs
are stable so a SIEM rule can cite one directly (e.g. an alert titled `D2-content-blocked`).

`detect(records, { protectedBranches })` is a pure function: `records` is an array of
already-parsed JSON objects, `protectedBranches` is an array of bare branch names (no
`refs/heads/` prefix — the same shape as a repository's `protectedBranches` in the broker
config). It returns `Alert[]`:

```
{ id: string, severity: 'high' | 'medium', runtimeId?: string, summary: string, evidence: number[] }
```

`evidence` lists the `seq` of every record backing the alert (per-record detections cite one
`seq`; windowed detections cite every record in the window that tripped the threshold).
`runtimeId` is omitted when no identity is available (see "Known gaps"). Detection never throws:
a record that is not an object, or is missing the fields a given detection needs (`seq`,
`timestamp`, or the detection's own filter fields), is silently skipped for that detection.
Input order does not matter — each detection sorts the records it cares about by timestamp
before sliding a window over them — and the returned alerts are in a deterministic order
(by `runtimeId`, then by the first `seq` in their evidence).

Windowed detections (D1, D3, D4, D6, D7) alert **once per burst**, not once per record and not
once per identity for the whole input: an alert fires when the sliding window first reaches the
threshold and cites every `seq` in that window; the detection then stays quiet while the window
remains at or above the threshold, and re-arms only after the window drains below it. A runtime
that bursts, goes quiet for longer than the window, and bursts again produces two alerts.

## Where the input comes from

Only `git.push`/`git.read`/GitHub-API decisions, `approval.review`, `config.*`, and error/
rejection records go through the broker's hash-chained audit (`src/state.js` `audit()`,
`src/audit-chain.js`) and get forwarded off-host by `scripts/audit-forward.js`. The egress proxy
(`src/egress-proxy.js`) and the model gateway (`src/model-gateway.js`) are separate processes
with their own `createLogger` output (`src/log.js`, JSON lines to stdout) — they are never part
of the chained audit and the forwarder never sees them. **`detect.js` expects the merged
stream**: concatenate the forwarded chained-audit records with the egress and model-gateway log
lines (e.g. via your log shipper) into one newline-delimited JSON file or pipe before running
detection; feeding it only the chained audit will silently starve `D3` and `D7` of input.

Run it locally for triage:

```sh
node scripts/detect.js merged.jsonl
node scripts/detect.js merged.jsonl --protected-branches=main,release
cat merged.jsonl | node scripts/detect.js -                 # stdin
node scripts/detect.js merged.jsonl --strict                # exit non-zero if any line failed to parse
AGENTGATE_PROTECTED_BRANCHES=main,release node scripts/detect.js merged.jsonl
```

It streams its input line by line (never buffers the whole file as one string) and prints one
JSON alert per line to stdout, so it composes with `jq`, a log shipper, or a scheduled cron job
that pipes into your SIEM's HTTP event collector. A line that fails to parse is skipped and
noted on stderr **by line number only** — never its content, since a record may carry a
`findings` path or other sensitive field. `--strict` makes the process exit non-zero once all
input has been read if any line was skipped (or, in strict mode, as soon as the first bad line is
seen); without it, `detect.js` degrades gracefully and keeps scanning.

## D1 — denial-burst

**Indicates:** a runtime probing the policy surface — trying ref after ref, repository after
repository, or operation after operation, until something is allowed.

**Fields:** `type: 'decision'`, `decision: 'deny'`, `runtime.runtimeId` (verified assertion
subject, or the static `config.runtime` for a single-runtime broker), `timestamp`, `seq`. Emitted
by `src/server.js` (repository/ref/LFS/push-option denials) and `src/github-api.js` (GitHub API
and merge denials) — every policy-level deny in the system uses this exact shape.

**Threshold:** 10 or more within a 10-minute sliding window, per `runtime.runtimeId`. Ten is
below what a legitimate CI-style agent would produce against a stable policy in ten minutes, and
high enough to not fire on one or two expected denials (e.g. an agent probing whether a specific
branch happens to be open before falling back).

**Severity:** medium (a normal policy is working as intended; it is the *volume* that is
suspicious).

**First response:** review the denied `action`/`repository`/`rule` values for the cited `seq`s to
see what the runtime was trying; if the pattern looks like brute-force probing rather than a
misconfigured client, consider revoking the runtime (Task 7's revocation list) pending review.

**SIEM query sketch (Splunk-like pseudocode):**

```
search index=agentgate type=decision decision=deny
| bucket _time span=10m
| stats count by "runtime.runtimeId", _time
| where count >= 10
```

## D2 — content-blocked

**Indicates:** a push was blocked by content scanning — a possible secret leaking into the
mirror, or an agent attempting to exfiltrate data by committing it.

**Fields:** `type: 'decision'`, `decision: 'content-blocked'`, `code: 'CONTENT_BLOCKED'`,
`runtime.runtimeId`, `approvalId`, `findings` (paths/patterns matched — **never** included in the
alert summary or otherwise echoed by `detect.js`). Emitted by `src/server.js` at the point
`scanPush()` (Task 6, `src/scan.js`) reports a hit on a push already past policy.

**Threshold:** none — every occurrence alerts (unwindowed). A single hit already warrants a look.

**Severity:** high.

**First response:** revoke the runtime via the revocation list (Task 7), inspect the blocked
commits in the broker mirror's quarantine (the objects never reached the real mirror or GitHub),
and rotate any real secret found. Confirm whether the finding was a true positive or a scanner
false positive before deciding whether to also review the runtime's other recent activity.

**SIEM query sketch:**

```
search index=agentgate code="CONTENT_BLOCKED"
| table _time "runtime.runtimeId" repository approvalId
```

## D3 — egress-probing

**Indicates:** a workspace probing the egress allowlist — scanning hosts/ports looking for an
open path off the allowlisted package registries, or testing whether a denied destination is
reachable some other way.

**Fields:** `type: 'egress'`, `decision: 'deny'`, `host`, `port`, `reason`, `timestamp`, `seq`.
Emitted by `src/egress-proxy.js` for every denied `CONNECT` attempt.

**Threshold:** 20 or more within a 10-minute window. Higher than `D1` because a single workspace
legitimately makes many outbound connections (package registry mirrors, CDN edges); 20 denials in
ten minutes is well past normal allowlist misses.

**Severity:** medium.

**Group key / known gap:** see "Known gaps" below — `src/egress-proxy.js` never saw a runtime
assertion prior to this task, so it cannot attribute a deny to a `runtimeId`. This task adds a
`client` field (the proxy's own tracked source socket address) to its audit events; `D3` groups
by that (`client:<address>`) instead. `Alert.runtimeId` for a `D3` alert is therefore a network
address, not a verified runtime identity — treat it as a strong hint for correlation (via DHCP/
container-runtime logs, or a 1:1 workspace-to-address deployment), not as authenticated identity.

**First response:** identify the workspace/runtime that owns the client address at the alert
time (from your container orchestrator's own logs, since the proxy itself doesn't know), inspect
the denied `host`/`port` values for the cited `seq`s, and treat this as a lower-confidence lead
than `D1`/`D2` given the address-only attribution.

**SIEM query sketch:**

```
search index=agentgate type=egress decision=deny
| bucket _time span=10m
| stats count by client, _time
| where count >= 20
```

## D4 — approval-rejections

**Indicates:** a runtime repeatedly requesting operations that human reviewers keep turning
down — either a misbehaving agent, or a reviewer flagging a pattern worth escalating.

**Fields:** `type: 'approval.review'`, `decision: 'deny'`, `context.runtime.runtimeId` (**not** a
top-level `runtime` field — the runtime identity is nested inside the persisted approval
`context`, per `src/state.js`), `reviewer`, `source`, `timestamp`, `seq`.

**Threshold:** 3 or more within 24 hours, per `context.runtime.runtimeId`. A day-long window
because human review is comparatively rare and slow; three rejections in a day is already an
unusual rate for a well-behaved runtime.

**Severity:** medium.

**First response:** read the rejected `context` (repository, changes/payload, rule) for the cited
approvals and check whether the runtime is retrying the *same* rejected request (possible replay/
automation bug) or making genuinely different requests reviewers keep declining (possible policy
gap or intentional misuse).

**SIEM query sketch:**

```
search index=agentgate type="approval.review" decision=deny
| bucket _time span=24h
| stats count by "context.runtime.runtimeId", _time
| where count >= 3
```

## D5 — off-hours-protected-push

**Indicates:** a policy-*allowed* push landed on a protected branch outside normal working
hours. Not a denial — policy let it through — but pushes to sensitive branches (`main`, release
branches) at 3 a.m. are worth a human glance even when authorized, since that is also when a
compromised or misused runtime is least likely to be noticed.

**Fields:** `type: 'decision'`, `decision: 'allow'`, `action: 'git.push'`, `changes` (an array of
`{ ref, oldOid, newOid, operation, effect, rule }` — `src/server.js` sets
`base.changes = decidePush(...).decisions`), `runtime.runtimeId`, `timestamp`. A repository's
`protectedBranches` (`src/config.js`) are configured as **bare branch names without
`refs/heads/`**; `detect.js` expands each to `refs/heads/<name>` before matching `changes[].ref`.
Pass the union of every repository's `protectedBranches` via `--protected-branches` (or
`AGENTGATE_PROTECTED_BRANCHES`); if repositories protect different branch names, a shared merged
stream means this can over-flag a push to a same-named-but-unprotected branch in another
repository — a known, accepted imprecision (see "Known gaps").

**Threshold:** none — any matching push between 22:00 and 06:00 UTC alerts (unwindowed). Adjust
the UTC boundary in `scripts/detect.js` (`isOffHoursUtc`) if your primary operating hours differ.

**Severity:** medium.

**First response:** confirm the push was expected (a scheduled release, an on-call fix) with the
runtime's owner; if not, treat it like any unexpected protected-branch change — check CI/deploy
status and consider a revert pending review. (`protectedBranches` here is the config surface used
for GitHub ruleset verification, `src/rulesets.js` — policy denial of protected-branch pushes, if
any, is a separate, repository-specific rule and shows up under `D1` instead.)

**SIEM query sketch:**

```
search index=agentgate type=decision decision=allow action="git.push"
| mvexpand changes
| where match(changes.ref, "^refs/heads/(main|release)$")
| eval hour=strftime(_time, "%H")
| where hour>=22 OR hour<6
```

## D6 — assertion-failures

**Indicates:** repeated failed runtime assertions — a runtime presenting an expired, forged, or
revoked assertion, or a caller brute-forcing the assertion header.

**Fields — the real shape, not a naive one:** `ASSERTION_INVALID` (`src/assertion.js`) is one of
five codes (`CLIENT_NOT_ALLOWED`, `UNAUTHENTICATED`, `RATE_LIMITED`, `ASSERTION_INVALID`,
`POLICY_EXPIRED`) that `src/server.js` deliberately does **not** write to the chained audit per
occurrence — an unauthenticated or barely-authenticated caller could otherwise force unlimited
fsync'd audit writes (disk pressure, forced rotation) just by sending bad requests. Instead they
are tallied in memory and flushed as a summary at most once per rolling 60-second window per
code: `{ type: 'rejections', code: 'ASSERTION_INVALID', count, windowStart }`. **There is no
per-runtime or per-caller identity on this record at all** — that is the whole point of
summarizing it. `D6` therefore sums `count` across `type: 'rejections', code: 'ASSERTION_INVALID'`
summaries within a 10-minute window, broker-wide, instead of counting individual events; the
resulting alert has no `runtimeId`.

**Threshold:** summed `count` reaching 5 or more within 10 minutes, broker-wide.

**Severity:** high (a burst of invalid assertions is one of the more direct signs of a credential
or assertion-issuance problem).

**Known detection-latency gap:** a summary only flushes when *another* rejection of the same code
arrives after its 60-second window elapses, or when the broker shuts down cleanly
(`src/server.js` `close()`). A final short burst with no follow-up traffic can sit unflushed in
memory indefinitely — `D6` will not see it until either another `ASSERTION_INVALID` occurs later
or the broker restarts. Do not rely on `D6` alone for real-time containment of an assertion
attack; pair it with rate-limit metrics (`agentgate_errors_total{code="ASSERTION_INVALID"}` is
counted immediately, per request, independent of the audit summary) if sub-minute detection
matters.

**First response:** correlate the alert's time window against `agentgate_errors_total` and
recent client network activity (broker access logs, TLS terminator logs) to find the source,
since the audit stream alone cannot; if a specific runtime's assertion is suspected compromised
or expired, rotate/revoke it (Task 7).

**SIEM query sketch:**

```
search index=agentgate type=rejections code="ASSERTION_INVALID"
| bucket _time span=10m
| stats sum(count) as total by _time
| where total >= 5
```

## D7 — model-volume

**Indicates:** an unusually large amount of data sent upstream to a proxied model API in a short
period — possibly bulk data exfiltration disguised as model traffic, rather than a normal prompt/
response exchange.

**Fields:** `type: 'model.request'`, `bytesUp`, `route`, `path`, `status`, `timestamp`, `seq`.
Emitted by `src/model-gateway.js` on every proxied call (success or failure).

**Threshold:** cumulative `bytesUp` reaching 50 MiB or more within a one-hour window.

**Severity:** medium (large payloads can be legitimate — big context windows, file uploads to a
model that accepts them — so this is a lead, not a confirmed incident).

**Group key / known gap:** identical to `D3` — `src/model-gateway.js` never saw a runtime
assertion either (every workspace presents the same shared `clientToken`); this task adds a
`client` field (the request socket's remote address) to its audit events, and `D7` groups by that
(`client:<address>`). Same caveat as `D3`: this is network-address attribution, not verified
runtime identity.

**First response:** identify the workspace/runtime that owns the client address at the alert
time, inspect which `route`/`path` absorbed the volume, and confirm with the runtime's owner
whether the volume was expected (e.g., a legitimate large-context batch job) before escalating.

**SIEM query sketch (KQL-like pseudocode):**

```
AgentBoxLogs
| where Type == "model.request"
| summarize TotalBytesUp = sum(BytesUp) by Client, bin(TimeGenerated, 1h)
| where TotalBytesUp >= 50 * 1024 * 1024
```

## Known gaps

Update (model gateway): with `identity` configured on the gateway and the workspace profile's
`ANTHROPIC_CUSTOM_HEADERS`, `model.request` records carry `runtime.runtimeId`, `runtime.human`,
and `runtime.jti` for tools that send the assertion (Claude Code, the Anthropic SDKs). Key `D6`
on `runtime.jti` when present and fall back to `client` otherwise. The same applies to `egress`
events when the proxy is configured with `identity` and the workspace sends its assertion as
proxy credentials: key `D3` on `runtime.jti` when present.

- **Egress and model-gateway records have no verified runtime identity.** Neither service ever
  sees the runtime assertion (`src/assertion.js` is only verified by `src/server.js`, the Git/API
  broker). This task adds a best-effort `client` field (source socket address) to both emitters'
  audit events so `D3`/`D7` can group *something*; treat any resulting `runtimeId` (rendered as
  `client:<address>`) as a network hint requiring external correlation (container/orchestrator
  logs), not an authenticated identity. A stronger fix would have each workspace present its
  runtime assertion to the egress proxy and model gateway too, which is out of this task's scope.
- **`ASSERTION_INVALID` (and the other four `REJECTION_SUMMARY_CODES`) are never audited
  per-event, by design**, and carry no identity even in their summarized form. `D6` is therefore
  broker-wide and can lag real time by up to the 60-second summary window (see D6's "Known
  detection-latency gap" above).
- **`D5`'s `protectedBranches` matching is global to whatever list you pass**, not scoped per
  repository. If your fleet has repositories with different protected-branch names, pass the
  union and expect some imprecision (a push to a same-named branch in an unprotected repository
  will also match). Splitting `detect.js` to accept a `{ [repository]: string[] }` map is a
  natural follow-up if this becomes a problem in practice.
- **A repository can also deny protected-branch pushes outright** via its own `git.push` policy
  rule; that shows up under `D1` (or as a single low-volume deny that never reaches `D1`'s
  threshold), not `D5` — `D5` only ever fires on pushes policy *allowed*.
- **Clock skew / out-of-order forwarding**: `detect.js` sorts by each record's own `timestamp`
  before windowing, so out-of-order arrival at the SIEM (batched forwarding, retries) is handled;
  it cannot correct for a wrong system clock on the broker or proxy host that produced the
  timestamp in the first place.
