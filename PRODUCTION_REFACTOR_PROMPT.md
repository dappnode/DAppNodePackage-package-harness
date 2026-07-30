# V1 Refactor Prompt: Package Harness Worker

You are working in `DAppNodePackage-package-harness`. Convert the current inbound job service into a small, reliable polling worker for tropibot.

This is intentionally a simple v1 for a trusted system with only a few workers. Do not introduce PostgreSQL, distributed consensus, fencing tokens, mTLS enrollment, worker capability scheduling, object storage, or a general workflow engine. Preserve clean interfaces so those can be added later.

The matching tropibot work is happening independently and in parallel. The HTTP protocol below is normative. Do not change endpoint paths, field names, casing, or response semantics without documenting the blocker.

Do not commit or push. Preserve all existing staged and unstaged user work.

## Responsibility boundary

The harness owns:

- Dappmanager access and destructive safety checks.
- One-at-a-time baseline/candidate execution.
- Stabilization, evidence capture, deterministic verdict, and cleanup.
- Heuristic and Nexus analysis.
- Redaction and size/time bounds.
- Local restart recovery.
- Polling tropibot and delivering results.

The harness does not own:

- GitHub credentials, comments, Checks, or Markdown rendering.
- Global job persistence or scheduling.
- PR-head freshness or result-publication policy.

Keep Nexus in the harness. Preserve the current bounded, redacted, no-tools request, heuristic fallback, and rule that Nexus cannot override deterministic failures.

## Simple v1 topology

```text
Harness
  -> poll tropibot
  -> persist claimed job locally
  -> execute one job
  -> heartbeat phase/cancellation state
  -> clean up
  -> persist exact completion payload
  -> retry completion until acknowledged
```

The worker needs outbound HTTPS access to tropibot. It should no longer require a publicly reachable mutation endpoint. Keep local health and readiness endpoints for supervision.

## Normative worker API v1

All JSON uses camelCase. Authenticate every request with one trusted shared secret:

```text
Authorization: Bearer <PACKAGE_HARNESS_WORKER_TOKEN>
Content-Type: application/json
User-Agent: dappnode-package-harness/<version>
```

Required configuration:

```text
TROPIBOT_URL=https://tropibot.example
PACKAGE_HARNESS_WORKER_ID=worker-01
PACKAGE_HARNESS_WORKER_TOKEN=<shared trusted secret>
PACKAGE_HARNESS_POLL_SECONDS=10
PACKAGE_HARNESS_HEARTBEAT_SECONDS=20
```

Validate values at startup and never log the token.

### Claim

`POST /v1/package-harness/jobs/claim`

```json
{
  "schemaVersion": 1,
  "workerId": "worker-01"
}
```

Responses:

- `204 No Content`: no work; wait the configured poll interval.
- `200 OK`: one job was atomically assigned to this worker.
- `401/403`: stop polling and report not-ready until configuration changes.
- `409`: this worker already has an unresolved job; reconcile local state.
- `429/5xx/network error`: retry with a small capped exponential backoff and jitter.

Claim response:

```json
{
  "schemaVersion": 1,
  "jobId": "gh-pr-42-0123456789ab-abcdef1234567890",
  "claimToken": "opaque-random-value",
  "source": {
    "repository": "dappnode/DAppNodePackage-example",
    "pullRequest": 42,
    "headSha": "0123456789abcdef0123456789abcdef01234567"
  },
  "package": {
    "dnpName": "example.dnp.dappnode.eth",
    "candidateRef": "/ipfs/QmCandidate",
    "baselineRef": null
  }
}
```

Persist the full claim before executing anything. Validate schema, job ID, package identity, references, and self/core-package restrictions before mutation.

### Heartbeat

`POST /v1/package-harness/jobs/{jobId}/heartbeat`

```json
{
  "schemaVersion": 1,
  "workerId": "worker-01",
  "claimToken": "opaque-random-value",
  "phase": "candidate_stabilization",
  "cleanupRequired": true
}
```

Response:

```json
{
  "schemaVersion": 1,
  "cancelRequested": false
}
```

Requirements:

- Heartbeat during long stabilization, analysis, and cleanup phases.
- Cancellation is checked at safe phase boundaries and inside bounded polling loops.
- Cancellation never skips required cleanup.
- A transient heartbeat failure does not erase the local job or permit claiming another.
- `404/409` means tropibot no longer recognizes the claim. Do not start another mutating phase; finish the current operation, reconcile and clean up, then retain the local record for operator inspection.

There is deliberately no automatic lease expiry or reassignment in v1. Tropibot may mark a silent worker as `worker_lost`, but a human or a later explicit retry decides what happens next.

### Complete

`POST /v1/package-harness/jobs/{jobId}/complete`

Normal result:

```json
{
  "schemaVersion": 1,
  "workerId": "worker-01",
  "claimToken": "opaque-random-value",
  "outcome": {
    "type": "result",
    "result": {}
  }
}
```

`outcome.result` is the existing harness result schema v1 and its `runId` equals `jobId`.

If the worker cannot produce a normal result, send:

```json
{
  "schemaVersion": 1,
  "workerId": "worker-01",
  "claimToken": "opaque-random-value",
  "outcome": {
    "type": "worker_error",
    "code": "interrupted",
    "summary": "bounded explanation",
    "cleanupStatus": "passed"
  }
}
```

Initial worker error codes are `interrupted`, `unsupported_job`, `cleanup_failed`, `local_persistence_failed`, and `unexpected_error`.

Completion responses:

- First valid payload: `200 { "schemaVersion": 1, "disposition": "recorded" }`.
- Exact duplicate: `200 { "schemaVersion": 1, "disposition": "duplicate" }`.
- Conflicting payload or invalid claim: `409`.

Persist the exact serialized completion body before sending it. Retry the identical body after transient failures and restarts. Do not claim another job until the completion is acknowledged. If cleanup failed, remain not-ready and retain the record for operator action.

## Required implementation

### 1. Replace inbound submission with polling

- Remove direct GitHub reporting, GitHub App credentials, JWT/token exchange, and Markdown rendering.
- Remove `github_pr_comment` configuration and dependencies.
- Remove the production use of `POST /v1/runs`; retain only read-only local diagnostics if useful.
- Add a typed `TropibotClient` or `CoordinatorClient` implementing claim, heartbeat, and complete.
- Keep protocol DTOs isolated in one module and add golden JSON fixtures.
- Bound request timeouts, response sizes, retries, and error previews.

### 2. Reuse simple local persistence

Keep the existing atomic file-based store rather than introducing a database. Extend the persisted record or add a small worker envelope containing:

- Full claimed job and claim token.
- Current phase and whether cleanup is required.
- Final result or worker error.
- Exact pending completion body.
- Completion acknowledgement state.
- A not-ready/manual-recovery reason when cleanup or claim reconciliation is unresolved.

Only one local active job is allowed. Persist before phase transitions that affect recovery.

Keep persistence behind the existing `RunStore` or a similarly narrow trait so SQLite or another implementation can be added later without changing the controller.

### 3. Integrate heartbeat and cancellation cleanly

- Keep the current `RunController`, `PackageManager`, analyzer, and comparison design where possible.
- Add a narrow progress/cancellation port rather than putting HTTP calls inside execution logic.
- Publish current phase to the heartbeat task.
- Check cancellation between phases and during stabilization polling.
- Once mutation may have happened, all cancellation/error paths must still clean up.
- Do not allow heartbeat work to block cleanup.

### 4. Recover safely after restart

On startup:

1. If a completion body is pending, resend it first.
2. If an interrupted job may have mutated the node, inspect Dappmanager state.
3. Perform bounded cleanup and confirm target absence.
4. Send a `worker_error` completion describing the interruption.
5. Poll for new work only after completion is acknowledged and cleanup is confirmed.

Never automatically rerun an interrupted job.

### 5. Preserve Nexus analysis

- Keep heuristic-only operation when no Nexus key is configured.
- Keep one bounded, redacted Nexus request with no tools.
- Never persist or send the Nexus credential.
- Keep Nexus failure advisory and non-blocking for cleanup/result delivery.
- Keep tests proving malformed or unavailable Nexus falls back safely.

### 6. Update packaging and documentation

Update `.env.example`, Compose, setup wizard, package metadata, README, architecture docs, and result docs:

- Replace inbound API/callback/GitHub settings with tropibot URL, worker ID, shared token, poll interval, and heartbeat interval.
- Explain that the token is appropriate for this small trusted v1 and can later become per-worker auth.
- Explain restart and manual-recovery behavior.
- Document that the Dappnode remains dedicated and disposable; cleanup is not a security boundary.
- Fix existing documentation inconsistencies such as the pinned Rust version.

## Deliberately deferred

Do not implement these in v1, but keep interfaces open for them:

- Per-worker credentials or mTLS.
- Leases, fencing tokens, and automatic failover.
- Multiple concurrent jobs per worker.
- Test-profile/capability scheduling.
- Ephemeral VM provisioning or snapshot automation.
- External evidence storage.

## Acceptance criteria

- Harness has no GitHub credentials or GitHub API code.
- Harness obtains work only by polling tropibot.
- Exactly one local job can execute.
- Claims and completion bodies survive restart.
- Completion delivery is idempotent and retried.
- Worker loss never causes automatic duplicate destructive execution.
- Cancellation still performs cleanup.
- Nexus remains in the harness with its current safety properties.
- Existing execution/verdict/cleanup tests remain meaningful.

Add tests for claim/no-job/auth failure, protocol fixtures, heartbeat cancellation, restart recovery, duplicate completion, conflicting completion, cleanup failure, and Nexus fallback.

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```

At completion, report changed files, tests run, remaining external work, and any protocol deviation. Do not commit or push.
