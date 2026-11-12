# Dappnode Package Harness

This package is a small, reliable polling worker for Tropibot. On a dedicated, disposable Dappnode it claims one package job at a time, resolves the requested baseline (the latest published release when omitted), reuses an already-installed target only when it matches that baseline, upgrades it to the candidate, captures bounded evidence, runs deterministic and advisory log analysis, restores the intended target state, and delivers the result back to Tropibot.

It is intentionally destructive. Never connect it to a personal or production Dappnode. The dedicated node is the safety boundary: cleanup is best effort and is not a security boundary. The harness refuses its own package and core packages, mutates only the claimed target, never mounts the Docker socket, and does not execute shell commands.

## Worker flow

```text
Tropibot claim → atomically persist claim → execute one package job
    → heartbeat phase/cancellation → cleanup → persist exact completion JSON
    → retry completion until Tropibot acknowledges it
```

The harness has no public job-submission or GitHub API. It needs outbound HTTPS access to Tropibot. Its package UI opens an embedded expert operator dashboard at `/` with local job history, current stage and phase timing, worker and delivery state, recovery plans, package inventory, container stabilization samples, comparison signals, analyzer findings, cleanup status, and recovery controls. Raw package logs, claim tokens, and persisted completion payloads are not exposed. The dashboard can also read the current worker-lost record from Tropibot and, after the operator confirms the old process is fenced and cleanup is complete, either release the worker or release it and requeue the package. These requests are proxied by the harness backend; the shared worker token is never exposed to browser JavaScript. `GET /api/jobs` supplies local history and expert diagnostics, while `GET /api/coordinator/lost-job` supplies the coordinator recovery state. `GET /healthz` is a process check; `GET /readyz` also checks Dappmanager tool availability and unresolved local recovery state.

For every accepted job, the deterministic controller:

1. verifies Dappmanager MCP tools and target safety;
2. checks whether the target is already installed and persists whether cleanup must restore or remove it;
3. previews the requested `baselineRef`, or previews the latest published release when it was omitted, and reuses an installed package only when both its version and its install origin match that resolved baseline (an IPFS build can share a released version);
4. waits for a stable, non-empty all-running container set, reported Docker health, and every configured application readiness probe;
5. captures normalized details and bounded, redacted log tails;
6. upgrades the baseline in place to the candidate;
7. repeats stabilization and capture, compares both observations, and performs optional Nexus analysis;
8. restores a pre-existing target by removing it without deleting volumes and freshly installing the explicit IPFS baseline when supplied, or the latest published release (`*`) otherwise; a target that was initially absent is removed with `deleteVolumes: true`. Cleanup verifies the restored version/origin and readiness, then confirms that unrelated packages and their versions are unchanged and no unexpected dependencies remain. A cleanup that already passed, automatically or through an operator, is never repeated.

If ENS cannot resolve a requested registry baseline (`UnreachableName`, `ResolverNotFound`, or Dappmanager's `NOREPO` error), the job completes as `inconclusive` with reason `baseline_unresolvable`: “No resolvable published baseline; upgrade comparison skipped.” No package is installed, updated, or removed, including when a copy is already installed. This is a package prerequisite, not a worker-wide outage or a failed candidate test. The result is acknowledged normally and the worker continues polling; deterministic resolution failures are not retried within the job. Network failures, timeouts, and unrelated contract reverts retain their infrastructure-error classification.

For a package without a resolvable published release, the coordinator can supply a known-good `baselineRef` such as `/ipfs/<cid>` to test the upgrade path. This does not silently substitute the currently installed package or turn the job into an installation-only test. For an existing target, cleanup and restart recovery use that exact persisted IPFS reference, preserve volumes, and verify the restored origin. A missing or non-IPFS reference for a pinned recovery plan blocks cleanup before removal. Registry baselines (omitted, `*`, or semver) keep the latest-release restoration policy.

Nexus is advisory. With no key, the harness uses the heuristic analyzer only. With a key, it analyzes the captured redacted logs in bounded JSON batches with no tools. Every captured container and every byte of its final captured window is included; serialized JSON is never cut to fit. Container pairs stay together when possible, and larger pairs are explicitly marked as partial service windows. Batch scope and deterministic stabilization/collection facts prevent a request for one service from being mistaken for evidence missing from the whole package. Nexus can never override a deterministic failure.

`NEXUS_MAX_INPUT_BYTES` limits each batch's serialized evidence, rather than cutting off later containers. The analyzer runs at most three requests concurrently and at most 64 requests overall, within one `NEXUS_TIMEOUT_MS` deadline. It combines findings with critical findings first; failed or unfinished batches are reported as partial coverage, while completed findings are retained. A request-count or metadata-size limit produces an explicit analyzer error rather than silently dropping evidence. Capture keeps the latest redacted 64 KiB per container, and analysis does not apply another 16 KiB cut or a 20-container cutoff. `LOG_TAIL` still controls the finite source log window; genuinely empty or unavailable evidence can remain inconclusive.

With Nexus enabled, `NEXUS_CLASSIFIER_MODEL` defaults to `jev`; set it to an empty value to disable classification. Jev uses Nexus's `/systemone` endpoint, separately from the `/chat/completions` explanation model. It assesses a small sample from every captured container and can request more startup evidence only when both confidence and selected probability are at least 0.8. It never approves a test, drops a container, or suppresses comparative analysis. Each side can collect at most two additional samples, five seconds apart, with a five-second classifier deadline and ten-second follow-up read deadlines. Empty log captures also get bounded follow-up attempts. Unknown decisions, malformed responses, unsupported models, and classifier outages leave the existing evidence available for normal analysis.

## Configuration

Required worker settings are validated on startup:

```text
TROPIBOT_URL=https://tropibot.example
PACKAGE_HARNESS_WORKER_ID=worker-01
PACKAGE_HARNESS_WORKER_TOKEN=<shared trusted secret>
PACKAGE_HARNESS_POLL_SECONDS=10
PACKAGE_HARNESS_HEARTBEAT_SECONDS=20
```

Startup fails with a nonzero exit before the worker can claim jobs if any required check fails. Fix the reported setting or dependency and restart the harness. Checks include:

- Valid package identity, nonempty data directory, credential formatting, and absolute service URLs without embedded credentials, queries, or fragments. Tropibot requires HTTPS; local Dappmanager and Nexus endpoints may use HTTP.
- The destructive-test acknowledgement (`ALLOW_DESTRUCTIVE_PACKAGE_TESTS=true`).
- Durable storage: create, write, sync, rename, read back, and delete a temporary probe in `DATA_DIR`. Existing records are reconciled before polling begins.
- Authenticated Dappmanager tool discovery, including all three mutation tools, followed by package inventory, details, a one-line log sample, and an install preview for an installed package. These checks never install, update, or remove a package; the log sample is discarded.
- Authenticated Tropibot worker-protocol access through the read-only lost-job endpoint. This does not claim or release work, and an existing lost job remains available for recovery.
- When `NEXUS_API_KEY` is configured, a synthetic chat completion with `max_tokens: 1` verifies access to `NEXUS_MODEL`, including inference authorization and credit checks. This uses a small amount of inference credit and sends no package evidence. A token-limit completion proves access even if the provider omits message content; actual log analysis still requires usable, complete output. Startup fails if this check fails; analysis during an accepted job still has the heuristic fallback.
- Binding the supervision port before starting the worker.

The shared bearer token is appropriate for this small trusted v1 deployment. The protocol deliberately leaves room for later per-worker credentials or mTLS, but neither is part of this version. The worker never logs the token.

Use [`.env.example`](.env.example) for all timeout, Dappmanager, cleanup, and optional Nexus settings. `MCP_TIMEOUT_MS` bounds read-only Dappmanager calls at 30 seconds by default, while `MCP_MUTATION_TIMEOUT_MS` gives each install, update, or removal attempt 30 minutes by default (up to one hour). Transient transport and package-download failures are retried three times with bounded exponential backoff; tune this with `MCP_MUTATION_ATTEMPTS` and `MCP_MUTATION_RETRY_DELAY_MS`. A mutation that exceeds its deadline is never resent, because Dappmanager keeps running it: the harness instead polls for the requested state for up to another `MCP_MUTATION_TIMEOUT_MS` and fails the step if it is not reached. `NEXUS_TIMEOUT_MS` gives advisory Nexus analysis five minutes by default. If the target package was installed before a run, cleanup preserves its volumes and freshly installs the explicit IPFS baseline when supplied, or the latest published release otherwise; an initially absent target and its volumes are removed. The pre-run package version never replaces the requested baseline. `TROPIBOT_TIMEOUT_MS` bounds each coordinator request. The Dappmanager MCP token and Nexus key remain local and are never sent to Tropibot or persisted in a job record.

## Application readiness and recovery

Set `READINESS_PROFILES` to a JSON object keyed by package name. Profiles are operator configuration; coordinator jobs, package manifests, and model output cannot supply probe destinations. Invalid profiles prevent startup. With the default `{}`, readiness checks container state and any reported Docker health, but does not infer application health from a running process.

```json
{
  "example.dnp.dappnode.eth": {
    "probes": [
      {"type": "http", "name": "health", "url": "http://example.dappnode:8080/healthz", "expectedStatus": 200, "bodyContains": "ok"},
      {"type": "tcp", "name": "database-port", "host": "database.example.dappnode", "port": 5432},
      {"type": "json_rpc", "name": "rpc", "url": "http://example.dappnode:8545", "method": "net_listening", "expectedResult": true}
    ]
  }
}
```

Replace these illustrative endpoints with addresses reachable from the harness container. HTTP probes default to status 200 and can require a body substring. TCP checks prove only that a port accepts connections. JSON-RPC checks reject error responses and missing/null results; `expectedResult` optionally requires an exact JSON value, and `net_listening` requires `true` by default. Supported methods are `web3_clientVersion`, `eth_blockNumber`, `eth_syncing`, `net_listening`, `getblockchaininfo`, and `getnetworkinfo`. HTTP and JSON-RPC probes accept a `headers` object for authentication. URLs, headers, and response bodies are never recorded in readiness diagnostics; only safe probe names and generic failures are retained. HTTP redirects are not followed.

All probes must pass for the configured consecutive stabilization samples. A changed container set, identity, creation/start time, or restart count resets that streak when Dappmanager exposes those fields. Reported `starting` or `unhealthy` Docker health blocks readiness. Set `requireDockerHealth: true` in a profile to also reject missing Docker health. The live Dappmanager checked during development exposes container identity but does not expose Docker health or restart count, so those missing fields appear as **Not reported** in the dashboard; application probes provide the additional observation on that server.

`STABILIZATION_TIMEOUT_MS` bounds the entire readiness phase, including metadata calls, probes, and polling waits. Each individual probe has a five-second deadline; response bodies used for matching or JSON-RPC parsing are limited to 64 KiB. Cleanup resolves the latest release before removal, then checks the restored package's version/origin, readiness, and final inventory within one post-install `CLEANUP_TIMEOUT_MS` verification budget. Mutation calls retain their separate MCP deadlines. Restart recovery uses the same readiness profiles. Failed recovery holds the worker and prevents new jobs until recovery is resolved.

Reinstallation preserves existing volumes. It does not restore a volume snapshot or reverse database migrations; a downgrade that cannot become ready requires operator recovery.

## Local fake mode

Rust 1.99.1 is pinned by `rust-toolchain.toml`. The process reads a local `.env` if it exists; existing process variables take precedence.

```bash
mkdir -p .data
PACKAGE_MANAGER_MODE=fake \
ALLOW_DESTRUCTIVE_PACKAGE_TESTS=true \
DATA_DIR=./.data \
TROPIBOT_URL=https://tropibot.example \
PACKAGE_HARNESS_WORKER_ID=worker-01 \
PACKAGE_HARNESS_WORKER_TOKEN=development-token \
cargo run
```

The fake package manager makes ordinary candidates pass. A candidate reference containing `unstable` simulates non-running containers and `install-error` simulates a failed upgrade; both paths still run cleanup.

## Operational logs

The default `info` logs are a concise execution narrative while retaining searchable `event`, `run_id`, package, duration, attempt, and status fields. Log levels carry severity, so messages do not repeat it with decorative prefixes. Long MCP mutations announce every attempt and configured deadline; active jobs emit a heartbeat liveness line about once per minute; stabilization logs each bounded container-health sample; Nexus logs its model, input size, timeout, duration, and fallback error; and cleanup reports both its selected recovery action and final inventory verification. Credentials and raw package evidence are never logged. Internal startup, persistence, and heartbeat lifecycle messages are available at `debug`.

Set `RUST_LOG=dappnode_package_harness=debug,tower_http=info` for polling and persistence diagnostics. The normal package default remains `info` to avoid logging an empty Tropibot poll on every interval.

## Tropibot protocol and recovery

The worker uses the fixed v1 paths:

```text
POST /v1/package-harness/jobs/claim
POST /v1/package-harness/jobs/{jobId}/heartbeat
POST /v1/package-harness/jobs/{jobId}/complete
```

Every request carries `Authorization: Bearer <PACKAGE_HARNESS_WORKER_TOKEN>`, `Content-Type: application/json`, and `User-Agent: dappnode-package-harness/<version>`. Protocol DTOs and their golden fixtures live under [`src/coordinator`](src/coordinator) and [`tests/fixtures`](tests/fixtures).

Claim input is validated before persistence or execution: `runId` is a bounded safe identifier, `source.repository` is an ASCII `owner/repository` name, `source.headSha` is a 7–64 character hexadecimal commit ID, and package names and references use the shared Dappnode parsers.

Before mutating, the worker atomically persists the full claim and opaque claim token under `DATA_DIR`. It persists every recovery-relevant phase and, before network delivery, the exact serialized completion JSON. Transient failures and coordinator compatibility rejections retry the same bytes with capped backoff and worker-specific jitter, so a coordinator upgrade heals delivery without a worker restart. An acknowledged delivery also clears a completion-conflict hold, so a restart that redelivers successfully needs no operator. The worker never claims another job until completion is acknowledged as `recorded` or `duplicate`.

On restart, a pending completion is retried first. An interrupted job is never rerun: if it may have mutated the target, the worker inspects Dappmanager, performs bounded cleanup, then sends an `interrupted` worker-error completion. A lost claim is released locally after cleanup succeeds; if Tropibot still holds unresolved coordinator state, the next claim receives a conflict and polling stops without inventing new local recovery work. Manual recovery is reserved for failed cleanup, ambiguous local records, or a conflicting completion that proves Tropibot already holds different state for the claim.

If Tropibot has marked this worker lost, the dashboard shows the exact fenced job and its last phase. The operator may choose **Cleanup done — release & retry** or **Cleanup done — release only**. The backend calls Tropibot's authenticated `POST /v1/package-harness/jobs/{jobId}/ready` endpoint with explicit cleanup confirmation, displays Tropibot's retry disposition, and wakes the paused polling task so no package restart is required. The emergency operator-token abandonment endpoint remains a separate Tropibot operation.

After manually completing a failed target cleanup, acknowledge that exact run through the internal supervision API:

```bash
curl --fail-with-body \
  --request POST \
  --header 'content-type: application/json' \
  --data '{"runId":"gh-pr-177-f33e0a37375d-f0181f51d12f8734","action":"continueAfterCleanup"}' \
  http://HARNESS_HOST:8080/operator/recovery/action
```

This action accepts only cleanup holds; the same endpoint takes `confirmCleanup`, `retryCompletion` and `acceptCoordinatorResult` for completion conflicts, as the dashboard does. It preserves the claim token and stored result, records the operator-verified cleanup, clears the persisted hold, and wakes the paused worker without a container restart.

The dashboard's local worker control remains visible for completion conflicts. It shows whether cleanup is confirmed, a completion payload is persisted, the local claim is held, and Tropibot acknowledged a result. Once cleanup is confirmed, the operator can either retry the exact persisted completion or explicitly accept Tropibot's existing result and release the local claim. The latter is destructive to the saved delivery obligation and requires typing the exact run ID. The worker remains alive and paused while waiting for either action, so no package restart is needed.

For planned package updates or host maintenance, choose **Drain worker** in the dashboard first. The lifecycle moves from `accepting` to `draining`; no new claim request is started, while an already claimed job is allowed to finish mutation, mandatory cleanup, and persisted completion delivery. Restart only after the dashboard reports `drained` and **Safe to restart**. **Resume accepting jobs** cancels or exits a drain. A claim response that crosses the drain boundary is completed safely because the v1 coordinator protocol has no claim-release operation. `POST /operator/worker/drain` and `POST /operator/worker/resume` expose the same controls and require an `application/json` body (`{}`). `/readyz` returns unavailable while draining or drained, but `/healthz` remains a process liveness check. SIGTERM also requests a drain, but Docker's default stop timeout of 10 seconds is far shorter than a package mutation, so drain first. A stop that interrupts a job is reconciled on the next start: the worker cleans up the target and reports the job as `interrupted` without rerunning it.

Heartbeats run independently of package execution. A cancellation request is observed at safe phase boundaries and inside stabilization polling. It prevents a new mutating phase but never bypasses required cleanup. If Tropibot no longer recognizes the claim, the worker finishes the current operation, reconciles cleanup, and releases the obsolete local claim when the target is safe.

## Dappmanager MCP

For real nodes set at least:

```text
PACKAGE_MANAGER_MODE=mcp
DAPPMANAGER_MCP_URL=https://dedicated-test-dappnode.example/mcp
DAPPMANAGER_MCP_TOKEN=<token>
```

Dappmanager must expose all seven tools listed in [`src/package_manager/mod.rs`](src/package_manager/mod.rs), including mutation tools. Use a valid MCP bearer token and enable external MCP mutating tools in **System > Advanced**. The harness checks these capabilities automatically before accepting work. Before using a new Dappmanager version, you can also run:

```bash
TROPIBOT_URL=https://tropibot.example \
PACKAGE_HARNESS_WORKER_ID=worker-01 \
PACKAGE_HARNESS_WORKER_TOKEN=development-token \
DAPPMANAGER_MCP_URL=... \
DAPPMANAGER_MCP_TOKEN=... \
cargo run -- --mcp-smoke
```

This requires all seven tools and checks the MCP transport and normalized package listing without running a destructive test. It does not require the destructive-test acknowledgement or contact Tropibot or Nexus.

## Development and package build

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```

The opt-in live Nexus contract probe uses `.env` credentials and a small amount of inference credit, sends synthetic logs only, and checks both Jev collection advice and a regression after a large cAdvisor log: `cargo test --test nexus_live -- --ignored --nocapture`. It is excluded from normal test runs.

The `Makefile` provides matching development commands. To build the container and package scaffold:

```bash
docker build -t package-harness.dnp.dappnode.eth:0.1.1 .
npx @dappnode/dappnodesdk@0.3.52 build --skip_save --skip_upload
```

The runtime is non-root, keeps `/data` in a persistent volume, has no Docker socket or host networking, drops all Linux capabilities, and uses `no-new-privileges`.

More detail: [`docs/architecture.md`](docs/architecture.md) and [`docs/result-schema.md`](docs/result-schema.md).
