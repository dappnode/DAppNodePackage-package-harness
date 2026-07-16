# Dappnode Package Harness

This package is a small, reliable polling worker for Tropibot. On a dedicated, disposable Dappnode it claims one package job at a time, uses an already-installed target as its baseline when available (or installs one when absent), upgrades it to the candidate, captures bounded evidence, runs deterministic and advisory log analysis, restores an existing target to its original version (or removes a newly installed target and its volumes), and delivers the result back to Tropibot.

It is intentionally destructive. Never connect it to a personal or production Dappnode. The dedicated node is the safety boundary: cleanup is best effort and is not a security boundary. The harness refuses its own package and core packages, mutates only the claimed target, never mounts the Docker socket, and does not execute shell commands.

## Worker flow

```text
Tropibot claim → atomically persist claim → execute one package job
    → heartbeat phase/cancellation → cleanup → persist exact completion JSON
    → retry completion until Tropibot acknowledges it
```

The harness has no public job-submission or GitHub API. It needs outbound HTTPS access to Tropibot. `GET /healthz` is a process check; `GET /readyz` also checks destructive configuration, Dappmanager tool availability, and unresolved local recovery state.

For every accepted job, the deterministic controller:

1. verifies Dappmanager MCP tools and target safety;
2. checks whether the target is already installed; if so, records its exact version and uses it as the baseline;
3. otherwise installs the latest registry baseline, or the explicit `baselineRef`;
4. waits for a stable, non-empty all-running container set;
5. captures normalized details and bounded, redacted log tails;
6. upgrades the baseline in place to the candidate;
7. repeats stabilization and capture, compares both observations, and performs optional Nexus analysis;
8. restores a pre-existing target to its recorded version; otherwise removes only the target with `deleteVolumes: true`, and reports unexpected leftover dependencies.

Nexus is advisory. With no key, the harness uses the heuristic analyzer only. With a key, it sends one bounded redacted request with no tools; Nexus failures fall back safely, and Nexus can never override a deterministic failure.

## Configuration

Required worker settings are validated on startup:

```text
TROPIBOT_URL=https://tropibot.example
PACKAGE_HARNESS_WORKER_ID=worker-01
PACKAGE_HARNESS_WORKER_TOKEN=<shared trusted secret>
PACKAGE_HARNESS_POLL_SECONDS=10
PACKAGE_HARNESS_HEARTBEAT_SECONDS=20
```

The shared bearer token is appropriate for this small trusted v1 deployment. The protocol deliberately leaves room for later per-worker credentials or mTLS, but neither is part of this version. The worker never logs the token.

Use [`.env.example`](.env.example) for all timeout, Dappmanager, cleanup, and optional Nexus settings. `MCP_TIMEOUT_MS` bounds read-only Dappmanager calls at 30 seconds by default, while `MCP_MUTATION_TIMEOUT_MS` gives installs, updates, and removals 30 minutes by default (up to one hour). `TROPIBOT_TIMEOUT_MS` bounds each coordinator request. The Dappmanager MCP token and Nexus key remain local and are never sent to Tropibot or persisted in a job record.

## Local fake mode

Rust 1.96.1 is pinned by `rust-toolchain.toml`. The process reads a local `.env` if it exists; existing process variables take precedence.

```bash
mkdir -p .data
PACKAGE_MANAGER_MODE=fake \
DATA_DIR=./.data \
ALLOW_DESTRUCTIVE_PACKAGE_TESTS=true \
TROPIBOT_URL=https://tropibot.example \
PACKAGE_HARNESS_WORKER_ID=worker-01 \
PACKAGE_HARNESS_WORKER_TOKEN=development-token \
cargo run
```

The fake package manager makes ordinary candidates pass. A candidate reference containing `unstable` simulates non-running containers and `install-error` simulates a failed upgrade; both paths still run cleanup.

## Tropibot protocol and recovery

The worker uses the fixed v1 paths:

```text
POST /v1/package-harness/jobs/claim
POST /v1/package-harness/jobs/{jobId}/heartbeat
POST /v1/package-harness/jobs/{jobId}/complete
```

Every request carries `Authorization: Bearer <PACKAGE_HARNESS_WORKER_TOKEN>`, `Content-Type: application/json`, and `User-Agent: dappnode-package-harness/<version>`. Protocol DTOs and their golden fixtures live under [`src/coordinator`](src/coordinator) and [`tests/fixtures`](tests/fixtures).

Before mutating, the worker atomically persists the full claim and opaque claim token under `DATA_DIR`. It persists every recovery-relevant phase and, before network delivery, the exact serialized completion JSON. Transient coordinator failures retry with capped backoff and worker-specific jitter; the same bytes are retried after a restart. The worker never claims another job until completion is acknowledged as `recorded` or `duplicate`.

On restart, a pending completion is retried first. An interrupted job is never rerun: if it may have mutated the target, the worker inspects Dappmanager, performs bounded cleanup, then sends an `interrupted` worker-error completion. Cleanup failure, a lost claim, or a conflicting completion leaves the local record in manual-recovery state and makes `/readyz` fail until an operator resolves it.

Heartbeats run independently of package execution. A cancellation request is observed at safe phase boundaries and inside stabilization polling. It prevents a new mutating phase but never bypasses required cleanup. If Tropibot no longer recognizes the claim, the worker finishes the current operation, reconciles cleanup, and stops for operator inspection.

## Dappmanager MCP

For real nodes set at least:

```text
PACKAGE_MANAGER_MODE=mcp
DAPPMANAGER_MCP_URL=https://dedicated-test-dappnode.example/mcp
DAPPMANAGER_MCP_TOKEN=<token>
ALLOW_DESTRUCTIVE_PACKAGE_TESTS=true
```

Dappmanager must expose all seven tools listed in [`src/package_manager/mod.rs`](src/package_manager/mod.rs), including mutation tools. Before using a new Dappmanager version, run:

```bash
TROPIBOT_URL=https://tropibot.example \
PACKAGE_HARNESS_WORKER_ID=worker-01 \
PACKAGE_HARNESS_WORKER_TOKEN=development-token \
DAPPMANAGER_MCP_URL=... \
DAPPMANAGER_MCP_TOKEN=... \
cargo run -- --mcp-smoke
```

This checks the MCP transport, tool inventory, and normalized package listing without running a destructive test.

## Development and package build

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```

The `Makefile` provides matching development commands. To build the container and package scaffold:

```bash
docker build -t package-harness.dnp.dappnode.eth:0.1.0 .
npx @dappnode/dappnodesdk@0.3.52 build --skip_save --skip_upload
```

The runtime is non-root, keeps `/data` in a persistent volume, has no Docker socket or host networking, drops all Linux capabilities, and uses `no-new-privileges`.

More detail: [`docs/architecture.md`](docs/architecture.md) and [`docs/result-schema.md`](docs/result-schema.md).
