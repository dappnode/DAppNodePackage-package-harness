# Dappnode Package Harness

This repository contains the first runnable proof of concept for testing Dappnode package builds on a dedicated disposable Dappnode. A caller submits an explicit package name and candidate IPFS reference. The harness installs the canonical registry version as a control, upgrades it in place to the candidate, compares the two observations, removes the tested package and its volumes, and optionally sends a signed result callback.

This service is intentionally destructive. Never point it at a personal or production Dappnode. It refuses core packages and its own package identity, mutates only the submitted target, runs one test at a time, and never mounts the Docker socket or executes shell commands.

## Test flow

For each accepted run, the deterministic controller:

1. verifies the required Dappmanager MCP tools and safety gates;
2. snapshots installed packages and removes any existing target installation;
3. previews and installs the canonical/latest registry version, or the explicit `baselineRef`;
4. waits until at least one container is running and the same sorted container-name set is observed for the configured number of consecutive samples;
5. captures normalized package details and redacted log tails;
6. previews the exact candidate reference and upgrades the baseline installation in place;
7. repeats the same stabilization and capture implementation;
8. compares deterministic evidence, then performs optional advisory log analysis;
9. removes only the target package with `deleteVolumes: true`, reports new leftover dependencies without removing them, and delivers the result callback.

Package-specific liveness endpoints, RPC calls, health checks, and package-owned test manifests are deliberately not required. Dappnode packages are heterogeneous, while container existence and stable running state are universally observable through the current MCP contract. This check is useful but limited: a running container does not prove application-level correctness.

Log analysis is fuzzy and advisory. The always-available heuristic analyzer looks for a small bounded set of candidate-only signatures. Nexus, when configured, receives one bounded, redacted baseline-and-candidate request with no tools and no conversation history. A critical AI finding can only turn a deterministic pass into a warning; it cannot override a deterministic container failure. Redaction is defense in depth, not a guarantee that arbitrary logs contain no sensitive data.

## Local fake mode

Rust 1.96.1 is pinned by `rust-toolchain.toml`. Start the service without a Dappnode.

The service auto-loads a `.env` file from the working directory on startup, so you can keep development configuration there. Process environment always wins over the file, and missing files are ignored. Copy `.env.example` to `.env` and edit it, or export variables in the shell instead.

Either way:

```bash
mkdir -p .data
PACKAGE_MANAGER_MODE=fake \
DATA_DIR=./.data \
HARNESS_API_TOKEN=development-token \
ALLOW_DESTRUCTIVE_PACKAGE_TESTS=true \
cargo run
```

In another terminal:

```bash
curl --fail-with-body \
  -H 'Authorization: Bearer development-token' \
  -H 'Content-Type: application/json' \
  --data @examples/run-request.json \
  http://127.0.0.1:8080/v1/runs

curl --fail-with-body \
  -H 'Authorization: Bearer development-token' \
  http://127.0.0.1:8080/v1/runs/pr-123-abcdef0-example-package
```

The fake package-manager implementation makes ordinary candidates pass. Use a `candidateRef` containing `unstable` to simulate a non-running candidate or `install-error` to simulate a failed upgrade; both paths still execute cleanup.

`GET /healthz` only checks the process. `GET /readyz` checks acceptance configuration and live MCP tool availability. The two run endpoints require the configured bearer token and accept at most 256 KiB of JSON.

## Real Dappmanager MCP mode

Set at least:

```bash
PACKAGE_MANAGER_MODE=mcp
DATA_DIR=./.data
HARNESS_API_TOKEN=replace-me
HARNESS_DNP_NAME=package-harness.dnp.dappnode.eth
ALLOW_DESTRUCTIVE_PACKAGE_TESTS=true
DAPPMANAGER_MCP_URL=https://dedicated-test-dappnode.example/mcp
DAPPMANAGER_MCP_TOKEN=replace-me
```

The MCP implementation uses the official `rmcp` 2.2.0 Streamable HTTP client and sends the configured token as bearer authentication. Dappmanager must expose all seven tools listed in `src/package_manager/mod.rs`. In particular, external MCP mutation tools must be enabled in the Dappmanager deployment; if only read tools are exposed, `/readyz` explicitly reports that mutating tools are probably disabled. The harness never sends `BYPASS_CORE_RESTRICTION` or `BYPASS_RESOLVER`.

Before running package tests against a new Dappmanager version, execute the interoperability milestone:

```bash
DAPPMANAGER_MCP_URL=... \
DAPPMANAGER_MCP_TOKEN=... \
cargo run -- --mcp-smoke
```

This initializes the official MCP transport, lists tools, verifies `dappnode_list_packages`, calls it, prints normalized package summaries, closes the transport, and exits. The full test harness should not be used against that endpoint until this succeeds.

All MCP operations, stabilization polls, cleanup polls, Nexus calls, and callback attempts are bounded. See `.env.example` for timeout and evidence limits. A missing Nexus key does not affect readiness or run completion.

## Result reporting

Set `RESULT_REPORTER` to choose how completed runs are delivered:

- `none` disables outbound reporting.
- `webhook` sends the raw signed harness result JSON to `RESULT_CALLBACK_URL`.
- `github_pr_comment` renders the result as Markdown and posts it directly to the pull request in `source.repository` / `source.pullRequest`.
- `auto` keeps the original PoC behavior: use `webhook` when `RESULT_CALLBACK_URL` is configured, otherwise report nowhere.

### Webhook authentication

Configure `RESULT_CALLBACK_URL` and `RESULT_CALLBACK_HMAC_SECRET` together when using webhook reporting. The URL is global and cannot be supplied by a job. The reporter serializes the versioned result once, computes HMAC-SHA256 over those exact raw bytes, and sends:

```text
X-Dappnode-Harness-Signature: sha256=<hex digest>
X-Dappnode-Harness-Run-Id: <runId>
Content-Type: application/json
```

Network errors, HTTP 408/429, and HTTP 5xx responses are retried at most three times. Other 4xx responses are not retried. Callback failure is persisted and never reruns the package test.

### GitHub PR comments

Configure:

```text
RESULT_REPORTER=github_pr_comment
GITHUB_APP_ID=<app id>
GITHUB_APP_PRIVATE_KEY_FILE=/run/secrets/github-app-private-key.pem
GITHUB_API_BASE_URL=https://api.github.com
```

The reporter calls:

```text
GET /repos/{source.repository}/installation
POST /app/installations/{installationId}/access_tokens
POST /repos/{source.repository}/issues/{source.pullRequest}/comments
```

It first signs a short-lived GitHub App JWT with `GITHUB_APP_PRIVATE_KEY` or `GITHUB_APP_PRIVATE_KEY_FILE`, exchanges it for an installation access token for `source.repository`, then posts a JSON body containing the Markdown comment. GitHub treats pull request comments as issue comments for this endpoint. The GitHub App installation needs permission to read repository metadata and write issue or pull request comments. Network errors, HTTP 408/429, and HTTP 5xx responses are retried at most three times for the final comment request; other 4xx responses are treated as final delivery failures.

## Persistence and restart behavior

Each validated run is atomically stored as one JSON file under `DATA_DIR` (`/data` in the package). Identical run IDs are idempotent; conflicting reuse returns HTTP 409. Queued runs are reloaded after restart. Previously running runs are marked `interrupted` and are not replayed. With `RECOVER_CLEANUP_ON_START=true`, the harness makes one bounded best-effort cleanup only after confirming that the interrupted target is installed, non-core, and not the harness.

Tokens and HTTP headers are not part of persisted run structures. Local log tails are redacted and bounded before persistence; callback evidence contains normalized summaries rather than arbitrary raw MCP JSON.

## Development and package build

Required checks:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```

The `Makefile` provides the Rust equivalents of the requested `dev`, `build`, `test`, `lint`, `typecheck`, and `start` workflows without adding a JavaScript runtime.

Build the container and Dappnode package scaffold:

```bash
docker build -t package-harness.dnp.dappnode.eth:0.1.0 .
npx @dappnode/dappnodesdk@0.3.52 build --skip_save --skip_upload
```

The SDK invocation is package-validation/build tooling only; Node.js is not present in the service or runtime image. The package uses a non-root runtime user, a persistent `/data` volume, no privileged mode, no host networking or mounts, no Docker socket, `no-new-privileges`, and no Linux capabilities.

## Current limitations

- Only default/empty setup-wizard settings are supported.
- Package-specific probes are not supported.
- Core packages and the harness package are not supported.
- The candidate is tested as an upgrade, not a clean installation.
- Dependency cleanup is reported but is not automatically performed.
- Log analysis is fuzzy and advisory.
- Container-running state does not prove application-level correctness.
- The callback URL is fixed global configuration.
- Jobs are accepted over HTTP even though polling may later suit Dappnodes behind NAT better.
- The PoC uses a single in-process FIFO and assumes one harness process.

Architecture details are in `docs/architecture.md`; the callback result contract is in `docs/result-schema.md`.
