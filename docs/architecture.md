# Architecture

The harness is a one-at-a-time polling worker. The local Axum server is supervision only; package jobs and result delivery are outbound to Tropibot.

```text
                 claim / heartbeat / complete over HTTPS
Tropibot  <-------------------------------------------->  Package harness
                                                              |
                                                              +-- RunStore → /data
                                                              +-- RunController → Dappmanager MCP
                                                              +-- LogAnalyzer → heuristic / Nexus
                                                              +-- local /healthz and /readyz
```

`CoordinatorClient` owns the three normative worker endpoints and their DTOs. It adds bearer authentication and the package version user-agent, bounds request timeouts and response bytes, previews errors, and classifies retryable failures. Golden fixtures make the camelCase JSON contract explicit.

`PackageHarnessWorker` persists a full claim before execution, then starts a heartbeat task beside the controller. The controller depends only on the narrow `RunProgress` port: it publishes its already-persisted phase and reads cancellation/claim-loss signals. No coordinator HTTP call runs in the controller or can block cleanup.

`RunRecord.worker` holds the opaque claim token, mutation/cleanup flag, final worker error when no normal result exists, exact pending completion JSON, acknowledgement status, and a manual-recovery reason. The atomic file store writes a temporary file in `/data` and persists it atomically. Only one unacknowledged claimed record is allowed to proceed.

On startup the worker finds an unresolved record before it polls. It retries a pending completion first. If an active job might have changed Dappmanager, it checks the target, refuses the harness and core packages, and reconciles the target: it restores the recorded pre-test version when the target existed before the run, otherwise it removes the target. It then sends an `interrupted` worker error. It never reruns the interrupted test. A failed reconciliation, lost claim, or conflicting completion stays visible as a not-ready/manual-recovery condition.

The controller’s baseline and candidate paths share stabilization and capture. Stabilization requires a non-empty, all-running container list with the same sorted names across consecutive samples. Failed detail calls, empty lists, non-running states, and container-set changes reset the streak. Evidence history, log collection, redaction, and analysis input are bounded.

Nexus receives only a single redacted, bounded request with no tools or conversation history. Its typed result is advisory; a failure falls back to the heuristic analyzer and no Nexus result can turn a deterministic failure into a pass.

V1 deliberately does not contain leases, fencing tokens, automatic reassignment, distributed persistence, worker scheduling, object storage, or per-worker authentication. The coordinator and persistence ports keep those additions possible without changing the deterministic execution core.
