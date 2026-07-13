# Architecture

The controller depends only on capability traits defined alongside their implementations. Axum, the MCP SDK, Reqwest, filesystem persistence, and Nexus parsing remain outside the runner.

```text
GitHub App
    |
    | authenticated run request
    v
Harness HTTP API
    |
    v
Deterministic RunController
    |
    +--> DappmanagerPackageManager --> Dappmanager MCP
    |
    +--> LogAnalyzer -------------> Heuristic / Nexus
    |
    +--> RunStore ----------------> /data
    |
    +--> ResultReporter ----------> GitHub App callback
```

The Axum API validates versioned request DTOs and converts them to newtyped model values before persistence. A bounded in-process channel feeds one worker, making package mutation strictly serial. Every phase transition is persisted with a UTC timestamp.

`PackageManager` exposes only package-oriented operations. The Dappmanager implementation creates a bounded official `rmcp` Streamable HTTP session for an operation, detects MCP-level errors, concatenates text content, parses its JSON in one place, normalizes containers, and closes the session. Raw `serde_json::Value` never enters the runner or model modules.

The baseline and candidate use the same stabilization and capture functions. Stabilization requires a non-empty container list, every container marked `running`, and an unchanged sorted name set across the configured consecutive window. Failed calls, empty lists, non-running states, and set changes reset the window. Both attempts and stored sample history are bounded.

Cleanup is a final-path operation once preflight authorizes the non-core target. It removes only that target with volumes, polls for absence, and compares the final package list with the preflight snapshot. A cleanup failure does not replace the original verdict, though it promotes an otherwise passing result to a warning.

The file store uses a temporary file in the destination directory followed by an atomic persist/rename. The PoC assumes one process and uses no database or distributed lock.

Nexus receives only redacted, bounded evidence in one request. Log text is explicitly untrusted data in its system instruction, no MCP tools are provided, `tool_choice` is `none`, and its typed response remains advisory. The redactor covers common authorization values, secret-bearing keys, URI credentials, private-key blocks, and long token-like strings, but is documented as defense in depth rather than perfect sanitization.
