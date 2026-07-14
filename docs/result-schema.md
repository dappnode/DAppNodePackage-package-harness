# Result schema version 1

`RunRecord.result` and Tropibot completion `outcome.result` use `schemaVersion: 1`. Enum values are stable `snake_case` strings. Unknown future result fields should be ignored by consumers; request version 1 is intentionally strict and rejects unknown fields.

Top-level fields:

| Field | Meaning |
| --- | --- |
| `schemaVersion` | Result contract version, currently `1`. |
| `runId` | Caller-selected safe idempotency key. |
| `source` | Repository, pull request number, and head SHA supplied by the trusted build flow. |
| `package` | Target name, requested references, and versions reported by Dappmanager. |
| `execution` | Completed execution status and UTC timing. Execution status is separate from verdict. |
| `verdict` | `passed`, `failed`, `warning`, `inconclusive`, or `infrastructure_error`. |
| `reasonCode` | Central machine-readable reason such as `candidate_containers_stable`. |
| `summary` | Bounded human-readable explanation. |
| `baseline`, `candidate` | Install timing, hard check, normalized containers, and log collection metadata. |
| `comparison` | Added/removed containers, versions, timing, last non-running states, and deterministic regressions. |
| `logAnalysis` | Advisory heuristic, Nexus, or composite analysis with bounded findings. |
| `cleanup` | Cleanup status, bounded error, and packages not present in the initial snapshot. |
| `errors` | Bounded typed run errors with the phase where each occurred. |

Representative successful result:

```json
{
  "schemaVersion": 1,
  "runId": "pr-123-abcdef0-example-package",
  "source": {
    "repository": "dappnode/example-package",
    "pullRequest": 123,
    "headSha": "abcdef0123456789"
  },
  "package": {
    "dnpName": "example.dnp.dappnode.eth",
    "baselineRequestedRef": null,
    "baselineResolvedVersion": "1.0.0",
    "candidateRef": "/ipfs/QmCandidate",
    "candidateReportedVersion": "1.0.1"
  },
  "execution": {
    "status": "completed",
    "startedAt": "2026-07-10T12:00:00Z",
    "finishedAt": "2026-07-10T12:01:00Z",
    "durationMs": 60000
  },
  "verdict": "passed",
  "reasonCode": "candidate_containers_stable",
  "summary": "Baseline and candidate containers became stably running",
  "baseline": {
    "install": { "status": "passed", "durationMs": 1000 },
    "hardCheck": {
      "passed": true,
      "reasonCodes": [],
      "containerCount": 1,
      "stableSamples": 3
    },
    "containers": [],
    "logCollection": { "status": "passed", "containerCount": 1 }
  },
  "candidate": {
    "install": { "status": "passed", "durationMs": 1000 },
    "hardCheck": {
      "passed": true,
      "reasonCodes": [],
      "containerCount": 1,
      "stableSamples": 3
    },
    "containers": [],
    "logCollection": { "status": "passed", "containerCount": 1 }
  },
  "comparison": {
    "baselineHardCheck": true,
    "candidateHardCheck": true,
    "baselineContainers": ["service"],
    "candidateContainers": ["service"],
    "containersAdded": [],
    "containersRemoved": [],
    "baselineVersion": "1.0.0",
    "candidateVersion": "1.0.1",
    "baselineStabilizationMs": 10000,
    "candidateStabilizationMs": 10000,
    "baselineLastNonRunningStates": [],
    "candidateLastNonRunningStates": [],
    "baselineLogsCollected": true,
    "candidateLogsCollected": true,
    "deterministicRegressions": []
  },
  "logAnalysis": {
    "analyzer": "heuristic",
    "status": "clean",
    "summary": "No configured candidate-only suspicious signature was found",
    "baseline": { "status": "clean", "summary": "No configured suspicious signature was found" },
    "candidate": { "status": "clean", "summary": "No configured suspicious signature was found" },
    "newFindings": []
  },
  "cleanup": { "status": "passed", "leftoverPackages": [], "error": null },
  "errors": []
}
```

## Worker completion envelope

Tropibot receives a normal result in this envelope:

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

If no normal result can be safely produced, the worker sends `type: "worker_error"` with one of `interrupted`, `unsupported_job`, `cleanup_failed`, `local_persistence_failed`, or `unexpected_error`, plus a bounded `summary` and `cleanupStatus`. The exact serialized envelope is stored before delivery and retried unchanged until Tropibot replies with `recorded` or `duplicate`.

The persisted surrounding `RunRecord` includes request, phase history, bounded redacted capture evidence, local worker-delivery state, and this result. The opaque claim token must be retained locally to complete after restart; the Tropibot shared bearer token, Dappmanager token, Nexus key, authorization headers, and raw unredacted logs are never result-schema fields.
