const state = {
  jobs: [],
  filter: "all",
  query: "",
  loading: false,
  coordinatorLoading: false,
  jobsFingerprint: "",
  lostJob: null,
  lostJobFingerprint: "",
  worker: null,
  expandedJobs: loadExpandedJobs(),
  // Selected detail tab per run, kept across the periodic re-render.
  jobTabs: new Map(),
};

const elements = {
  jobs: document.querySelector("#jobs"),
  jobTable: document.querySelector("#job-table"),
  empty: document.querySelector("#empty-state"),
  error: document.querySelector("#error-notice"),
  workerState: document.querySelector("#worker-state"),
  workerLabel: document.querySelector("#worker-label"),
  workerMessage: document.querySelector("#worker-message"),
  updated: document.querySelector("#last-updated"),
  refresh: document.querySelector("#refresh-button"),
  search: document.querySelector("#search-input"),
  total: document.querySelector("#metric-total"),
  attention: document.querySelector("#metric-attention"),
  active: document.querySelector("#metric-active"),
  delivered: document.querySelector("#metric-delivered"),
  toastRegion: document.querySelector("#toast-region"),
  coordinatorRecovery: document.querySelector("#coordinator-recovery"),
  lostJobPackage: document.querySelector("#lost-job-package"),
  lostJobId: document.querySelector("#lost-job-id"),
  lostJobPhase: document.querySelector("#lost-job-phase"),
  lostJobHeartbeat: document.querySelector("#lost-job-heartbeat"),
  readyAndRetry: document.querySelector("#ready-and-retry"),
  readyWithoutRetry: document.querySelector("#ready-without-retry"),
  localRecovery: document.querySelector("#local-recovery"),
  localRecoveryTitle: document.querySelector("#local-recovery-title"),
  localRecoveryKind: document.querySelector("#local-recovery-kind"),
  localRecoveryReason: document.querySelector("#local-recovery-reason"),
  localRecoveryContext: document.querySelector("#local-recovery-context"),
  localRecoveryExplanation: document.querySelector("#local-recovery-explanation"),
  localRecoveryActions: document.querySelector("#local-recovery-actions"),
  drainLifecycle: document.querySelector("#drain-lifecycle"),
  drainCurrentJob: document.querySelector("#drain-current-job"),
  drainSafety: document.querySelector("#drain-safety"),
  drainStatus: document.querySelector("#drain-status"),
  drainWorker: document.querySelector("#drain-worker"),
  resumeWorker: document.querySelector("#resume-worker"),
};

/* -------------------------------------------------------------------------
   Formatting
   ------------------------------------------------------------------------- */

function humanize(value) {
  if (!value) return "Unknown";
  return value
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function compactRef(value) {
  if (!value) return "Latest published";
  if (value.length <= 44) return value;
  return `${value.slice(0, 24)}…${value.slice(-12)}`;
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return value;
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return value;
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}

function relativeTime(value) {
  if (!value) return "Not started";
  const date = new Date(value);
  const seconds = Math.round((date.valueOf() - Date.now()) / 1000);
  const absolute = Math.abs(seconds);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (absolute < 60) return formatter.format(seconds, "second");
  if (absolute < 3600) return formatter.format(Math.round(seconds / 60), "minute");
  if (absolute < 86400) return formatter.format(Math.round(seconds / 3600), "hour");
  return formatter.format(Math.round(seconds / 86400), "day");
}

function formatDuration(milliseconds) {
  if (milliseconds === null || milliseconds === undefined) return "—";
  const seconds = Math.max(0, Math.round(milliseconds / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

function elapsedBetween(start, end) {
  if (!start || !end) return null;
  const duration = new Date(end).valueOf() - new Date(start).valueOf();
  return Number.isFinite(duration) ? duration : null;
}

function yesNo(value) {
  return value ? "Yes" : "No";
}

function tryFormatJson(raw) {
  if (!raw) return null;
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------
   DOM helpers
   ------------------------------------------------------------------------- */

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function isNode(value) {
  return value && typeof value === "object" && "nodeType" in value;
}

function setContent(element, value) {
  if (isNode(value)) {
    element.append(value);
  } else {
    element.textContent = value === null || value === undefined || value === "" ? "—" : value;
  }
  return element;
}

function badge(value) {
  return node("span", `badge ${value || "pending"}`, humanize(value || "pending"));
}

function externalLink(label, href) {
  const link = node("a", "external-link", label);
  link.href = href;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  return link;
}

/** `<div><dt/><dd/></div>` for use inside a `.kv` description list. */
function kvItem(label, value, { mono = false } = {}) {
  const item = node("div");
  item.append(node("dt", null, label), setContent(node("dd", mono ? "mono" : null), value));
  return item;
}

function kvList(entries, className = "kv") {
  const list = node("dl", className);
  entries.forEach(([label, value, options]) => list.append(kvItem(label, value, options)));
  return list;
}

/**
 * Plain table. Cells may be strings, nodes, or `{ value, className }`.
 * `rowHeaders` renders the first cell of each row as a `<th scope="row">`.
 */
function table(headers, rows, { mono = false, rowHeaders = false, rowClass } = {}) {
  const wrapper = node("div", "table-wrap");
  const element = node("table", `table${mono ? " table-mono" : ""}`);
  const head = node("thead");
  const headRow = node("tr");
  headers.forEach((header) => headRow.append(node("th", null, header)));
  head.append(headRow);
  const body = node("tbody");
  rows.forEach((row, rowIndex) => {
    const tr = node("tr", rowClass ? rowClass(rowIndex) : null);
    row.forEach((cell, cellIndex) => {
      const header = rowHeaders && cellIndex === 0;
      const td = node(header ? "th" : "td");
      if (header) td.scope = "row";
      if (cell && typeof cell === "object" && !isNode(cell)) {
        if (cell.className) td.className = cell.className;
        setContent(td, cell.value);
      } else {
        setContent(td, cell);
      }
      tr.append(td);
    });
    body.append(tr);
  });
  element.append(head, body);
  wrapper.append(element);
  return wrapper;
}

function subsection(title, ...children) {
  const section = node("section", "subsection");
  if (title) section.append(node("h4", null, title));
  section.append(...children);
  return section;
}

function emptyCopy(text) {
  return node("p", "empty-copy", text);
}

function flag(ok, good, bad) {
  return { value: ok ? good : bad, className: ok ? "is-good" : "is-bad" };
}

/* -------------------------------------------------------------------------
   Network
   ------------------------------------------------------------------------- */

async function readJson(response, failureLabel = "Request failed") {
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`${failureLabel}: invalid JSON response (${response.status})`);
  }
  if (!response.ok) {
    throw new Error(payload?.error || `${failureLabel} (${response.status})`);
  }
  return payload;
}

function postJson(url, body) {
  return fetch(url, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

/* -------------------------------------------------------------------------
   Session storage
   ------------------------------------------------------------------------- */

function loadExpandedJobs() {
  try {
    return new Set(JSON.parse(sessionStorage.getItem("expandedHarnessJobs") || "[]"));
  } catch {
    return new Set();
  }
}

function persistExpandedJobs() {
  try {
    sessionStorage.setItem("expandedHarnessJobs", JSON.stringify([...state.expandedJobs]));
  } catch {
    // The dashboard still works when browser storage is unavailable.
  }
}

/* -------------------------------------------------------------------------
   Job detail tabs
   ------------------------------------------------------------------------- */

function captureSummaryRows(baseline, candidate) {
  const value = (capture, read) => (capture ? read(capture) : "Not captured");
  const rows = [
    ["Install", (c) => humanize(c.installStatus)],
    ["Install duration", (c) => formatDuration(c.installDurationMs)],
    ["Readiness passed", (c) => flag(c.stabilization.passed, "Yes", "No")],
    ["Stable samples", (c) => String(c.stabilization.stableSamples)],
    ["Application checks", (c) => {
      const checks = c.stabilization.samples?.at(-1)?.probeResults || [];
      return checks.length ? checks.map((check) => `${check.name}: ${check.passed ? "ready" : check.error || "not ready"}`).join(" · ") : "No application probes recorded";
    }],
    ["Stabilization time", (c) => formatDuration(c.stabilization.durationMs)],
    [
      "Logs",
      (c) =>
        c.logError
          ? { value: `${c.logEntryCount} entries · ${c.logError}`, className: "is-bad" }
          : `${c.logEntryCount} entries`,
    ],
  ];
  return rows.map(([label, read]) => [label, value(baseline, read), value(candidate, read)]);
}

function previewBlock(preview) {
  if (!preview) return emptyCopy("No install preview.");
  const wrapper = node("div", "preview");
  const entries = [
    ["Package", preview.packageName, { mono: true }],
    ["Version", preview.version, { mono: true }],
    ["Images", preview.imageCount === null || preview.imageCount === undefined ? null : String(preview.imageCount)],
    ["Requires input", yesNo(preview.requiresUserInput)],
  ].filter(([, value]) => value !== null && value !== undefined && value !== "");
  wrapper.append(kvList(entries, "kv kv-2"));
  const formatted = tryFormatJson(preview.summary);
  if (formatted) {
    const pre = node("pre", "json-block");
    pre.append(node("code", null, formatted));
    wrapper.append(pre);
  } else if (preview.summary) {
    wrapper.append(node("p", "muted", preview.summary));
  }
  return wrapper;
}

function containersTable(capture) {
  if (!capture?.containers.length) return emptyCopy("No containers recorded.");
  return table(
    ["Service", "State", "Docker health", "Restarts", "Image"],
    capture.containers.map((container) => [
      container.serviceName,
      { value: container.state, className: container.running ? "is-good" : "is-bad" },
      container.health || "Not reported",
      container.restartCount === undefined || container.restartCount === null ? "Not reported" : String(container.restartCount),
      { value: container.image, className: "mono" },
    ]),
  );
}

function samplesTable(capture) {
  if (!capture?.stabilization.samples.length) return emptyCopy("No samples recorded.");
  return table(
    ["Observed", "Containers ready", "Checks / error"],
    capture.stabilization.samples.map((sample) => [
      formatTime(sample.observedAt),
      flag(sample.allRunning, "yes", "no"),
      sample.error || [...sample.nonRunningStates, ...(sample.probeResults || []).map((probe) => `${probe.name}: ${probe.passed ? "ready" : probe.error || "not ready"}`)].join(", ") || "none",
    ]),
  );
}

/** One baseline/candidate row: both columns start at the same height. */
function pairRow(title, render, baseline, candidate) {
  const pair = node("div", "pair");
  [
    ["Baseline", baseline],
    ["Candidate", candidate],
  ].forEach(([label, capture]) => {
    const column = node("div");
    column.append(node("div", "pair-label", label));
    column.append(capture ? render(capture) : emptyCopy("Stage not captured."));
    pair.append(column);
  });
  return subsection(title, pair);
}

function renderCapturesTab(job) {
  const { baseline, candidate } = job.diagnostics;
  return [
    subsection(
      "Stage summary",
      table(["", "Baseline", "Candidate"], captureSummaryRows(baseline, candidate), {
        rowHeaders: true,
      }),
    ),
    pairRow("Containers", containersTable, baseline, candidate),
    pairRow("Stabilization samples", samplesTable, baseline, candidate),
    pairRow("Install preview", (capture) => previewBlock(capture.preview), baseline, candidate),
  ];
}

function renderComparisonTab(job) {
  const comparison = job.diagnostics.comparison;
  if (!comparison) return [emptyCopy("No comparison produced yet.")];
  const sections = [
    subsection(
      "Baseline vs candidate",
      table(
        ["", "Baseline", "Candidate"],
        [
          [
            "Version",
            { value: comparison.baselineVersion || "Unknown", className: "mono" },
            { value: comparison.candidateVersion || "Unknown", className: "mono" },
          ],
          [
            "Hard check",
            flag(comparison.baselineHardCheck, "Passed", "Failed"),
            flag(comparison.candidateHardCheck, "Passed", "Failed"),
          ],
          [
            "Stabilization",
            formatDuration(comparison.baselineStabilizationMs),
            formatDuration(comparison.candidateStabilizationMs),
          ],
          [
            "Logs",
            flag(comparison.baselineLogsCollected, "Collected", "Missing"),
            flag(comparison.candidateLogsCollected, "Collected", "Missing"),
          ],
        ],
        { rowHeaders: true },
      ),
    ),
  ];
  const signals = [
    ["Containers added", comparison.containersAdded],
    ["Containers removed", comparison.containersRemoved],
    ["Baseline non-running", comparison.baselineLastNonRunningStates],
    ["Candidate non-running", comparison.candidateLastNonRunningStates],
    ["Deterministic regressions", comparison.deterministicRegressions],
  ].filter(([, values]) => values?.length);
  sections.push(
    subsection(
      "Signals",
      signals.length
        ? table(
            ["Signal", "Values"],
            signals.map(([label, values]) => [label, { value: values.join(", "), className: "mono" }]),
            { rowHeaders: true },
          )
        : emptyCopy("No differences detected."),
    ),
  );
  return sections;
}

function jobErrors(job) {
  const errors = [...(job.diagnostics.errors || [])];
  if (job.diagnostics.workerError) {
    errors.unshift({
      phase: "worker",
      code: job.diagnostics.workerError.code,
      message: job.diagnostics.workerError.summary,
    });
  }
  return errors;
}

function renderErrorsTab(job) {
  const errors = jobErrors(job);
  const sections = [
    subsection(
      "Execution errors",
      errors.length
        ? table(
            ["Stage", "Code", "Message"],
            errors.map((error) => [
              humanize(error.phase),
              { value: error.code, className: "mono" },
              error.message,
            ]),
          )
        : emptyCopy("No execution errors recorded."),
    ),
  ];
  const analysis = job.diagnostics.logAnalysis;
  const analysisChildren = [];
  if (analysis) {
    analysisChildren.push(
      kvList([
        ["Analyzer", humanize(analysis.analyzer)],
        ["Status", badge(analysis.status)],
        ["Summary", analysis.summary],
      ], "kv kv-3"),
    );
    if (analysis.newFindings?.length) {
      analysisChildren.push(
        table(
          ["Severity", "Container", "Reason", "Evidence"],
          analysis.newFindings.map((finding) => [
            humanize(finding.severity),
            finding.container,
            finding.reason,
            { value: finding.evidence, className: "mono" },
          ]),
        ),
      );
    }
  } else {
    analysisChildren.push(emptyCopy("Log analysis has not run."));
  }
  sections.push(subsection("Log analysis", ...analysisChildren));
  return sections;
}

function renderTimelineTab(job) {
  const history = job.diagnostics.phaseHistory || [];
  if (!history.length) return [emptyCopy("No phase events recorded.")];
  const currentIndex = history.findLastIndex((entry) => entry.phase === job.phase);
  return [
    table(
      ["Time", "Phase", "Since previous"],
      history.map((entry, index) => {
        const previous = history[index - 1];
        const elapsed = previous ? elapsedBetween(previous.at, entry.at) : null;
        return [
          formatDate(entry.at),
          { value: entry.phase, className: "mono" },
          elapsed === null ? "—" : `+${formatDuration(elapsed)}`,
        ];
      }),
      { rowClass: (index) => (index === currentIndex ? "is-current" : null) },
    ),
  ];
}

function renderDeliveryTab(job) {
  const diagnostics = job.diagnostics;
  const sections = [
    kvList([
      ["Execution", humanize(job.status)],
      ["Current stage", humanize(job.phase)],
      ["Blocks next claim", yesNo(diagnostics.blocksWorker)],
      ["Cleanup required", yesNo(diagnostics.cleanupRequired)],
      ["Recovery plan", diagnostics.cleanupRequired ? humanize(diagnostics.targetRecovery) : "None"],
      ["Claim", job.hasClaim ? "Persisted" : "Released"],
      ["Saved completion", job.pendingCompletion ? "Pending" : "None"],
      ["Acknowledged", yesNo(job.completionAcknowledged)],
      ["Disposition", job.completionDisposition ? humanize(job.completionDisposition) : "—"],
    ]),
  ];
  if (diagnostics.workerError) {
    sections.push(
      node("p", "alert", `${humanize(diagnostics.workerError.code)} · ${diagnostics.workerError.summary}`),
    );
  }
  return sections;
}

function renderInventoryTab(job) {
  const rows = [];
  job.diagnostics.initialPackages.forEach((pkg) =>
    rows.push(["Before", { value: pkg.dnpName, className: "mono" }, { value: pkg.version, className: "mono" }, yesNo(pkg.isCore)]),
  );
  job.diagnostics.finalPackages.forEach((pkg) =>
    rows.push(["After", { value: pkg.dnpName, className: "mono" }, { value: pkg.version, className: "mono" }, yesNo(pkg.isCore)]),
  );
  return [
    rows.length
      ? table(["Snapshot", "Package", "Version", "Core"], rows)
      : emptyCopy("No package inventory captured."),
  ];
}

const JOB_TABS = [
  { id: "captures", label: "Captures", render: renderCapturesTab },
  { id: "comparison", label: "Comparison", render: renderComparisonTab },
  {
    id: "errors",
    label: "Errors & analysis",
    render: renderErrorsTab,
    count: (job) => jobErrors(job).length,
  },
  {
    id: "timeline",
    label: "Timeline",
    render: renderTimelineTab,
    count: (job) => (job.diagnostics.phaseHistory || []).length,
  },
  { id: "delivery", label: "Worker & delivery", render: renderDeliveryTab },
  { id: "inventory", label: "Inventory", render: renderInventoryTab },
];

function renderTabs(job) {
  const wrapper = node("div", "job-tabs");
  const tabList = node("div", "tabs");
  tabList.setAttribute("role", "tablist");
  const panel = node("div", "tab-panel");
  panel.setAttribute("role", "tabpanel");
  panel.id = `panel-${job.runId}`;

  const buttons = JOB_TABS.map((tab) => {
    const button = node("button", "tab");
    button.type = "button";
    button.id = `tab-${job.runId}-${tab.id}`;
    button.setAttribute("role", "tab");
    button.setAttribute("aria-controls", panel.id);
    button.append(node("span", null, tab.label));
    const count = tab.count?.(job);
    if (count) {
      const isAlert = tab.id === "errors";
      button.append(node("span", `tab-count${isAlert ? " is-alert" : ""}`, String(count)));
    }
    button.addEventListener("click", () => select(tab.id));
    tabList.append(button);
    return button;
  });

  function select(id) {
    const tab = JOB_TABS.find((candidate) => candidate.id === id) || JOB_TABS[0];
    state.jobTabs.set(job.runId, tab.id);
    buttons.forEach((button, index) => {
      const selected = JOB_TABS[index] === tab;
      button.setAttribute("aria-selected", String(selected));
      button.tabIndex = selected ? 0 : -1;
    });
    panel.setAttribute("aria-labelledby", `tab-${job.runId}-${tab.id}`);
    panel.replaceChildren(...tab.render(job));
  }

  tabList.addEventListener("keydown", (event) => {
    if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
    const current = JOB_TABS.findIndex((tab) => tab.id === state.jobTabs.get(job.runId));
    const step = event.key === "ArrowRight" ? 1 : -1;
    const next = (current + step + JOB_TABS.length) % JOB_TABS.length;
    select(JOB_TABS[next].id);
    buttons[next].focus();
    event.preventDefault();
  });

  select(state.jobTabs.get(job.runId) || "captures");
  wrapper.append(tabList, panel);
  return wrapper;
}

/* -------------------------------------------------------------------------
   Recovery
   ------------------------------------------------------------------------- */

const RECOVERY_TITLES = {
  cleanup: "Manual cleanup must be verified",
  completion_conflict: "Completion conflicts with Tropibot",
};

function recoveryActionButton(job, action, label, className = "button-primary") {
  const button = node("button", `button ${className}`, label);
  button.type = "button";
  button.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    runRecoveryAction(job, action, button);
  });
  return button;
}

/** Guidance text and action buttons for a job that holds the worker. */
function recoveryGuidance(job) {
  if (job.recoveryKind === "cleanup") {
    return {
      text: "Verify the target package is restored or removed as intended. Confirming records the manual cleanup and asks the live worker to reconcile again.",
      buttons: [recoveryActionButton(job, "continueAfterCleanup", "Cleanup verified — continue")],
    };
  }
  if (job.recoveryKind === "completion_conflict") {
    if (!["passed", "skipped"].includes(job.cleanupStatus)) {
      return {
        text: "Tropibot holds different state, but local cleanup is not recorded as safe. Verify the package state first; completion controls unlock after that confirmation.",
        buttons: [recoveryActionButton(job, "confirmCleanup", "Cleanup verified — unlock resolution")],
      };
    }
    return {
      text: "Tropibot already holds different state for this claim. Retry is non-destructive and resends the exact saved payload. Accept coordinator result permanently discards the local pending payload and releases the claim.",
      buttons: [
        recoveryActionButton(job, "retryCompletion", "Retry exact completion"),
        recoveryActionButton(job, "acceptCoordinatorResult", "Accept Tropibot result & release", "button-danger"),
      ],
    };
  }
  return {
    text: "This hold has no safe automated override. Inspect the reason and local record, then refresh after correcting the underlying state.",
    buttons: [],
  };
}

function renderJobRecovery(job) {
  const callout = node("section", "callout callout-warning");
  const title = node("div", "panel-title");
  title.append(node("h3", null, RECOVERY_TITLES[job.recoveryKind] || "Worker recovery required"));
  callout.append(title, node("p", "callout-reason", job.manualRecoveryReason));
  const guidance = recoveryGuidance(job);
  callout.append(node("p", "callout-note", guidance.text));
  if (guidance.buttons.length) {
    const actions = node("div", "actions");
    actions.append(...guidance.buttons);
    callout.append(actions);
  }
  return callout;
}

function renderLocalRecovery() {
  const job = state.jobs.find((candidate) => candidate.manualRecoveryReason);
  elements.localRecovery.classList.toggle("is-hidden", !job);
  if (!job) return;

  elements.localRecoveryTitle.textContent = RECOVERY_TITLES[job.recoveryKind] || "Worker recovery required";
  elements.localRecoveryKind.textContent = humanize(job.recoveryKind);
  elements.localRecoveryReason.textContent = job.manualRecoveryReason;
  elements.localRecoveryContext.replaceChildren(
    kvItem("Package", job.dnpName),
    kvItem("Run", job.runId, { mono: true }),
    kvItem("Cleanup", humanize(job.cleanupStatus)),
    kvItem("Saved delivery", job.pendingCompletion ? "Pending" : "None"),
    kvItem("Local claim", job.hasClaim ? "Held" : "Released"),
    kvItem("Tropibot acknowledgement", job.completionAcknowledged ? "Recorded" : "Missing"),
  );
  const guidance = recoveryGuidance(job);
  elements.localRecoveryExplanation.textContent = guidance.text;
  elements.localRecoveryActions.replaceChildren(...guidance.buttons);
}

function renderCoordinatorRecovery() {
  const job = state.lostJob;
  elements.coordinatorRecovery.classList.toggle("is-hidden", !job);
  if (!job) return;
  elements.lostJobPackage.textContent = job.package.dnpName;
  elements.lostJobId.textContent = job.jobId;
  elements.lostJobPhase.textContent = humanize(job.phase);
  elements.lostJobHeartbeat.textContent = job.lastHeartbeatAtMs
    ? `${formatDate(job.lastHeartbeatAtMs)} · ${relativeTime(job.lastHeartbeatAtMs)}`
    : "Not reported";
}

/* -------------------------------------------------------------------------
   Jobs
   ------------------------------------------------------------------------- */

function isActive(job) {
  return !job.completionAcknowledged && (job.status === "queued" || job.status === "running");
}

function jobMatches(job) {
  const filterMatch =
    state.filter === "all" ||
    (state.filter === "attention" && job.requiresAttention) ||
    (state.filter === "active" && isActive(job)) ||
    (state.filter === "completed" && job.status === "completed");
  const haystack = `${job.runId} ${job.dnpName} ${job.repository}`.toLowerCase();
  return filterMatch && haystack.includes(state.query);
}

function cell(className, primary, secondary) {
  const element = node("div", `cell ${className}`);
  element.append(isNode(primary) ? primary : node("div", "cell-primary", primary));
  if (secondary) element.append(node("div", "cell-secondary", secondary));
  return element;
}

function renderJobSummary(job) {
  const summary = node("summary");
  const date = cell(
    "cell-date",
    formatDate(job.createdAt),
    relativeTime(job.finishedAt || job.startedAt || job.createdAt),
  );
  date.title = `Created ${new Date(job.createdAt).toLocaleString()}`;
  summary.append(
    cell("cell-package", job.dnpName, job.runId),
    cell("cell-result", badge(job.verdict || job.status)),
    cell("cell-stage", humanize(job.phase)),
    cell("cell-cleanup", badge(job.cleanupStatus)),
    date,
    node("span", "chevron", "›"),
  );
  return summary;
}

function renderJobOverview(job) {
  const repositoryUrl = `https://github.com/${job.repository}`;
  const repository = node("span");
  repository.append(
    externalLink(job.repository, repositoryUrl),
    document.createTextNode(" · "),
    externalLink(`PR #${job.pullRequest}`, `${repositoryUrl}/pull/${job.pullRequest}`),
  );
  return kvList([
    ["Repository", repository],
    ["Head commit", externalLink(compactRef(job.headSha), `${repositoryUrl}/commit/${job.headSha}`), { mono: true }],
    ["Baseline", compactRef(job.baselineRef), { mono: true }],
    ["Candidate", compactRef(job.candidateRef), { mono: true }],
    ["Execution", humanize(job.status)],
    ["Reason", job.reasonCode ? humanize(job.reasonCode) : "—"],
    ["Errors", String(job.errorCount)],
    [
      "Delivery",
      job.completionAcknowledged
        ? `Acknowledged${job.completionDisposition ? ` · ${humanize(job.completionDisposition)}` : ""}`
        : "Not acknowledged",
    ],
    ["Created", formatDate(job.createdAt)],
    ["Started", formatDate(job.startedAt)],
    ["Finished", formatDate(job.finishedAt)],
    [
      "Elapsed",
      formatDuration(elapsedBetween(job.startedAt || job.createdAt, job.finishedAt || new Date())),
    ],
  ], "kv kv-overview");
}

function renderJobNotes(job) {
  const notes = [
    ["Summary", job.summary, false],
    ["Cleanup error", job.cleanupError, true],
    ["Leftovers", job.leftoverPackages.join(", "), true],
  ].filter(([, text]) => text);
  if (!notes.length) return null;
  const wrapper = node("div", "job-notes");
  notes.forEach(([label, text, isError]) => {
    const row = node("div", `job-note${isError ? " is-error" : ""}`);
    row.append(node("span", "label", label), node("p", null, text));
    wrapper.append(row);
  });
  return wrapper;
}

function renderJob(job) {
  const card = node("details", `job${job.requiresAttention ? " needs-attention" : ""}`);
  card.dataset.runId = job.runId;
  card.open = job.requiresAttention || state.expandedJobs.has(job.runId);
  card.addEventListener("toggle", () => {
    if (card.open) {
      state.expandedJobs.add(job.runId);
    } else {
      state.expandedJobs.delete(job.runId);
    }
    persistExpandedJobs();
  });
  card.append(renderJobSummary(job));

  const body = node("div", "job-body");
  if (job.manualRecoveryReason) body.append(renderJobRecovery(job));
  const overview = node("div");
  overview.append(renderJobOverview(job));
  const notes = renderJobNotes(job);
  if (notes) overview.append(notes);
  body.append(overview, renderTabs(job));
  card.append(body);
  return card;
}

function renderJobs() {
  const visible = state.jobs.filter(jobMatches);
  elements.jobs.replaceChildren(...visible.map(renderJob));
  elements.jobs.setAttribute("aria-busy", "false");
  elements.jobTable.classList.toggle("is-hidden", visible.length === 0);
  elements.empty.classList.toggle("is-hidden", visible.length !== 0);
}

function renderMetrics() {
  elements.total.textContent = String(state.jobs.length);
  const localAttention = state.jobs.filter((job) => job.requiresAttention).length;
  const coordinatorAttention =
    state.lostJob &&
    !state.jobs.some((job) => job.runId === state.lostJob.jobId && job.requiresAttention)
      ? 1
      : 0;
  elements.attention.textContent = String(localAttention + coordinatorAttention);
  elements.active.textContent = String(state.jobs.filter(isActive).length);
  elements.delivered.textContent = String(
    state.jobs.filter((job) => job.completionAcknowledged).length,
  );
}

/* -------------------------------------------------------------------------
   Worker
   ------------------------------------------------------------------------- */

function renderWorker(worker) {
  state.worker = worker;
  elements.workerState.dataset.status = worker.status;
  elements.workerLabel.textContent = humanize(worker.status);
  elements.workerMessage.textContent = worker.message;
  elements.drainLifecycle.textContent = humanize(worker.lifecycle);
  elements.drainLifecycle.className = `badge ${worker.safeToRestart ? "ready" : worker.lifecycle}`;
  const active = state.jobs.find((job) => !job.completionAcknowledged && job.hasClaim);
  elements.drainCurrentJob.textContent = active
    ? `${active.dnpName} · ${humanize(active.phase)}`
    : "No active job";
  elements.drainSafety.textContent = worker.safeToRestart
    ? "Safe to restart"
    : worker.lifecycle === "draining"
      ? "Waiting for safe completion"
      : "Drain required";
  elements.drainStatus.classList.toggle("is-safe", worker.safeToRestart);
  elements.drainWorker.disabled = worker.lifecycle !== "accepting";
  elements.resumeWorker.disabled = worker.lifecycle === "accepting";
}

/* -------------------------------------------------------------------------
   Actions
   ------------------------------------------------------------------------- */

async function setWorkerLifecycle(action) {
  const draining = action === "drain";
  if (
    draining &&
    !window.confirm(
      "Stop claiming new jobs and finish all current mutation, cleanup, and delivery work before restart?",
    )
  ) {
    return;
  }
  elements.drainWorker.disabled = true;
  elements.resumeWorker.disabled = true;
  try {
    const response = await postJson(`/operator/worker/${action}`, {});
    const payload = await readJson(response);
    toast(payload.message, "success");
    state.jobsFingerprint = "";
    await loadJobs();
    window.setTimeout(() => loadJobs({ quiet: true }), 500);
  } catch (error) {
    toast(error instanceof Error ? error.message : String(error), "error");
    if (state.worker) renderWorker(state.worker);
  }
}

async function markCoordinatorReady(retry, button) {
  const job = state.lostJob;
  if (!job) return;
  const action = retry
    ? "release the worker and retry this package"
    : "release the worker without retrying";
  const confirmed = window.confirm(
    `Confirm the old worker process is stopped and cleanup for ${job.package.dnpName} is complete.\n\nThis will ${action}.`,
  );
  if (!confirmed) return;

  const originalLabel = button.textContent;
  elements.readyAndRetry.disabled = true;
  elements.readyWithoutRetry.disabled = true;
  button.textContent = retry ? "Releasing & retrying…" : "Releasing…";
  try {
    const response = await postJson("/operator/coordinator/ready", { jobId: job.jobId, retry });
    const payload = await readJson(response);
    const retryResult = humanize(payload.retryDisposition);
    const blocked = payload.blockingJobIds?.length
      ? ` Blocking jobs: ${payload.blockingJobIds.join(", ")}.`
      : "";
    toast(
      `Tropibot accepted the command. Retry: ${retryResult}.${blocked} Checking the resulting worker state…`,
      "success",
    );
    await Promise.all([loadJobs(), loadCoordinatorRecovery()]);
  } catch (error) {
    toast(error instanceof Error ? error.message : String(error), "error");
  } finally {
    button.textContent = originalLabel;
    elements.readyAndRetry.disabled = false;
    elements.readyWithoutRetry.disabled = false;
  }
}

async function runRecoveryAction(job, action, button) {
  const acceptingCoordinator = action === "acceptCoordinatorResult";
  const confirmation = acceptingCoordinator
    ? window.prompt(
        `This discards the saved local completion and trusts Tropibot's existing result.\n\nType the run ID to continue:\n${job.runId}`,
      ) === job.runId
    : window.confirm(
        ["continueAfterCleanup", "confirmCleanup"].includes(action)
          ? `Confirm manual cleanup for ${job.dnpName} is complete and verified?`
          : `Retry the exact persisted completion for ${job.runId}?`,
      );
  if (!confirmation) return;
  const originalLabel = button.textContent;
  button.disabled = true;
  button.textContent = acceptingCoordinator ? "Releasing…" : "Working…";
  try {
    const response = await postJson("/operator/recovery/action", { runId: job.runId, action });
    const payload = await readJson(response);
    toast(payload.message || "Worker recovery action accepted", "success");
    state.jobsFingerprint = "";
    await loadJobs();
    window.setTimeout(() => loadJobs({ quiet: true }), 750);
  } catch (error) {
    toast(error instanceof Error ? error.message : String(error), "error");
  } finally {
    button.disabled = false;
    button.textContent = originalLabel;
  }
}

function toast(message, kind) {
  const item = node("div", `toast ${kind}`, message);
  elements.toastRegion.append(item);
  window.setTimeout(() => item.remove(), 5000);
}

/* -------------------------------------------------------------------------
   Loading
   ------------------------------------------------------------------------- */

function showError(error) {
  elements.error.textContent = error instanceof Error ? error.message : String(error);
  elements.error.classList.remove("is-hidden");
}

async function loadJobs({ quiet = false } = {}) {
  if (state.loading) return;
  state.loading = true;
  elements.refresh.disabled = true;
  if (!quiet) elements.error.classList.add("is-hidden");
  try {
    const response = await fetch("/api/jobs", {
      headers: { accept: "application/json" },
      cache: "no-store",
    });
    const payload = await readJson(response, "Loading jobs failed");
    const jobsFingerprint = JSON.stringify(payload.jobs);
    const jobsChanged = jobsFingerprint !== state.jobsFingerprint;
    state.jobs = payload.jobs;
    state.jobsFingerprint = jobsFingerprint;
    renderWorker(payload.worker);
    if (jobsChanged) {
      renderMetrics();
      renderJobs();
      renderLocalRecovery();
    }
    elements.updated.textContent = `Updated ${formatTime(new Date())}`;
  } catch (error) {
    showError(error);
  } finally {
    state.loading = false;
    elements.refresh.disabled = false;
  }
}

async function loadCoordinatorRecovery({ quiet = false } = {}) {
  if (state.coordinatorLoading) return;
  state.coordinatorLoading = true;
  try {
    const response = await fetch("/api/coordinator/lost-job", {
      headers: { accept: "application/json" },
      cache: "no-store",
    });
    let lostJob = null;
    if (response.status !== 204) {
      lostJob = await readJson(response, "Tropibot recovery check failed");
    }
    const fingerprint = JSON.stringify(lostJob);
    if (fingerprint !== state.lostJobFingerprint) {
      state.lostJob = lostJob;
      state.lostJobFingerprint = fingerprint;
      renderCoordinatorRecovery();
      renderMetrics();
    }
  } catch (error) {
    if (!quiet) showError(error);
  } finally {
    state.coordinatorLoading = false;
  }
}

/* -------------------------------------------------------------------------
   Wiring
   ------------------------------------------------------------------------- */

elements.refresh.addEventListener("click", () => {
  loadJobs();
  loadCoordinatorRecovery();
});
elements.readyAndRetry.addEventListener("click", () =>
  markCoordinatorReady(true, elements.readyAndRetry),
);
elements.readyWithoutRetry.addEventListener("click", () =>
  markCoordinatorReady(false, elements.readyWithoutRetry),
);
elements.drainWorker.addEventListener("click", () => setWorkerLifecycle("drain"));
elements.resumeWorker.addEventListener("click", () => setWorkerLifecycle("resume"));
elements.search.addEventListener("input", (event) => {
  state.query = event.target.value.trim().toLowerCase();
  renderJobs();
});
document.querySelectorAll(".filter").forEach((button) => {
  button.addEventListener("click", () => {
    state.filter = button.dataset.filter;
    document.querySelectorAll(".filter").forEach((candidate) => {
      candidate.classList.toggle("is-active", candidate === button);
    });
    renderJobs();
  });
});

loadJobs();
loadCoordinatorRecovery();
window.setInterval(() => {
  loadJobs({ quiet: true });
  loadCoordinatorRecovery({ quiet: true });
}, 5000);
