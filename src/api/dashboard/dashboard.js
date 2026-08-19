const state = {
  jobs: [],
  filter: "all",
  query: "",
  loading: false,
  coordinatorLoading: false,
  jobsFingerprint: "",
  lostJob: null,
  lostJobFingerprint: "",
  expandedJobs: loadExpandedJobs(),
};

const elements = {
  jobs: document.querySelector("#jobs"),
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
};

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

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function loadExpandedJobs() {
  try {
    return new Set(JSON.parse(sessionStorage.getItem("expandedHarnessJobs") || "[]"));
  } catch {
    return new Set();
  }
}

function persistExpandedJobs() {
  try {
    sessionStorage.setItem(
      "expandedHarnessJobs",
      JSON.stringify([...state.expandedJobs]),
    );
  } catch {
    // The dashboard still works when browser storage is unavailable.
  }
}

function badge(value) {
  return node("span", `badge ${value || "pending"}`, humanize(value || "pending"));
}

function detail(label, value) {
  const wrapper = node("div");
  wrapper.append(node("span", "detail-label", label));
  wrapper.append(node("span", "detail-value", value || "—"));
  return wrapper;
}

function jobMatches(job) {
  const active = job.status === "queued" || job.status === "running";
  const filterMatch =
    state.filter === "all" ||
    (state.filter === "attention" && job.requiresAttention) ||
    (state.filter === "active" && active) ||
    (state.filter === "completed" && job.status === "completed");
  const haystack = `${job.runId} ${job.dnpName} ${job.repository}`.toLowerCase();
  return filterMatch && haystack.includes(state.query);
}

function renderMetrics() {
  elements.total.textContent = String(state.jobs.length);
  const localAttention = state.jobs.filter((job) => job.requiresAttention).length;
  const coordinatorAttention =
    state.lostJob &&
    !state.jobs.some(
      (job) => job.runId === state.lostJob.jobId && job.requiresAttention,
    )
      ? 1
      : 0;
  elements.attention.textContent = String(
    localAttention + coordinatorAttention,
  );
  elements.active.textContent = String(
    state.jobs.filter((job) => job.status === "queued" || job.status === "running")
      .length,
  );
  elements.delivered.textContent = String(
    state.jobs.filter((job) => job.completionAcknowledged).length,
  );
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

function recoveryContextItem(label, value) {
  const item = node("div");
  item.append(node("span", null, label), node("strong", null, value));
  return item;
}

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

function recoveryPanelContent(job, compact = false) {
  const fragment = document.createDocumentFragment();
  const copy = node("p", compact ? null : "recovery-guidance");
  const actions = node("div", compact ? "stacked-actions" : "recovery-actions");

  if (job.recoveryKind === "cleanup") {
    copy.textContent =
      "Verify the target package is restored or removed as intended. Confirming records the manual cleanup and asks the live worker to reconcile again.";
    actions.append(
      recoveryActionButton(
        job,
        "continueAfterCleanup",
        "Cleanup verified — continue",
      ),
    );
  } else if (job.recoveryKind === "completion_conflict") {
    const cleanupConfirmed = ["passed", "skipped"].includes(job.cleanupStatus);
    if (!cleanupConfirmed) {
      copy.textContent =
        "Tropibot holds different state, but local cleanup is not recorded as safe. Verify the package state first; completion controls unlock after that confirmation.";
      actions.append(
        recoveryActionButton(job, "confirmCleanup", "Cleanup verified — unlock resolution"),
      );
    } else {
      copy.textContent =
        "Tropibot already holds different state for this claim. Retry is non-destructive and resends the exact saved payload. Accept coordinator result permanently discards the local pending payload and releases the claim.";
      actions.append(
        recoveryActionButton(job, "retryCompletion", "Retry exact completion"),
        recoveryActionButton(
          job,
          "acceptCoordinatorResult",
          "Accept Tropibot result & release",
          "button-danger",
        ),
      );
    }
  } else {
    copy.textContent =
      "This hold has no safe automated override. Inspect the reason and local record, then refresh after correcting the underlying state.";
  }
  fragment.append(copy, actions);
  return fragment;
}

function renderLocalRecovery() {
  const job = state.jobs.find((candidate) => candidate.manualRecoveryReason);
  elements.localRecovery.classList.toggle("is-hidden", !job);
  if (!job) return;

  const titles = {
    cleanup: "Manual cleanup must be verified",
    completion_conflict: "Completion conflicts with Tropibot",
    manual: "Manual recovery required",
  };
  elements.localRecoveryTitle.textContent = titles[job.recoveryKind] || titles.manual;
  elements.localRecoveryKind.textContent = humanize(job.recoveryKind || "manual");
  elements.localRecoveryReason.textContent = job.manualRecoveryReason;
  elements.localRecoveryContext.replaceChildren(
    recoveryContextItem("Package", job.dnpName),
    recoveryContextItem("Run", job.runId),
    recoveryContextItem("Cleanup", humanize(job.cleanupStatus)),
    recoveryContextItem(
      "Saved delivery",
      job.pendingCompletion ? "Pending" : "None",
    ),
    recoveryContextItem("Local claim", job.hasClaim ? "Held" : "Released"),
    recoveryContextItem(
      "Tropibot acknowledgement",
      job.completionAcknowledged ? "Recorded" : "Missing",
    ),
  );
  elements.localRecoveryExplanation.replaceChildren();
  elements.localRecoveryActions.replaceChildren();
  const content = recoveryPanelContent(job);
  const children = [...content.childNodes];
  elements.localRecoveryExplanation.append(children[0]);
  if (children[1]) elements.localRecoveryActions.append(...children[1].childNodes);
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
  const summary = node("summary");

  const packageCell = node("div", "package-cell");
  packageCell.append(node("div", "package-name", job.dnpName));
  packageCell.append(node("div", "run-id", job.runId));

  const statusCell = node("div", "status-cell");
  statusCell.append(node("span", "cell-label", job.verdict ? "Verdict" : "Status"));
  statusCell.append(badge(job.verdict || job.status));
  statusCell.append(node("span", "phase", humanize(job.phase)));

  const cleanupCell = node("div", "cleanup-cell");
  cleanupCell.append(node("span", "cell-label", "Cleanup"));
  cleanupCell.append(badge(job.cleanupStatus));

  const dateCell = node("div", "date-cell");
  dateCell.append(node("div", null, formatDate(job.createdAt)));
  dateCell.append(node("div", "phase", relativeTime(job.finishedAt || job.startedAt || job.createdAt)));

  summary.append(packageCell, statusCell, cleanupCell, dateCell, node("span", "chevron", "›"));
  card.append(summary);

  const body = node("div", "job-details");
  const information = node("div");
  const grid = node("div", "detail-grid");
  grid.append(
    detail("Repository", `${job.repository} · PR #${job.pullRequest}`),
    detail("Baseline", compactRef(job.baselineRef)),
    detail("Candidate", compactRef(job.candidateRef)),
    detail("Reason", humanize(job.reasonCode)),
    detail("Errors", String(job.errorCount)),
    detail(
      "Delivery",
      job.completionAcknowledged
        ? `Acknowledged${job.completionDisposition ? ` · ${job.completionDisposition}` : ""}`
        : "Not acknowledged",
    ),
  );
  information.append(grid);
  if (job.summary) information.append(node("p", "summary-copy", job.summary));
  if (job.cleanupError) {
    information.append(node("p", "summary-copy", `Cleanup: ${job.cleanupError}`));
  }
  if (job.leftoverPackages.length) {
    information.append(
      node("p", "summary-copy", `Leftovers: ${job.leftoverPackages.join(", ")}`),
    );
  }
  body.append(information);

  if (job.manualRecoveryReason) {
    const recovery = node("aside", "recovery-panel");
    recovery.append(
      node(
        "h3",
        null,
        job.recoveryKind === "completion_conflict"
          ? "Completion conflict"
          : "Manual cleanup required",
      ),
    );
    recovery.append(
      node("p", null, job.manualRecoveryReason),
    );
    recovery.append(recoveryPanelContent(job, true));
    body.append(recovery);
  }

  card.append(body);
  return card;
}

function renderJobs() {
  const visible = state.jobs.filter(jobMatches);
  elements.jobs.replaceChildren(...visible.map(renderJob));
  elements.jobs.setAttribute("aria-busy", "false");
  elements.empty.classList.toggle("is-hidden", visible.length !== 0);
}

function renderWorker(worker) {
  elements.workerState.dataset.status = worker.status;
  elements.workerLabel.textContent = humanize(worker.status);
  elements.workerMessage.textContent = worker.message;
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
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
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
    elements.updated.textContent = `Updated ${new Intl.DateTimeFormat(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }).format(new Date())}`;
  } catch (error) {
    elements.error.textContent = error instanceof Error ? error.message : String(error);
    elements.error.classList.remove("is-hidden");
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
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(
          payload.error || `Tropibot recovery check failed (${response.status})`,
        );
      }
      lostJob = payload;
    }
    const fingerprint = JSON.stringify(lostJob);
    if (fingerprint !== state.lostJobFingerprint) {
      state.lostJob = lostJob;
      state.lostJobFingerprint = fingerprint;
      renderCoordinatorRecovery();
      renderMetrics();
    }
  } catch (error) {
    if (!quiet) {
      elements.error.textContent =
        error instanceof Error ? error.message : String(error);
      elements.error.classList.remove("is-hidden");
    }
  } finally {
    state.coordinatorLoading = false;
  }
}

async function markCoordinatorReady(retry, button) {
  const job = state.lostJob;
  if (!job) return;
  const action = retry ? "release the worker and retry this package" : "release the worker without retrying";
  const confirmed = window.confirm(
    `Confirm the old worker process is stopped and cleanup for ${job.package.dnpName} is complete.\n\nThis will ${action}.`,
  );
  if (!confirmed) return;

  const originalLabel = button.textContent;
  button.disabled = true;
  elements.readyAndRetry.disabled = true;
  elements.readyWithoutRetry.disabled = true;
  button.textContent = retry ? "Releasing & retrying…" : "Releasing…";
  try {
    const response = await fetch("/operator/coordinator/ready", {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify({ jobId: job.jobId, retry }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
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
    const response = await fetch("/operator/recovery/action", {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify({ runId: job.runId, action }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
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
