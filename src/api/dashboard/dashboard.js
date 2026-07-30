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

function renderJob(job) {
  const card = node("details", `job${job.requiresAttention ? " needs-attention" : ""}`);
  card.dataset.runId = job.runId;
  card.open = state.expandedJobs.has(job.runId);
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

  if (job.canContinueAfterCleanup) {
    const recovery = node("aside", "recovery-panel");
    recovery.append(node("h3", null, "Manual cleanup required"));
    recovery.append(
      node(
        "p",
        null,
        job.manualRecoveryReason ||
          "The worker is paused until the target has been cleaned up manually.",
      ),
    );
    const action = node("button", "button button-primary", "Cleanup done — continue");
    action.type = "button";
    action.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      continueRecovery(job, action);
    });
    recovery.append(action);
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
    toast(`Worker released. Retry: ${retryResult}.${blocked}`, "success");
    state.lostJob = null;
    state.lostJobFingerprint = "null";
    renderCoordinatorRecovery();
    renderMetrics();
    await Promise.all([loadJobs(), loadCoordinatorRecovery()]);
  } catch (error) {
    toast(error instanceof Error ? error.message : String(error), "error");
  } finally {
    button.textContent = originalLabel;
    elements.readyAndRetry.disabled = false;
    elements.readyWithoutRetry.disabled = false;
  }
}

async function continueRecovery(job, button) {
  const confirmed = window.confirm(
    `Confirm that manual cleanup for ${job.dnpName} is complete and allow the worker to continue?`,
  );
  if (!confirmed) return;
  button.disabled = true;
  button.textContent = "Continuing…";
  try {
    const response = await fetch("/operator/recovery/continue", {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify({ runId: job.runId }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
    toast(payload.message || "Worker recovery resumed", "success");
    await loadJobs();
  } catch (error) {
    toast(error instanceof Error ? error.message : String(error), "error");
    button.disabled = false;
    button.textContent = "Cleanup done — continue";
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
