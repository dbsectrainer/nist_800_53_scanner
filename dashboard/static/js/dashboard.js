// ============================================================
// NIST 800-53 Compliance Dashboard — main frontend JS
// Single-page app: hash-based router, stale-while-revalidate
// cache, lazy loading, inline editing, shared modal.
// ============================================================

"use strict";

// ── Constants ──────────────────────────────────────────────

const VIEWS = [
  "posture",
  "families",
  "controls",
  "poam",
  "risk",
  "assessments",
  "monitoring",
  "evidence",
  "assets",
  "owners",
  "exceptions",
  "trends",
  "integrations",
];

const API = {
  posture: "/api/v2/posture",
  families: "/api/v2/families",
  controls: "/api/v2/controls",
  poam: "/api/v2/poam",
  poamSync: "/api/v2/poam/sync",
  risk: "/api/v2/risk",
  assessments: "/api/v2/assessments",
  monitoring: "/api/v2/monitoring",
  evidence: "/api/v2/evidence",
  assets: "/api/v2/assets",
  owners: "/api/v2/owners",
  exceptions: "/api/v2/exceptions",
  trends: "/api/v2/trends",
  integrations: "/api/v2/integrations",
  scanReports: "/api/v2/scan/reports",
  scanTrigger: "/api/v2/scan/trigger",
  logout: "/logout",
};

const CACHE_TTL = 30_000; // 30 seconds
const viewCache = {};
let currentRole = "isso";

// Plotly shared config and layout base
const PLOTLY_CONFIG = { responsive: true, displayModeBar: false };
const PLOTLY_LAYOUT_BASE = {
  margin: { t: 10, r: 10, b: 40, l: 40 },
  paper_bgcolor: "transparent",
  plot_bgcolor: "transparent",
  font: {
    family: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    size: 12,
    color: "#374151",
  },
};

// Brand colours
const C = {
  green: "#10b981",
  amber: "#f59e0b",
  red: "#ef4444",
  purple: "#7c3aed",
  blue: "#3b82f6",
  grey: "#6b7280",
};

// ── API helpers ────────────────────────────────────────────

async function apiFetch(url, options = {}) {
  try {
    const res = await fetch(url, {
      method: "GET",
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
    });
    if (res.status === 401) {
      window.location.href = "/login";
      return null;
    }
    if (!res.ok) {
      console.error(`apiFetch ${url} → HTTP ${res.status}`);
      return null;
    }
    return await res.json();
  } catch (err) {
    console.error(`apiFetch ${url} error:`, err);
    return null;
  }
}

async function apiPut(url, body) {
  return apiFetch(url, {
    method: "PUT",
    body: JSON.stringify(body),
  });
}

async function apiPost(url, body) {
  return apiFetch(url, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

async function apiDelete(url) {
  return apiFetch(url, { method: "DELETE" });
}

// ── Router ─────────────────────────────────────────────────

function navigateTo(viewName) {
  if (!VIEWS.includes(viewName)) viewName = "posture";

  VIEWS.forEach((v) => {
    document.getElementById("view-" + v)?.classList.remove("active");
    document
      .querySelector('[data-view="' + v + '"]')
      ?.classList.remove("active");
  });

  document.getElementById("view-" + viewName)?.classList.add("active");
  document
    .querySelector('[data-view="' + viewName + '"]')
    ?.classList.add("active");

  window.location.hash = viewName;
  loadView(viewName);
}

async function loadView(viewName) {
  const now = Date.now();
  if (viewCache[viewName] && now - viewCache[viewName].ts < CACHE_TTL) return;

  const loaders = {
    posture: loadPostureView,
    families: loadFamiliesView,
    controls: loadControlsView,
    poam: loadPoamView,
    risk: loadRiskView,
    assessments: loadAssessmentsView,
    monitoring: loadMonitoringView,
    evidence: loadEvidenceView,
    assets: loadAssetsView,
    owners: loadOwnersView,
    exceptions: loadExceptionsView,
    trends: loadTrendsView,
    integrations: loadIntegrationsView,
  };

  await loaders[viewName]?.();
  viewCache[viewName] = { ts: now };
}

function invalidateCache(viewName) {
  delete viewCache[viewName];
}

// ── Rendering helpers ──────────────────────────────────────

function complianceBadge(pct) {
  const val = typeof pct === "number" ? pct : 0;
  const cls =
    val >= 80 ? "badge-closed" : val >= 60 ? "badge-medium" : "badge-high";
  return `<span class="badge ${cls}">${val.toFixed(1)}%</span>`;
}

function severityBadge(severity) {
  const s = (severity || "").toLowerCase();
  const map = {
    critical: "badge-critical",
    high: "badge-high",
    medium: "badge-medium",
    low: "badge-low",
    info: "badge-info",
  };
  const cls = map[s] || "badge-info";
  return `<span class="badge ${cls}">${severity || "Unknown"}</span>`;
}

function statusBadge(status) {
  const s = (status || "").toLowerCase().replace(/\s+/g, "-");
  const map = {
    open: "badge-high",
    closed: "badge-closed",
    "in-progress": "badge-medium",
    overdue: "badge-critical",
    active: "badge-closed",
    inactive: "badge-info",
    scheduled: "badge-medium",
    approved: "badge-closed",
    rejected: "badge-high",
    expired: "badge-critical",
    pending: "badge-medium",
  };
  const cls = map[s] || "badge-info";
  return `<span class="badge ${cls}">${status || "Unknown"}</span>`;
}

function showLoading(viewName) {
  document
    .getElementById(viewName + "-loading")
    ?.style.setProperty("display", "block");
  const content = document.getElementById(viewName + "-content");
  if (content) content.style.display = "none";
}

function showContent(viewName) {
  document
    .getElementById(viewName + "-loading")
    ?.style.setProperty("display", "none");
  const content = document.getElementById(viewName + "-content");
  if (content) content.style.display = "block";
}

function renderScorecards(containerId, cards) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = cards
    .map(
      (c) => `
    <div class="scorecard ${c.colorClass || ""}">
      <div class="scorecard-value">${c.value ?? "—"}</div>
      <div class="scorecard-label">${c.label || ""}</div>
      ${c.sub ? `<div class="scorecard-sub">${c.sub}</div>` : ""}
    </div>
  `,
    )
    .join("");
}

function makeEditable(cell, field, itemId, endpoint) {
  cell.classList.add("cell-editable");
  cell.title = "Double-click to edit";
  cell.ondblclick = () => {
    const original = cell.textContent.trim();
    cell.innerHTML = `<input class="inline-edit" value="${original.replace(/"/g, "&quot;")}">`;
    const input = cell.querySelector("input");
    input.focus();
    input.select();
    const save = async () => {
      const newVal = input.value;
      if (newVal === original) {
        cell.textContent = original;
        return;
      }
      const ok = await apiPut(endpoint + "/" + itemId, { [field]: newVal });
      cell.textContent = ok ? newVal : original;
    };
    input.onblur = save;
    input.onkeydown = (e) => {
      if (e.key === "Enter") save();
      if (e.key === "Escape") cell.textContent = original;
    };
  };
}

function isNoData(data) {
  return !data || data.no_data || data.encrypted;
}

function noDataMessage(data, viewName) {
  showContent(viewName);
  const el = document.getElementById(viewName + "-content");
  if (el) {
    el.innerHTML = `
      <div class="empty-state">
        <h3>${data?.message || "No data available"}</h3>
        <p>Run a scan to generate compliance data.</p>
      </div>`;
  }
}

function plotlyLayout(overrides = {}) {
  return { ...PLOTLY_LAYOUT_BASE, ...overrides };
}

// ── View: Posture ──────────────────────────────────────────

async function loadPostureView() {
  showLoading("posture");
  const data = await apiFetch(API.posture);
  if (isNoData(data)) {
    noDataMessage(data, "posture");
    return;
  }

  const compliance = data.compliance_pct ?? data.compliance_percentage ?? 0;
  const totalControls = data.total_controls ?? 0;
  const openPoams = data.open_poams ?? 0;
  const atoStatus = data.ato_status ?? "Unknown";
  const atoClass = atoStatus.toLowerCase().includes("authorized")
    ? "ato-authorized"
    : "ato-pending";

  renderScorecards("posture-scorecards", [
    {
      value: `${compliance.toFixed(1)}%`,
      label: "Compliance Score",
      colorClass:
        compliance >= 80
          ? "score-good"
          : compliance >= 60
            ? "score-warning"
            : "score-bad",
    },
    { value: totalControls, label: "Total Controls", colorClass: "" },
    {
      value: openPoams,
      label: "Open POA&Ms",
      colorClass: openPoams > 0 ? "score-warning" : "",
    },
    { value: atoStatus, label: "ATO Status", colorClass: atoClass },
  ]);

  showContent("posture");

  // Gauge chart
  Plotly.newPlot(
    "chart-posture-gauge",
    [
      {
        type: "indicator",
        mode: "gauge+number",
        value: compliance,
        number: { suffix: "%", font: { size: 32 } },
        gauge: {
          axis: { range: [0, 100], tickwidth: 1 },
          bar: {
            color:
              compliance >= 80 ? C.green : compliance >= 60 ? C.amber : C.red,
          },
          steps: [
            { range: [0, 60], color: "#fee2e2" },
            { range: [60, 80], color: "#fef3c7" },
            { range: [80, 100], color: "#d1fae5" },
          ],
          threshold: {
            line: { color: C.blue, width: 4 },
            thickness: 0.75,
            value: 80,
          },
        },
      },
    ],
    plotlyLayout({ margin: { t: 20, r: 20, b: 20, l: 20 }, height: 220 }),
    PLOTLY_CONFIG,
  );

  // Family summary horizontal bar
  const families = data.family_summary ?? [];
  if (families.length) {
    const sorted = [...families].sort(
      (a, b) => (a.compliance_pct ?? 0) - (b.compliance_pct ?? 0),
    );
    Plotly.newPlot(
      "chart-posture-families",
      [
        {
          type: "bar",
          orientation: "h",
          x: sorted.map((f) => f.compliance_pct ?? 0),
          y: sorted.map((f) => f.family ?? f.name ?? ""),
          marker: {
            color: sorted.map((f) =>
              (f.compliance_pct ?? 0) >= 80
                ? C.green
                : (f.compliance_pct ?? 0) >= 60
                  ? C.amber
                  : C.red,
            ),
          },
        },
      ],
      plotlyLayout({
        xaxis: { range: [0, 100], title: "Compliance %" },
        yaxis: { automargin: true },
      }),
      PLOTLY_CONFIG,
    );
  }

  // Compliant vs non-compliant distribution
  const compliant =
    data.compliant_controls ?? Math.round((totalControls * compliance) / 100);
  const nonCompliant = totalControls - compliant;
  Plotly.newPlot(
    "chart-posture-distribution",
    [
      {
        type: "pie",
        labels: ["Compliant", "Non-Compliant"],
        values: [compliant, nonCompliant],
        marker: { colors: [C.green, C.red] },
        hole: 0.35,
        textinfo: "label+percent",
      },
    ],
    plotlyLayout({ margin: { t: 10, r: 10, b: 10, l: 10 } }),
    PLOTLY_CONFIG,
  );
}

// ── View: Families ─────────────────────────────────────────

async function loadFamiliesView() {
  showLoading("families");
  const data = await apiFetch(API.families);
  if (isNoData(data)) {
    noDataMessage(data, "families");
    return;
  }

  const families = Array.isArray(data) ? data : (data.families ?? []);
  const tbody = document.querySelector("#table-families tbody");
  if (tbody) {
    tbody.innerHTML = families
      .map((f) => {
        const pct = f.compliance_pct ?? f.compliance_percentage ?? 0;
        const barColor = pct >= 80 ? C.green : pct >= 60 ? C.amber : C.red;
        return `<tr>
        <td><strong>${f.family ?? f.id ?? ""}</strong></td>
        <td>${f.name ?? f.family_name ?? ""}</td>
        <td>${f.total_controls ?? 0}</td>
        <td>${f.compliant_controls ?? 0}</td>
        <td>
          ${complianceBadge(pct)}
          <div class="compliance-bar" style="background:#e5e7eb;border-radius:4px;height:6px;margin-top:4px">
            <div style="width:${Math.min(pct, 100)}%;background:${barColor};height:6px;border-radius:4px"></div>
          </div>
        </td>
        <td><button class="btn btn-sm btn-secondary" onclick="showFamilyDrilldown('${f.family ?? f.id ?? ""}')">Drill down</button></td>
      </tr>`;
      })
      .join("");
  }

  showContent("families");

  // Heatmap
  if (families.length) {
    const labels = families.map((f) => f.family ?? f.id ?? "");
    const scores = families.map((f) => [
      f.compliance_pct ?? f.compliance_percentage ?? 0,
    ]);
    Plotly.newPlot(
      "chart-families-heatmap",
      [
        {
          type: "heatmap",
          z: scores,
          x: ["Compliance %"],
          y: labels,
          colorscale: [
            [0, C.red],
            [0.6, C.amber],
            [1, C.green],
          ],
          zmin: 0,
          zmax: 100,
          showscale: true,
        },
      ],
      plotlyLayout({ yaxis: { automargin: true } }),
      PLOTLY_CONFIG,
    );
  }
}

async function showFamilyDrilldown(family) {
  const data = await apiFetch(`${API.families}/${encodeURIComponent(family)}`);
  const drillEl = document.getElementById("family-drilldown");
  if (!drillEl) return;
  drillEl.style.display = "block";

  const controls = Array.isArray(data) ? data : (data?.controls ?? []);
  const tbody = document.querySelector("#table-drilldown tbody");
  if (tbody) {
    tbody.innerHTML =
      controls
        .map(
          (c) => `<tr>
      <td>${c.control_id ?? ""}</td>
      <td>${c.title ?? ""}</td>
      <td>${statusBadge(c.status)}</td>
      <td>${severityBadge(c.severity)}</td>
      <td>${c.last_assessed ?? "—"}</td>
    </tr>`,
        )
        .join("") || '<tr><td colspan="5">No controls found.</td></tr>';
  }

  const header = document.getElementById("drilldown-family-name");
  if (header) header.textContent = family;
}

function closeDrilldown() {
  const el = document.getElementById("family-drilldown");
  if (el) el.style.display = "none";
}

// ── View: Controls ─────────────────────────────────────────

let activeControlFilters = {};

async function loadControlsView() {
  showLoading("controls");
  const params = new URLSearchParams(activeControlFilters).toString();
  const url = params ? `${API.controls}?${params}` : API.controls;
  const data = await apiFetch(url);
  if (isNoData(data)) {
    noDataMessage(data, "controls");
    return;
  }

  const controls = Array.isArray(data) ? data : (data.controls ?? []);

  const countEl = document.getElementById("controls-count");
  if (countEl) countEl.textContent = controls.length;

  // Populate family filter
  const families = [
    ...new Set(controls.map((c) => c.family).filter(Boolean)),
  ].sort();
  const familySelect = document.getElementById("controls-filter-family");
  if (familySelect && familySelect.options.length <= 1) {
    families.forEach((fam) => {
      const opt = document.createElement("option");
      opt.value = fam;
      opt.textContent = fam;
      familySelect.appendChild(opt);
    });
  }

  const tbody = document.querySelector("#table-controls tbody");
  if (tbody) {
    tbody.innerHTML =
      controls
        .map(
          (c) => `<tr>
      <td>${c.control_id ?? ""}</td>
      <td>${c.family ?? ""}</td>
      <td>${c.title ?? ""}</td>
      <td>${statusBadge(c.status)}</td>
      <td>${severityBadge(c.severity)}</td>
      <td>${c.last_assessed ?? "—"}</td>
      <td>${c.owner ?? "—"}</td>
    </tr>`,
        )
        .join("") || '<tr><td colspan="7">No controls found.</td></tr>';
  }

  showContent("controls");
}

async function applyControlFilters() {
  const family = document.getElementById("controls-filter-family")?.value ?? "";
  const status = document.getElementById("controls-filter-status")?.value ?? "";
  const severity =
    document.getElementById("controls-filter-severity")?.value ?? "";
  const search = document.getElementById("controls-filter-search")?.value ?? "";

  activeControlFilters = {};
  if (family) activeControlFilters.family = family;
  if (status) activeControlFilters.status = status;
  if (severity) activeControlFilters.severity = severity;
  if (search) activeControlFilters.q = search;

  invalidateCache("controls");
  await loadControlsView();
}

// ── View: POA&M ────────────────────────────────────────────

async function loadPoamView() {
  showLoading("poam");
  const data = await apiFetch(API.poam);
  if (isNoData(data)) {
    noDataMessage(data, "poam");
    return;
  }

  const items = Array.isArray(data)
    ? data
    : (data.items ?? data.poam_items ?? []);
  const total = items.length;
  const open = items.filter(
    (i) => (i.status ?? "").toLowerCase() === "open",
  ).length;
  const overdue = items.filter(
    (i) => (i.status ?? "").toLowerCase() === "overdue",
  ).length;
  const closed = items.filter(
    (i) => (i.status ?? "").toLowerCase() === "closed",
  ).length;

  renderScorecards("poam-scorecards", [
    { value: total, label: "Total POA&Ms", colorClass: "" },
    { value: open, label: "Open", colorClass: open > 0 ? "score-warning" : "" },
    {
      value: overdue,
      label: "Overdue",
      colorClass: overdue > 0 ? "score-bad" : "",
    },
    {
      value: closed,
      label: "Closed",
      colorClass: closed > 0 ? "score-good" : "",
    },
  ]);

  // Aging buckets
  const buckets = { "<30": 0, "30-60": 0, "60-90": 0, ">90": 0 };
  items.forEach((item) => {
    const age = item.age_days ?? item.days_open ?? 0;
    if (age < 30) buckets["<30"]++;
    else if (age < 60) buckets["30-60"]++;
    else if (age < 90) buckets["60-90"]++;
    else buckets[">90"]++;
  });

  Plotly.newPlot(
    "chart-poam-aging",
    [
      {
        type: "bar",
        x: Object.keys(buckets),
        y: Object.values(buckets),
        marker: { color: [C.green, C.amber, C.red, C.purple] },
        name: "Age Buckets",
      },
    ],
    plotlyLayout({
      xaxis: { title: "Days Open" },
      yaxis: { title: "Count" },
    }),
    PLOTLY_CONFIG,
  );

  // Status donut
  const statusCounts = {};
  items.forEach((i) => {
    const s = i.status ?? "Unknown";
    statusCounts[s] = (statusCounts[s] ?? 0) + 1;
  });
  Plotly.newPlot(
    "chart-poam-status",
    [
      {
        type: "pie",
        labels: Object.keys(statusCounts),
        values: Object.values(statusCounts),
        hole: 0.4,
        marker: { colors: [C.amber, C.green, C.red, C.purple, C.blue] },
        textinfo: "label+value",
      },
    ],
    plotlyLayout({ margin: { t: 10, r: 10, b: 10, l: 10 } }),
    PLOTLY_CONFIG,
  );

  // Table
  const tbody = document.querySelector("#table-poam tbody");
  if (tbody) {
    tbody.innerHTML =
      items
        .map((item) => {
          const age = item.age_days ?? item.days_open ?? 0;
          const ageCls =
            age >= 90 ? "overdue" : age >= 60 ? "aging-warning" : "";
          return `<tr class="${ageCls}">
        <td>${item.poam_id ?? item.id ?? ""}</td>
        <td>${item.control_id ?? ""}</td>
        <td>${item.title ?? item.weakness ?? ""}</td>
        <td class="editable-status">${statusBadge(item.status)}</td>
        <td class="editable-owner">${item.owner ?? "—"}</td>
        <td>${item.scheduled_completion ?? item.due_date ?? "—"}</td>
        <td>${age} days</td>
        <td>${severityBadge(item.severity)}</td>
      </tr>`;
        })
        .join("") || '<tr><td colspan="8">No POA&M items found.</td></tr>';

    // Make status and owner editable
    items.forEach((item, idx) => {
      const row = tbody.rows[idx];
      if (!row) return;
      const id = item.poam_id ?? item.id ?? idx;
      makeEditable(row.cells[3], "status", id, API.poam);
      makeEditable(row.cells[4], "owner", id, API.poam);
    });
  }

  showContent("poam");
}

async function applyPoamFilters() {
  const status = document.getElementById("poam-filter-status")?.value ?? "";
  const severity = document.getElementById("poam-filter-severity")?.value ?? "";
  const owner = document.getElementById("poam-filter-owner")?.value ?? "";

  const params = new URLSearchParams();
  if (status) params.set("status", status);
  if (severity) params.set("severity", severity);
  if (owner) params.set("owner", owner);

  const url = params.toString() ? `${API.poam}?${params}` : API.poam;
  showLoading("poam");
  const data = await apiFetch(url);
  if (!isNoData(data)) {
    invalidateCache("poam");
    await loadPoamView();
  }
}

async function syncPoam() {
  const res = await apiPost(API.poamSync, {});
  if (res !== null) {
    invalidateCache("poam");
    await loadPoamView();
    const msg = document.getElementById("poam-sync-msg");
    if (msg) {
      msg.textContent = "POA&M synced successfully.";
      msg.style.display = "inline";
      setTimeout(() => {
        msg.style.display = "none";
      }, 3000);
    }
  }
}

// ── View: Risk ─────────────────────────────────────────────

async function loadRiskView() {
  showLoading("risk");
  const data = await apiFetch(API.risk);
  if (isNoData(data)) {
    noDataMessage(data, "risk");
    return;
  }

  const score = data.aggregate_risk_score ?? data.risk_score ?? 0;
  const level = data.risk_level ?? "Unknown";
  const inherent = data.inherent_risk ?? 0;
  const residual = data.residual_risk ?? 0;

  renderScorecards("risk-scorecards", [
    {
      value: score.toFixed(1),
      label: "Aggregate Risk Score",
      colorClass:
        score >= 7 ? "score-bad" : score >= 4 ? "score-warning" : "score-good",
    },
    { value: severityBadge(level), label: "Risk Level", colorClass: "" },
    { value: inherent.toFixed(1), label: "Inherent Risk", colorClass: "" },
    {
      value: residual.toFixed(1),
      label: "Residual Risk",
      colorClass: residual < inherent ? "score-good" : "score-warning",
    },
  ]);

  // Radar
  const families = data.family_risks ?? [];
  if (families.length) {
    const theta = families.map((f) => f.family ?? "");
    Plotly.newPlot(
      "chart-risk-radar",
      [
        {
          type: "scatterpolar",
          r: families.map((f) => f.inherent_risk ?? 0),
          theta,
          fill: "toself",
          name: "Inherent",
          line: { color: C.red },
          fillcolor: "rgba(239,68,68,0.2)",
        },
        {
          type: "scatterpolar",
          r: families.map((f) => f.residual_risk ?? 0),
          theta,
          fill: "toself",
          name: "Residual",
          line: { color: C.blue },
          fillcolor: "rgba(59,130,246,0.2)",
        },
      ],
      plotlyLayout({
        polar: { radialaxis: { visible: true, range: [0, 10] } },
        showlegend: true,
        legend: { orientation: "h", y: -0.1 },
      }),
      PLOTLY_CONFIG,
    );

    // Grouped bar
    Plotly.newPlot(
      "chart-risk-comparison",
      [
        {
          type: "bar",
          name: "Inherent",
          x: theta,
          y: families.map((f) => f.inherent_risk ?? 0),
          marker: { color: C.red },
        },
        {
          type: "bar",
          name: "Residual",
          x: theta,
          y: families.map((f) => f.residual_risk ?? 0),
          marker: { color: C.blue },
        },
      ],
      plotlyLayout({
        barmode: "group",
        xaxis: { automargin: true },
        yaxis: { title: "Risk Score" },
        legend: { orientation: "h", y: -0.25 },
      }),
      PLOTLY_CONFIG,
    );
  }

  // Trend line
  const trend = data.risk_trend ?? [];
  if (trend.length) {
    Plotly.newPlot(
      "chart-risk-trend",
      [
        {
          type: "scatter",
          mode: "lines+markers",
          x: trend.map((t) => t.date ?? t.period ?? ""),
          y: trend.map((t) => t.risk_score ?? 0),
          line: { color: C.red },
          marker: { color: C.red },
        },
      ],
      plotlyLayout({
        xaxis: { title: "Date" },
        yaxis: { title: "Risk Score", range: [0, 10] },
      }),
      PLOTLY_CONFIG,
    );
  }

  showContent("risk");
}

// ── View: Assessments ──────────────────────────────────────

async function loadAssessmentsView() {
  showLoading("assessments");
  const data = await apiFetch(API.assessments);
  if (isNoData(data)) {
    noDataMessage(data, "assessments");
    return;
  }

  const scans = data.total_scans ?? data.scans?.length ?? 0;
  const evidencePct = data.evidence_completeness_pct ?? data.evidence_pct ?? 0;

  renderScorecards("assessments-scorecards", [
    { value: scans, label: "Total Scans", colorClass: "" },
    {
      value: `${evidencePct.toFixed(1)}%`,
      label: "Evidence Completeness",
      colorClass: evidencePct >= 80 ? "score-good" : "score-warning",
    },
  ]);

  // Compliance history line
  const history = data.compliance_history ?? [];
  if (history.length) {
    Plotly.newPlot(
      "chart-assessments-history",
      [
        {
          type: "scatter",
          mode: "lines+markers",
          x: history.map((h) => h.date ?? h.period ?? ""),
          y: history.map((h) => h.compliance_pct ?? 0),
          line: { color: C.blue },
          marker: { color: C.blue },
        },
      ],
      plotlyLayout({
        xaxis: { title: "Date" },
        yaxis: { title: "Compliance %", range: [0, 100] },
      }),
      PLOTLY_CONFIG,
    );
  }

  // Evidence completeness bar
  const withEvidence = data.controls_with_evidence ?? 0;
  const withoutEvidence = data.controls_without_evidence ?? 0;
  if (withEvidence + withoutEvidence > 0) {
    Plotly.newPlot(
      "chart-assessments-evidence",
      [
        {
          type: "bar",
          x: ["With Evidence", "Without Evidence"],
          y: [withEvidence, withoutEvidence],
          marker: { color: [C.green, C.red] },
        },
      ],
      plotlyLayout({ yaxis: { title: "Controls" } }),
      PLOTLY_CONFIG,
    );
  }

  // Scan history table
  const scanList = data.scans ?? [];
  const scansTbody = document.querySelector("#table-assessments tbody");
  if (scansTbody) {
    scansTbody.innerHTML =
      scanList
        .map(
          (s) => `<tr>
      <td>${s.scan_id ?? s.id ?? ""}</td>
      <td>${s.scan_date ?? s.date ?? "—"}</td>
      <td>${s.scan_type ?? "—"}</td>
      <td>${complianceBadge(s.compliance_pct ?? 0)}</td>
      <td>${s.controls_scanned ?? 0}</td>
      <td>${s.findings ?? 0}</td>
      <td><button class="btn btn-sm btn-secondary" onclick="viewAssessmentReport('${s.scan_id ?? s.id ?? ""}')">View</button></td>
    </tr>`,
        )
        .join("") || '<tr><td colspan="7">No scan history found.</td></tr>';
  }

  // Root causes table
  const rootCauses = data.root_causes ?? data.failure_recurrence ?? [];
  const rcTbody = document.querySelector("#table-root-causes tbody");
  if (rcTbody) {
    rcTbody.innerHTML =
      rootCauses
        .map(
          (r) => `<tr>
      <td>${r.control_id ?? ""}</td>
      <td>${r.failure_reason ?? r.reason ?? "—"}</td>
      <td>${r.occurrences ?? r.count ?? 0}</td>
      <td>${r.last_seen ?? "—"}</td>
    </tr>`,
        )
        .join("") ||
      '<tr><td colspan="4">No recurring failures found.</td></tr>';
  }

  showContent("assessments");
}

async function viewAssessmentReport(reportId) {
  if (!reportId) return;
  const data = await apiFetch(
    `${API.scanReports}/${encodeURIComponent(reportId)}`,
  );
  if (!data) {
    alert("Report not available.");
    return;
  }

  const body = `
    <div class="report-summary">
      <p><strong>Report ID:</strong> ${data.scan_id ?? reportId}</p>
      <p><strong>Date:</strong> ${data.scan_date ?? "—"}</p>
      <p><strong>Compliance:</strong> ${(data.compliance_pct ?? 0).toFixed(1)}%</p>
      <p><strong>Controls Scanned:</strong> ${data.controls_scanned ?? 0}</p>
      <p><strong>Findings:</strong> ${data.findings ?? 0}</p>
    </div>`;
  openModal("Assessment Report", body, () => closeModal());
}

// ── View: Monitoring ───────────────────────────────────────

async function loadMonitoringView() {
  showLoading("monitoring");
  const data = await apiFetch(API.monitoring);
  if (isNoData(data)) {
    noDataMessage(data, "monitoring");
    return;
  }

  const items = Array.isArray(data)
    ? data
    : (data.items ?? data.controls ?? []);
  const automated = items.filter(
    (i) => (i.method ?? "").toLowerCase() === "automated",
  ).length;
  const manual = items.filter(
    (i) => (i.method ?? "").toLowerCase() === "manual",
  ).length;
  const overdue = items.filter(
    (i) => i.overdue === true || (i.status ?? "").toLowerCase() === "overdue",
  ).length;

  renderScorecards("monitoring-scorecards", [
    { value: automated, label: "Automated", colorClass: "score-good" },
    { value: manual, label: "Manual", colorClass: "" },
    {
      value: overdue,
      label: "Overdue",
      colorClass: overdue > 0 ? "score-bad" : "",
    },
  ]);

  // Coverage pie
  Plotly.newPlot(
    "chart-monitoring-coverage",
    [
      {
        type: "pie",
        labels: ["Automated", "Manual"],
        values: [automated || 0, manual || 0],
        marker: { colors: [C.blue, C.amber] },
        hole: 0.35,
        textinfo: "label+percent",
      },
    ],
    plotlyLayout({ margin: { t: 10, r: 10, b: 10, l: 10 } }),
    PLOTLY_CONFIG,
  );

  // Table
  const tbody = document.querySelector("#table-monitoring tbody");
  if (tbody) {
    tbody.innerHTML =
      items
        .map((item) => {
          const overdueCls =
            item.overdue || (item.status ?? "").toLowerCase() === "overdue"
              ? "overdue"
              : "";
          return `<tr class="${overdueCls}">
        <td>${item.control_id ?? ""}</td>
        <td>${item.title ?? item.control_name ?? ""}</td>
        <td>${item.method ?? "—"}</td>
        <td>${item.frequency ?? "—"}</td>
        <td>${item.last_checked ?? "—"}</td>
        <td>${item.next_due ?? "—"}</td>
        <td>${statusBadge(item.status)}</td>
      </tr>`;
        })
        .join("") || '<tr><td colspan="7">No monitoring data found.</td></tr>';
  }

  showContent("monitoring");
}

// ── View: Evidence ─────────────────────────────────────────

async function loadEvidenceView() {
  showLoading("evidence");
  const data = await apiFetch(API.evidence);
  if (isNoData(data)) {
    noDataMessage(data, "evidence");
    return;
  }

  const items = Array.isArray(data)
    ? data
    : (data.items ?? data.evidence ?? []);
  const total = items.length;
  const fresh = items.filter(
    (i) => (i.status ?? "").toLowerCase() === "fresh" || i.is_fresh,
  ).length;
  const stale = items.filter(
    (i) => (i.status ?? "").toLowerCase() === "stale" || i.is_stale,
  ).length;
  const missing = total - fresh - stale;

  renderScorecards("evidence-scorecards", [
    { value: total, label: "Total Evidence", colorClass: "" },
    { value: fresh, label: "Fresh", colorClass: fresh > 0 ? "score-good" : "" },
    {
      value: stale,
      label: "Stale",
      colorClass: stale > 0 ? "score-warning" : "",
    },
  ]);

  Plotly.newPlot(
    "chart-evidence-status",
    [
      {
        type: "bar",
        x: ["Fresh", "Stale", "Missing"],
        y: [fresh, stale, Math.max(missing, 0)],
        marker: { color: [C.green, C.amber, C.red] },
      },
    ],
    plotlyLayout({ yaxis: { title: "Count" } }),
    PLOTLY_CONFIG,
  );

  const tbody = document.querySelector("#table-evidence tbody");
  if (tbody) {
    tbody.innerHTML =
      items
        .map(
          (item) => `<tr>
      <td>${item.evidence_id ?? item.id ?? ""}</td>
      <td>${item.control_id ?? ""}</td>
      <td>${item.title ?? item.doc_title ?? ""}</td>
      <td>${item.doc_type ?? "—"}</td>
      <td>${statusBadge(item.status ?? (item.is_fresh ? "fresh" : "stale"))}</td>
      <td>${item.last_reviewed ?? "—"}</td>
      <td>${item.url ? `<a href="${item.url}" target="_blank" rel="noopener">Link</a>` : "—"}</td>
    </tr>`,
        )
        .join("") || '<tr><td colspan="7">No evidence records found.</td></tr>';
  }

  showContent("evidence");
}

// ── View: Assets ───────────────────────────────────────────

async function loadAssetsView() {
  showLoading("assets");
  const data = await apiFetch(API.assets);
  if (isNoData(data)) {
    noDataMessage(data, "assets");
    return;
  }

  const items = Array.isArray(data) ? data : (data.assets ?? data.items ?? []);
  const tbody = document.querySelector("#table-assets tbody");
  if (tbody) {
    tbody.innerHTML =
      items
        .map(
          (item) => `<tr>
      <td>${item.asset_id ?? item.id ?? ""}</td>
      <td>${item.asset_name ?? item.name ?? ""}</td>
      <td>${item.asset_type ?? item.type ?? "—"}</td>
      <td>${item.environment ?? "—"}</td>
      <td>${statusBadge(item.status)}</td>
      <td>${item.owner ?? "—"}</td>
      <td>${Array.isArray(item.applicable_families) ? item.applicable_families.join(", ") : (item.applicable_families ?? "—")}</td>
    </tr>`,
        )
        .join("") || '<tr><td colspan="7">No assets found.</td></tr>';
  }

  showContent("assets");
}

// ── View: Owners ───────────────────────────────────────────

async function loadOwnersView() {
  showLoading("owners");
  const data = await apiFetch(API.owners);
  if (isNoData(data)) {
    noDataMessage(data, "owners");
    return;
  }

  const items = Array.isArray(data) ? data : (data.owners ?? data.items ?? []);
  const tbody = document.querySelector("#table-owners tbody");
  if (tbody) {
    tbody.innerHTML =
      items
        .map(
          (item) => `<tr>
      <td>${item.control_id ?? ""}</td>
      <td class="editable-owner-name">${item.owner_name ?? "—"}</td>
      <td class="editable-owner-email">${item.owner_email ?? "—"}</td>
      <td class="editable-role">${item.role ?? "—"}</td>
      <td class="editable-team">${item.team ?? "—"}</td>
    </tr>`,
        )
        .join("") || '<tr><td colspan="5">No owner records found.</td></tr>';

    items.forEach((item, idx) => {
      const row = tbody.rows[idx];
      if (!row) return;
      const id = item.owner_id ?? item.id ?? idx;
      makeEditable(row.cells[1], "owner_name", id, API.owners);
      makeEditable(row.cells[2], "owner_email", id, API.owners);
      makeEditable(row.cells[3], "role", id, API.owners);
      makeEditable(row.cells[4], "team", id, API.owners);
    });
  }

  showContent("owners");
}

// ── View: Exceptions ───────────────────────────────────────

async function loadExceptionsView() {
  showLoading("exceptions");
  const data = await apiFetch(API.exceptions);
  if (isNoData(data)) {
    noDataMessage(data, "exceptions");
    return;
  }

  const items = Array.isArray(data)
    ? data
    : (data.exceptions ?? data.items ?? []);
  const today = Date.now();
  const tbody = document.querySelector("#table-exceptions tbody");
  if (tbody) {
    tbody.innerHTML =
      items
        .map((item) => {
          const expiry = item.expiration_date
            ? new Date(item.expiration_date).getTime()
            : null;
          const expiredCls = expiry && expiry < today ? "expired" : "";
          const expiryLabel = expiry
            ? expiry < today
              ? `<span class="badge badge-critical">${item.expiration_date} (Expired)</span>`
              : item.expiration_date
            : "—";
          return `<tr class="${expiredCls}">
        <td>${item.exception_id ?? item.id ?? ""}</td>
        <td>${item.control_id ?? ""}</td>
        <td>${item.exception_type ?? "—"}</td>
        <td>${item.title ?? item.description ?? ""}</td>
        <td>${item.approved_by ?? "—"}</td>
        <td>${expiryLabel}</td>
        <td>${statusBadge(item.status)}</td>
      </tr>`;
        })
        .join("") || '<tr><td colspan="7">No exceptions found.</td></tr>';
  }

  showContent("exceptions");
}

// ── View: Trends ───────────────────────────────────────────

async function loadTrendsView() {
  showLoading("trends");
  const data = await apiFetch(API.trends);
  if (isNoData(data)) {
    noDataMessage(data, "trends");
    return;
  }

  const forecastPct = data.forecast_compliance_pct ?? data.forecast_pct ?? 0;
  const avgMttr = data.avg_mttr_days ?? data.avg_mttr ?? 0;

  renderScorecards("trends-scorecards", [
    {
      value: `${forecastPct.toFixed(1)}%`,
      label: "Forecast Compliance",
      colorClass: forecastPct >= 80 ? "score-good" : "score-warning",
    },
    {
      value: `${avgMttr.toFixed(1)}d`,
      label: "Avg MTTR",
      colorClass:
        avgMttr > 30
          ? "score-bad"
          : avgMttr > 14
            ? "score-warning"
            : "score-good",
    },
  ]);

  // Compliance trend with forecast point
  const trend = data.compliance_trend ?? [];
  if (trend.length) {
    const lastDate = trend[trend.length - 1]?.date ?? "";
    const lastScore = trend[trend.length - 1]?.compliance_pct ?? 0;
    const forecastDate =
      data.forecast_date ?? (lastDate ? _offsetDate(lastDate, 30) : "Forecast");

    Plotly.newPlot(
      "chart-trends-compliance",
      [
        {
          type: "scatter",
          mode: "lines+markers",
          name: "Actual",
          x: trend.map((t) => t.date ?? ""),
          y: trend.map((t) => t.compliance_pct ?? 0),
          line: { color: C.blue },
          marker: { color: C.blue },
        },
        {
          type: "scatter",
          mode: "markers+lines",
          name: "Forecast",
          x: [lastDate, forecastDate],
          y: [lastScore, forecastPct],
          line: { dash: "dash", color: C.amber },
          marker: { color: C.amber, symbol: "diamond", size: 10 },
        },
      ],
      plotlyLayout({
        xaxis: { title: "Date" },
        yaxis: { title: "Compliance %", range: [0, 100] },
        legend: { orientation: "h", y: -0.25 },
      }),
      PLOTLY_CONFIG,
    );
  }

  // MTTR by family
  const mttrData = data.mttr_by_family ?? [];
  if (mttrData.length) {
    Plotly.newPlot(
      "chart-trends-mttr",
      [
        {
          type: "bar",
          x: mttrData.map((m) => m.family ?? ""),
          y: mttrData.map((m) => m.mttr_days ?? 0),
          marker: { color: C.purple },
        },
      ],
      plotlyLayout({
        xaxis: { automargin: true },
        yaxis: { title: "Days" },
      }),
      PLOTLY_CONFIG,
    );
  }

  // Failure recurrence top 10
  const recurrence = (data.failure_recurrence ?? []).slice(0, 10);
  if (recurrence.length) {
    Plotly.newPlot(
      "chart-trends-recurrence",
      [
        {
          type: "bar",
          orientation: "h",
          x: recurrence.map((r) => r.occurrences ?? r.count ?? 0),
          y: recurrence.map((r) => r.control_id ?? ""),
          marker: { color: C.red },
        },
      ],
      plotlyLayout({
        xaxis: { title: "Occurrences" },
        yaxis: { automargin: true },
      }),
      PLOTLY_CONFIG,
    );
  }

  showContent("trends");
}

// Offset an ISO date string by N days (for forecast point)
function _offsetDate(dateStr, days) {
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return dateStr;
  d.setDate(d.getDate() + days);
  return d.toISOString().slice(0, 10);
}

// ── View: Integrations ─────────────────────────────────────

async function loadIntegrationsView() {
  showLoading("integrations");
  const data = await apiFetch(API.integrations);
  if (isNoData(data)) {
    noDataMessage(data, "integrations");
    return;
  }

  const items = Array.isArray(data)
    ? data
    : (data.integrations ?? data.items ?? []);
  const grid = document.getElementById("integrations-grid");
  if (grid) {
    grid.innerHTML =
      items
        .map((item) => {
          const enabled = item.enabled ?? item.active ?? false;
          const statusCls = enabled
            ? "integration-enabled"
            : "integration-disabled";
          const statusLabel = enabled ? "Enabled" : "Disabled";
          const icon = item.icon ?? item.logo_url ?? "";
          return `<div class="integration-card ${statusCls}">
        ${icon ? `<img src="${icon}" alt="${item.name ?? ""}" class="integration-icon">` : '<div class="integration-icon-placeholder"></div>'}
        <div class="integration-name">${item.name ?? item.integration_name ?? ""}</div>
        <div class="integration-type">${item.type ?? item.category ?? ""}</div>
        <div class="integration-status">${statusBadge(statusLabel)}</div>
        ${item.last_sync ? `<div class="integration-sync">Last sync: ${item.last_sync}</div>` : ""}
      </div>`;
        })
        .join("") || '<p class="empty-state">No integrations configured.</p>';
  }

  showContent("integrations");
}

// ── Modal forms ────────────────────────────────────────────

function openModal(title, bodyHTML, onSubmit) {
  document.getElementById("modal-title").textContent = title;
  document.getElementById("modal-body").innerHTML =
    bodyHTML +
    `
    <div style="margin-top:16px;text-align:right">
      <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
      <button class="btn btn-primary" id="modal-submit" style="margin-left:8px">Save</button>
    </div>`;
  document.getElementById("modal-submit").onclick = onSubmit;
  document.getElementById("modal-overlay").style.display = "flex";
}

function closeModal() {
  document.getElementById("modal-overlay").style.display = "none";
}

function openAddEvidenceForm() {
  const body = `
    <div class="form-group">
      <label class="form-label">Control ID</label>
      <input class="form-input" id="ef-control-id" placeholder="e.g. AC-1">
    </div>
    <div class="form-group">
      <label class="form-label">Title</label>
      <input class="form-input" id="ef-title" placeholder="Evidence title">
    </div>
    <div class="form-group">
      <label class="form-label">Document Type</label>
      <select class="form-input" id="ef-doc-type">
        <option value="">Select type…</option>
        <option value="policy">Policy</option>
        <option value="procedure">Procedure</option>
        <option value="screenshot">Screenshot</option>
        <option value="report">Report</option>
        <option value="audit_log">Audit Log</option>
        <option value="configuration">Configuration</option>
        <option value="other">Other</option>
      </select>
    </div>
    <div class="form-group">
      <label class="form-label">URL</label>
      <input class="form-input" id="ef-url" type="url" placeholder="https://…">
    </div>
    <div class="form-group">
      <label class="form-label">Last Reviewed</label>
      <input class="form-input" id="ef-last-reviewed" type="date">
    </div>`;

  openModal("Add Evidence", body, async () => {
    const payload = {
      control_id: document.getElementById("ef-control-id")?.value.trim(),
      title: document.getElementById("ef-title")?.value.trim(),
      doc_type: document.getElementById("ef-doc-type")?.value,
      url: document.getElementById("ef-url")?.value.trim(),
      last_reviewed: document.getElementById("ef-last-reviewed")?.value,
    };
    if (!payload.control_id || !payload.title) {
      alert("Control ID and title are required.");
      return;
    }
    const res = await apiPost(API.evidence, payload);
    if (res) {
      closeModal();
      invalidateCache("evidence");
      loadView("evidence");
    } else {
      alert("Failed to add evidence. Please try again.");
    }
  });
}

function openAddAssetForm() {
  const body = `
    <div class="form-group">
      <label class="form-label">Asset Name</label>
      <input class="form-input" id="af-name" placeholder="e.g. Web Server 01">
    </div>
    <div class="form-group">
      <label class="form-label">Asset Type</label>
      <select class="form-input" id="af-type">
        <option value="">Select type…</option>
        <option value="server">Server</option>
        <option value="workstation">Workstation</option>
        <option value="network_device">Network Device</option>
        <option value="application">Application</option>
        <option value="database">Database</option>
        <option value="cloud_service">Cloud Service</option>
        <option value="other">Other</option>
      </select>
    </div>
    <div class="form-group">
      <label class="form-label">Environment</label>
      <select class="form-input" id="af-env">
        <option value="">Select environment…</option>
        <option value="production">Production</option>
        <option value="staging">Staging</option>
        <option value="development">Development</option>
        <option value="dr">DR</option>
      </select>
    </div>
    <div class="form-group">
      <label class="form-label">Applicable Families (comma-separated)</label>
      <input class="form-input" id="af-families" placeholder="e.g. AC, AU, IA">
    </div>`;

  openModal("Add Asset", body, async () => {
    const famsRaw = document.getElementById("af-families")?.value ?? "";
    const payload = {
      asset_name: document.getElementById("af-name")?.value.trim(),
      asset_type: document.getElementById("af-type")?.value,
      environment: document.getElementById("af-env")?.value,
      applicable_families: famsRaw
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    };
    if (!payload.asset_name) {
      alert("Asset name is required.");
      return;
    }
    const res = await apiPost(API.assets, payload);
    if (res) {
      closeModal();
      invalidateCache("assets");
      loadView("assets");
    } else {
      alert("Failed to add asset. Please try again.");
    }
  });
}

function openAddOwnerForm() {
  const body = `
    <div class="form-group">
      <label class="form-label">Control ID</label>
      <input class="form-input" id="of-control-id" placeholder="e.g. AC-1">
    </div>
    <div class="form-group">
      <label class="form-label">Owner Name</label>
      <input class="form-input" id="of-name" placeholder="Full name">
    </div>
    <div class="form-group">
      <label class="form-label">Owner Email</label>
      <input class="form-input" id="of-email" type="email" placeholder="user@example.com">
    </div>
    <div class="form-group">
      <label class="form-label">Role</label>
      <select class="form-input" id="of-role">
        <option value="">Select role…</option>
        <option value="isso">ISSO</option>
        <option value="issm">ISSM</option>
        <option value="system_owner">System Owner</option>
        <option value="control_owner">Control Owner</option>
        <option value="authorizing_official">Authorizing Official</option>
        <option value="assessor">Assessor</option>
      </select>
    </div>
    <div class="form-group">
      <label class="form-label">Team</label>
      <input class="form-input" id="of-team" placeholder="e.g. Security Ops">
    </div>`;

  openModal("Assign Owner", body, async () => {
    const payload = {
      control_id: document.getElementById("of-control-id")?.value.trim(),
      owner_name: document.getElementById("of-name")?.value.trim(),
      owner_email: document.getElementById("of-email")?.value.trim(),
      role: document.getElementById("of-role")?.value,
      team: document.getElementById("of-team")?.value.trim(),
    };
    if (!payload.control_id || !payload.owner_name) {
      alert("Control ID and owner name are required.");
      return;
    }
    const res = await apiPost(API.owners, payload);
    if (res) {
      closeModal();
      invalidateCache("owners");
      loadView("owners");
    } else {
      alert("Failed to assign owner. Please try again.");
    }
  });
}

function openAddExceptionForm() {
  const body = `
    <div class="form-group">
      <label class="form-label">Control ID</label>
      <input class="form-input" id="xf-control-id" placeholder="e.g. AC-1">
    </div>
    <div class="form-group">
      <label class="form-label">Exception Type</label>
      <select class="form-input" id="xf-type">
        <option value="">Select type…</option>
        <option value="risk_acceptance">Risk Acceptance</option>
        <option value="compensating_control">Compensating Control</option>
        <option value="planned_remediation">Planned Remediation</option>
        <option value="operational_requirement">Operational Requirement</option>
      </select>
    </div>
    <div class="form-group">
      <label class="form-label">Title</label>
      <input class="form-input" id="xf-title" placeholder="Exception title">
    </div>
    <div class="form-group">
      <label class="form-label">Justification</label>
      <textarea class="form-input" id="xf-justification" rows="3" placeholder="Provide justification…"></textarea>
    </div>
    <div class="form-group">
      <label class="form-label">Approved By</label>
      <input class="form-input" id="xf-approved-by" placeholder="Approver name or email">
    </div>
    <div class="form-group">
      <label class="form-label">Expiration Date</label>
      <input class="form-input" id="xf-expiration" type="date">
    </div>`;

  openModal("Add Exception", body, async () => {
    const payload = {
      control_id: document.getElementById("xf-control-id")?.value.trim(),
      exception_type: document.getElementById("xf-type")?.value,
      title: document.getElementById("xf-title")?.value.trim(),
      justification: document.getElementById("xf-justification")?.value.trim(),
      approved_by: document.getElementById("xf-approved-by")?.value.trim(),
      expiration_date: document.getElementById("xf-expiration")?.value,
    };
    if (!payload.control_id || !payload.title) {
      alert("Control ID and title are required.");
      return;
    }
    const res = await apiPost(API.exceptions, payload);
    if (res) {
      closeModal();
      invalidateCache("exceptions");
      loadView("exceptions");
    } else {
      alert("Failed to add exception. Please try again.");
    }
  });
}

// ── Initialization ─────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  // Sidebar nav
  document.querySelectorAll(".nav-item[data-view]").forEach((item) => {
    item.onclick = () => navigateTo(item.dataset.view);
  });

  // Logout
  document.getElementById("btn-logout")?.addEventListener("click", async () => {
    await apiPost(API.logout, {});
    window.location.href = "/login";
  });

  // Trigger scan
  document
    .getElementById("btn-sync-scan")
    ?.addEventListener("click", async () => {
      const btn = document.getElementById("btn-sync-scan");
      if (btn) btn.disabled = true;
      await apiPost(API.scanTrigger, {});
      invalidateCache("posture");
      invalidateCache("assessments");
      alert("Scan triggered. Results will appear after the scan completes.");
      if (btn) btn.disabled = false;
    });

  // Role selector
  document.getElementById("role-select")?.addEventListener("change", (e) => {
    currentRole = e.target.value;
    invalidateCache("posture");
    loadView("posture");
  });

  // Add form buttons
  document
    .getElementById("btn-add-evidence")
    ?.addEventListener("click", () => openAddEvidenceForm());
  document
    .getElementById("btn-add-asset")
    ?.addEventListener("click", () => openAddAssetForm());
  document
    .getElementById("btn-add-owner")
    ?.addEventListener("click", () => openAddOwnerForm());
  document
    .getElementById("btn-add-exception")
    ?.addEventListener("click", () => openAddExceptionForm());

  // POA&M filter/sync buttons
  document
    .getElementById("btn-apply-poam-filters")
    ?.addEventListener("click", () => applyPoamFilters());
  document
    .getElementById("btn-sync-poam")
    ?.addEventListener("click", () => syncPoam());

  // Controls filter button
  document
    .getElementById("btn-apply-controls-filters")
    ?.addEventListener("click", () => applyControlFilters());

  // Close drilldown button
  document
    .getElementById("btn-close-drilldown")
    ?.addEventListener("click", () => closeDrilldown());

  // Modal overlay click-outside-to-close
  document.getElementById("modal-overlay")?.addEventListener("click", (e) => {
    if (e.target === document.getElementById("modal-overlay")) closeModal();
  });

  // Hash navigation
  window.addEventListener("hashchange", () => {
    const view = window.location.hash.slice(1);
    navigateTo(view);
  });

  // Initial view
  const initialView = window.location.hash.slice(1);
  navigateTo(initialView || "posture");
});
