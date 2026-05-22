/* ── Dashboard JS ─────────────────────────────────────── */

let timelineChart = null;
let attackChart = null;
let refreshTimer = null;
let currentHours = 6;

// ── Init ──────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  refreshAll();
  refreshTimer = setInterval(refreshAll, 5000); // live refresh every 5s
});

async function refreshAll() {
  await Promise.all([loadStats(), loadTimeline(currentHours), loadRecentAttacks()]);
}

// ── Stats Cards ───────────────────────────────────────────
async function loadStats() {
  try {
    const res = await fetch("/api/stats");
    const d = await res.json();

    setText("totalRequests", fmt(d.total_requests));
    setText("totalBlocked", fmt(d.total_blocked));
    setText("blockRate", d.block_rate + "%");
    setText("rpm", d.requests_per_minute);
    setText("req24h", `Last 24h: ${fmt(d.requests_24h)}`);
    setText("blocked24h", `Last 24h: ${fmt(d.blocked_24h)}`);
    setText("avgConf", `AI Confidence: ${d.avg_confidence}%`);

    renderTopIPs(d.top_attacker_ips || []);
    updateAttackChart(d.attack_breakdown || {});
  } catch (e) {
    console.error("Stats error:", e);
  }
}

// ── Timeline Chart ────────────────────────────────────────
function initCharts() {
  const tlCtx = document.getElementById("timelineChart").getContext("2d");
  timelineChart = new Chart(tlCtx, {
    type: "line",
    data: { labels: [], datasets: [
      {
        label: "Total Requests",
        data: [],
        borderColor: "#3b82f6",
        backgroundColor: "rgba(59,130,246,0.1)",
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 2,
      },
      {
        label: "Blocked",
        data: [],
        borderColor: "#ef4444",
        backgroundColor: "rgba(239,68,68,0.08)",
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 2,
      },
    ]},
    options: {
      responsive: true,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: {
          labels: { color: "#94a3b8", font: { size: 12 } }
        },
        tooltip: {
          backgroundColor: "#1a1f3a",
          borderColor: "#1e2545",
          borderWidth: 1,
          titleColor: "#e2e8f0",
          bodyColor: "#94a3b8",
        }
      },
      scales: {
        x: {
          ticks: { color: "#475569", maxTicksLimit: 8 },
          grid: { color: "#1e2545" }
        },
        y: {
          ticks: { color: "#475569" },
          grid: { color: "#1e2545" },
          beginAtZero: true,
        }
      }
    }
  });

  const atkCtx = document.getElementById("attackChart").getContext("2d");
  attackChart = new Chart(atkCtx, {
    type: "doughnut",
    data: {
      labels: [],
      datasets: [{
        data: [],
        backgroundColor: ["#ef4444","#f59e0b","#3b82f6","#10b981","#8b5cf6","#06b6d4"],
        borderColor: "#12152b",
        borderWidth: 3,
      }]
    },
    options: {
      responsive: true,
      cutout: "65%",
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#1a1f3a",
          borderColor: "#1e2545",
          borderWidth: 1,
          titleColor: "#e2e8f0",
          bodyColor: "#94a3b8",
        }
      }
    }
  });
}

async function loadTimeline(hours) {
  try {
    const res = await fetch(`/api/timeline?hours=${hours}`);
    const data = await res.json();
    const labels = data.map(d => {
      const dt = new Date(d.bucket);
      return dt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    });
    timelineChart.data.labels = labels;
    timelineChart.data.datasets[0].data = data.map(d => d.total);
    timelineChart.data.datasets[1].data = data.map(d => d.blocked);
    timelineChart.update("none");
  } catch (e) { console.error("Timeline error:", e); }
}

function updateAttackChart(breakdown) {
  const labels = Object.keys(breakdown);
  const values = Object.values(breakdown);
  attackChart.data.labels = labels;
  attackChart.data.datasets[0].data = values;
  attackChart.update("none");

  // Legend
  const colors = ["#ef4444","#f59e0b","#3b82f6","#10b981","#8b5cf6","#06b6d4"];
  const legend = document.getElementById("attackLegend");
  legend.innerHTML = labels.map((l, i) =>
    `<div class="legend-item">
      <div class="legend-dot" style="background:${colors[i % colors.length]}"></div>
      <span>${l} <strong style="color:#e2e8f0">(${values[i]})</strong></span>
    </div>`
  ).join("");
}

function setTimeRange(hours, btn) {
  currentHours = hours;
  document.querySelectorAll(".chart-controls .btn-sm").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  loadTimeline(hours);
}

// ── Recent Attacks Table ──────────────────────────────────
async function loadRecentAttacks() {
  try {
    const res = await fetch("/api/requests?limit=20&blocked_only=true");
    const rows = await res.json();
    const tbody = document.getElementById("attacksTable");
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-row">No blocked requests yet. Try the payload tester!</td></tr>`;
      return;
    }
    tbody.innerHTML = rows.map(r => {
      const attacks = (r.attack_types || []).map(a =>
        `<span class="badge badge-red" style="font-size:10px;margin:1px">${a}</span>`
      ).join("");
      const conf = Math.round((r.confidence || 0) * 100);
      const ts = new Date(r.timestamp).toLocaleTimeString();
      return `<tr>
        <td style="color:#475569">${ts}</td>
        <td style="font-family:monospace;color:#06b6d4">${r.ip}</td>
        <td class="method-${r.method}" style="font-weight:700">${r.method}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace;font-size:11px">${escHtml(r.path)}</td>
        <td>${attacks || '<span class="badge badge-gray">Unknown</span>'}</td>
        <td>
          <div class="conf-bar">
            <div class="conf-track"><div class="conf-fill" style="width:${conf}%"></div></div>
            <span style="font-size:11px;color:#94a3b8">${conf}%</span>
          </div>
        </td>
        <td><span class="badge threat-${r.threat_level}">${r.threat_level || "—"}</span></td>
      </tr>`;
    }).join("");
  } catch (e) { console.error("Attacks error:", e); }
}

// ── Top IPs ───────────────────────────────────────────────
function renderTopIPs(ips) {
  const el = document.getElementById("topIPs");
  if (!ips.length) {
    el.innerHTML = `<p style="color:#475569;text-align:center;padding:20px">No attacker IPs yet</p>`;
    return;
  }
  const max = ips[0]?.count || 1;
  el.innerHTML = ips.map(ip => `
    <div class="ip-item">
      <div>
        <div class="ip-addr">${ip.ip}</div>
        <div style="height:3px;background:#1e2545;border-radius:2px;margin-top:4px;width:120px">
          <div style="height:100%;background:#ef4444;border-radius:2px;width:${Math.round(ip.count/max*100)}%"></div>
        </div>
      </div>
      <span class="ip-count">${ip.count}</span>
    </div>`
  ).join("");
}

// ── Test Modal ────────────────────────────────────────────
function openTestModal() {
  document.getElementById("testModal").classList.remove("hidden");
}
function closeTestModal(e) {
  if (!e || e.target.id === "testModal" || e.target.classList.contains("modal-close")) {
    document.getElementById("testModal").classList.add("hidden");
    document.getElementById("testResult").classList.add("hidden");
  }
}

async function runTest() {
  const payload = document.getElementById("testPayload").value.trim();
  const field = document.getElementById("testField").value;
  const method = document.getElementById("testMethod").value;
  const resultEl = document.getElementById("testResult");

  if (!payload) { alert("Enter a payload to test"); return; }

  resultEl.classList.remove("hidden", "blocked", "allowed");
  resultEl.textContent = "Analyzing…";

  try {
    const res = await fetch("/api/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ payload, field, method })
    });
    const d = await res.json();
    const isBlocked = d.verdict === "BLOCKED";
    resultEl.classList.add(isBlocked ? "blocked" : "allowed");
    resultEl.textContent = [
      `VERDICT: ${d.verdict}`,
      ``,
      `── Rule Engine ─────────────────`,
      `  Blocked:    ${d.rule_engine.blocked}`,
      `  Confidence: ${Math.round(d.rule_engine.confidence * 100)}%`,
      `  Attacks:    ${d.rule_engine.attack_types.join(", ") || "None"}`,
      `  Rule:       ${d.rule_engine.rule_triggered || "None"}`,
      ``,
      `── AI Engine ───────────────────`,
      `  Blocked:    ${d.ai_engine.blocked}`,
      `  Confidence: ${Math.round(d.ai_engine.confidence * 100)}%`,
      `  Attacks:    ${d.ai_engine.attack_types.join(", ") || "None"}`,
    ].join("\n");
  } catch (e) {
    resultEl.textContent = "Error: " + e.message;
  }
}

// ── Helpers ───────────────────────────────────────────────
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}
function fmt(n) {
  if (n === undefined || n === null) return "0";
  return Number(n).toLocaleString();
}
function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
