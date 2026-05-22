/* ── Config Page JS ──────────────────────────────────────── */

const RULES_META = [
  { id: "SQLI-001", name: "Classic OR-based SQLi", type: "SQLi", severity: "CRITICAL" },
  { id: "SQLI-002", name: "UNION SELECT injection", type: "SQLi", severity: "CRITICAL" },
  { id: "SQLI-003", name: "SQL comment termination", type: "SQLi", severity: "HIGH" },
  { id: "SQLI-004", name: "Stacked queries", type: "SQLi", severity: "CRITICAL" },
  { id: "SQLI-005", name: "Time-based blind SQLi (MySQL)", type: "SQLi", severity: "CRITICAL" },
  { id: "SQLI-006", name: "Time-based blind SQLi (MSSQL)", type: "SQLi", severity: "CRITICAL" },
  { id: "SQLI-007", name: "Information Schema extraction", type: "SQLi", severity: "CRITICAL" },
  { id: "XSS-001", name: "Script tag injection", type: "XSS", severity: "CRITICAL" },
  { id: "XSS-002", name: "JavaScript protocol handler", type: "XSS", severity: "CRITICAL" },
  { id: "XSS-003", name: "Event handler injection", type: "XSS", severity: "HIGH" },
  { id: "XSS-004", name: "DOM manipulation", type: "XSS", severity: "HIGH" },
  { id: "XSS-005", name: "SVG-based XSS", type: "XSS", severity: "HIGH" },
  { id: "XSS-006", name: "Base64 encoded XSS", type: "XSS", severity: "MEDIUM" },
  { id: "LFI-001", name: "Path traversal sequence", type: "Path Traversal", severity: "HIGH" },
  { id: "LFI-002", name: "Sensitive file access", type: "Path Traversal", severity: "CRITICAL" },
  { id: "LFI-003", name: "PHP wrapper injection", type: "Path Traversal", severity: "CRITICAL" },
  { id: "CMDI-001", name: "Shell command injection", type: "Command Injection", severity: "CRITICAL" },
  { id: "CMDI-002", name: "Null byte injection", type: "Command Injection", severity: "HIGH" },
  { id: "BOT-001", name: "Known attack tool user agent", type: "Suspicious", severity: "HIGH" },
];

const SEVERITY_COLORS = {
  CRITICAL: "#ff2d55",
  HIGH: "#f59e0b",
  MEDIUM: "#3b82f6",
  LOW: "#10b981",
};

document.addEventListener("DOMContentLoaded", () => {
  loadConfig();
  loadBlockedIPs();
  renderRules();
});

// ── Settings ──────────────────────────────────────────────
async function loadConfig() {
  try {
    const res = await fetch("/api/config");
    const cfg = await res.json();

    const modeEl = document.getElementById("wafMode");
    if (modeEl) modeEl.value = cfg.mode || "active";

    const threshEl = document.getElementById("blockThreshold");
    if (threshEl) {
      const val = Math.round((cfg.block_threshold || 0.60) * 100);
      threshEl.value = val;
      document.getElementById("thresholdVal").textContent = val + "%";
    }

    const rlEnabled = document.getElementById("rateLimitEnabled");
    if (rlEnabled) rlEnabled.checked = cfg.rate_limit_enabled !== false;

    const rlRps = document.getElementById("rateLimitRps");
    if (rlRps) rlRps.value = cfg.rate_limit_rps || 100;
  } catch (e) { console.error("Config load error:", e); }
}

async function saveSettings() {
  const mode = document.getElementById("wafMode").value;
  const threshold = parseFloat(document.getElementById("blockThreshold").value) / 100;
  try {
    await Promise.all([
      postConfig("mode", mode),
      postConfig("block_threshold", threshold),
    ]);
    showMsg("settingsMsg", "✅ Settings saved!", "success");
  } catch (e) {
    showMsg("settingsMsg", "❌ Error: " + e.message, "error");
  }
}

async function saveRateLimit() {
  const enabled = document.getElementById("rateLimitEnabled").checked;
  const rps = parseInt(document.getElementById("rateLimitRps").value);
  try {
    await Promise.all([
      postConfig("rate_limit_enabled", enabled),
      postConfig("rate_limit_rps", rps),
    ]);
    showMsg("rateLimitMsg", "✅ Rate limit saved!", "success");
  } catch (e) {
    showMsg("rateLimitMsg", "❌ Error: " + e.message, "error");
  }
}

async function postConfig(key, value) {
  const res = await fetch("/api/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key, value }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

// ── Blocked IPs ───────────────────────────────────────────
async function loadBlockedIPs() {
  const tbody = document.getElementById("blockedIPsTable");
  try {
    const res = await fetch("/api/blocked-ips");
    const ips = await res.json();
    if (!ips.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-row">No blocked IPs</td></tr>`;
      return;
    }
    tbody.innerHTML = ips.map(ip => `
      <tr>
        <td style="font-family:monospace;color:#06b6d4">${ip.ip}</td>
        <td style="color:#94a3b8">${ip.reason || "—"}</td>
        <td style="color:#475569;font-size:12px">${ip.blocked_at || "—"}</td>
        <td style="color:#475569;font-size:12px">${ip.expires_at || "Never"}</td>
        <td>
          <button class="btn-sm" onclick="unblockIP('${ip.ip}')">✅ Unblock</button>
        </td>
      </tr>`
    ).join("");
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-row">Error: ${e.message}</td></tr>`;
  }
}

async function addBlockedIP() {
  const ip = document.getElementById("blockIpInput").value.trim();
  const reason = document.getElementById("blockReasonInput").value.trim() || "Manual block";
  if (!ip) { alert("Enter an IP address"); return; }
  try {
    await fetch("/api/block-ip", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, reason, hours: 24 }),
    });
    document.getElementById("blockIpInput").value = "";
    document.getElementById("blockReasonInput").value = "";
    loadBlockedIPs();
  } catch (e) { alert("Error: " + e.message); }
}

async function unblockIP(ip) {
  try {
    await fetch(`/api/block-ip/${encodeURIComponent(ip)}`, { method: "DELETE" });
    loadBlockedIPs();
  } catch (e) { alert("Error: " + e.message); }
}

// ── Rules List ────────────────────────────────────────────
function renderRules() {
  const el = document.getElementById("rulesList");
  const typeColors = {
    "SQLi": "#ef4444",
    "XSS": "#f59e0b",
    "Path Traversal": "#8b5cf6",
    "Command Injection": "#06b6d4",
    "Suspicious": "#10b981",
  };
  el.innerHTML = RULES_META.map(r => `
    <div class="rule-item">
      <div style="display:flex;align-items:center;gap:12px">
        <span class="rule-id">${r.id}</span>
        <div>
          <div class="rule-name">${r.name}</div>
          <div class="rule-type">${r.type}</div>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <span class="badge" style="background:rgba(0,0,0,0.3);color:${typeColors[r.type]||'#94a3b8'};font-size:10px">${r.type}</span>
        <span class="badge" style="background:rgba(0,0,0,0.3);color:${SEVERITY_COLORS[r.severity]};font-size:10px">${r.severity}</span>
        <span class="badge badge-green" style="font-size:10px">✓ Active</span>
      </div>
    </div>`
  ).join("");
}

// ── Helper ────────────────────────────────────────────────
function showMsg(id, msg, type) {
  const el = document.getElementById(id);
  el.className = `config-msg ${type}`;
  el.textContent = msg;
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("hidden"), 3000);
}
