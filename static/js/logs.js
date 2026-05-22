/* ── Logs Page JS ────────────────────────────────────────── */

document.addEventListener("DOMContentLoaded", () => {
  loadLogs();
});

async function loadLogs() {
  const limit = document.getElementById("limitSelect").value;
  const blockedOnly = document.getElementById("blockedOnly").checked;
  const tbody = document.getElementById("logsTable");
  tbody.innerHTML = `<tr><td colspan="12" class="empty-row">Loading...</td></tr>`;

  try {
    const res = await fetch(`/api/requests?limit=${limit}&blocked_only=${blockedOnly}`);
    const rows = await res.json();
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="12" class="empty-row">No logs found.</td></tr>`;
      return;
    }
    tbody.innerHTML = rows.map((r, i) => {
      const attacks = (r.attack_types || []).map(a =>
        `<span class="badge badge-red" style="font-size:10px;margin:1px">${a}</span>`
      ).join("") || '<span class="badge badge-gray" style="font-size:10px">—</span>';
      const conf = Math.round((r.confidence || 0) * 100);
      const ts = new Date(r.timestamp).toLocaleString();
      const status = r.is_blocked
        ? `<span class="badge badge-red">BLOCKED</span>`
        : `<span class="badge badge-green">ALLOWED</span>`;
      return `<tr style="cursor:pointer" onclick="showDetail(${JSON.stringify(escRow(r)).replace(/"/g, "&quot;")})">
        <td style="color:#475569;font-size:11px">${r.id}</td>
        <td style="font-size:11px;color:#475569">${ts}</td>
        <td style="font-family:monospace;color:#06b6d4;font-size:12px">${r.ip}</td>
        <td class="method-${r.method}" style="font-weight:700">${r.method}</td>
        <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace;font-size:11px" title="${escHtml(r.path)}">${escHtml(r.path)}</td>
        <td>${status}</td>
        <td>${attacks}</td>
        <td>
          <div class="conf-bar">
            <div class="conf-track"><div class="conf-fill" style="width:${conf}%;background:${conf>70?'#ef4444':conf>40?'#f59e0b':'#10b981'}"></div></div>
            <span style="font-size:11px;color:#94a3b8">${conf}%</span>
          </div>
        </td>
        <td><span class="badge threat-${r.threat_level}" style="font-size:10px">${r.threat_level || '—'}</span></td>
        <td style="font-family:monospace;font-size:10px;color:#6366f1">${r.rule_triggered || '—'}</td>
        <td style="font-size:11px;color:#475569">${r.process_time_ms ? r.process_time_ms.toFixed(1) : '—'}</td>
        <td>
          <button class="btn-sm" onclick="event.stopPropagation();blockThisIP('${r.ip}')">🚫 Block</button>
        </td>
      </tr>`;
    }).join("");
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="12" class="empty-row">Error: ${e.message}</td></tr>`;
  }
}

function showDetail(row) {
  const panel = document.getElementById("detailPanel");
  const body = document.getElementById("detailBody");
  panel.classList.remove("hidden");

  const attacks = (row.attack_types || []).join(", ") || "None";
  const status = row.is_blocked
    ? `<span class="badge badge-red">BLOCKED</span>`
    : `<span class="badge badge-green">ALLOWED</span>`;

  body.innerHTML = `
    <div class="detail-row"><div class="detail-label">Status</div><div>${status}</div></div>
    <div class="detail-row"><div class="detail-label">Timestamp</div><div class="detail-val">${row.timestamp}</div></div>
    <div class="detail-row"><div class="detail-label">IP Address</div><div class="detail-val">${row.ip}</div></div>
    <div class="detail-row"><div class="detail-label">Method</div><div class="detail-val">${row.method}</div></div>
    <div class="detail-row"><div class="detail-label">Path</div><div class="detail-val">${escHtml(row.path)}</div></div>
    <div class="detail-row"><div class="detail-label">Attack Types</div><div class="detail-val">${attacks}</div></div>
    <div class="detail-row"><div class="detail-label">Threat Level</div><div class="detail-val">${row.threat_level || '—'}</div></div>
    <div class="detail-row"><div class="detail-label">AI Confidence</div><div class="detail-val">${Math.round((row.confidence||0)*100)}%</div></div>
    <div class="detail-row"><div class="detail-label">Rule Triggered</div><div class="detail-val">${row.rule_triggered || 'None'}</div></div>
    <div class="detail-row"><div class="detail-label">Process Time</div><div class="detail-val">${row.process_time_ms ? row.process_time_ms.toFixed(2) + ' ms' : '—'}</div></div>
    <div class="detail-row"><div class="detail-label">User-Agent</div><div class="detail-val">${escHtml(row.user_agent || '—')}</div></div>
    ${row.request_body ? `<div class="detail-row"><div class="detail-label">Request Body</div><div class="detail-val">${escHtml(row.request_body.substring(0,500))}</div></div>` : ''}
    <div style="margin-top:20px">
      <button class="btn btn-danger full-width" onclick="blockThisIP('${row.ip}')">🚫 Block IP ${row.ip}</button>
    </div>
  `;
}

function closeDetail() {
  document.getElementById("detailPanel").classList.add("hidden");
}

async function blockThisIP(ip) {
  if (!confirm(`Block IP ${ip} for 24 hours?`)) return;
  try {
    await fetch("/api/block-ip", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, reason: "Blocked from logs page", hours: 24 })
    });
    alert(`IP ${ip} has been blocked.`);
  } catch (e) { alert("Error blocking IP: " + e.message); }
}

function escRow(r) {
  return {
    id: r.id, ip: r.ip, method: r.method, path: r.path || "",
    is_blocked: r.is_blocked, attack_types: r.attack_types || [],
    threat_level: r.threat_level || "", confidence: r.confidence || 0,
    rule_triggered: r.rule_triggered || "", process_time_ms: r.process_time_ms || 0,
    user_agent: r.user_agent || "", request_body: r.request_body || "",
    timestamp: r.timestamp || ""
  };
}
function escHtml(str) {
  return String(str || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
