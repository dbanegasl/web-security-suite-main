/* ── Web Security Suite — app.js ────────────────────────────────
   Fase A: Autenticación JWT + historial persistente
────────────────────────────────────────────────────────────── */

const API_BASE = "";
const TOKEN_KEY = "wss_token";
const USER_KEY  = "wss_user";

// ══════════════════════════════════════════════════════════════
// AUTENTICACIÓN
// ══════════════════════════════════════════════════════════════
const loginScreen  = document.getElementById("login-screen");
const formLogin    = document.getElementById("form-login");
const loginError   = document.getElementById("login-error");
const btnLogout    = document.getElementById("btn-logout");
const sidebarUser  = document.getElementById("sidebar-user");

function getToken()  { return localStorage.getItem(TOKEN_KEY); }
function getUser()   { return JSON.parse(localStorage.getItem(USER_KEY) || "null"); }
function saveAuth(token, user) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}
function clearAuth() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

function showLogin() {
  loginScreen.classList.remove("hidden");
  document.getElementById("login-username").focus();
}
function hideLogin() {
  loginScreen.classList.add("hidden");
}

function applyUserUI() {
  const user = getUser();
  if (user) sidebarUser.textContent = `👤 ${user.username}`;
}

formLogin.addEventListener("submit", async e => {
  e.preventDefault();
  loginError.classList.add("hidden");
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;
  const btn = document.getElementById("btn-login");
  btn.disabled = true;
  btn.textContent = "Verificando…";

  try {
    const data = await apiFetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    saveAuth(data.access_token, { username: data.username, role: data.role });
    applyUserUI();
    hideLogin();
    loadHistoryPage(0, true);
  } catch (err) {
    loginError.textContent = err.message;
    loginError.classList.remove("hidden");
  } finally {
    btn.disabled = false;
    btn.textContent = "Iniciar sesión";
  }
});

btnLogout.addEventListener("click", e => {
  e.preventDefault();
  clearAuth();
  showLogin();
});

// Verificar token al cargar
(async function init() {
  const token = getToken();
  if (!token) { showLogin(); return; }
  try {
    await apiFetch("/api/auth/me", { method: "GET" });
    applyUserUI();
    hideLogin();
    loadHistoryPage(0, true);
  } catch {
    clearAuth();
    showLogin();
  }
})();

// ── Navegación ────────────────────────────────────────────────
document.querySelectorAll(".nav-item").forEach(link => {
  link.addEventListener("click", e => {
    e.preventDefault();
    const target = link.dataset.view;
    document.querySelectorAll(".nav-item").forEach(l => l.classList.remove("active"));
    document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
    link.classList.add("active");
    document.getElementById(`view-${target}`)?.classList.add("active");
    if (target === "history") loadHistoryPage(0, true);
  });
});

// ══════════════════════════════════════════════════════════════
// ANÁLISIS INDIVIDUAL
// ══════════════════════════════════════════════════════════════
const formScan      = document.getElementById("form-scan");
const btnScan       = document.getElementById("btn-scan");
const scanProgress  = document.getElementById("scan-progress");
const progressFill  = document.getElementById("progress-fill");
const resultsDiv    = document.getElementById("results");
const errorBanner   = document.getElementById("error-banner");

formScan.addEventListener("submit", async e => {
  e.preventDefault();
  hideResults();
  hideError();

  const domain = document.getElementById("domain").value.trim();
  const cookie = document.getElementById("session-cookie").value.trim();
  const ip     = document.getElementById("ip").value.trim();

  if (!domain) { showError("El dominio es obligatorio."); return; }

  startProgress();
  try {
    const data = await apiPost("/api/scan", { domain, session_cookie: cookie, ip });
    stopProgress();
    renderResults(data);
  } catch (err) {
    stopProgress();
    showError(err.message);
  }
});

document.getElementById("btn-download-md")?.addEventListener("click", () => {
  const data = resultsDiv._scanData;
  if (!data) return;
  downloadFile(`${data.domain}-scan.md`, buildMarkdownReport(data), "text/markdown");
});

let _progressTimer = null;
function startProgress() {
  btnScan.disabled = true;
  scanProgress.classList.remove("hidden");
  progressFill.style.width = "10%";
  let pct = 10;
  _progressTimer = setInterval(() => {
    pct = Math.min(pct + Math.random() * 4, 85);
    progressFill.style.width = `${pct}%`;
  }, 600);
}
function stopProgress() {
  clearInterval(_progressTimer);
  progressFill.style.width = "100%";
  setTimeout(() => {
    scanProgress.classList.add("hidden");
    progressFill.style.width = "0%";
  }, 400);
  btnScan.disabled = false;
}

function renderResults(data) {
  resultsDiv._scanData = data;
  document.getElementById("results-domain").textContent = data.domain;
  document.getElementById("results-meta").textContent =
    `${data.baseUrl}  ·  ${data.startedAt}`;

  const s = data.summary;
  document.getElementById("summary-cards").innerHTML = `
    <div class="summary-card card-pass"><div class="count">${s.pass}</div><div class="label">PASS</div></div>
    <div class="summary-card card-fail"><div class="count">${s.fail}</div><div class="label">FAIL</div></div>
    <div class="summary-card card-warn"><div class="count">${s.warn}</div><div class="label">WARN</div></div>
    <div class="summary-card card-skip"><div class="count">${s.skip}</div><div class="label">SKIP</div></div>
  `;

  const tbody = document.getElementById("tests-tbody");
  tbody.innerHTML = "";
  for (const t of data.tests) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(t.id)}</td>
      <td>
        ${escapeHtml(t.name)}
        <a href="/wiki.html#t${t.id}" target="_blank" rel="noopener" class="wiki-link" title="Ver en wiki">📖</a>
      </td>
      <td><span class="badge badge-${t.result}">${t.result}</span></td>
      <td class="muted">${escapeHtml(t.detail || "—")}</td>
    `;
    tbody.appendChild(tr);
  }
  resultsDiv.classList.remove("hidden");
}

function hideResults() { resultsDiv.classList.add("hidden"); }
function showError(msg) {
  errorBanner.textContent = "❌ " + msg;
  errorBanner.classList.remove("hidden");
}
function hideError() { errorBanner.classList.add("hidden"); }

// ══════════════════════════════════════════════════════════════
// ANÁLISIS BATCH
// ══════════════════════════════════════════════════════════════
const csvDropArea   = document.getElementById("csv-drop-area");
const csvFileInput  = document.getElementById("csv-file-input");
const csvPreview    = document.getElementById("csv-preview");
const csvCount      = document.getElementById("csv-count");
const csvList       = document.getElementById("csv-list");
const btnBatchRun   = document.getElementById("btn-batch-run");
const batchProgress = document.getElementById("batch-progress");
const batchDomList  = document.getElementById("batch-domain-list");
const batchResults  = document.getElementById("batch-results");

let _csvContent = "";

csvDropArea.addEventListener("dragover", e => {
  e.preventDefault();
  csvDropArea.classList.add("drag-over");
});
csvDropArea.addEventListener("dragleave", () => csvDropArea.classList.remove("drag-over"));
csvDropArea.addEventListener("drop", e => {
  e.preventDefault();
  csvDropArea.classList.remove("drag-over");
  const file = e.dataTransfer.files[0];
  if (file) loadCsvFile(file);
});
csvFileInput.addEventListener("change", e => {
  const file = e.target.files[0];
  if (file) loadCsvFile(file);
});

function loadCsvFile(file) {
  const reader = new FileReader();
  reader.onload = ev => {
    _csvContent = ev.target.result;
    previewCsv(_csvContent);
  };
  reader.readAsText(file);
}

function previewCsv(content) {
  const lines = content.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"));
  csvCount.textContent = lines.length;
  csvList.innerHTML = lines.map(l => `<li>${escapeHtml(l)}</li>`).join("");
  csvPreview.classList.remove("hidden");
}

btnBatchRun?.addEventListener("click", async () => {
  if (!_csvContent) return;
  btnBatchRun.disabled = true;
  batchProgress.classList.remove("hidden");
  batchResults.classList.add("hidden");
  batchDomList.innerHTML = "";

  const lines = _csvContent.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"));
  lines.forEach(line => {
    const domain = line.split(",")[0];
    const row = document.createElement("div");
    row.className = "batch-row";
    row.id = `brow-${sanitizeId(domain)}`;
    row.innerHTML = `<span class="domain-name">${escapeHtml(domain)}</span>
                     <span class="status-label">En espera…</span>`;
    batchDomList.appendChild(row);
  });

  try {
    const data = await apiPost("/api/batch", { csv_content: _csvContent });
    renderBatchResults(data, lines);
  } catch (err) {
    batchDomList.innerHTML = `<p style="color:var(--red)">❌ ${escapeHtml(err.message)}</p>`;
  } finally {
    btnBatchRun.disabled = false;
  }
});

function renderBatchResults(data, lines) {
  const results = data.results;
  const TESTS   = Array.from({ length: 20 }, (_, i) => String(i + 1).padStart(2, "0"));

  results.forEach((r, idx) => {
    const domain = r.domain || lines[idx]?.split(",")[0] || "?";
    const row = document.getElementById(`brow-${sanitizeId(domain)}`);
    if (!row) return;
    if (r.error) {
      row.querySelector(".status-label").textContent = `⚠ ${r.error}`;
      row.querySelector(".status-label").style.color = "var(--red)";
      return;
    }
    const s = r.summary;
    row.querySelector(".status-label").textContent =
      `✅ ${s.pass}P  ❌ ${s.fail}F  ⚠ ${s.warn}W  ⏭ ${s.skip}S`;
  });

  const table = document.getElementById("batch-summary-table");
  const colCount = TESTS.length + 4;
  let html = "<thead><tr><th>Dominio</th>";
  TESTS.forEach(t => { html += `<th><a href="/wiki.html#t${t}" target="_blank" rel="noopener" class="wiki-th-link" title="TEST-${t}">${t}</a></th>`; });
  html += "<th>OK</th><th>FL</th><th>WN</th></tr></thead><tbody>";

  results.forEach((r, idx) => {
    const domain = r.domain || lines[idx]?.split(",")[0] || "?";
    const key = sanitizeId(domain);
    html += `<tr class="batch-domain-row" data-key="${key}">`;
    html += `<td class="domain-cell"><span class="expand-toggle">▶</span> ${escapeHtml(domain)}</td>`;
    if (r.error) {
      html += `<td colspan="${TESTS.length + 3}" style="color:var(--red)">${escapeHtml(r.error)}</td>`;
    } else {
      const testMap = Object.fromEntries(r.tests.map(t => [t.id, t]));
      let p = 0, f = 0, w = 0;
      TESTS.forEach(t => {
        const test = testMap[t];
        const res = test?.result || "?";
        const cls = res === "PASS" ? "cell-P" : res === "FAIL" ? "cell-F"
                  : res === "WARN" ? "cell-W" : res === "SKIP" ? "cell-S" : "";
        const ch  = res === "PASS" ? "P" : res === "FAIL" ? "F"
                  : res === "WARN" ? "W" : res === "SKIP" ? "S" : "?";
        if (res === "PASS") p++;
        if (res === "FAIL") f++;
        if (res === "WARN") w++;
        html += `<td class="${cls}">${ch}</td>`;
      });
      html += `<td class="cell-P">${p}</td><td class="cell-F">${f}</td><td class="cell-W">${w}</td>`;
    }
    html += "</tr>";
    html += `<tr class="batch-detail-row hidden" id="bdetail-${key}"><td colspan="${colCount}">`;
    html += `<div class="batch-detail-wrap">`;
    if (!r.error) {
      r.tests.forEach(t => {
        const cls = t.result === "PASS" ? "cell-P" : t.result === "FAIL" ? "cell-F"
                  : t.result === "WARN" ? "cell-W" : "cell-S";
        html += `<div class="detail-test-row"><span class="detail-id">TEST-${t.id}</span>`;
        html += `<span class="detail-name">${escapeHtml(t.name)}</span>`;
        html += `<span class="detail-result ${cls}">${t.result}</span>`;
        if (t.detail) html += `<span class="detail-info">${escapeHtml(t.detail)}</span>`;
        html += "</div>";
      });
    }
    html += "</div></td></tr>";
  });
  html += "</tbody>";
  table.innerHTML = html;

  table.querySelectorAll(".batch-domain-row").forEach(row => {
    row.addEventListener("click", () => {
      const detail = document.getElementById(`bdetail-${row.dataset.key}`);
      const tog = row.querySelector(".expand-toggle");
      if (!detail) return;
      detail.classList.toggle("hidden");
      tog.textContent = detail.classList.contains("hidden") ? "▶" : "▼";
    });
  });

  batchResults.classList.remove("hidden");
}

document.getElementById("btn-batch-download")?.addEventListener("click", () => {
  const table = document.getElementById("batch-summary-table");
  if (!table) return;
  downloadFile("batch-results.csv",
    Array.from(table.rows).map(r => Array.from(r.cells).map(c => c.textContent).join(",")).join("\n"),
    "text/csv"
  );
});

// ══════════════════════════════════════════════════════════════
// HISTORIAL (persistente, desde API)
// ══════════════════════════════════════════════════════════════
let _historyOffset = 0;
const _historyLimit = 50;
let _historyTotal  = 0;
let _selectedScans = [];   // hasta 2 IDs seleccionados para comparar

const historyList    = document.getElementById("history-list");
const historyCount   = document.getElementById("history-count");
const historySearch  = document.getElementById("history-search");
const btnCompare     = document.getElementById("btn-compare");
const btnLoadMore    = document.getElementById("btn-load-more");

let _searchDebounce = null;
historySearch?.addEventListener("input", () => {
  clearTimeout(_searchDebounce);
  _searchDebounce = setTimeout(() => loadHistoryPage(0, true), 350);
});

btnLoadMore?.addEventListener("click", () => loadHistoryPage(_historyOffset, false));

btnCompare?.addEventListener("click", async () => {
  if (_selectedScans.length !== 2) return;
  try {
    const data = await apiGet(`/api/history/compare?a=${_selectedScans[0]}&b=${_selectedScans[1]}`);
    openCompareModal(data);
  } catch (err) {
    alert("Error al cargar comparativa: " + err.message);
  }
});

async function loadHistoryPage(offset, reset) {
  const domain = historySearch?.value.trim() || "";
  const params = new URLSearchParams({ limit: _historyLimit, offset });
  if (domain) params.set("domain", domain);

  try {
    const data = await apiGet(`/api/history?${params}`);
    _historyTotal  = data.total;
    _historyOffset = offset + data.items.length;

    if (reset) {
      historyList.innerHTML = "";
      _selectedScans = [];
      updateCompareBtn();
    }

    historyCount.textContent = `${_historyTotal} scan${_historyTotal !== 1 ? "s" : ""} en total`;

    data.items.forEach(item => {
      const badge = item.fail_count > 0 ? "FAIL" : item.warn_count > 0 ? "WARN" : "PASS";
      const li = document.createElement("li");
      li.className = "history-item";
      li.dataset.id = item.id;
      li.innerHTML = `
        <input type="checkbox" class="history-check" data-id="${item.id}" title="Seleccionar para comparar" />
        <span class="h-domain">${escapeHtml(item.domain)}</span>
        <span class="badge badge-${badge} h-badge">
          ${item.fail_count > 0 ? `❌ ${item.fail_count}F` : item.warn_count > 0 ? `⚠ ${item.warn_count}W` : "✅ OK"}
        </span>
        <span class="h-mode">${item.scan_mode}</span>
        <span class="h-date">${formatDate(item.scanned_at)}</span>
        <button class="btn btn-sm h-view-btn" data-id="${item.id}">Ver</button>
      `;
      historyList.appendChild(li);
    });

    // Checkboxes para comparar
    historyList.querySelectorAll(".history-check").forEach(cb => {
      cb.addEventListener("change", () => {
        const id = parseInt(cb.dataset.id, 10);
        if (cb.checked) {
          if (_selectedScans.length >= 2) {
            cb.checked = false;
            return;
          }
          _selectedScans.push(id);
        } else {
          _selectedScans = _selectedScans.filter(x => x !== id);
        }
        updateCompareBtn();
      });
    });

    // Botón "Ver" — carga el scan en la vista individual
    historyList.querySelectorAll(".h-view-btn").forEach(btn => {
      btn.addEventListener("click", async () => {
        try {
          const detail = await apiGet(`/api/history/${btn.dataset.id}`);
          navigateTo("individual");
          renderResults(detail.results);
        } catch (err) {
          alert("Error al cargar scan: " + err.message);
        }
      });
    });

    btnLoadMore.classList.toggle("hidden", _historyOffset >= _historyTotal);
  } catch (err) {
    historyCount.textContent = "Error al cargar historial";
  }
}

function updateCompareBtn() {
  btnCompare.disabled = _selectedScans.length !== 2;
  btnCompare.textContent = _selectedScans.length === 2
    ? "⚖ Comparar seleccionados"
    : `⚖ Comparar (${_selectedScans.length}/2 seleccionados)`;
}

// ══════════════════════════════════════════════════════════════
// MODAL COMPARATIVA
// ══════════════════════════════════════════════════════════════
const compareModal = document.getElementById("compare-modal");

document.getElementById("btn-modal-close")?.addEventListener("click", () => {
  compareModal.classList.add("hidden");
});
compareModal?.addEventListener("click", e => {
  if (e.target === compareModal) compareModal.classList.add("hidden");
});

function openCompareModal(data) {
  document.getElementById("compare-th-a").textContent =
    `${data.scan_a.domain} · ${formatDate(data.scan_a.scanned_at)}`;
  document.getElementById("compare-th-b").textContent =
    `${data.scan_b.domain} · ${formatDate(data.scan_b.scanned_at)}`;

  const changed = data.diff.filter(d => d.changed).length;
  document.getElementById("compare-meta").innerHTML =
    `<span class="${changed > 0 ? "cell-F" : "cell-P"}">${changed} test${changed !== 1 ? "s" : ""} cambiaron</span>`;

  const tbody = document.getElementById("compare-tbody");
  tbody.innerHTML = data.diff.map(d => {
    const arrow = !d.changed ? "—"
      : d.result_b === "PASS" ? '<span class="cell-P">↑ PASS</span>'
      : d.result_b === "FAIL" ? '<span class="cell-F">↓ FAIL</span>'
      : `<span class="cell-W">~ ${d.result_b}</span>`;
    return `<tr class="${d.changed ? "diff-changed" : ""}">
      <td>${escapeHtml(d.id)}</td>
      <td>${escapeHtml(d.name)}</td>
      <td><span class="badge badge-${d.result_a}">${d.result_a}</span></td>
      <td><span class="badge badge-${d.result_b}">${d.result_b}</span></td>
      <td>${arrow}</td>
    </tr>`;
  }).join("");

  compareModal.classList.remove("hidden");
}

// ══════════════════════════════════════════════════════════════
// UTILIDADES
// ══════════════════════════════════════════════════════════════
function navigateTo(view) {
  document.querySelectorAll(".nav-item").forEach(l => l.classList.remove("active"));
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  document.querySelector(`[data-view='${view}']`)?.classList.add("active");
  document.getElementById(`view-${view}`)?.classList.add("active");
}

async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = { ...(options.headers || {}) };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (res.status === 401) {
    clearAuth();
    showLogin();
    throw new Error("Sesión expirada. Por favor inicia sesión de nuevo.");
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

async function apiPost(path, body) {
  return apiFetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function apiGet(path) {
  return apiFetch(path, { method: "GET" });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function sanitizeId(str) {
  return str.replace(/[^a-zA-Z0-9_-]/g, "_");
}

function formatDate(isoStr) {
  try {
    return new Date(isoStr).toLocaleString("es-EC", {
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit",
    });
  } catch {
    return isoStr;
  }
}

function downloadFile(name, content, type) {
  const a  = document.createElement("a");
  const bl = new Blob([content], { type });
  a.href   = URL.createObjectURL(bl);
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

function buildMarkdownReport(data) {
  const s = data.summary;
  let md = `# Reporte de Seguridad — ${data.domain}\n\n`;
  md += `| Campo | Valor |\n|-------|-------|\n`;
  md += `| **Fecha** | ${data.startedAt} |\n`;
  md += `| **URL base** | ${data.baseUrl} |\n\n`;
  md += `## Resumen\n\n`;
  md += `| ✅ PASS | ❌ FAIL | ⚠️ WARN | ⏭ SKIP |\n|:---:|:---:|:---:|:---:|\n`;
  md += `| ${s.pass} | ${s.fail} | ${s.warn} | ${s.skip} |\n\n`;
  md += `## Detalle\n\n| # | Test | Resultado | Detalle |\n|---|------|:---------:|---------|\n`;
  for (const t of data.tests) {
    md += `| ${t.id} | ${t.name} | ${t.result} | ${t.detail || "—"} |\n`;
  }
  md += `\n---\n_Generado con Web Security Suite v3.2_\n`;
  return md;
}


// ── Historial en memoria de sesión ──────────────────────────────
const scanHistory = [];

// ── Navegación ────────────────────────────────────────────────
document.querySelectorAll(".nav-item").forEach(link => {
  link.addEventListener("click", e => {
    e.preventDefault();
    const target = link.dataset.view;
    document.querySelectorAll(".nav-item").forEach(l => l.classList.remove("active"));
    document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
    link.classList.add("active");
    document.getElementById(`view-${target}`)?.classList.add("active");
  });
});

