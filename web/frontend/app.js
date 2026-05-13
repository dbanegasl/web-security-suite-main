/* ── Web Security Suite — app.js ────────────────────────────────
   Fase 3: frontend skeleton
   Conecta con la API en /api/scan y /api/batch
────────────────────────────────────────────────────────────── */

// API siempre en ruta relativa — nginx hace el proxy reverso a /api/
const API_BASE = "";

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

// ═══════════════════════════════════════════════════════════════
// ANÁLISIS INDIVIDUAL
// ═══════════════════════════════════════════════════════════════
const formScan      = document.getElementById("form-scan");
const btnScan       = document.getElementById("btn-scan");
const scanProgress  = document.getElementById("scan-progress");
const progressFill  = document.getElementById("progress-fill");
const progressLabel = document.getElementById("progress-label");
const resultsDiv    = document.getElementById("results");
const errorBanner   = document.getElementById("error-banner");

formScan.addEventListener("submit", async e => {
  e.preventDefault();
  hideResults();
  hideError();

  const domain  = document.getElementById("domain").value.trim();
  const cookie  = document.getElementById("session-cookie").value.trim();
  const ip      = document.getElementById("ip").value.trim();

  if (!domain) {
    showError("El dominio es obligatorio.");
    return;
  }

  startProgress();

  try {
    const data = await apiPost("/api/scan", { domain, session_cookie: cookie, ip });
    stopProgress();
    renderResults(data);
    addToHistory(data);
  } catch (err) {
    stopProgress();
    showError(err.message);
  }
});

document.getElementById("btn-download-md")?.addEventListener("click", () => {
  const data = resultsDiv._scanData;
  if (!data) return;
  const md = buildMarkdownReport(data);
  downloadFile(`${data.domain}-scan.md`, md, "text/markdown");
});

// ── Progreso animado ──────────────────────────────────────────
let _progressTimer = null;
function startProgress() {
  btnScan.disabled = true;
  scanProgress.classList.remove("hidden");
  progressFill.style.width = "10%";
  // Avance simulado — se detiene al 85% esperando la respuesta real
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

// ── Render resultados ─────────────────────────────────────────
function renderResults(data) {
  resultsDiv._scanData = data;
  document.getElementById("results-domain").textContent = data.domain;
  document.getElementById("results-meta").textContent =
    `${data.baseUrl}  ·  ${data.startedAt}`;

  // Tarjetas de resumen
  const s = data.summary;
  document.getElementById("summary-cards").innerHTML = `
    <div class="summary-card card-pass"><div class="count">${s.pass}</div><div class="label">PASS</div></div>
    <div class="summary-card card-fail"><div class="count">${s.fail}</div><div class="label">FAIL</div></div>
    <div class="summary-card card-warn"><div class="count">${s.warn}</div><div class="label">WARN</div></div>
    <div class="summary-card card-skip"><div class="count">${s.skip}</div><div class="label">SKIP</div></div>
  `;

  // Filas de tests
  const tbody = document.getElementById("tests-tbody");
  tbody.innerHTML = "";
  for (const t of data.tests) {
    const wikiUrl = `/wiki.html#t${t.id}`;
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(t.id)}</td>
      <td>
        ${escapeHtml(t.name)}
        <a href="${wikiUrl}" target="_blank" rel="noopener" class="wiki-link" title="Ver en wiki: ${escapeHtml(t.name)}">📖</a>
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

// ═══════════════════════════════════════════════════════════════
// ANÁLISIS BATCH
// ═══════════════════════════════════════════════════════════════
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

// Drag & drop
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
  const lines = content.split("\n")
    .map(l => l.trim())
    .filter(l => l && !l.startsWith("#"));
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

  // Mostrar filas en espera
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

  // Tabla comparativa
  const table = document.getElementById("batch-summary-table");
  let html = "<tr><th>Dominio</th>";
  TESTS.forEach(t => { html += `<th><a href="/wiki.html#t${t}" target="_blank" rel="noopener" class="wiki-th-link" title="Ver TEST-${t} en wiki">${t}</a></th>`; });
  html += "<th>OK</th><th>FL</th><th>WN</th></tr>";

  results.forEach((r, idx) => {
    const domain = r.domain || lines[idx]?.split(",")[0] || "?";
    html += `<tr><td class="domain-cell">${escapeHtml(domain)}</td>`;
    if (r.error) {
      html += `<td colspan="${TESTS.length + 3}" style="color:var(--red)">${escapeHtml(r.error)}</td>`;
    } else {
      const testMap = Object.fromEntries(r.tests.map(t => [t.id, t.result]));
      let p = 0, f = 0, w = 0;
      TESTS.forEach(t => {
        const res = testMap[t] || "?";
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
  });
  table.innerHTML = html;
  batchResults.classList.remove("hidden");
}

document.getElementById("btn-batch-download")?.addEventListener("click", () => {
  // Simplificado: descarga el CSV de resultados
  const table = document.getElementById("batch-summary-table");
  if (!table) return;
  downloadFile("batch-results.csv",
    Array.from(table.rows).map(r => Array.from(r.cells).map(c => c.textContent).join(",")).join("\n"),
    "text/csv"
  );
});

// ═══════════════════════════════════════════════════════════════
// HISTORIAL
// ═══════════════════════════════════════════════════════════════
function addToHistory(data) {
  scanHistory.unshift(data);
  renderHistory();
}

function renderHistory() {
  const list = document.getElementById("history-list");
  if (!list) return;
  list.innerHTML = scanHistory.map((d, i) => `
    <li class="history-item" data-idx="${i}">
      <span class="h-domain">${escapeHtml(d.domain)}</span>
      <span class="badge badge-${d.summary.fail > 0 ? "FAIL" : d.summary.warn > 0 ? "WARN" : "PASS"}">
        ${d.summary.fail > 0 ? "FAIL" : d.summary.warn > 0 ? "WARN" : "PASS"}
      </span>
      <span class="h-date">${d.startedAt}</span>
    </li>
  `).join("");

  list.querySelectorAll(".history-item").forEach(item => {
    item.addEventListener("click", () => {
      const idx  = parseInt(item.dataset.idx, 10);
      const data = scanHistory[idx];
      // Navegar a vista individual y mostrar resultado
      document.querySelectorAll(".nav-item").forEach(l => l.classList.remove("active"));
      document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
      document.querySelector("[data-view='individual']")?.classList.add("active");
      document.getElementById("view-individual")?.classList.add("active");
      renderResults(data);
    });
  });
}

// ═══════════════════════════════════════════════════════════════
// UTILIDADES
// ═══════════════════════════════════════════════════════════════
async function apiPost(path, body) {
  const res = await fetch(`${API_BASE}${path}`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function sanitizeId(str) {
  return str.replace(/[^a-zA-Z0-9_-]/g, "_");
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
  md += `\n---\n_Generado con Web Security Suite v3.1_\n`;
  return md;
}
