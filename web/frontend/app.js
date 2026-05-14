/* ── Web Security Suite — app.js ────────────────────────────────
   Fase A: Autenticación JWT + historial persistente
────────────────────────────────────────────────────────────── */

const API_BASE = "";

// ── Versión de la aplicación ─────────────────────────────────
// Leída desde /version.json (asset estático servido por nginx).
// Para bumps de versión solo editar ese archivo — no tocar app.js.
let APP_VERSION = "—";
let BUILD_DATE  = "—";

fetch(`${API_BASE}/version.json`)
  .then(r => r.json())
  .then(({ version = "—", build = "—" }) => {
    APP_VERSION = version;
    BUILD_DATE  = build;
    console.info(
      `%cWeb Security Suite v${APP_VERSION} | Build: ${BUILD_DATE}`,
      "color:#a78bfa;font-weight:bold;font-size:13px"
    );
  })
  .catch(() => console.warn("[WSS] version.json no disponible"));

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
  if (!user) return;
  sidebarUser.textContent = `👤 ${user.username}`;
  // Mostrar enlace de admin solo si el rol es admin
  const adminItem = document.getElementById("nav-admin-item");
  if (adminItem) {
    if (user.role === "admin") adminItem.classList.remove("hidden");
    else adminItem.classList.add("hidden");
  }
  // Versión en el footer del sidebar
  const verEl = document.getElementById("app-version");
  if (verEl) verEl.textContent = `v${APP_VERSION} | Build: ${BUILD_DATE}`;
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
    navigateTo("home");
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
    navigateFromHash();  // Respetar hash en URL; si vacío → home
  } catch {
    clearAuth();
    showLogin();
  }
})();

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

// ── Botón Nuevo scan ──────────────────────────────────────────────────────────
document.getElementById("btn-new-scan")?.addEventListener("click", () => {
  formScan.reset();
  document.getElementById("cookie-tags").innerHTML = "";
  document.getElementById("cookie-tags").classList.add("hidden");
  hideResults();
  hideError();
  document.getElementById("domain").focus();
});

// ── Descubrir cookies disponibles ────────────────────────────────────────────
document.getElementById("btn-discover-cookies")?.addEventListener("click", async () => {
  const domain  = document.getElementById("domain").value.trim();
  const ip      = document.getElementById("ip").value.trim();
  const tagsEl  = document.getElementById("cookie-tags");
  const btn     = document.getElementById("btn-discover-cookies");

  if (!domain) {
    showError("Ingresa el dominio antes de buscar cookies.");
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Buscando…';
  tagsEl.innerHTML = "";
  tagsEl.classList.add("hidden");

  try {
    const params = new URLSearchParams({ domain });
    if (ip) params.set("ip", ip);
    const res  = await fetch(`${API_BASE}/api/discover-cookies?${params}`, {
      headers: { "Authorization": `Bearer ${getToken()}` },
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      throw new Error(d.detail || `Error ${res.status}`);
    }
    const { cookies } = await res.json();

    if (!cookies.length) {
      tagsEl.innerHTML = '<span class="cookie-tag-empty">No se encontraron cookies en la raíz del dominio.</span>';
    } else {
      tagsEl.innerHTML = cookies.map(name =>
        `<button type="button" class="cookie-tag" data-name="${escapeHtml(name)}">${escapeHtml(name)}</button>`
      ).join("");
      tagsEl.querySelectorAll(".cookie-tag").forEach(tag => {
        tag.addEventListener("click", () => {
          document.getElementById("session-cookie").value = tag.dataset.name;
          tagsEl.querySelectorAll(".cookie-tag").forEach(t => t.classList.remove("active"));
          tag.classList.add("active");
        });
      });
    }
    tagsEl.classList.remove("hidden");
  } catch (err) {
    showError("Error al obtener cookies: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-magnifying-glass-plus me-1"></i>Obtener cookies';
  }
});

document.getElementById("btn-download-md")?.addEventListener("click", () => {
  const data = resultsDiv._scanData;
  if (!data) return;
  const filename = `${makeTimestamp()}-individual-${slugify(data.domain)}.md`;
  downloadFile(filename, buildMarkdownReport(data), "text/markdown");
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

  // Chips de metadatos: URL · fecha · cookie detectada · IP resuelta
  const metaChip = (icon, label, value, dimmed = false) =>
    `<span class="scan-meta-chip${dimmed ? " scan-meta-dim" : ""}">` +
    `<i class="fa-solid ${icon}"></i> ` +
    `<span class="scan-meta-label">${label}</span> ` +
    `<span class="scan-meta-value">${escapeHtml(value)}</span></span>`;

  const dateStr = data.startedAt
    ? new Date(data.startedAt).toLocaleString("es-EC", { dateStyle: "short", timeStyle: "short" })
    : "—";
  const cookieVal = data.sessionCookie || null;
  const ipVal     = data.resolvedIp    || null;

  let metaHtml = metaChip("fa-link", "URL", data.baseUrl || `https://${data.domain}/`);
  metaHtml    += metaChip("fa-calendar", "Fecha", dateStr);
  metaHtml    += cookieVal
    ? metaChip("fa-cookie-bite", "Cookie", cookieVal)
    : metaChip("fa-cookie-bite", "Cookie", "no detectada", true);
  metaHtml    += ipVal
    ? metaChip("fa-server", "IP", ipVal)
    : metaChip("fa-server", "IP", "no resuelta", true);

  document.getElementById("results-meta").innerHTML = metaHtml;

  const s = data.summary;
  document.getElementById("summary-cards").innerHTML = `
    <div class="col"><div class="card summary-card card-pass"><div class="card-body py-2"><div class="count">${s.pass}</div><div class="label">PASS</div></div></div></div>
    <div class="col"><div class="card summary-card card-fail"><div class="card-body py-2"><div class="count">${s.fail}</div><div class="label">FAIL</div></div></div></div>
    <div class="col"><div class="card summary-card card-warn"><div class="card-body py-2"><div class="count">${s.warn}</div><div class="label">WARN</div></div></div></div>
    <div class="col"><div class="card summary-card card-skip"><div class="card-body py-2"><div class="count">${s.skip}</div><div class="label">SKIP</div></div></div></div>
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
    batchDomList.innerHTML = `<p class="text-danger">❌ ${escapeHtml(err.message)}</p>`;
  } finally {
    btnBatchRun.disabled = false;
  }
});

function renderBatchResults(data, lines) {
  const results = data.results;

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
  table._batchResults = results;   // guardado para el reporte MD
  renderBatchTable(table, results, lines);
  batchResults.classList.remove("hidden");
}

/**
 * Rellena una <table> con los resultados de un análisis batch.
 * @param {HTMLTableElement} table - El elemento tabla destino
 * @param {Array} results - Array de resultados de scan
 * @param {Array} [lines] - Líneas CSV originales (opcional, para fallback de nombre de dominio)
 */
const TESTS = Array.from({ length: 25 }, (_, i) => String(i + 1).padStart(2, "0"));

/** Metadatos de cada test: bloque, nivel de riesgo y peso para score */
const TESTS_META = [
  { id:"01", name:"Cookie: Secure",               block:"Cookies",          risk:"Medio",   weight:5,  riskDesc:"Cookie enviada en claro por HTTP" },
  { id:"02", name:"Cookie: HttpOnly",              block:"Cookies",          risk:"Alto",    weight:8,  riskDesc:"Robo de sesión via XSS" },
  { id:"03", name:"Cookie: SameSite=Lax|Strict",  block:"Cookies",          risk:"Medio",   weight:5,  riskDesc:"CSRF cross-site" },
  { id:"04", name:"Cookie: Path definido",         block:"Cookies",          risk:"Bajo",    weight:2,  riskDesc:"Scope de cookie sin restringir" },
  { id:"05", name:"HTTP → HTTPS redirect",         block:"Transporte",       risk:"Medio",   weight:5,  riskDesc:"Tráfico en claro posible" },
  { id:"06", name:"HSTS Strict-Transport-Security",block:"Transporte",       risk:"Alto",    weight:8,  riskDesc:"SSL stripping attack" },
  { id:"07", name:"TLS 1.0 deshabilitado",         block:"Transporte",       risk:"Alto",    weight:8,  riskDesc:"Protocolo roto (POODLE/BEAST)" },
  { id:"08", name:"TLS 1.1 deshabilitado",         block:"Transporte",       risk:"Medio",   weight:5,  riskDesc:"Protocolo obsoleto" },
  { id:"09", name:"Certificado SSL vigente",       block:"Transporte",       risk:"Crítico", weight:10, riskDesc:"Conexión insegura si expira" },
  { id:"10", name:"X-Frame-Options",               block:"Cabeceras HTTP",   risk:"Alto",    weight:8,  riskDesc:"Clickjacking via iframes maliciosos" },
  { id:"11", name:"X-Content-Type-Options: nosniff",block:"Cabeceras HTTP",  risk:"Medio",   weight:5,  riskDesc:"MIME confusion attack" },
  { id:"12", name:"Content-Security-Policy (CSP)", block:"Cabeceras HTTP",   risk:"Alto",    weight:8,  riskDesc:"XSS sin restricción de scripts" },
  { id:"13", name:"Referrer-Policy",               block:"Cabeceras HTTP",   risk:"Bajo",    weight:2,  riskDesc:"Fuga de URLs a terceros" },
  { id:"14", name:"Permissions-Policy",            block:"Cabeceras HTTP",   risk:"Bajo",    weight:2,  riskDesc:"Acceso sin control a APIs del navegador" },
  { id:"15", name:"Server header oculto",          block:"Fuga de info",     risk:"Medio",   weight:5,  riskDesc:"Revela versión del servidor" },
  { id:"16", name:"X-Powered-By ausente",          block:"Fuga de info",     risk:"Medio",   weight:5,  riskDesc:"Revela stack tecnológico (PHP, etc.)" },
  { id:"17", name:"X-AspNet-Version ausente",      block:"Fuga de info",     risk:"Medio",   weight:5,  riskDesc:"Revela versión de .NET" },
  { id:"18", name:"CORS sin wildcard",             block:"Config. servidor", risk:"Alto",    weight:8,  riskDesc:"Acceso cross-origin irrestricto" },
  { id:"19", name:"HTTP TRACE deshabilitado",      block:"Config. servidor", risk:"Medio",   weight:5,  riskDesc:"XST (Cross-Site Tracing)" },
  { id:"20", name:"Cache-Control seguro",          block:"Config. servidor", risk:"Medio",   weight:5,  riskDesc:"Datos sensibles en caché del navegador" },
  { id:"21", name:"Headers deprecados ausentes",   block:"Modernización",    risk:"Bajo",    weight:2,  riskDesc:"X-XSS-Protection y Expect-CT son obsoletos" },
  { id:"22", name:"COOP (Cross-Origin-Opener)",    block:"Aislamiento",      risk:"Medio",   weight:5,  riskDesc:"Ataques de ventana cross-origin" },
  { id:"23", name:"COEP (Cross-Origin-Embedder)",  block:"Aislamiento",      risk:"Medio",   weight:5,  riskDesc:"Necesario para aislamiento de contexto" },
  { id:"24", name:"CORP (Cross-Origin-Resource)",  block:"Aislamiento",      risk:"Medio",   weight:5,  riskDesc:"Recursos cargables desde orígenes externos" },
  { id:"25", name:"X-Permitted-Cross-Domain",      block:"Aislamiento",      risk:"Bajo",    weight:2,  riskDesc:"Acceso de Flash/PDF a recursos del dominio" },
];

/**
 * Calcula un score 0–100 ponderado por nivel de riesgo.
 * PASS=100% del peso, WARN=50%, FAIL/SKIP=0%.
 */
function calcScore(tests) {
  let earned = 0, max = 0;
  for (const t of tests) {
    const meta = TESTS_META.find(m => m.id === t.id);
    if (!meta || t.result === "SKIP") continue;
    max += meta.weight;
    if (t.result === "PASS") earned += meta.weight;
    else if (t.result === "WARN") earned += meta.weight * 0.5;
  }
  return max > 0 ? Math.round((earned / max) * 100) : 0;
}

/** Devuelve emoji + etiqueta según puntuación */
function scoreLabel(score) {
  if (score >= 90) return "🟢 Excelente";
  if (score >= 75) return "🟡 Aceptable";
  if (score >= 50) return "🟠 Mejorable";
  return "🔴 Crítico";
}

/** Bloque Markdown con la tabla de referencia de todos los tests */
function mdReferenceTable() {
  let t  = `## Referencia de tests\n\n`;
  t += `| ID | Test | Bloque | Riesgo | Riesgo si falla |\n`;
  t += `|:--:|------|--------|:------:|-----------------|\n`;
  for (const m of TESTS_META) {
    const riskBold = m.risk === "Alto" || m.risk === "Crítico" ? `**${m.risk}**` : m.risk;
    t += `| ${m.id} | ${m.name} | ${m.block} | ${riskBold} | ${m.riskDesc} |\n`;
  }
  return t + "\n";
}

function renderBatchTable(table, results, lines = []) {
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
}

document.getElementById("btn-batch-download")?.addEventListener("click", () => {
  const table = document.getElementById("batch-summary-table");
  if (!table || !table._batchResults) return;
  const filename = `${makeTimestamp()}-batch.md`;
  downloadFile(filename, buildBatchMarkdownReport(table._batchResults, "Análisis Batch"), "text/markdown");
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
    showToast("error", "Error al cargar comparativa", err.message);
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
      li.className = "d-flex align-items-center gap-2 p-2 mb-1 rounded border border-secondary-subtle";
      li.style.cursor = "default";
      li.dataset.id = item.id;
      li.innerHTML = `
        <input type="checkbox" class="history-check form-check-input" data-id="${item.id}" title="Seleccionar para comparar" />
        <span class="h-domain flex-grow-1 font-monospace small">${escapeHtml(item.domain)}</span>
        <span class="badge badge-${badge} h-badge">
          ${item.fail_count > 0 ? `❌ ${item.fail_count}F` : item.warn_count > 0 ? `⚠ ${item.warn_count}W` : "✅ OK"}
        </span>
        <span class="badge bg-secondary text-light h-mode">${item.scan_mode}</span>
        <span class="text-muted small h-date">${formatDate(item.scanned_at)}</span>
        <button class="btn btn-outline-secondary btn-sm h-view-btn" data-id="${item.id}">Ver</button>
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
          showToast("error", "Error al cargar scan", err.message);
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
async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = { ...(options.headers || {}) };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  // Si hay body como string JSON y no se especificó Content-Type, agregarlo automáticamente
  if (typeof options.body === "string" && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (res.status === 401) {
    // Solo redirigir al login si había un token activo (sesión expirada).
    // Si no había token (ej.: intento de login fallido), dejar que caiga
    // al bloque !res.ok para mostrar el mensaje real de la API.
    if (token) {
      clearAuth();
      showLogin();
      throw new Error("Sesión expirada. Por favor inicia sesión de nuevo.");
    }
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    // FastAPI devuelve detail como array en errores de validación Pydantic
    let msg = err.detail;
    if (Array.isArray(msg)) {
      msg = msg.map(e => e.msg || JSON.stringify(e)).join(" | ");
    }
    throw new Error(msg || `HTTP ${res.status}`);
  }
  // 204 No Content y respuestas sin body no tienen JSON
  if (res.status === 204 || res.headers.get("content-length") === "0") return null;
  const ct = res.headers.get("content-type") || "";
  if (!ct.includes("application/json")) return null;
  return res.json();
}

async function apiPost(path, body) {
  return apiFetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function apiPut(path, body) {
  return apiFetch(path, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function apiDelete(path) {
  return apiFetch(path, { method: "DELETE" });
}

async function apiGet(path) {
  return apiFetch(path, { method: "GET" });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/**
 * Muestra una notificación toast no bloqueante.
 * @param {string} type  - 'success' | 'error' | 'warn' | 'info'
 * @param {string} title - Título breve
 * @param {string} [msg] - Detalle opcional (puede tener saltos de línea)
 * @param {number} [duration=4000] - ms antes de auto-cerrar (0 = manual)
 */
function showToast(type, title, msg = "", duration = 4000) {
  const icons = { success: "✓", error: "✕", warn: "⚠", info: "ℹ" };
  const container = document.getElementById("toast-container");

  const toast = document.createElement("div");
  toast.className = `toast-wss is-${type}`;

  const msgHtml = msg
    ? `<div class="toast-msg">${escapeHtml(msg).replace(/\n/g, "<br>")}</div>`
    : "";

  toast.innerHTML = `
    <span class="toast-icon">${icons[type] || "ℹ"}</span>
    <div class="toast-body">
      <div class="toast-title">${escapeHtml(title)}</div>
      ${msgHtml}
    </div>
    <button class="toast-close" aria-label="Cerrar">×</button>`;

  const remove = () => {
    toast.classList.add("toast-out");
    toast.addEventListener("animationend", () => toast.remove(), { once: true });
  };

  toast.querySelector(".toast-close").addEventListener("click", remove);
  container.appendChild(toast);

  if (duration > 0) setTimeout(remove, duration);
  return toast;
}

function sanitizeId(str) {
  return str.replace(/[^a-zA-Z0-9_-]/g, "_");
}

/**
 * Reemplaza confirm() nativo por un modal no bloqueante.
 * @param {string} msg    - Pregunta principal
 * @param {string} [title] - Título del modal
 * @param {string} [okLabel] - Texto del botón de confirmación
 * @returns {Promise<boolean>}
 */
function showConfirm(msg, title = "Confirmar", okLabel = "Eliminar") {
  return new Promise(resolve => {
    const overlay = document.getElementById("confirm-modal");
    document.getElementById("confirm-modal-title").textContent = title;
    document.getElementById("confirm-modal-msg").textContent = msg;
    document.getElementById("confirm-modal-ok").textContent = okLabel;
    overlay.classList.remove("hidden");

    const close = (result) => {
      overlay.classList.add("hidden");
      btnOk.removeEventListener("click", onOk);
      btnCancel.removeEventListener("click", onCancel);
      resolve(result);
    };
    const btnOk = document.getElementById("confirm-modal-ok");
    const btnCancel = document.getElementById("confirm-modal-cancel");
    const onOk = () => close(true);
    const onCancel = () => close(false);
    btnOk.addEventListener("click", onOk, { once: true });
    btnCancel.addEventListener("click", onCancel, { once: true });
    overlay.addEventListener("click", e => { if (e.target === overlay) close(false); }, { once: true });
  });
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

/** Genera un timestamp con formato YYYYMMDDHHMMSS para nombres de archivo */
function makeTimestamp() {
  const d = new Date();
  const pad = n => String(n).padStart(2, "0");
  return `${d.getFullYear()}${pad(d.getMonth()+1)}${pad(d.getDate())}${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

/** Normaliza un string para usarlo en nombres de archivo (sin caracteres especiales) */
function slugify(str) {
  return str.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function buildMarkdownReport(data) {
  const s = data.summary;
  const score = calcScore(data.tests);
  const label = scoreLabel(score);
  const total = s.pass + s.fail + s.warn + s.skip;
  const now = new Date().toLocaleString("es-EC");

  let md = `# Reporte de Seguridad Web — ${data.domain}\n\n`;

  // Cabecera
  md += `| Campo | Valor |\n|-------|-------|\n`;
  md += `| **Fecha** | ${now} |\n`;
  md += `| **URL base** | ${data.baseUrl || `https://${data.domain}/`} |\n`;
  md += `| **Generado con** | Web Security Suite v${APP_VERSION} |\n\n`;
  md += `---\n\n`;

  // Score
  md += `## Puntuación de seguridad\n\n`;
  md += `| Métrica | Valor |\n|---------|-------|\n`;
  md += `| **Score** | **${score} / 100** |\n`;
  md += `| **Estado** | ${label} |\n`;
  md += `| **Tests ejecutados** | ${total} |\n\n`;

  // Resumen
  md += `## Resumen de resultados\n\n`;
  md += `| ✅ PASS | ❌ FAIL | ⚠️ WARN | ⏭ SKIP |\n|:---:|:---:|:---:|:---:|\n`;
  md += `| ${s.pass} | ${s.fail} | ${s.warn} | ${s.skip} |\n\n`;
  md += `---\n\n`;

  // Detalle completo
  md += `## Detalle de tests\n\n`;
  md += `| # | Test | Resultado | Detalle |\n|---|------|:---------:|---------|\n`;
  for (const t of data.tests) {
    const icon = t.result === "PASS" ? "✅ PASS" : t.result === "FAIL" ? "❌ FAIL" : t.result === "WARN" ? "⚠️ WARN" : "⏭ SKIP";
    md += `| ${t.id} | ${t.name} | ${icon} | ${t.detail || "—"} |\n`;
  }
  md += `\n---\n\n`;

  // Hallazgos críticos (FAIL)
  const fails = data.tests.filter(t => t.result === "FAIL");
  if (fails.length) {
    md += `## ❌ Hallazgos críticos — acción requerida\n\n`;
    for (const t of fails) {
      const meta = TESTS_META.find(m => m.id === t.id);
      md += `### TEST-${t.id} — ${t.name}\n\n`;
      md += `- **Riesgo:** ${meta?.risk || "—"}\n`;
      md += `- **Impacto:** ${meta?.riskDesc || "—"}\n`;
      if (t.detail) md += `- **Detalle:** ${t.detail}\n`;
      md += `\n`;
    }
    md += `---\n\n`;
  }

  // Advertencias (WARN)
  const warns = data.tests.filter(t => t.result === "WARN");
  if (warns.length) {
    md += `## ⚠️ Advertencias — revisión recomendada\n\n`;
    for (const t of warns) {
      const meta = TESTS_META.find(m => m.id === t.id);
      md += `- **TEST-${t.id} — ${t.name}**: ${t.detail || meta?.riskDesc || "—"}\n`;
    }
    md += `\n---\n\n`;
  }

  // Tabla de referencia
  md += mdReferenceTable();
  md += `---\n\n`;
  md += `> **Nota para IA:** Este reporte fue generado automáticamente por Web Security Suite. `;
  md += `Contiene los resultados de ${total} tests de seguridad HTTP sobre \`${data.domain}\`. `;
  md += `Score obtenido: ${score}/100 (${label.replace(/^[^ ]+ /, "")}). `;
  if (fails.length) md += `Hay ${fails.length} hallazgo(s) crítico(s) que requieren acción inmediata. `;
  if (warns.length) md += `Hay ${warns.length} advertencia(s) a revisar. `;
  md += `Analiza los fallos, sugiere configuraciones concretas y prioriza por nivel de riesgo.\n`;

  return md;
}

/**
 * Genera un reporte Markdown para análisis batch o scan de lista.
 * @param {Array}  results  - Array de resultados de dominio
 * @param {string} title    - Título del reporte
 */
function buildBatchMarkdownReport(results, title = "Análisis Batch") {
  const now = new Date().toLocaleString("es-EC");
  const validResults = results.filter(r => !r.error);

  let md = `# ${title}\n\n`;
  md += `| Campo | Valor |\n|-------|-------|\n`;
  md += `| **Fecha** | ${now} |\n`;
  md += `| **Dominios analizados** | ${results.length} |\n`;
  md += `| **Generado con** | Web Security Suite v${APP_VERSION} |\n\n`;
  md += `---\n\n`;

  // Tabla resumen con score y estado
  md += `## Tabla resumen por dominio\n\n`;
  md += `| Dominio | Score | Estado | ✅ OK | ❌ FL | ⚠️ WN | ⏭ SK |\n`;
  md += `|---------|:-----:|--------|:----:|:----:|:----:|:----:|\n`;
  for (const r of results) {
    if (r.error) {
      md += `| ${r.domain} | — | ⚠ ${r.error} | — | — | — | — |\n`;
    } else {
      const score = calcScore(r.tests);
      const label = scoreLabel(score);
      const s = r.summary;
      md += `| ${r.domain} | **${score}** | ${label} | ${s.pass} | ${s.fail} | ${s.warn} | ${s.skip} |\n`;
    }
  }
  md += `\n---\n\n`;

  // Matriz por test (P/F/W/S)
  if (validResults.length) {
    md += `## Matriz de resultados por test\n\n`;
    md += `_P=PASS · F=FAIL · W=WARN · S=SKIP_\n\n`;
    const header = `| Dominio | ${TESTS.join(" | ")} |\n`;
    const sep    = `|${"-|".repeat(TESTS.length + 1)}\n`;
    md += header + sep;
    for (const r of validResults) {
      const cells = TESTS.map(id => {
        const t = r.tests.find(x => x.id === id);
        if (!t) return " ";
        return t.result === "PASS" ? "P" : t.result === "FAIL" ? "F" : t.result === "WARN" ? "W" : "S";
      });
      md += `| ${r.domain} | ${cells.join(" | ")} |\n`;
    }
    md += `\n---\n\n`;

    // Fallos más frecuentes
    const failCount = {};
    for (const r of validResults) {
      for (const t of r.tests) {
        if (t.result === "FAIL") failCount[t.id] = (failCount[t.id] || 0) + 1;
      }
    }
    const sortedFails = Object.entries(failCount).sort((a, b) => b[1] - a[1]);
    if (sortedFails.length) {
      md += `## Fallos más frecuentes\n\n`;
      md += `| Test | Descripción | Dominios afectados | Riesgo |\n`;
      md += `|:----:|-------------|:-----------------:|:------:|\n`;
      for (const [id, count] of sortedFails) {
        const meta = TESTS_META.find(m => m.id === id);
        const pct  = Math.round(count / validResults.length * 100);
        const riskBold = meta?.risk === "Alto" || meta?.risk === "Crítico" ? `**${meta.risk}**` : (meta?.risk || "—");
        md += `| ${id} | ${meta?.name || "—"} | ${count} / ${validResults.length} (${pct}%) | ${riskBold} |\n`;
      }
      md += `\n---\n\n`;
    }
  }

  // Detalle por dominio
  md += `## Detalle por dominio\n\n`;
  for (const r of results) {
    const score = r.error ? null : calcScore(r.tests);
    const label = score !== null ? scoreLabel(score) : null;
    md += `### ${r.domain}${score !== null ? `  —  Score: ${score}/100 ${label}` : ""}\n\n`;
    if (r.error) {
      md += `> ⚠ Error: ${r.error}\n\n`;
      continue;
    }
    md += `| # | Test | Resultado | Detalle |\n|---|------|:---------:|---------|\n`;
    for (const t of r.tests) {
      const icon = t.result === "PASS" ? "✅" : t.result === "FAIL" ? "❌" : t.result === "WARN" ? "⚠️" : "⏭";
      md += `| ${t.id} | ${t.name} | ${icon} ${t.result} | ${t.detail || "—"} |\n`;
    }
    md += `\n`;
  }
  md += `---\n\n`;

  // Tabla de referencia
  md += mdReferenceTable();
  md += `---\n\n`;

  // Nota para IA
  const totalFails = validResults.reduce((acc, r) => acc + r.summary.fail, 0);
  const avgScore = validResults.length
    ? Math.round(validResults.reduce((acc, r) => acc + calcScore(r.tests), 0) / validResults.length)
    : 0;
  md += `> **Nota para IA:** Este reporte cubre ${results.length} dominio(s). `;
  md += `Score promedio: ${avgScore}/100. `;
  if (totalFails > 0) md += `Total de fallos entre todos los dominios: ${totalFails}. `;
  md += `Identifica patrones comunes, prioriza los fallos de mayor riesgo y sugiere configuraciones concretas para cada tipo de fallo encontrado.\n`;

  return md;
}


// ── Historial en memoria de sesión ──────────────────────────────
const scanHistory = [];

// ── Navegación centralizada con hash routing ─────────────────
const VALID_VIEWS = new Set(["home","individual","batch","lists","history","evolution","admin","wiki"]);

function navigateTo(target, { pushHash = true } = {}) {
  if (!target || !VALID_VIEWS.has(target)) return;
  const user = getUser();
  // Proteger vista admin: redirigir a home si no es admin
  if (target === "admin" && user?.role !== "admin") target = "home";
  // Actualizar hash sin disparar hashchange de nuevo
  if (pushHash && location.hash !== `#${target}`) {
    history.pushState(null, "", `#${target}`);
  }
  // Actualizar nav items del sidebar
  document.querySelectorAll(".sidebar-nav .nav-item").forEach(l => l.classList.remove("active"));
  const navLink = document.querySelector(`.sidebar-nav .nav-item[data-view="${target}"]`);
  if (navLink) navLink.classList.add("active");
  // Actualizar vistas
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  document.getElementById(`view-${target}`)?.classList.add("active");
  // Datos específicos por vista
  if (target === "home") {
    const homeUser = document.getElementById("home-username");
    if (homeUser) homeUser.textContent = user?.username || "";
  }
  if (target === "history")   loadHistoryPage(0, true);
  if (target === "lists")     loadListsIndex();
  if (target === "evolution") initEvolutionView();
  if (target === "admin")     loadAdminUsers();
  // Cerrar sidebar en mobile
  if (window.innerWidth < 992) {
    document.querySelector(".sidebar")?.classList.remove("sidebar-open");
    document.getElementById("sidebar-backdrop")?.classList.remove("show");
  }
}

// Leer hash actual y navegar (sin re-pushear)
function navigateFromHash() {
  const hash = location.hash.replace(/^#/, "").trim();
  navigateTo(VALID_VIEWS.has(hash) ? hash : "home", { pushHash: false });
}

// Botón atrás / adelante del navegador
window.addEventListener("popstate", () => {
  if (getToken()) navigateFromHash();
});

document.querySelectorAll(".sidebar-nav .nav-item").forEach(link => {
  link.addEventListener("click", e => {
    e.preventDefault();
    navigateTo(link.dataset.view);
  });
});

// Clicks en tarjetas del home
document.querySelectorAll(".home-action-card[data-nav]").forEach(card => {
  card.addEventListener("click", () => navigateTo(card.dataset.nav));
});


// ═══════════════════════════════════════════════════════════════
// FASE B — LISTAS DE DOMINIOS
// ═══════════════════════════════════════════════════════════════

let _activeListId = null;
let _editingDomainId = null;
let _importCsvContent = null;

// ── Helpers de modal ──────────────────────────────────────────
function openModal(id) { document.getElementById(id).classList.remove("hidden"); }
function closeModal(id) { document.getElementById(id).classList.add("hidden"); }

// ── Índice de listas ──────────────────────────────────────────
async function loadListsIndex() {
  const ul = document.getElementById("lists-index");
  ul.innerHTML = '<li class="muted" style="padding:8px 12px">Cargando…</li>';
  try {
    const rows = await apiGet("/api/lists");
    ul.innerHTML = "";
    if (!rows.length) {
      ul.innerHTML = '<li class="muted" style="padding:8px 12px">Sin listas todavía.</li>';
      return;
    }
    rows.forEach(list => {
      const li = document.createElement("li");
      li.className = "list-index-item" + (_activeListId === list.id ? " active" : "");
      li.dataset.id = list.id;
      li.innerHTML = `
        <span class="list-index-name">${escapeHtml(list.name)}</span>
        <span class="list-index-count">${list.domain_count} dominios</span>`;
      li.addEventListener("click", () => selectList(list.id));
      ul.appendChild(li);
    });
  } catch {
    ul.innerHTML = '<li class="muted" style="padding:8px 12px">Error al cargar listas.</li>';
  }
}

// ── Seleccionar lista ─────────────────────────────────────────
async function selectList(listId) {
  _activeListId = listId;
  document.querySelectorAll(".list-index-item").forEach(li => {
    li.classList.toggle("active", Number(li.dataset.id) === listId);
  });
  document.getElementById("list-empty-state").classList.add("hidden");
  document.getElementById("list-active").classList.remove("hidden");
  document.getElementById("list-scan-result").classList.add("hidden");

  try {
    const data = await apiGet(`/api/lists/${listId}`);
    document.getElementById("list-title").textContent = data.name;
    document.getElementById("list-description").textContent = data.description || "";
    renderListDomains(data.domains);
  } catch {
    showListError("Error al cargar la lista.");
  }
}

// ── Renderizar tabla de dominios ──────────────────────────────
function renderListDomains(domains) {
  const tbody = document.getElementById("list-domains-tbody");
  document.getElementById("list-domain-count").textContent =
    `${domains.length} dominio${domains.length !== 1 ? "s" : ""}`;
  tbody.innerHTML = "";
  domains.forEach(d => {
    const tr = document.createElement("tr");
    tr.dataset.id = d.id;
    tr.innerHTML = `
      <td><code>${escapeHtml(d.domain)}</code></td>
      <td class="muted">${escapeHtml(d.session_cookie) || "—"}</td>
      <td class="muted">${escapeHtml(d.ip) || "—"}</td>
      <td class="muted">${escapeHtml(d.notes) || "—"}</td>
      <td><span class="badge ${d.is_active ? "badge-pass" : "badge-skip"}">${d.is_active ? "Sí" : "No"}</span></td>
      <td>
        <button class="btn btn-sm" onclick="openEditDomain(${d.id})">✏</button>
        <button class="btn btn-sm btn-danger-sm" onclick="deleteDomain(${d.id})">🗑</button>
      </td>`;
    tbody.appendChild(tr);
  });
}

function showListError(msg) {
  console.error(msg);
}

// ── Nueva lista ───────────────────────────────────────────────
document.getElementById("btn-new-list").addEventListener("click", () => {
  document.getElementById("list-form-title").textContent = "Nueva lista";
  document.getElementById("list-name").value = "";
  document.getElementById("list-desc-input").value = "";
  document.getElementById("list-form-error").classList.add("hidden");
  document.getElementById("form-list").dataset.editId = "";
  openModal("list-form-modal");
});

["btn-list-form-close", "btn-list-form-cancel"].forEach(id =>
  document.getElementById(id).addEventListener("click", () => closeModal("list-form-modal"))
);

document.getElementById("form-list").addEventListener("submit", async e => {
  e.preventDefault();
  const name = document.getElementById("list-name").value.trim();
  const description = document.getElementById("list-desc-input").value.trim();
  const editId = document.getElementById("form-list").dataset.editId;
  const errEl = document.getElementById("list-form-error");
  errEl.classList.add("hidden");

  const jsonHeaders = { "Content-Type": "application/json" };
  try {
    if (editId) {
      await apiFetch(`/api/lists/${editId}`, { method: "PUT", headers: jsonHeaders, body: JSON.stringify({ name, description }) });
    } else {
      await apiFetch("/api/lists", { method: "POST", headers: jsonHeaders, body: JSON.stringify({ name, description }) });
    }
    closeModal("list-form-modal");
    await loadListsIndex();
    if (editId) await selectList(Number(editId));
    showToast("success", editId ? "Lista actualizada" : "Lista creada");
  } catch (err) {
    errEl.textContent = err.message || "Error al guardar la lista.";
    errEl.classList.remove("hidden");
  }
});

// ── Editar lista ──────────────────────────────────────────────
document.getElementById("btn-list-edit").addEventListener("click", async () => {
  if (!_activeListId) return;
  const data = await apiGet(`/api/lists/${_activeListId}`);
  document.getElementById("list-form-title").textContent = "Editar lista";
  document.getElementById("list-name").value = data.name;
  document.getElementById("list-desc-input").value = data.description || "";
  document.getElementById("list-form-error").classList.add("hidden");
  document.getElementById("form-list").dataset.editId = _activeListId;
  openModal("list-form-modal");
});

// ── Eliminar lista ────────────────────────────────────────────
document.getElementById("btn-list-delete").addEventListener("click", async () => {
  if (!_activeListId) return;
  const name = document.getElementById("list-title").textContent;
  if (!await showConfirm(`¿Eliminar la lista "${name}" y todos sus dominios? Esta acción no se puede deshacer.`, "Eliminar lista")) return;
  try {
    await apiFetch(`/api/lists/${_activeListId}`, { method: "DELETE" });
    _activeListId = null;
    document.getElementById("list-empty-state").classList.remove("hidden");
    document.getElementById("list-active").classList.add("hidden");
    await loadListsIndex();
  } catch (err) {
    showToast("error", "Error al eliminar la lista", err.message);
  }
});

// ── Añadir dominio ────────────────────────────────────────────
document.getElementById("btn-add-domain").addEventListener("click", () => {
  _editingDomainId = null;
  document.getElementById("domain-form-title").textContent = "Añadir dominio";
  ["df-domain", "df-cookie", "df-ip", "df-notes"].forEach(id =>
    document.getElementById(id).value = ""
  );
  document.getElementById("domain-form-error").classList.add("hidden");
  openModal("domain-form-modal");
});

["btn-domain-form-close", "btn-domain-form-cancel"].forEach(id =>
  document.getElementById(id).addEventListener("click", () => closeModal("domain-form-modal"))
);

document.getElementById("form-domain").addEventListener("submit", async e => {
  e.preventDefault();
  const body = {
    domain: document.getElementById("df-domain").value.trim(),
    session_cookie: document.getElementById("df-cookie").value.trim(),
    ip: document.getElementById("df-ip").value.trim(),
    notes: document.getElementById("df-notes").value.trim(),
    is_active: true,
  };
  const errEl = document.getElementById("domain-form-error");
  errEl.classList.add("hidden");
  const jsonHeaders = { "Content-Type": "application/json" };
  try {
    if (_editingDomainId) {
      await apiFetch(`/api/lists/${_activeListId}/domains/${_editingDomainId}`,
        { method: "PUT", headers: jsonHeaders, body: JSON.stringify(body) });
    } else {
      await apiFetch(`/api/lists/${_activeListId}/domains`,
        { method: "POST", headers: jsonHeaders, body: JSON.stringify(body) });
    }
    closeModal("domain-form-modal");
    await selectList(_activeListId);
    showToast("success", _editingDomainId ? "Dominio actualizado" : "Dominio añadido");
  } catch (err) {
    errEl.textContent = err.message || "Error al guardar el dominio.";
    errEl.classList.remove("hidden");
  }
});

window.openEditDomain = async function(domainId) {
  _editingDomainId = domainId;
  const data = await apiGet(`/api/lists/${_activeListId}`);
  const d = data.domains.find(x => x.id === domainId);
  if (!d) return;
  document.getElementById("domain-form-title").textContent = "Editar dominio";
  document.getElementById("df-domain").value = d.domain;
  document.getElementById("df-cookie").value = d.session_cookie;
  document.getElementById("df-ip").value = d.ip;
  document.getElementById("df-notes").value = d.notes;
  document.getElementById("domain-form-error").classList.add("hidden");
  openModal("domain-form-modal");
};

window.deleteDomain = async function(domainId) {
  if (!await showConfirm("¿Eliminar este dominio de la lista?", "Eliminar dominio")) return;
  try {
    await apiFetch(`/api/lists/${_activeListId}/domains/${domainId}`, { method: "DELETE" });
    await selectList(_activeListId);
  } catch (err) {
    showToast("error", "Error al eliminar el dominio", err.message);
  }
};

// ── Exportar CSV ──────────────────────────────────────────────
document.getElementById("btn-list-export").addEventListener("click", async () => {
  if (!_activeListId) return;
  const token = getToken();
  const a = document.createElement("a");
  a.href = `/api/lists/${_activeListId}/export-csv`;
  // Añadir token como parámetro no es seguro; usamos fetch + blob
  try {
    const resp = await fetch(`${API_BASE}/api/lists/${_activeListId}/export-csv`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!resp.ok) throw new Error("Error al exportar");
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const name = document.getElementById("list-title").textContent;
    link.href = url;
    link.download = `${name}.csv`;
    link.click();
    URL.revokeObjectURL(url);
    showToast("success", "CSV exportado", `${name}.csv`);
  } catch (err) {
    showToast("error", "Error al exportar CSV", err.message);
  }
});

// ── Importar CSV ──────────────────────────────────────────────
document.getElementById("btn-list-import").addEventListener("click", () => {
  _importCsvContent = null;
  document.getElementById("import-preview-count").textContent = "";
  document.getElementById("import-error").classList.add("hidden");
  document.getElementById("import-file-input").value = "";
  document.getElementById("btn-import-csv-confirm").disabled = true;
  openModal("import-csv-modal");
});

["btn-import-csv-close", "btn-import-csv-cancel"].forEach(id =>
  document.getElementById(id).addEventListener("click", () => closeModal("import-csv-modal"))
);

document.getElementById("import-file-input").addEventListener("change", e => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = ev => {
    _importCsvContent = ev.target.result;
    const lines = _importCsvContent.split("\n").filter(l => l.trim() && !l.startsWith("#"));
    document.getElementById("import-preview-count").textContent =
      `${lines.length} dominio${lines.length !== 1 ? "s" : ""} detectado${lines.length !== 1 ? "s" : ""}`;
    document.getElementById("btn-import-csv-confirm").disabled = lines.length === 0;
  };
  reader.readAsText(file);
});

document.getElementById("btn-import-csv-confirm").addEventListener("click", async () => {
  if (!_importCsvContent || !_activeListId) return;
  const errEl = document.getElementById("import-error");
  errEl.classList.add("hidden");
  try {
    const res = await apiPost(`/api/lists/${_activeListId}/import-csv`, { csv_content: _importCsvContent });
    closeModal("import-csv-modal");
    await selectList(_activeListId);
    await loadListsIndex();
    const toastType = res.errors?.length ? "warn" : "success";
    const toastTitle = res.errors?.length ? "Importación con advertencias" : "Importación completada";
    const parts = [`Añadidos: ${res.added}`];
    if (res.skipped > 0) parts.push(`Omitidos (duplicados): ${res.skipped}`);
    if (res.errors?.length) parts.push(`Líneas con error: ${res.errors.length}`);
    showToast(toastType, toastTitle, parts.join("\n"), res.errors?.length ? 0 : 4000);
  } catch (err) {
    errEl.textContent = err.message || "Error al importar CSV.";
    errEl.classList.remove("hidden");
  }
});

// ── Scan desde lista (SSE) ────────────────────────────────────────────────────
document.getElementById("btn-list-scan").addEventListener("click", () => {
  if (!_activeListId) return;
  const progressWrap = document.getElementById("list-scan-progress");
  const fill         = document.getElementById("list-progress-fill");
  const label        = document.getElementById("list-progress-label");
  const resultDiv    = document.getElementById("list-scan-result");

  progressWrap.classList.remove("hidden");
  resultDiv.classList.add("hidden");
  fill.style.width = "0%";
  label.textContent = "Iniciando scan…";

  const token = localStorage.getItem("wss_token");
  const url = `/api/lists/${_activeListId}/scan-stream?token=${encodeURIComponent(token)}`;
  const es = new EventSource(url);

  const allResults = [];
  let total = 0;

  es.addEventListener("start", e => {
    const d = JSON.parse(e.data);
    total = d.total;
    label.textContent = `Escaneando 0 / ${total}…`;
    fill.style.width = "2%";
  });

  es.addEventListener("result", e => {
    const d = JSON.parse(e.data);
    allResults.push(d.result);

    const pct = Math.round((d.index / d.total) * 100);
    fill.style.width = `${pct}%`;
    label.textContent = `Escaneando ${d.index} / ${d.total} — ${d.result.domain || ""}`;

    // Renderizar tabla progresivamente
    const table = document.getElementById("list-batch-table");
    table._listScanData = { results: allResults };
    renderBatchTable(table, allResults);
    resultDiv.classList.remove("hidden");
  });

  es.addEventListener("done", e => {
    const d = JSON.parse(e.data);
    fill.style.width = "100%";
    label.textContent = `Completado — ${d.completed} dominio${d.completed !== 1 ? "s" : ""}`;
    document.getElementById("list-scan-meta").textContent =
      `Scan completado: ${new Date().toLocaleString()} — ${d.completed} dominios`;
    setTimeout(() => progressWrap.classList.add("hidden"), 1500);
    es.close();
  });

  es.addEventListener("error", e => {
    let msg = "Error de conexión";
    try { msg = JSON.parse(e.data).detail; } catch (_) {}
    fill.style.width = "0%";
    label.textContent = "Error: " + msg;
    es.close();
  });

  // Fallback: si EventSource cierra sin evento done
  es.onerror = () => {
    if (fill.style.width !== "100%") {
      fill.style.width = "0%";
      label.textContent = "Error: conexión interrumpida";
    }
    es.close();
  };
});

document.getElementById("btn-list-download-md")?.addEventListener("click", () => {
  const table = document.getElementById("list-batch-table");
  if (!table?._listScanData) return;
  const data = table._listScanData;
  // Obtener el nombre de la lista activa del sidebar
  const activeItem = document.querySelector(".list-index-item.active .list-index-name");
  const listSlug = slugify(activeItem?.textContent || "lista");
  const filename = `${makeTimestamp()}-list-${listSlug}.md`;
  const title = `Análisis de lista — ${activeItem?.textContent || "Lista"}`;
  downloadFile(filename, buildBatchMarkdownReport(data.results, title), "text/markdown");
});



// ══════════════════════════════════════════════════════════════════════════════
// FASE C.5 — VISTA EVOLUCIÓN TEMPORAL
// ══════════════════════════════════════════════════════════════════════════════

async function initEvolutionView() {
  // Cargar listas disponibles en el selector
  try {
    const lists = await apiFetch("/api/lists");
    const sel = document.getElementById("evo-list-select");
    sel.innerHTML = `<option value="">-- Selecciona una lista --</option>`;
    lists.forEach(l => {
      const opt = document.createElement("option");
      opt.value = l.id;
      opt.textContent = `${l.name} (${l.domain_count} dominios)`;
      sel.appendChild(opt);
    });
  } catch (err) {
    // No crítico: las listas son opcionales
  }
}

// Tabs de la vista evolución
document.querySelectorAll("[data-evo-tab]").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("[data-evo-tab]").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    const tab = btn.dataset.evoTab;
    document.getElementById("evo-tab-domain").classList.toggle("hidden", tab !== "domain");
    document.getElementById("evo-tab-list").classList.toggle("hidden", tab !== "list");
  });
});

async function loadEvolution() {
  const domain  = document.getElementById("evo-domain").value.trim();
  const days    = parseInt(document.getElementById("evo-days").value, 10);
  const errEl   = document.getElementById("evo-error");
  const resultEl = document.getElementById("evo-result");

  errEl.classList.add("hidden");
  resultEl.classList.add("hidden");

  if (!domain) {
    errEl.textContent = "Introduce un dominio para analizar.";
    errEl.classList.remove("hidden");
    return;
  }

  const btn = document.getElementById("btn-evo-load");
  btn.disabled = true;
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin me-1"></i>Cargando…`;

  try {
    const data = await apiFetch(`/api/history/evolution/${encodeURIComponent(domain)}?days=${days}`);
    renderEvolutionMatrix(data);
    resultEl.classList.remove("hidden");
  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.remove("hidden");
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-magnifying-glass me-1"></i>Analizar`;
  }
}

function renderEvolutionMatrix(data) {
  const container = document.getElementById("evo-matrix");

  if (!data.total_scans) {
    container.innerHTML = `<p class="text-muted">No hay scans de <strong>${escapeHtml(data.domain)}</strong> en los últimos ${data.days} días.</p>`;
    return;
  }

  // Recolectar todas las fechas únicas ordenadas
  const allDates = [...new Set(data.tests.flatMap(t => t.series.map(s => s.date)))].sort();

  const fmtDate = iso => {
    const d = new Date(iso);
    return `${d.getDate().toString().padStart(2,"0")}/${(d.getMonth()+1).toString().padStart(2,"0")}<br><small>${d.getHours().toString().padStart(2,"0")}:${d.getMinutes().toString().padStart(2,"0")}</small>`;
  };

  let html = `<p class="text-muted small mb-2"><strong>${escapeHtml(data.domain)}</strong> — ${data.total_scans} scan${data.total_scans !== 1 ? "s" : ""} en los últimos ${data.days} días</p>`;
  html += `<div class="table-responsive"><table class="table table-dark table-sm table-bordered evo-table">`;
  html += `<thead><tr><th style="min-width:130px">Test</th>`;
  allDates.forEach(d => html += `<th class="text-center" style="min-width:60px">${fmtDate(d)}</th>`);
  html += `</tr></thead><tbody>`;

  data.tests.forEach(test => {
    const byDate = Object.fromEntries(test.series.map(s => [s.date, s.result]));
    html += `<tr><td class="small"><span class="text-muted">${escapeHtml(test.id)}</span> ${escapeHtml(test.name)}</td>`;
    allDates.forEach(d => {
      const r = byDate[d];
      if (!r) { html += `<td class="text-center text-muted">—</td>`; return; }
      const cls = r === "PASS" ? "cell-P" : r === "FAIL" ? "cell-F" : r === "WARN" ? "cell-W" : r === "SKIP" ? "cell-S" : "";
      html += `<td class="text-center ${cls}"><span class="badge badge-${r}">${r}</span></td>`;
    });
    html += `</tr>`;
  });

  html += `</tbody></table></div>`;
  container.innerHTML = html;
}

document.getElementById("btn-evo-load")?.addEventListener("click", loadEvolution);
document.getElementById("evo-domain")?.addEventListener("keydown", e => {
  if (e.key === "Enter") loadEvolution();
});

// Vista por lista: matriz dominios × tests (último scan)
async function loadEvolutionByList() {
  const listId  = document.getElementById("evo-list-select").value;
  const errEl   = document.getElementById("evo-list-error");
  const resultEl = document.getElementById("evo-list-result");

  errEl.classList.add("hidden");
  resultEl.classList.add("hidden");

  if (!listId) {
    errEl.textContent = "Selecciona una lista primero.";
    errEl.classList.remove("hidden");
    return;
  }

  const btn = document.getElementById("btn-evo-list-load");
  btn.disabled = true;
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin me-1"></i>Cargando…`;

  try {
    const data = await apiFetch(`/api/lists/${listId}/summary`);
    renderListEvolutionMatrix(data);
    resultEl.classList.remove("hidden");
  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.remove("hidden");
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-table me-1"></i>Ver matriz`;
  }
}

function renderListEvolutionMatrix(data) {
  const container = document.getElementById("evo-list-matrix");

  if (!data.domains.length) {
    container.innerHTML = `<p class="text-muted">La lista <strong>${escapeHtml(data.list_name)}</strong> no tiene dominios activos.</p>`;
    return;
  }

  // Obtener IDs de tests del primer dominio con scans
  const testIds = TESTS_META.map(t => t.id);
  const trendIcon = t => t === "improving" ? `<i class="fa-solid fa-arrow-trend-up text-success" title="Mejorando"></i>`
                       : t === "worsening" ? `<i class="fa-solid fa-arrow-trend-down text-danger" title="Empeorando"></i>`
                       : `<i class="fa-solid fa-minus text-muted" title="Estable"></i>`;

  let html = `<p class="text-muted small mb-2"><strong>${escapeHtml(data.list_name)}</strong> — ${data.domains.length} dominio${data.domains.length !== 1 ? "s" : ""}</p>`;
  html += `<div class="table-responsive"><table class="table table-dark table-sm table-bordered evo-table">`;
  html += `<thead><tr><th style="min-width:160px">Dominio</th><th class="text-center">Tendencia</th>`;
  testIds.forEach(id => html += `<th class="text-center" style="min-width:44px" title="${TESTS_META.find(t=>t.id===id)?.name||id}">${id}</th>`);
  html += `</tr></thead><tbody>`;

  data.domains.forEach(d => {
    const dateStr = d.last_scanned_at ? formatDate(d.last_scanned_at) : "—";
    html += `<tr>
      <td class="small font-monospace" title="Último scan: ${escapeHtml(dateStr)}">${escapeHtml(d.domain)}</td>
      <td class="text-center">${trendIcon(d.trend)}</td>`;
    testIds.forEach(id => {
      const r = d.tests[id];
      if (!r) { html += `<td class="text-center text-muted small">—</td>`; return; }
      const cls = r === "PASS" ? "cell-P" : r === "FAIL" ? "cell-F" : r === "WARN" ? "cell-W" : r === "SKIP" ? "cell-S" : "";
      html += `<td class="text-center ${cls}"><span class="badge badge-${r}" style="font-size:10px">${r}</span></td>`;
    });
    html += `</tr>`;
  });

  html += `</tbody></table></div>`;
  container.innerHTML = html;
}

document.getElementById("btn-evo-list-load")?.addEventListener("click", loadEvolutionByList);


// ══════════════════════════════════════════════════════════════════════════════
// FASE C.6 — VISTA ADMINISTRACIÓN DE USUARIOS
// ══════════════════════════════════════════════════════════════════════════════

async function loadAdminUsers() {
  const tbody = document.getElementById("admin-users-tbody");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="6" class="text-muted text-center"><i class="fa-solid fa-spinner fa-spin me-1"></i>Cargando…</td></tr>`;
  try {
    const users = await apiFetch("/api/admin/users");
    const meId  = getUser()?.id;

    tbody.innerHTML = users.map(u => `
      <tr data-uid="${u.id}">
        <td class="font-monospace small fw-semibold">${escapeHtml(u.username)}</td>
        <td>
          <select class="form-select form-select-sm admin-role-select" data-uid="${u.id}" ${u.id === meId ? "disabled" : ""}>
            <option value="admin"   ${u.role === "admin"   ? "selected" : ""}>admin</option>
            <option value="analyst" ${u.role === "analyst" ? "selected" : ""}>analyst</option>
          </select>
        </td>
        <td class="text-center">
          <div class="form-check form-switch d-flex justify-content-center mb-0">
            <input class="form-check-input admin-active-toggle" type="checkbox"
              data-uid="${u.id}" ${u.is_active ? "checked" : ""} ${u.id === meId ? "disabled" : ""} />
          </div>
        </td>
        <td class="text-muted small">${formatDate(u.created_at)}</td>
        <td class="text-muted small">${u.last_login ? formatDate(u.last_login) : "—"}</td>
        <td>
          <div class="d-flex gap-1">
            <button class="btn btn-outline-secondary btn-sm admin-reset-pwd"
              data-uid="${u.id}" data-uname="${escapeHtml(u.username)}"
              title="Cambiar contraseña"><i class="fa-solid fa-key"></i></button>
            ${u.id !== meId ? `
            <button class="btn btn-danger btn-sm admin-delete-user"
              data-uid="${u.id}" data-uname="${escapeHtml(u.username)}"
              title="Eliminar usuario"><i class="fa-solid fa-trash"></i></button>` : ""}
          </div>
        </td>
      </tr>
    `).join("");

    // Bind: cambio de rol
    tbody.querySelectorAll(".admin-role-select").forEach(sel => {
      sel.addEventListener("change", async () => {
        const uid  = parseInt(sel.dataset.uid, 10);
        const row  = tbody.querySelector(`tr[data-uid="${uid}"]`);
        const active = row.querySelector(".admin-active-toggle").checked;
        await adminUpdateUser(uid, sel.value, active);
      });
    });

    // Bind: toggle activo
    tbody.querySelectorAll(".admin-active-toggle").forEach(cb => {
      cb.addEventListener("change", async () => {
        const uid  = parseInt(cb.dataset.uid, 10);
        const row  = tbody.querySelector(`tr[data-uid="${uid}"]`);
        const role = row.querySelector(".admin-role-select").value;
        await adminUpdateUser(uid, role, cb.checked);
      });
    });

    // Bind: reset contraseña
    tbody.querySelectorAll(".admin-reset-pwd").forEach(btn => {
      btn.addEventListener("click", () =>
        openResetPasswordModal(parseInt(btn.dataset.uid, 10), btn.dataset.uname)
      );
    });

    // Bind: eliminar usuario
    tbody.querySelectorAll(".admin-delete-user").forEach(btn => {
      btn.addEventListener("click", () =>
        confirmDeleteUser(parseInt(btn.dataset.uid, 10), btn.dataset.uname)
      );
    });

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-danger">${escapeHtml(err.message)}</td></tr>`;
  }
}

async function adminUpdateUser(uid, role, isActive) {
  try {
    await apiPut(`/api/admin/users/${uid}`, { role, is_active: isActive });
    showToast("success", "Usuario actualizado");
  } catch (err) {
    showToast("error", "Error al actualizar", err.message);
    loadAdminUsers();  // revertir UI
  }
}

function openResetPasswordModal(uid, username) {
  document.getElementById("reset-pwd-uid").value = uid;
  document.getElementById("reset-pwd-username").textContent = username;
  document.getElementById("reset-pwd-input").value = "";
  document.getElementById("reset-pwd-error").classList.add("hidden");
  openModal("reset-pwd-modal");
}

document.getElementById("btn-reset-pwd-confirm")?.addEventListener("click", async () => {
  const uid   = parseInt(document.getElementById("reset-pwd-uid").value, 10);
  const pwd   = document.getElementById("reset-pwd-input").value;
  const errEl = document.getElementById("reset-pwd-error");
  errEl.classList.add("hidden");
  if (!pwd || pwd.length < 6) {
    errEl.textContent = "La contraseña debe tener al menos 6 caracteres.";
    errEl.classList.remove("hidden");
    return;
  }
  try {
    await apiPut(`/api/admin/users/${uid}/reset-password`, { password: pwd });
    closeModal("reset-pwd-modal");
    showToast("success", "Contraseña actualizada");
  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.remove("hidden");
  }
});

["btn-reset-pwd-close", "btn-reset-pwd-cancel"].forEach(id =>
  document.getElementById(id)?.addEventListener("click", () => closeModal("reset-pwd-modal"))
);

async function confirmDeleteUser(uid, username) {
  const ok = await showConfirm(
    `¿Eliminar al usuario "${username}"? Esta acción no se puede deshacer.`,
    "Eliminar usuario"
  );
  if (!ok) return;
  try {
    await apiDelete(`/api/admin/users/${uid}`);
    showToast("success", "Usuario eliminado");
    loadAdminUsers();
  } catch (err) {
    showToast("error", "Error al eliminar", err.message);
  }
}

document.getElementById("btn-admin-new-user")?.addEventListener("click", () => {
  document.getElementById("form-new-user")?.reset();
  document.getElementById("new-user-error").classList.add("hidden");
  openModal("new-user-modal");
});

["btn-new-user-close", "btn-new-user-cancel"].forEach(id =>
  document.getElementById(id)?.addEventListener("click", () => closeModal("new-user-modal"))
);

document.getElementById("form-new-user")?.addEventListener("submit", async e => {
  e.preventDefault();
  const errEl    = document.getElementById("new-user-error");
  errEl.classList.add("hidden");
  const username = document.getElementById("nu-username").value.trim();
  const password = document.getElementById("nu-password").value;
  const role     = document.getElementById("nu-role").value;
  if (!username || !password) {
    errEl.textContent = "Usuario y contraseña son obligatorios.";
    errEl.classList.remove("hidden");
    return;
  }
  try {
    await apiPost("/api/admin/users", { username, password, role });
    closeModal("new-user-modal");
    showToast("success", "Usuario creado", username);
    loadAdminUsers();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.remove("hidden");
  }
});

// ── Vaciar historial ─────────────────────────────────────────────────────────

document.getElementById("btn-purge-history")?.addEventListener("click", () => {
  document.getElementById("purge-history-pwd").value = "";
  document.getElementById("purge-history-error").classList.add("hidden");
  openModal("purge-history-modal");
  setTimeout(() => document.getElementById("purge-history-pwd")?.focus(), 80);
});

document.getElementById("btn-purge-cancel")?.addEventListener("click", () =>
  closeModal("purge-history-modal")
);

document.getElementById("btn-purge-confirm")?.addEventListener("click", async () => {
  const pwd    = document.getElementById("purge-history-pwd").value;
  const errEl  = document.getElementById("purge-history-error");
  errEl.classList.add("hidden");

  if (!pwd) {
    errEl.textContent = "Ingresa tu contraseña para confirmar.";
    errEl.classList.remove("hidden");
    return;
  }

  const btn = document.getElementById("btn-purge-confirm");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Eliminando…';

  try {
    const res = await fetch(`${API_BASE}/api/admin/history`, {
      method: "DELETE",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${getToken()}`,
      },
      body: JSON.stringify({ password: pwd }),
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || `Error ${res.status}`);
    }

    const data = await res.json();
    closeModal("purge-history-modal");
    showToast("success", "Historial vaciado", `${data.deleted} registro${data.deleted !== 1 ? "s" : ""} eliminado${data.deleted !== 1 ? "s" : ""}`);
  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.remove("hidden");
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-trash-can me-1"></i>Sí, vaciar historial';
  }
});
