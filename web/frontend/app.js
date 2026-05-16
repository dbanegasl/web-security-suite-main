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
const THEME_KEY = "wss-theme";

// ══════════════════════════════════════════════════════════════
// TEMA
// ══════════════════════════════════════════════════════════════
const THEMES = {
  vapor: {
    href:      "https://cdn.jsdelivr.net/npm/bootswatch@5.3.8/dist/vapor/bootstrap.min.css",
    bsTheme:   "dark",
    btnLabel:  '<i class="fa-solid fa-sun fa-fw me-1"></i>LIGHT',
    next:      "brite",
  },
  brite: {
    href:      "https://cdn.jsdelivr.net/npm/bootswatch@5.3.8/dist/brite/bootstrap.min.css",
    bsTheme:   "light",
    btnLabel:  '<i class="fa-solid fa-moon fa-fw me-1"></i>DARK',
    next:      "vapor",
  },
};

function setTheme(name) {
  const cfg = THEMES[name] || THEMES.vapor;
  document.getElementById("theme-css").href = cfg.href;
  document.documentElement.setAttribute("data-bs-theme", cfg.bsTheme);
  const btn = document.getElementById("btn-theme-toggle");
  if (btn) btn.innerHTML = cfg.btnLabel;
  localStorage.setItem(THEME_KEY, name);
}

function toggleTheme() {
  const current = localStorage.getItem(THEME_KEY) || "vapor";
  setTheme(THEMES[current]?.next || "brite");
}

// Aplicar tema guardado antes de que el DOM sea visible (evita flash)
(function initTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved && THEMES[saved]) setTheme(saved);
})();

// ══════════════════════════════════════════════════════════════
// AUTENTICACIÓN
// ══════════════════════════════════════════════════════════════
const loginScreen  = document.getElementById("login-screen");
const formLogin    = document.getElementById("form-login");
const loginError   = document.getElementById("login-error");
const btnLogout      = document.getElementById("btn-logout");
const topbarUsername = document.getElementById("topbar-username");

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
  // Avatar: foto real o iniciales
  const initialsEl = document.getElementById("topbar-avatar-initials");
  const avatarImg  = document.getElementById("topbar-avatar-img");
  if (user.avatar) {
    if (avatarImg)  { avatarImg.src = user.avatar; avatarImg.classList.remove("hidden"); }
    if (initialsEl) initialsEl.textContent = "";
  } else {
    if (avatarImg)  avatarImg.classList.add("hidden");
    if (initialsEl) initialsEl.textContent = user.username.slice(0, 2).toUpperCase();
  }
  // Nombre de usuario
  if (topbarUsername) topbarUsername.textContent = user.username;
  // Badge de rol
  const roleEl = document.getElementById("topbar-role");
  if (roleEl) {
    roleEl.textContent = user.role === "admin" ? "admin" : "viewer";
    roleEl.className = "badge topbar-role-badge " + (user.role === "admin" ? "bg-primary" : "bg-secondary");
  }
  // Mostrar enlace de admin solo si el rol es admin
  const adminItem = document.getElementById("nav-admin-item");
  if (adminItem) {
    if (user.role === "admin") adminItem.classList.remove("hidden");
    else adminItem.classList.add("hidden");
  }
  // Marcar body para ocultar/mostrar elementos admin-only-el via CSS
  document.body.classList.toggle("is-admin", user.role === "admin");
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
    saveAuth(data.access_token, { id: data.id, username: data.username, role: data.role, avatar: data.avatar || null });
    // Recargar settings de plataforma con el token ya disponible
    loadAndApplySettings();
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
  loadAndApplySettings();   // branding visible antes del login
  const token = getToken();
  if (!token) { showLogin(); return; }
  try {
    const me = await apiFetch("/api/auth/me", { method: "GET" });
    // Actualizar usuario guardado con datos frescos (incluye avatar)
    const stored = getUser();
    if (stored) saveAuth(getToken(), { ...stored, ...me });
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
    tr.dataset.block    = t.block    || "";
    tr.dataset.severity = t.severity || "";
    tr.dataset.result   = t.result   || "";
    tr.innerHTML = `
      <td class="text-center align-middle pe-0">
        <button class="btn btn-link btn-sm p-0 lh-1" title="Ver en wiki"
                onclick="openWikiModal('${escapeHtml(String(t.id))}')">
          <i class="fa-solid fa-book-open text-info" style="font-size:.8rem"></i>
        </button>
      </td>
      <td>${escapeHtml(t.id)}</td>
      <td>${escapeHtml(t.name)}</td>
      <td><span class="badge badge-${escapeHtml(t.result)}">${escapeHtml(t.result)}</span></td>
      <td class="muted">${escapeHtml(t.detail || "—")}</td>
    `;
    tbody.appendChild(tr);
  }

  // Resetear filtros y aplicarlos por primera vez
  document.getElementById("filter-block").value    = "";
  document.getElementById("filter-severity").value = "";
  document.getElementById("filter-result").value   = "";
  _applyFilters();

  resultsDiv.classList.remove("hidden");
}

function hideResults() { resultsDiv.classList.add("hidden"); }

// ── Filtros de tests ─────────────────────────────────────────
function _applyFilters() {
  const selBlock    = document.getElementById("filter-block")?.value    || "";
  const selSeverity = document.getElementById("filter-severity")?.value || "";
  const selResult   = document.getElementById("filter-result")?.value   || "";
  const rows = document.querySelectorAll("#tests-tbody tr");
  let visible = 0;
  rows.forEach(tr => {
    const matchBlock    = !selBlock    || tr.dataset.block    === selBlock;
    const matchSeverity = !selSeverity || tr.dataset.severity === selSeverity;
    const matchResult   = !selResult   || tr.dataset.result   === selResult;
    if (matchBlock && matchSeverity && matchResult) {
      tr.classList.remove("wss-hidden");
      visible++;
    } else {
      tr.classList.add("wss-hidden");
    }
  });
  const countEl = document.getElementById("filter-count");
  if (countEl) {
    countEl.textContent = (selBlock || selSeverity || selResult)
      ? `${visible} / ${rows.length} tests`
      : "";
  }
}

["filter-block", "filter-severity", "filter-result"].forEach(id => {
  document.getElementById(id)?.addEventListener("change", _applyFilters);
});

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
    batchProgress.classList.add("hidden");
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
  TESTS.forEach(t => { html += `<th><a href="${API_BASE}/wiki.html#t${t}" target="_blank" rel="noopener" class="wiki-th-link" title="TEST-${t}">${t}</a></th>`; });
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
      : `<span class="cell-W">~ ${escapeHtml(d.result_b)}</span>`;
    return `<tr class="${d.changed ? "diff-changed" : ""}">
      <td>${escapeHtml(d.id)}</td>
      <td>${escapeHtml(d.name)}</td>
      <td><span class="badge badge-${escapeHtml(d.result_a)}">${escapeHtml(d.result_a)}</span></td>
      <td><span class="badge badge-${escapeHtml(d.result_b)}">${escapeHtml(d.result_b)}</span></td>
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
const VIEW_TITLES = {
  home:       "Inicio",
  individual: "Análisis individual",
  batch:      "Análisis batch",
  lists:      "Análisis listas",
  history:    "Historial",
  evolution:  "Evolución",
  admin:      "Administración",
  settings:   "Configuración",
  wiki:       "Wiki de tests"
};

const VALID_VIEWS = new Set(["home","individual","batch","lists","history","evolution","admin","settings","wiki"]);

// ── Wiki dinámica ─────────────────────────────────────────────────────────
let _wikiData = null; // caché de la última respuesta de /api/tests

async function initWikiView() {
  const loading  = document.getElementById("wiki-loading");
  const errorEl  = document.getElementById("wiki-error");
  const tableWrap= document.getElementById("wiki-table-wrap");
  const filterBlock = document.getElementById("wiki-filter-block");
  const filterSev   = document.getElementById("wiki-filter-severity");
  const searchEl    = document.getElementById("wiki-search");

  loading?.classList.remove("hidden");
  errorEl?.classList.add("hidden");
  tableWrap?.classList.add("hidden");

  try {
    if (!_wikiData) {
      _wikiData = await apiFetch("/api/tests");
      // Poblar select de bloques (solo la primera vez)
      if (filterBlock && filterBlock.options.length <= 1) {
        _wikiData.blocks.forEach(b => {
          const opt = document.createElement("option");
          opt.value = b.block;
          opt.textContent = `Bloque ${b.block} — ${b.name}`;
          filterBlock.appendChild(opt);
        });
      }
    }

    loading?.classList.add("hidden");
    tableWrap?.classList.remove("hidden");
    _renderWikiTable();

    // Listeners (idempotentes: se adjuntan al contenedor, no cada vez)
    filterBlock?.addEventListener("change", _renderWikiTable, { signal: _wikiAbortCtrl?.signal });
    filterSev?.addEventListener("change", _renderWikiTable,   { signal: _wikiAbortCtrl?.signal });
    searchEl?.addEventListener("input",   _renderWikiTable,   { signal: _wikiAbortCtrl?.signal });
  } catch (err) {
    loading?.classList.add("hidden");
    if (errorEl) { errorEl.textContent = `Error al cargar el catálogo: ${err.message}`; errorEl.classList.remove("hidden"); }
  }
}

// AbortController para limpiar listeners cuando se sale de la wiki
let _wikiAbortCtrl = null;
// (Re-inicializar en cada visita)
const _origNavigateTo = navigateTo;  // guardamos referencia previa para wrapping inline

function _renderWikiTable() {
  if (!_wikiData) return;
  const filterBlock = document.getElementById("wiki-filter-block");
  const filterSev   = document.getElementById("wiki-filter-severity");
  const searchEl    = document.getElementById("wiki-search");
  const tbody       = document.getElementById("wiki-tbody");
  const countEl     = document.getElementById("wiki-count");
  if (!tbody) return;

  const blk   = filterBlock?.value || "";
  const sev   = filterSev?.value   || "";
  const query = (searchEl?.value   || "").toLowerCase().trim();

  const SEV_COLOR = { CRITICAL: "danger", HIGH: "warning", MEDIUM: "info", LOW: "secondary" };

  const filtered = _wikiData.tests.filter(t => {
    if (blk && String(t.block) !== blk) return false;
    if (sev && t.severity !== sev)       return false;
    if (query && !(
      t.id.includes(query) ||
      t.name.toLowerCase().includes(query) ||
      (t.description || "").toLowerCase().includes(query) ||
      (t.cwe || "").toLowerCase().includes(query)
    )) return false;
    return true;
  });

  tbody.innerHTML = filtered.map(t => {
    const sColor = SEV_COLOR[t.severity] || "secondary";
    return `<tr class="wiki-row" data-test-id="${t.id}" style="cursor:pointer">
      <td><code class="text-info">${t.id}</code></td>
      <td>${escapeHtml(t.name)}${t.description ? `<div class="text-muted small text-truncate wiki-desc-preview" style="max-width:300px">${escapeHtml(t.description.replace(/<[^>]+>/g," ").replace(/\s+/g," ").trim().substring(0,80))}…</div>` : ""}</td>
      <td><span class="badge bg-secondary">${t.block} — ${escapeHtml(t.block_name)}</span></td>
      <td><span class="badge bg-${sColor}">${t.severity}</span></td>
      <td>${t.cwe ? `<a href="https://cwe.mitre.org/data/definitions/${t.cwe.replace("CWE-","")}.html" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">${t.cwe}</a>` : "—"}</td>
    </tr>`;
  }).join("");

  if (countEl) countEl.textContent = `Mostrando ${filtered.length} de ${_wikiData.total} tests`;
}

// Panel de detalle wiki
let _wikiDetailTestId = null;

function openWikiDetailPanel(testId) {
  const t = _wikiData?.tests?.find(x => x.id === testId);
  if (!t) return;
  _wikiDetailTestId = testId;

  const SEV_COLOR = { CRITICAL: "danger", HIGH: "warning", MEDIUM: "info", LOW: "secondary" };

  const panel     = document.getElementById("wiki-detail-panel");
  const layout    = document.getElementById("wiki-layout");
  if (!panel || !layout) return;

  document.getElementById("wd-id").textContent           = t.id;
  document.getElementById("wd-name").textContent         = t.name;

  const sevEl = document.getElementById("wd-severity");
  sevEl.textContent  = t.severity;
  sevEl.className    = `badge bg-${SEV_COLOR[t.severity] || "secondary"}`;

  document.getElementById("wd-block").textContent        = `${t.block} — ${t.block_name}`;

  const cweEl = document.getElementById("wd-cwe");
  if (t.cwe) {
    cweEl.textContent = t.cwe;
    cweEl.href        = `https://cwe.mitre.org/data/definitions/${t.cwe.replace("CWE-","")}.html`;
    cweEl.style.display = "";
  } else {
    cweEl.style.display = "none";
  }

  const descEl       = document.getElementById("wd-description");
  const descEmpty    = document.getElementById("wd-description-empty");
  if (t.description && t.description.trim()) {
    descEl.innerHTML = t.description;
    descEl.classList.remove("hidden");
    descEmpty?.classList.add("hidden");
  } else {
    descEl.classList.add("hidden");
    descEmpty?.classList.remove("hidden");
  }

  const refs = Array.isArray(t.references) ? t.references : [];
  const refsWrap = document.getElementById("wd-references-wrap");
  const refsList  = document.getElementById("wd-references");
  if (refs.length && refsWrap && refsList) {
    refsList.innerHTML = refs.map(u => {
      let display = u;
      try { display = new URL(u).hostname; } catch {}
      return `<li><a href="${u}" target="_blank" rel="noopener noreferrer">${escapeHtml(display)}</a></li>`;
    }).join("");
    refsWrap.style.display = "";
  } else if (refsWrap) {
    refsWrap.style.display = "none";
  }

  // Botón "Editar" — visible solo para admins via CSS class admin-only-el

  // Resaltar fila activa
  document.querySelectorAll(".wiki-row").forEach(r => r.classList.remove("table-active"));
  document.querySelector(`.wiki-row[data-test-id="${testId}"]`)?.classList.add("table-active");

  // Mostrar panel
  panel.classList.remove("hidden");
  layout.classList.add("wiki-layout-split");
}

// Listener: clic en filas de la tabla wiki (delegación)
document.getElementById("wiki-tbody")?.addEventListener("click", e => {
  const row = e.target.closest(".wiki-row");
  if (!row) return;
  const testId = row.dataset.testId;
  if (_wikiDetailTestId === testId) {
    // Clic en la misma fila: cerrar panel
    closeWikiDetailPanel();
  } else {
    openWikiDetailPanel(testId);
  }
});

function closeWikiDetailPanel() {
  _wikiDetailTestId = null;
  document.getElementById("wiki-detail-panel")?.classList.add("hidden");
  document.getElementById("wiki-layout")?.classList.remove("wiki-layout-split");
  document.querySelectorAll(".wiki-row").forEach(r => r.classList.remove("table-active"));
}

document.getElementById("btn-wiki-detail-close")?.addEventListener("click", closeWikiDetailPanel);

// Tabs de remediación en el panel de detalle (data-tab-target custom, sin Bootstrap Tab)
document.getElementById("wd-description")?.addEventListener("click", e => {
  const btn = e.target.closest("[data-tab-target]");
  if (!btn) return;
  e.preventDefault();
  const navList = btn.closest("ul");
  if (!navList) return;
  const tabContent = navList.nextElementSibling;
  if (!tabContent) return;
  navList.querySelectorAll(".nav-link").forEach(b => b.classList.remove("active"));
  tabContent.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
  btn.classList.add("active");
  const target = tabContent.querySelector(btn.getAttribute("data-tab-target"));
  if (target) target.classList.add("active");
});

// Handler de tabs dentro del modal wiki (misma lógica, distinto contenedor)
document.getElementById("wm-description")?.addEventListener("click", e => {
  const btn = e.target.closest("[data-tab-target]");
  if (!btn) return;
  e.preventDefault();
  const navList = btn.closest("ul");
  if (!navList) return;
  const tabContent = navList.nextElementSibling;
  if (!tabContent) return;
  navList.querySelectorAll(".nav-link").forEach(b => b.classList.remove("active"));
  tabContent.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
  btn.classList.add("active");
  const target = tabContent.querySelector(btn.getAttribute("data-tab-target"));
  if (target) target.classList.add("active");
});

async function openWikiModal(testId) {
  const normId = id => String(parseInt(id, 10) || 0).padStart(2, "0");
  const norm = normId(testId);

  if (!_wikiData) {
    try { _wikiData = await apiFetch("/api/tests"); } catch { _wikiData = null; }
  }
  const t = _wikiData?.tests?.find(x => normId(x.id) === norm);

  const SEV_COLOR = { CRITICAL: "danger", HIGH: "warning", MEDIUM: "info", LOW: "secondary" };

  document.getElementById("wm-id").textContent   = t ? t.id : testId;
  document.getElementById("wm-name").textContent = t?.name || "";

  const sevEl = document.getElementById("wm-severity");
  sevEl.textContent = t?.severity || "";
  sevEl.className   = `badge bg-${SEV_COLOR[t?.severity] || "secondary"}`;

  document.getElementById("wm-block").textContent =
    t ? `${t.block} — ${t.block_name}` : "";

  const cweEl = document.getElementById("wm-cwe");
  if (t?.cwe) {
    cweEl.textContent = t.cwe;
    cweEl.href = `https://cwe.mitre.org/data/definitions/${t.cwe.replace("CWE-", "")}.html`;
    cweEl.style.display = "";
  } else {
    cweEl.style.display = "none";
  }

  const descEl    = document.getElementById("wm-description");
  const descEmpty = document.getElementById("wm-description-empty");
  if (t?.description?.trim()) {
    descEl.innerHTML = t.description;
    descEl.classList.remove("hidden");
    descEmpty?.classList.add("hidden");
  } else {
    descEl.innerHTML = "";
    descEl.classList.add("hidden");
    descEmpty?.classList.remove("hidden");
  }

  const refs     = Array.isArray(t?.references) ? t.references : [];
  const refsWrap = document.getElementById("wm-references-wrap");
  const refsList  = document.getElementById("wm-references");
  if (refs.length && refsWrap && refsList) {
    refsList.innerHTML = refs.map(u => {
      let display = u;
      try { display = new URL(u).hostname; } catch {}
      return `<li><a href="${u}" target="_blank" rel="noopener noreferrer">${escapeHtml(display)}</a></li>`;
    }).join("");
    refsWrap.style.display = "";
  } else if (refsWrap) {
    refsWrap.style.display = "none";
  }

  // Botones Copiar MD / Descargar .md
  const copyBtn = document.getElementById("wm-copy-md");
  const dlBtn   = document.getElementById("wm-download-md");
  if (copyBtn) copyBtn.onclick = async () => {
    try {
      await navigator.clipboard.writeText(buildTestMarkdown(t));
      const orig = copyBtn.innerHTML;
      copyBtn.innerHTML = '<i class="fa-solid fa-check me-1"></i>Copiado';
      copyBtn.classList.replace("btn-outline-info", "btn-outline-success");
      setTimeout(() => {
        copyBtn.innerHTML = orig;
        copyBtn.classList.replace("btn-outline-success", "btn-outline-info");
      }, 2000);
    } catch { /* clipboard no disponible */ }
  };
  if (dlBtn) dlBtn.onclick = () => {
    const md = buildTestMarkdown(t);
    const slug = (t?.name || testId).replace(/[^a-z0-9]/gi, "-").toLowerCase().replace(/-+/g, "-");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([md], { type: "text/markdown" }));
    a.download = `TEST-${t?.id || testId}-${slug}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  bootstrap.Modal.getOrCreateInstance(
    document.getElementById("wiki-quick-modal")
  ).show();
}

/* ─── Markdown export helpers ─────────────────────────────────── */

// Convierte nodos inline de un elemento HTML a sintaxis Markdown
function htmlInlineToMd(el) {
  let html = el.innerHTML
    .replace(/<code[^>]*>(.*?)<\/code>/gi,          (_, c) => "`" + c + "`")
    .replace(/<(?:strong|b)[^>]*>(.*?)<\/(?:strong|b)>/gi, (_, c) => `**${c}**`)
    .replace(/<(?:em|i)[^>]*>(.*?)<\/(?:em|i)>/gi,  (_, c) => `*${c}*`)
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<[^>]+>/g, "");
  const tmp = document.createElement("textarea");
  tmp.innerHTML = html;
  return tmp.value.trim();
}

// Convierte los datos de un test al formato Markdown completo
function buildTestMarkdown(t) {
  if (!t) return "";
  const lines = [];
  lines.push(`# TEST-${t.id} — ${t.name}`, "");
  lines.push(`**Severidad:** ${t.severity || "—"}  `);
  lines.push(`**Bloque:** ${t.block} — ${t.block_name || "—"}  `);
  if (t.cwe) {
    const num = t.cwe.replace(/\D/g, "");
    lines.push(`**CWE:** [${t.cwe}](https://cwe.mitre.org/data/definitions/${num}.html)  `);
  }
  lines.push("");

  if (t.description?.trim()) {
    const tmp = document.createElement("div");
    tmp.innerHTML = t.description;
    const ICON = { PASS: "✅", FAIL: "❌", WARN: "⚠️", SKIP: "⏭️" };

    for (const el of tmp.children) {
      if (el.classList.contains("wiki-sect-head")) {
        lines.push(`## ${el.textContent.trim()}`, "");

      } else if (el.tagName === "P") {
        lines.push(htmlInlineToMd(el), "");

      } else if (el.tagName === "DIV" && el.querySelector(".badge")) {
        // Filas de resultados posibles
        for (const row of el.querySelectorAll("[class*='mb-1']")) {
          const badge = row.querySelector(".badge");
          if (!badge) continue;
          const result = badge.textContent.trim();
          const text   = row.textContent.replace(result, "").trim();
          lines.push(`- ${ICON[result] || "•"} **${result}** — ${text}`);
        }
        lines.push("");

      } else if (el.tagName === "UL" && el.classList.contains("nav")) {
        // nav-tabs: se procesa junto con tab-content a continuación

      } else if (el.classList.contains("tab-content")) {
        for (const pane of el.querySelectorAll(".tab-pane")) {
          const btn     = tmp.querySelector(`[data-tab-target="#${pane.id}"]`);
          const tabName = btn ? btn.textContent.trim() : pane.id.split("-").pop();
          const pre     = pane.querySelector("pre");
          if (pre) {
            lines.push(`### ${tabName}`, "```", pre.textContent.trim(), "```", "");
          }
        }
      }
    }
  }

  const refs = Array.isArray(t.references) ? t.references : [];
  if (refs.length) {
    lines.push("## Referencias", "");
    for (const r of refs) {
      let display = r;
      try { display = new URL(r).hostname; } catch { /**/ }
      lines.push(`- [${display}](${r})`);
    }
    lines.push("");
  }

  return lines.join("\n");
}



async function _loadHomeStats() {
  try {
    const data = await apiFetch("/api/tests");
    // Números del hero
    const totEl  = document.getElementById("home-total-tests");
    const blkEl  = document.getElementById("home-total-blocks");
    if (totEl) totEl.textContent = data.total;
    if (blkEl) blkEl.textContent = data.blocks.length;
    // Título de cobertura
    const titleEl = document.getElementById("home-coverage-title");
    if (titleEl) titleEl.innerHTML =
      `<i class="fa-solid fa-chart-pie me-2"></i>Cobertura — ${data.total} tests en ${data.blocks.length} bloques`;
    // Mini-badges
    const badgesRow = document.getElementById("home-mini-badges-row");
    if (badgesRow) {
      badgesRow.innerHTML = data.blocks.map(b => {
        const colorCls = (b.color || "hb-blue").replace("hb-", "hb-") + "-txt";
        return `<span class="home-mini-badge ${colorCls}"><i class="fa-solid ${b.icon} fa-fw"></i> ${b.name}</span>`;
      }).join("");
    }
    // Grid de bloques
    const grid = document.getElementById("home-coverage-grid");
    if (grid) {
      grid.innerHTML = data.blocks.map(b =>
        `<div class="hb-card ${b.color}" title="${b.description || ''}">
          <div class="hb-num">${b.count}</div>
          <div class="hb-icon"><i class="fa-solid ${b.icon}"></i></div>
          <div class="hb-label">${b.name}</div>
        </div>`
      ).join("");
    }
  } catch {
    // Si falla (e.g. token expirado), dejar los placeholders "—"
  }
}

function navigateTo(target, { pushHash = true } = {}) {
  if (!target || !VALID_VIEWS.has(target)) return;
  const user = getUser();
  // Proteger vista admin: redirigir a home si no es admin
  if (target === "admin" && user?.role !== "admin") target = "home";
  // Actualizar título de sección en topbar
  const titleEl = document.getElementById("topbar-section-title");
  if (titleEl) titleEl.textContent = VIEW_TITLES[target] || target;
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
    _loadHomeStats();
  }
  if (target === "history")   loadHistoryPage(0, true);
  if (target === "lists")     loadListsIndex();
  if (target === "evolution") initEvolutionView();
  if (target === "admin")     loadAdminUsers();
  if (target === "settings")  initSettingsView();
  if (target === "wiki")      initWikiView();
  // Al salir de la wiki, cerrar panel de detalle
  if (target !== "wiki")      closeWikiDetailPanel?.();
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
  const url = `${API_BASE}/api/lists/${_activeListId}/scan-stream?token=${encodeURIComponent(token)}`;
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
      html += `<td class="text-center ${cls}"><span class="badge badge-${escapeHtml(r)}">${escapeHtml(r)}</span></td>`;
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
      html += `<td class="text-center ${cls}"><span class="badge badge-${escapeHtml(r)}" style="font-size:10px">${escapeHtml(r)}</span></td>`;
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



// ══════════════════════════════════════════════════════════════
// ADMIN: CATÁLOGO DE TESTS
// ══════════════════════════════════════════════════════════════

let _adminTestsData = [];   // cache de todos los tests admin

const _SEVERITY_BADGE = {
  CRITICAL: "danger",
  HIGH:     "warning",
  MEDIUM:   "info",
  LOW:      "secondary",
};

async function loadAdminTests() {
  try {
    const data = await apiFetch("/api/admin/tests");
    _adminTestsData = data;
    _populateAdminBlockFilter(data);
    _renderAdminTests(data);
  } catch (err) {
    const tbody = document.getElementById("admin-tests-tbody");
    if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger py-4">${err.message}</td></tr>`;
  }
}

function _populateAdminBlockFilter(tests) {
  const sel = document.getElementById("admin-tests-filter-block");
  if (!sel) return;
  const blocks = [...new Map(tests.map(t => [t.block, t.block_name])).entries()]
    .sort((a, b) => a[0] - b[0]);
  const current = sel.value;
  sel.innerHTML = '<option value="">Todos los bloques</option>';
  blocks.forEach(([b, name]) => {
    const opt = document.createElement("option");
    opt.value = b;
    opt.textContent = `Bloque ${b}: ${name}`;
    if (String(b) === current) opt.selected = true;
    sel.appendChild(opt);
  });
}

function _renderAdminTests(tests) {
  const search   = (document.getElementById("admin-tests-search")?.value || "").toLowerCase();
  const block    = document.getElementById("admin-tests-filter-block")?.value || "";
  const status   = document.getElementById("admin-tests-filter-status")?.value || "";

  let filtered = tests.filter(t => {
    if (search && !`${t.id} ${t.name}`.toLowerCase().includes(search)) return false;
    if (block && String(t.block) !== block) return false;
    if (status === "active" && !t.is_active) return false;
    if (status === "inactive" && t.is_active) return false;
    return true;
  });

  const count = document.getElementById("admin-tests-count");
  if (count) count.textContent = `${filtered.length} test${filtered.length !== 1 ? "s" : ""}`;

  const tbody = document.getElementById("admin-tests-tbody");
  if (!tbody) return;
  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">Sin resultados</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(t => {
    const sevCls = _SEVERITY_BADGE[t.severity] || "secondary";
    const activeBadge = t.is_active
      ? '<span class="badge rounded-pill bg-success">activo</span>'
      : '<span class="badge rounded-pill bg-secondary">inactivo</span>';
    const customMark = t.description_custom ? ' <i class="fa-solid fa-pen-to-square text-info fa-xs" title="Descripción editada"></i>' : "";
    return `
      <tr class="${t.is_active ? "" : "opacity-50"}">
        <td><code class="text-info">${t.id}</code></td>
        <td>
          ${escapeHtml(t.name)}${customMark}
          ${t.description ? `<div class="text-muted small text-truncate" style="max-width:320px">${escapeHtml(t.description.substring(0, 80))}${t.description.length > 80 ? "…" : ""}</div>` : ""}
        </td>
        <td><span class="text-muted small">${escapeHtml(t.block_name)}</span></td>
        <td><span class="badge bg-${sevCls}">${t.severity}</span></td>
        <td class="text-center">
          <div class="form-check form-switch d-inline-block m-0">
            <input class="form-check-input admin-test-toggle" type="checkbox" role="switch"
              data-test-id="${t.id}" ${t.is_active ? "checked" : ""}
              title="${t.is_active ? "Desactivar" : "Activar"} test ${t.id}">
          </div>
        </td>
        <td class="text-end">
          <button class="btn btn-outline-info btn-xs admin-test-edit-btn" data-test-id="${t.id}"
            title="Editar test ${t.id}">
            <i class="fa-solid fa-pen fa-xs"></i>
          </button>
        </td>
      </tr>`;
  }).join("");
}

// Filtros en tiempo real
["admin-tests-search", "admin-tests-filter-block", "admin-tests-filter-status"].forEach(id => {
  document.getElementById(id)?.addEventListener("input", () => _renderAdminTests(_adminTestsData));
  document.getElementById(id)?.addEventListener("change", () => _renderAdminTests(_adminTestsData));
});

// Toggle activo/inactivo (delegación de eventos)
document.getElementById("admin-tests-tbody")?.addEventListener("change", async e => {
  const toggle = e.target.closest(".admin-test-toggle");
  if (!toggle) return;
  const testId   = toggle.dataset.testId;
  const isActive = toggle.checked;
  toggle.disabled = true;
  try {
    await apiFetch(`/api/admin/tests/${testId}`, {
      method: "PATCH",
      body: JSON.stringify({ is_active: isActive }),
    });
    const idx = _adminTestsData.findIndex(t => t.id === testId);
    if (idx !== -1) _adminTestsData[idx].is_active = isActive;
    _renderAdminTests(_adminTestsData);
    showToast("success", `Test ${testId} ${isActive ? "activado" : "desactivado"}`);
  } catch (err) {
    toggle.checked = !isActive;   // revertir
    showToast("error", "Error al actualizar", err.message);
  } finally {
    toggle.disabled = false;
  }
});

// Abrir modal de edición (delegación)
document.getElementById("admin-tests-tbody")?.addEventListener("click", e => {
  const btn = e.target.closest(".admin-test-edit-btn");
  if (!btn) return;
  const testId = btn.dataset.testId;
  openAdminTestEditModal(testId);
});

function openAdminTestEditModal(testId) {
  const t = _adminTestsData.find(x => x.id === testId);
  if (!t) return;
  document.getElementById("edit-test-id").value          = t.id;
  document.getElementById("edit-test-name").value        = t.name;
  document.getElementById("edit-test-description").value = t.description || "";
  document.getElementById("edit-test-block").value       = `${t.block} — ${t.block_name}`;
  document.getElementById("edit-test-cwe").value         = t.cwe || "";
  const sevSel = document.getElementById("edit-test-severity");
  sevSel.value = t.severity;
  const badge = document.getElementById("edit-test-custom-badge");
  if (badge) badge.style.display = t.description_custom ? "" : "none";
  const title = document.getElementById("modal-edit-test-label");
  if (title) title.innerHTML = `<i class="fa-solid fa-pen-to-square me-2 text-info"></i>Editar test <code>${t.id}</code> — ${escapeHtml(t.name)}`;
  const modalEl = document.getElementById("modal-edit-test");
  const modal = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
  modal.show();
}

document.getElementById("btn-edit-test-save")?.addEventListener("click", async () => {
  const testId = document.getElementById("edit-test-id").value;
  const name        = document.getElementById("edit-test-name").value.trim();
  const severity    = document.getElementById("edit-test-severity").value;
  const cwe         = document.getElementById("edit-test-cwe").value.trim();
  const description = document.getElementById("edit-test-description").value;
  if (!name) { showToast("error", "El nombre no puede estar vacío"); return; }
  const btn = document.getElementById("btn-edit-test-save");
  btn.disabled = true;
  try {
    const updated = await apiFetch(`/api/admin/tests/${testId}`, {
      method: "PATCH",
      body: JSON.stringify({ name, severity, cwe: cwe || "", description }),
    });
    const idx = _adminTestsData.findIndex(t => t.id === testId);
    if (idx !== -1) Object.assign(_adminTestsData[idx], updated);
    _renderAdminTests(_adminTestsData);
    bootstrap.Modal.getInstance(document.getElementById("modal-edit-test"))?.hide();
    showToast("success", `Test ${testId} guardado`);
  } catch (err) {
    showToast("error", "Error al guardar", err.message);
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("btn-edit-test-reset")?.addEventListener("click", async () => {
  const testId = document.getElementById("edit-test-id").value;
  // Cerrar el modal de edición primero para que el confirm no quede detrás
  const editModalEl = document.getElementById("modal-edit-test");
  bootstrap.Modal.getInstance(editModalEl)?.hide();
  const ok = await showConfirm(
    `¿Restablecer el test ${testId} a los valores originales del código? Se perderán nombre, severidad y descripción personalizados.`,
    "Restablecer test"
  );
  if (!ok) return;
  const btn = document.getElementById("btn-edit-test-reset");
  btn.disabled = true;
  try {
    await apiFetch(`/api/admin/tests/${testId}/reset`, { method: "POST" });
    bootstrap.Modal.getInstance(document.getElementById("modal-edit-test"))?.hide();
    showToast("success", `Test ${testId} restablecido`);
    await loadAdminTests();
  } catch (err) {
    showToast("error", "Error al restablecer", err.message);
  } finally {
    btn.disabled = false;
  }
});

// Cargar tests cuando se activa el tab
document.getElementById("admin-tab-tests-btn")?.addEventListener("shown.bs.tab", () => {
  loadAdminTests();
});


// ══════════════════════════════════════════════════════════════
// BRANDING — carga y aplica configuración de plataforma
// ══════════════════════════════════════════════════════════════

/** Carga los settings de plataforma desde la API (público) y los aplica. */
async function loadAndApplySettings() {
  try {
    const res = await fetch(`${API_BASE}/api/settings`);
    if (!res.ok) return;
    const settings = await res.json();
    applyBranding(settings);
  } catch {
    // Si la API no está disponible, seguir con los defaults CSS
  }
}

/** Aplica branding dinámico al DOM: título, logo, colores y favicon. */
function applyBranding(settings) {
  // ── Título ──────────────────────────────────────────────────
  const title = (settings.app_title || "Web Security Suite").trim();
  document.title = title;
  const titleTargets = ["sidebar-app-title", "login-app-title", "home-hero-title"];
  titleTargets.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = title;
  });

  // ── Logo ────────────────────────────────────────────────────
  const logo = settings.logo_base64 || "";
  const logoSets = [
    { img: "sidebar-logo-img",   icon: "sidebar-logo-icon" },
    { img: "login-logo-img",     icon: "login-logo-icon" },
    { img: "home-hero-logo-img", icon: "home-hero-fa-icon" },
  ];
  logoSets.forEach(({ img, icon }) => {
    const imgEl  = document.getElementById(img);
    const iconEl = document.getElementById(icon);
    if (imgEl)  { imgEl.src = logo; imgEl.classList.toggle("hidden", !logo); }
    if (iconEl) iconEl.classList.toggle("hidden", !!logo);
  });

  // ── Colores de acento ───────────────────────────────────────
  const colorMap = {
    "--wss-pass": settings.color_pass || "#3fb950",
    "--wss-fail": settings.color_fail || "#f85149",
    "--wss-warn": settings.color_warn || "#d29922",
    "--wss-skip": settings.color_skip || "#bc8cff",
  };
  Object.entries(colorMap).forEach(([prop, val]) => {
    document.documentElement.style.setProperty(prop, val);
  });

  // ── Favicon ─────────────────────────────────────────────────
  const favicon = settings.favicon_base64 || "";
  if (favicon) {
    let link = document.querySelector("link[rel='icon']");
    if (!link) {
      link = document.createElement("link");
      link.rel = "icon";
      document.head.appendChild(link);
    }
    link.href = favicon;
  }
}

// ══════════════════════════════════════════════════════════════
// VISTA CONFIGURACIÓN
// ══════════════════════════════════════════════════════════════

// Defaults originales para restaurar colores
const _COLOR_DEFAULTS = {
  "color-pass": "#3fb950",
  "color-fail": "#f85149",
  "color-warn": "#d29922",
  "color-skip": "#bc8cff",
};

/** Inicializa la vista de configuración al navegar hacia ella. */
function initSettingsView() {
  const user = getUser();

  // Mostrar/ocultar tab Plataforma según rol
  const platformTabLi = document.getElementById("settings-tab-platform-li");
  if (platformTabLi) {
    platformTabLi.classList.toggle("hidden", user?.role !== "admin");
  }

  // Si el usuario no es admin y el tab activo es Plataforma, activar Mi Perfil
  if (user?.role !== "admin") {
    const profileTab = document.getElementById("settings-tab-profile");
    if (profileTab) profileTab.click();
  }

  // Cargar formulario de plataforma si es admin
  if (user?.role === "admin") _loadPlatformForm();

  // Cargar preview de avatar
  _loadProfileAvatarPreview();
}

/** Rellena el formulario de configuración de plataforma con los valores actuales. */
async function _loadPlatformForm() {
  try {
    const res = await fetch(`${API_BASE}/api/settings`);
    if (!res.ok) return;
    const settings = await res.json();

    // Título
    const titleInput = document.getElementById("settings-app-title");
    if (titleInput) titleInput.value = settings.app_title || "";

    // Preview de logo actual
    _updateLogoPreview(settings.logo_base64 || "");

    // Colores
    [["color-pass","color_pass"], ["color-fail","color_fail"],
     ["color-warn","color_warn"], ["color-skip","color_skip"]].forEach(([inputId, key]) => {
      const el    = document.getElementById(inputId);
      const hexEl = document.getElementById(`${inputId}-hex`);
      const val   = settings[key] || _COLOR_DEFAULTS[inputId];
      if (el) el.value = val;
      if (hexEl) hexEl.textContent = val;
    });
  } catch {
    // Silencioso
  }
}

function _updateLogoPreview(src) {
  const previewEl     = document.getElementById("settings-logo-preview");
  const placeholderEl = document.getElementById("settings-logo-placeholder");
  if (!previewEl || !placeholderEl) return;
  if (src) {
    previewEl.src = src;
    previewEl.classList.remove("hidden");
    placeholderEl.classList.add("hidden");
  } else {
    previewEl.src = "";
    previewEl.classList.add("hidden");
    placeholderEl.classList.remove("hidden");
  }
}

function _loadProfileAvatarPreview() {
  const user = getUser();
  const initialsEl = document.getElementById("profile-avatar-initials");
  const avatarImg  = document.getElementById("profile-avatar-img");
  if (!initialsEl || !avatarImg) return;
  if (user?.avatar) {
    avatarImg.src = user.avatar;
    avatarImg.classList.remove("hidden");
    initialsEl.classList.add("hidden");
  } else {
    avatarImg.classList.add("hidden");
    initialsEl.classList.remove("hidden");
    initialsEl.textContent = (user?.username || "?").slice(0, 2).toUpperCase();
  }
}

// ── Handlers: logo ───────────────────────────────────────────

// Preview inmediato al seleccionar archivo
document.getElementById("settings-logo-file")?.addEventListener("change", e => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = ev => _updateLogoPreview(ev.target.result);
  reader.readAsDataURL(file);
});

document.getElementById("btn-save-logo")?.addEventListener("click", async () => {
  const file = document.getElementById("settings-logo-file")?.files[0];
  const msgEl = document.getElementById("settings-logo-msg");
  if (!file) { _showSettingsMsg(msgEl, "Selecciona un archivo primero.", "warning"); return; }

  const reader = new FileReader();
  reader.onload = async ev => {
    const b64 = ev.target.result;
    try {
      await apiPut("/api/admin/settings", { key: "logo_base64", value: b64 });
      _showSettingsMsg(msgEl, "Logo guardado.", "success");
      loadAndApplySettings();
    } catch (err) {
      _showSettingsMsg(msgEl, err.message, "danger");
    }
  };
  reader.readAsDataURL(file);
});

document.getElementById("btn-remove-logo")?.addEventListener("click", async () => {
  const msgEl = document.getElementById("settings-logo-msg");
  try {
    await apiPut("/api/admin/settings", { key: "logo_base64", value: "" });
    _showSettingsMsg(msgEl, "Logo eliminado.", "success");
    document.getElementById("settings-logo-file").value = "";
    _updateLogoPreview("");
    loadAndApplySettings();
  } catch (err) {
    _showSettingsMsg(msgEl, err.message, "danger");
  }
});

// ── Handlers: título ─────────────────────────────────────────

document.getElementById("btn-save-title")?.addEventListener("click", async () => {
  const val   = document.getElementById("settings-app-title")?.value.trim();
  const msgEl = document.getElementById("settings-title-msg");
  if (!val) { _showSettingsMsg(msgEl, "El título no puede estar vacío.", "warning"); return; }
  try {
    await apiPut("/api/admin/settings", { key: "app_title", value: val });
    _showSettingsMsg(msgEl, "Título guardado.", "success");
    loadAndApplySettings();
  } catch (err) {
    _showSettingsMsg(msgEl, err.message, "danger");
  }
});

// ── Handlers: colores ────────────────────────────────────────

// Actualizar texto hex en tiempo real al mover el color picker
["color-pass","color-fail","color-warn","color-skip"].forEach(id => {
  document.getElementById(id)?.addEventListener("input", e => {
    const hexEl = document.getElementById(`${id}-hex`);
    if (hexEl) hexEl.textContent = e.target.value;
  });
});

document.getElementById("btn-save-colors")?.addEventListener("click", async () => {
  const msgEl = document.getElementById("settings-colors-msg");
  const pairs = [
    ["color_pass", "color-pass"],
    ["color_fail", "color-fail"],
    ["color_warn", "color-warn"],
    ["color_skip", "color-skip"],
  ];
  try {
    for (const [key, inputId] of pairs) {
      const val = document.getElementById(inputId)?.value || "";
      await apiPut("/api/admin/settings", { key, value: val });
    }
    _showSettingsMsg(msgEl, "Colores guardados.", "success");
    loadAndApplySettings();
  } catch (err) {
    _showSettingsMsg(msgEl, err.message, "danger");
  }
});

document.getElementById("btn-reset-colors")?.addEventListener("click", async () => {
  const msgEl = document.getElementById("settings-colors-msg");
  try {
    for (const [inputId, val] of Object.entries(_COLOR_DEFAULTS)) {
      const key = inputId.replace("-", "_");  // "color-pass" → "color_pass"
      await apiPut("/api/admin/settings", { key, value: val });
      const el = document.getElementById(inputId);
      const hexEl = document.getElementById(`${inputId}-hex`);
      if (el) el.value = val;
      if (hexEl) hexEl.textContent = val;
    }
    _showSettingsMsg(msgEl, "Colores restaurados.", "success");
    loadAndApplySettings();
  } catch (err) {
    _showSettingsMsg(msgEl, err.message, "danger");
  }
});

// ── Handlers: avatar ─────────────────────────────────────────

// Preview inmediato al seleccionar archivo de avatar
document.getElementById("profile-avatar-file")?.addEventListener("change", e => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = ev => {
    // Redimensionar a 150x150 con canvas para reducir peso
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = 150; canvas.height = 150;
      const ctx = canvas.getContext("2d");
      // Recorte centrado (mantener aspect ratio como cover)
      const size = Math.min(img.width, img.height);
      const sx   = (img.width  - size) / 2;
      const sy   = (img.height - size) / 2;
      ctx.drawImage(img, sx, sy, size, size, 0, 0, 150, 150);
      const b64 = canvas.toDataURL("image/jpeg", 0.85);
      // Mostrar preview
      const previewImg  = document.getElementById("profile-avatar-img");
      const previewInit = document.getElementById("profile-avatar-initials");
      if (previewImg)  { previewImg.src = b64; previewImg.classList.remove("hidden"); }
      if (previewInit) previewInit.classList.add("hidden");
      // Guardar temporalmente en el input para el botón guardar
      document.getElementById("profile-avatar-file")._b64 = b64;
    };
    img.src = ev.target.result;
  };
  reader.readAsDataURL(file);
});

document.getElementById("btn-save-avatar")?.addEventListener("click", async () => {
  const msgEl = document.getElementById("settings-avatar-msg");
  const fileInput = document.getElementById("profile-avatar-file");
  const b64 = fileInput?._b64;
  if (!b64) { _showSettingsMsg(msgEl, "Selecciona una imagen primero.", "warning"); return; }
  try {
    await apiPost("/api/users/me/avatar", { avatar_base64: b64 });
    // Actualizar usuario en localStorage
    const stored = getUser();
    if (stored) saveAuth(getToken(), { ...stored, avatar: b64 });
    applyUserUI();
    _loadProfileAvatarPreview();
    _showSettingsMsg(msgEl, "Foto de perfil guardada.", "success");
    fileInput._b64 = null;
  } catch (err) {
    _showSettingsMsg(msgEl, err.message, "danger");
  }
});

document.getElementById("btn-remove-avatar")?.addEventListener("click", async () => {
  const msgEl = document.getElementById("settings-avatar-msg");
  try {
    await apiFetch("/api/users/me/avatar", { method: "DELETE" });
    const stored = getUser();
    if (stored) saveAuth(getToken(), { ...stored, avatar: null });
    applyUserUI();
    _loadProfileAvatarPreview();
    document.getElementById("profile-avatar-file").value = "";
    document.getElementById("profile-avatar-file")._b64 = null;
    _showSettingsMsg(msgEl, "Foto eliminada.", "success");
  } catch (err) {
    _showSettingsMsg(msgEl, err.message, "danger");
  }
});

// ── Handlers: cambiar contraseña ─────────────────────────────

document.getElementById("form-change-pwd")?.addEventListener("submit", async e => {
  e.preventDefault();
  const msgEl   = document.getElementById("change-pwd-msg");
  const current = document.getElementById("change-pwd-current").value;
  const newPwd  = document.getElementById("change-pwd-new").value;
  const confirm = document.getElementById("change-pwd-confirm").value;

  if (newPwd !== confirm) {
    _showSettingsMsg(msgEl, "Las contraseñas no coinciden.", "warning");
    return;
  }
  if (newPwd.length < 6) {
    _showSettingsMsg(msgEl, "La nueva contraseña debe tener al menos 6 caracteres.", "warning");
    return;
  }

  try {
    await apiPut("/api/users/me/password", { current_password: current, new_password: newPwd });
    _showSettingsMsg(msgEl, "Contraseña actualizada correctamente.", "success");
    document.getElementById("form-change-pwd").reset();
  } catch (err) {
    _showSettingsMsg(msgEl, err.message, "danger");
  }
});

// ── Utilidad: mostrar mensaje inline en settings ─────────────

function _showSettingsMsg(el, msg, type = "info") {
  if (!el) return;
  el.innerHTML = `<div class="alert alert-${type} py-1 px-2 small mb-0">${escapeHtml(msg)}</div>`;
  setTimeout(() => { if (el) el.innerHTML = ""; }, 4000);
}
