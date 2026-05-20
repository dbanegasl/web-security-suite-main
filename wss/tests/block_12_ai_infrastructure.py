"""Bloque 12 — Infraestructura de IA expuesta (AI-LLM-API-EXPOSED a AI-DEVTOOLS-EXPOSED)."""
from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from wss.core.context import ScanContext
from wss.core.registry import test
from wss.core.result import Result

_BLOCK = 12
_BLOCK_NAME = "Infraestructura de IA expuesta"


# ── Helpers ────────────────────────────────────────────────────────────────────


async def _get(
    ctx: ScanContext, path: str, *, timeout: float = 4.0
) -> Optional[httpx.Response]:
    """GET a https://{host}{path}. Devuelve None en error de red."""
    try:
        return await ctx.client.get(
            f"https://{ctx.host}{path}",
            follow_redirects=False,
            timeout=timeout,
        )
    except Exception:
        return None


async def _get_alt(
    ctx: ScanContext, port: int, path: str, *, timeout: float = 3.0
) -> Optional[httpx.Response]:
    """GET a http://{host}:{port}{path} (puerto no estándar, sin TLS). Devuelve None en error."""
    try:
        return await ctx.client.get(
            f"http://{ctx.host}:{port}{path}",
            follow_redirects=False,
            timeout=timeout,
        )
    except Exception:
        return None


def _has_all(text: str, keywords: list[str]) -> bool:
    """True si todos los keywords están presentes en text (case-insensitive)."""
    tl = text.lower()
    return all(k.lower() in tl for k in keywords)


def _has_any(text: str, keywords: list[str]) -> bool:
    """True si algún keyword está presente en text (case-insensitive)."""
    tl = text.lower()
    return any(k.lower() in tl for k in keywords)


# ── AI-LLM-API-EXPOSED ────────────────────────────────────────────────────────

_LLM_PATHS_HTTPS = [
    ("/v1/models", ["\"object\"", "\"data\""]),         # OpenAI-compatible (LiteLLM, etc.)
    ("/api/tags", ["\"models\""]),                       # Ollama
    ("/", ["Ollama is running"]),                        # Ollama home
]
_LLM_ALT_PORTS = [
    (11434, "/api/tags", ["\"models\""]),                # Ollama default port
    (4000, "/v1/models", ["\"object\"", "\"data\""]),    # LiteLLM proxy default port
]


@test(
    "AI-LLM-API-EXPOSED",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="API LLM no expuesta sin autenticación",
    severity="CRITICAL",
    cwe="CWE-306",
)
async def test_llm_api_exposed(ctx: ScanContext) -> Result:
    """Detecta APIs de LLM (OpenAI-compatible, Ollama, LiteLLM) expuestas sin autenticación."""
    # Probar paths HTTPS principales y puertos alternativos en paralelo
    https_coros = [_get(ctx, path) for path, _ in _LLM_PATHS_HTTPS]
    alt_coros = [_get_alt(ctx, port, path) for port, path, _ in _LLM_ALT_PORTS]

    https_resps, alt_resps = await asyncio.gather(
        asyncio.gather(*https_coros),
        asyncio.gather(*alt_coros),
    )

    for resp, (path, keywords) in zip(https_resps, _LLM_PATHS_HTTPS):
        if resp is not None and resp.status_code == 200:
            if _has_all(resp.text, keywords):
                return Result.fail(
                    f"API LLM accesible sin autenticación en {path} — "
                    f"expone modelos disponibles"
                )

    for resp, (port, path, keywords) in zip(alt_resps, _LLM_ALT_PORTS):
        if resp is not None and resp.status_code == 200:
            if _has_all(resp.text, keywords):
                return Result.fail(
                    f"API LLM accesible sin autenticación en puerto {port}{path} — "
                    f"expone modelos disponibles"
                )

    return Result.pass_("No se detectó API LLM expuesta sin autenticación")


# ── AI-JUPYTER-EXPOSED ────────────────────────────────────────────────────────

_JUPYTER_API_PATHS = [
    ("/api/kernels", ["[{"]),        # JSON array de kernels
    ("/api/contents", ["\"type\""]), # Listado de archivos
]
_JUPYTER_HTML_PATHS = ["/tree", "/lab"]
_JUPYTER_PORT = 8888


@test(
    "AI-JUPYTER-EXPOSED",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Jupyter Notebook/Lab sin token de autenticación",
    severity="CRITICAL",
    cwe="CWE-306",
)
async def test_jupyter_exposed(ctx: ScanContext) -> Result:
    """Detecta Jupyter Notebook/Lab accesible sin token de autenticación."""
    # API endpoints — si responden 200 sin auth, el servidor está abierto
    api_coros = [_get(ctx, p) for p, _ in _JUPYTER_API_PATHS]
    html_coros = [_get(ctx, p) for p in _JUPYTER_HTML_PATHS]
    alt_api_coro = _get_alt(ctx, _JUPYTER_PORT, "/api/kernels")

    api_resps, html_resps, alt_resp = await asyncio.gather(
        asyncio.gather(*api_coros),
        asyncio.gather(*html_coros),
        alt_api_coro,
    )

    for resp, (path, keywords) in zip(api_resps, _JUPYTER_API_PATHS):
        if resp is not None and resp.status_code == 200:
            if _has_any(resp.text, keywords):
                return Result.fail(
                    f"Jupyter expuesto sin token en {path} — "
                    f"acceso completo a kernels y sistema de archivos"
                )

    if alt_resp is not None and alt_resp.status_code == 200:
        if _has_any(alt_resp.text, ["[{"]):
            return Result.fail(
                f"Jupyter expuesto sin token en puerto {_JUPYTER_PORT}/api/kernels"
            )

    # Fallback: UI HTML accesible sin redirección a login
    for resp, path in zip(html_resps, _JUPYTER_HTML_PATHS):
        if resp is not None and resp.status_code == 200:
            body = resp.text.lower()
            if "jupyter" in body and "login" not in body:
                return Result.warn(
                    f"Interfaz Jupyter accesible en {path} (sin confirmación de token)"
                )

    return Result.pass_("No se detectó Jupyter expuesto sin autenticación")


# ── AI-VECTORDB-EXPOSED ───────────────────────────────────────────────────────

_CHROMA_PATHS = [
    ("/api/v1/heartbeat", ["nanosecond heartbeat"]),
    ("/api/v1/collections", ["["]),
]
_WEAVIATE_PATHS = [
    ("/v1/meta", ["\"version\"", "\"hostname\""]),
    ("/v1/.well-known/ready", [""]),  # 200 es suficiente
]
_VECTORDB_ALT_PORTS = [8000, 8080]


@test(
    "AI-VECTORDB-EXPOSED",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Base de datos vectorial no expuesta",
    severity="HIGH",
    cwe="CWE-306",
)
async def test_vectordb_exposed(ctx: ScanContext) -> Result:
    """Detecta bases de datos vectoriales (Chroma, Weaviate) expuestas sin autenticación."""
    # Probar paths en HTTPS base + puertos alternativos HTTP en paralelo
    all_coros = (
        [_get(ctx, p) for p, _ in _CHROMA_PATHS]
        + [_get(ctx, p) for p, _ in _WEAVIATE_PATHS]
        + [_get_alt(ctx, port, p) for port in _VECTORDB_ALT_PORTS for p, _ in _CHROMA_PATHS]
        + [_get_alt(ctx, port, p) for port in _VECTORDB_ALT_PORTS for p, _ in _WEAVIATE_PATHS]
    )

    results = await asyncio.gather(*all_coros)
    idx = 0

    # HTTPS — Chroma
    for (path, keywords), resp in zip(_CHROMA_PATHS, results[idx:idx + len(_CHROMA_PATHS)]):
        idx += 1
        if resp is not None and resp.status_code == 200:
            if not keywords or _has_any(resp.text, keywords):
                return Result.fail(f"ChromaDB expuesto sin autenticación en {path}")

    # HTTPS — Weaviate
    for (path, keywords), resp in zip(_WEAVIATE_PATHS, results[idx:idx + len(_WEAVIATE_PATHS)]):
        idx += 1
        if resp is not None and resp.status_code == 200:
            if not keywords or _has_all(resp.text, keywords):
                return Result.fail(f"Weaviate expuesto sin autenticación en {path}")
            if path == "/v1/.well-known/ready":
                return Result.fail(f"Weaviate health endpoint accesible en {path}")

    # Puertos alternativos — Chroma
    for port in _VECTORDB_ALT_PORTS:
        for (path, keywords), resp in zip(_CHROMA_PATHS, results[idx:idx + len(_CHROMA_PATHS)]):
            idx += 1
            if resp is not None and resp.status_code == 200:
                if not keywords or _has_any(resp.text, keywords):
                    return Result.fail(
                        f"ChromaDB expuesto sin autenticación en puerto {port}{path}"
                    )

    # Puertos alternativos — Weaviate
    for port in _VECTORDB_ALT_PORTS:
        for (path, keywords), resp in zip(_WEAVIATE_PATHS, results[idx:idx + len(_WEAVIATE_PATHS)]):
            idx += 1
            if resp is not None and resp.status_code == 200:
                if not keywords or _has_all(resp.text, keywords):
                    return Result.fail(
                        f"Weaviate expuesto sin autenticación en puerto {port}{path}"
                    )

    return Result.pass_("No se detectó base de datos vectorial expuesta")


# ── AI-GRADIO-EXPOSED ─────────────────────────────────────────────────────────

_GRADIO_PORT = 7860
_GRADIO_HOME_SIGNATURES = ["window.gradio_config", "<gradio-app"]


@test(
    "AI-GRADIO-EXPOSED",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Interfaz Gradio no expuesta",
    severity="HIGH",
    cwe="CWE-306",
)
async def test_gradio_exposed(ctx: ScanContext) -> Result:
    """Detecta interfaces Gradio expuestas sin autenticación en HTTPS y puerto 7860."""
    config_resp, home_resp, alt_config_resp = await asyncio.gather(
        _get(ctx, "/config"),
        _get(ctx, "/"),
        _get_alt(ctx, _GRADIO_PORT, "/config"),
    )

    # /config → API JSON de Gradio (componentes + versión)
    for resp, source in [(config_resp, "/config"), (alt_config_resp, f":{_GRADIO_PORT}/config")]:
        if resp is not None and resp.status_code == 200:
            if _has_all(resp.text, ["\"components\"", "\"version\""]):
                return Result.fail(
                    f"API Gradio expuesta sin autenticación en {source} — "
                    f"expone configuración completa de la app"
                )

    # / → firma Gradio en HTML
    if home_resp is not None and home_resp.status_code == 200:
        if _has_any(home_resp.text, _GRADIO_HOME_SIGNATURES):
            return Result.warn(
                "Interfaz Gradio detectada en / (verificar si requiere autenticación)"
            )

    return Result.pass_("No se detectó interfaz Gradio expuesta")


# ── AI-MLFLOW-EXPOSED ─────────────────────────────────────────────────────────

_MLFLOW_PATHS = [
    "/api/2.0/mlflow/experiments/list",
    "/api/2.0/mlflow/runs/search",
]
_MLFLOW_PORT = 5000


@test(
    "AI-MLFLOW-EXPOSED",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="MLflow tracking server no expuesto",
    severity="HIGH",
    cwe="CWE-306",
)
async def test_mlflow_exposed(ctx: ScanContext) -> Result:
    """Detecta MLflow tracking server accesible sin autenticación."""
    https_coros = [_get(ctx, p) for p in _MLFLOW_PATHS]
    alt_coro = _get_alt(ctx, _MLFLOW_PORT, _MLFLOW_PATHS[0])

    https_resps, alt_resp = await asyncio.gather(
        asyncio.gather(*https_coros),
        alt_coro,
    )

    # Experimentos listados sin auth → exposición de datos de entrenamiento
    exp_resp = https_resps[0]
    if exp_resp is not None and exp_resp.status_code == 200:
        if _has_any(exp_resp.text, ["\"experiments\""]):
            return Result.fail(
                f"MLflow tracking server expuesto en {_MLFLOW_PATHS[0]} — "
                f"experimentos accesibles sin autenticación"
            )

    # Runs accesibles sin auth
    runs_resp = https_resps[1]
    if runs_resp is not None and runs_resp.status_code == 200:
        return Result.warn(
            f"MLflow endpoint de runs accesible en {_MLFLOW_PATHS[1]}"
        )

    # Puerto alternativo
    if alt_resp is not None and alt_resp.status_code == 200:
        if _has_any(alt_resp.text, ["\"experiments\""]):
            return Result.fail(
                f"MLflow tracking server expuesto en puerto {_MLFLOW_PORT}"
            )

    return Result.pass_("No se detectó MLflow tracking server expuesto")


# ── AI-PROMPT-FILES-EXPOSED ────────────────────────────────────────────────────

_PROMPT_PATHS = [
    "/claude.md",
    "/.claude.md",
    "/CLAUDE.md",
    "/AGENTS.md",
    "/.cursorrules",
    "/system_prompt.txt",
    "/prompt.md",
    "/ai_config.json",
    "/.openai_api_key",
    "/.anthropic_api_key",
]

# Patrones de API keys — si están presentes el impacto escala a crítico
_API_KEY_PATTERNS = ["sk-ant-", "sk-proj-", "sk-"]

# Indicador SA-040: AGENTS.md o CLAUDE.md grande sugiere repositorio de agente desplegado
_SA040_INDICATOR_PATHS = ["/claude.md", "/.claude.md", "/CLAUDE.md", "/AGENTS.md"]
_SA040_MIN_LINES = 500


@test(
    "AI-PROMPT-FILES-EXPOSED",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Archivos de prompt IA no expuestos",
    severity="HIGH",
    cwe="CWE-552",
)
async def test_prompt_files_exposed(ctx: ScanContext) -> Result:
    """Detecta archivos de configuración de IA (system prompts, API keys) expuestos públicamente."""
    responses = await asyncio.gather(*[_get(ctx, p) for p in _PROMPT_PATHS])

    for path, resp in zip(_PROMPT_PATHS, responses):
        if resp is None or resp.status_code != 200:
            continue

        body = resp.text

        # Prioridad máxima: API key expuesta → FAIL con nota crítica
        found_key = next((k for k in _API_KEY_PATTERNS if k in body), None)
        if found_key:
            return Result.fail(
                f"API key IA expuesta en {path} — token '{found_key}...' encontrado "
                f"(impacto CRÍTICO: rotación inmediata requerida)"
            )

        # Indicador SA-040: archivo de agente con gran volumen de instrucciones
        if path in _SA040_INDICATOR_PATHS and body.count("\n") >= _SA040_MIN_LINES:
            return Result.fail(
                f"Archivo de agente IA expuesto en {path} — "
                f"{body.count(chr(10))} líneas (posible indicador SA-040)"
            )

        # Archivo de prompt accesible sin API key
        return Result.warn(
            f"Archivo de configuración IA accesible en {path} — "
            f"puede revelar instrucciones de sistema o arquitectura del agente"
        )

    return Result.pass_("No se detectaron archivos de configuración IA expuestos")


# ── AI-DEVTOOLS-EXPOSED ───────────────────────────────────────────────────────

_OPENWEBUI_SIGNATURES = ["\"webui_name\"", "open-webui", "ollama"]


@test(
    "AI-DEVTOOLS-EXPOSED",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Consola web IA no expuesta",
    severity="MEDIUM",
    cwe="CWE-306",
)
async def test_devtools_exposed(ctx: ScanContext) -> Result:
    """Detecta consolas web de IA (Open WebUI, Ollama UI) expuestas sin autenticación."""
    config_resp, version_resp, home_resp = await asyncio.gather(
        _get(ctx, "/api/config"),
        _get(ctx, "/api/version"),
        _get(ctx, "/"),
    )

    # /api/config → JSON con webui_name (Open WebUI)
    if config_resp is not None and config_resp.status_code == 200:
        if "\"webui_name\"" in config_resp.text:
            return Result.fail(
                "Open WebUI expuesto sin autenticación en /api/config — "
                "configuración del servidor accesible"
            )

    # /api/version → string open-webui
    if version_resp is not None and version_resp.status_code == 200:
        if "open-webui" in version_resp.text.lower():
            return Result.warn(
                "Open WebUI detectado en /api/version — verificar si requiere autenticación"
            )

    # / → firma Ollama o Open WebUI en body
    if home_resp is not None and home_resp.status_code == 200:
        body = home_resp.text.lower()
        if "open-webui" in body or ("ollama" in body and "running" in body):
            return Result.warn(
                "Interfaz web de IA detectada en / (Open WebUI u Ollama UI)"
            )

    return Result.pass_("No se detectó consola web de IA expuesta")
