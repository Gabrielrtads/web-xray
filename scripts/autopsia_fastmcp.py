#!/usr/bin/env python3
"""
Autópsia FastMCP Server v3.0.0
Servidor FastMCP nativo para inspeção técnica, raios-X de aplicações web via CDP,
sanitização determinística contra vazamento de segredos e integração com Swarmv2.
Compatível com Antigravity IDE, Claude Code, OpenAI Codex e clientes FastMCP.
"""

import os
import sys
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx
from fastmcp import FastMCP

# Blindagem de encoding UTF-8 no Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

SCRIPT_DIR = Path(__file__).resolve().parent
ENGINE_JS = SCRIPT_DIR / "autopsia_engine.mjs"

mcp = FastMCP("Autopsia FastMCP Server")

SENSITIVE_KEY_PATTERN = re.compile(
    r"(token|secret|password|pwd|credential|api_key|apikey|access_token|refresh_token|id_token|private_key|auth|session|cookie|hash|cvv|cpf|cartao|credit_card)",
    re.IGNORECASE
)

FORBIDDEN_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-session-id",
    "x-csrf-token",
    "x-xsrf-token",
    "cf-access-jwt-assertion",
    "cf-access-client-id",
    "cf-access-client-secret"
}

def _redact_url(raw_url: str) -> str:
    """Mascara query params de URLs para evitar vazamento de chaves e assinaturas."""
    if not raw_url:
        return ""
    try:
        parsed = urlparse(raw_url)
        if not parsed.query:
            return raw_url
        qs = parse_qs(parsed.query, keep_blank_values=True)
        sanitized_qs = {k: "[REDACTED]" for k in qs}
        new_query = urlencode(sanitized_qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
    except Exception:
        return raw_url

def _scrub_object(obj):
    """Sanitiza recursivamente dicionários e listas mascarando segredos."""
    if isinstance(obj, dict):
        clean = {}
        for k, v in obj.items():
            if SENSITIVE_KEY_PATTERN.search(str(k)):
                clean[k] = "[REDACTED_SECRET]"
            else:
                clean[k] = _scrub_object(v)
        return clean
    elif isinstance(obj, list):
        return [_scrub_object(item) for item in obj]
    elif isinstance(obj, str):
        # Mascara formatos conhecidos
        masked = re.sub(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "[REDACTED_JWT]", obj)
        masked = re.sub(r"sk-[a-zA-Z0-9_-]{20,}", "[REDACTED_KEY]", masked)
        masked = re.sub(r"ghp_[a-zA-Z0-9]{36}", "[REDACTED_TOKEN]", masked)
        return masked
    return obj

# ==========================================
# 🛠️ TOOLS DO SERVIDOR FASTMCP
# ==========================================

@mcp.tool()
def autopsia_list_tabs(host: str = "127.0.0.1", port: str = "9222") -> dict:
    """
    Lista todas as abas abertas no navegador CDP (Porta 9222 por padrão).
    Retorna apenas títulos, IDs de target e URLs com parâmetros devidamente mascarados.
    """
    url = f"http://{host}:{port}/json/list"
    try:
        with httpx.Client(timeout=5.0) as client:
            res = client.get(url)
            if res.status_code != 200:
                return {
                    "success": False,
                    "error": f"Falha ao conectar no CDP: HTTP {res.status_code}"
                }
            items = res.json()
            pages = [item for item in items if item.get("type") == "page"]
            
            clean_pages = []
            for p in pages:
                clean_pages.append({
                    "id": p.get("id"),
                    "title": p.get("title", "Sem Título"),
                    "url": _redact_url(p.get("url", "")),
                    "devtoolsFrontendUrl": p.get("devtoolsFrontendUrl", "")
                })
            
            return {
                "success": True,
                "totalTabs": len(clean_pages),
                "tabs": clean_pages
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"Erro de conexão com a porta CDP {host}:{port}: {str(e)}",
            "hint": "Certifique-se de que o Chrome/Comet foi iniciado com a flag --remote-debugging-port=9222"
        }

@mcp.tool()
def autopsia_run_scan(
    target_filter: str = "",
    host: str = "127.0.0.1",
    port: str = "9222",
    enable_storage: bool = True,
    enable_console: bool = True,
    enable_screenshot: bool = False,
    network_wait_ms: int = 2500
) -> dict:
    """
    Executa a autópsia técnica completa na aba especificada via Chrome DevTools Protocol.
    Extrai: Tech Stack, links/inputs, endpoints REST de rede, storage seguro (apenas chaves)
    e screenshot do viewport opcional. Todas as credenciais e dados sensíveis são censurados.
    """
    if not ENGINE_JS.exists():
        return {
            "success": False,
            "error": f"Motor JavaScript não encontrado em: {ENGINE_JS}"
        }

    env = os.environ.copy()
    env["CDP_HOST"] = host
    env["CHROME_DEBUG_PORT"] = port

    cmd = ["node", str(ENGINE_JS), target_filter]
    if not enable_storage:
        cmd.append("--no-storage")
    if not enable_console:
        cmd.append("--no-console")
    if enable_screenshot:
        cmd.append("--screenshot")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=45
        )
        if proc.returncode != 0:
            return {
                "success": False,
                "error": "Erro durante a execução do motor de autópsia.",
                "stderr": proc.stderr,
                "stdout": proc.stdout
            }

        # Extrair paths do stdout
        stdout = proc.stdout
        report_match = re.search(r"Relatório Sanitizado:\s*(.+)", stdout)
        screenshot_match = re.search(r"Evidência Visual:\s*(.+)", stdout)
        manifest_match = re.search(r"Manifesto Swarmv2(?:\s*Pronto)?:\s*(.+)", stdout)

        report_path = report_match.group(1).strip() if report_match else ""
        screenshot_path = screenshot_match.group(1).strip() if screenshot_match else ""
        manifest_path = manifest_match.group(1).strip() if manifest_match else ""

        report_data = {}
        if report_path and Path(report_path).exists():
            with open(report_path, "r", encoding="utf-8") as f:
                report_data = json.load(f)

        return {
            "success": True,
            "target": report_data.get("target", {}),
            "techStack": report_data.get("techStack", []),
            "endpointsCount": report_data.get("network", {}).get("totalCapturedEndpoints", 0),
            "storageKeysFound": len(report_data.get("storageAudit", {}).get("localStorage", [])),
            "reportPath": report_path,
            "screenshotPath": screenshot_path,
            "manifestPath": manifest_path,
            "reportSummary": {
                "domNodes": report_data.get("domOverview", {}).get("totalDomNodes", 0),
                "totalLinks": report_data.get("uiAnalysis", {}).get("stats", {}).get("totalLinks", 0),
                "totalInputs": report_data.get("uiAnalysis", {}).get("stats", {}).get("totalInputs", 0)
            }
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Timeout de 45 segundos excedido durante a autópsia."}
    except Exception as e:
        return {"success": False, "error": f"Falha na invocação da autópsia: {str(e)}"}

@mcp.tool()
def autopsia_sanitize_payload(payload_json: str) -> dict:
    """
    Higieniza e sanitiza um payload JSON contra extração acidental de segredos.
    Aplica denylist de chaves (senhas, tokens, cookies, chaves de API, PII)
    e substitui valores sensíveis por marcadores [REDACTED_SECRET].
    """
    try:
        data = json.loads(payload_json)
        sanitized = _scrub_object(data)
        return {
            "success": True,
            "sanitized": sanitized
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Erro ao processar JSON: {str(e)}"
        }

@mcp.tool()
def autopsia_create_swarm_manifest(
    report_path: str,
    screenshot_path: str = "",
    target_title: str = "Aplicação Alvo"
) -> dict:
    """
    Gera um manifesto Swarmv2 customizado para orquestração paralela com 3 perspectivas:
    1. Arquiteto de Sistemas (Backend, APIs, Fluxo de Dados)
    2. Designer UI/UX (Frontend, Componentes, Arsenal de Design)
    3. Auditor de Segurança (Red Team, Superfície de Ataque, DEFCON)
    """
    manifest = [
        {
            "id": "autopsia_architect",
            "engine": "agy",
            "mode": "plan",
            "model": "gemini-3.8-flash-high",
            "effort": "high",
            "prompt": f"Analise o relatório de autópsia técnica ({report_path}) de '{target_title}'. Dissecte os endpoints de API, a arquitetura de backend observada e gere diagramas Mermaid do fluxo de dados e dos contratos de rotas."
        },
        {
            "id": "autopsia_ux_designer",
            "engine": "claude",
            "mode": "plan",
            "model": "sonnet",
            "effort": "high",
            "prompt": f"Analise os elementos de interface ({report_path}) e o screenshot visual ({screenshot_path}) de '{target_title}'. Mapeie os componentes correspondentes no Arsenal de Design (shadcn/ui, Tremor Raw, Origin UI, Aceternity) e avalie a densidade de tela."
        },
        {
            "id": "autopsia_security_auditor",
            "engine": "codex",
            "mode": "plan",
            "model": "gpt-6-sol",
            "effort": "high",
            "prompt": f"Audite a superfície de ataque e a exposição de segurança de '{target_title}' com base em ({report_path}). Classifique o nível DEFCON (1 a 4), aponte possíveis riscos de PII, parâmetros inseguros e rotas sensíveis."
        }
    ]
    return {
        "success": True,
        "tasksCount": len(manifest),
        "manifest": manifest
    }

if __name__ == "__main__":
    mcp.run()
