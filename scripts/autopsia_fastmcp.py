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

# Redação compartilhada (stdlib pura) entre web_xray_fastmcp.py e autopsia_fastmcp.py
sys.path.insert(0, str(SCRIPT_DIR))
from xray_redact import (  # noqa: E402
    redact_url as _redact_url,
    scrub_object as _scrub_object,
    sanitize_page_text,
    wrap_untrusted,
    UNTRUSTED_DATA_NOTICE,
)

mcp = FastMCP("Autopsia FastMCP Server")

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
                    "title": sanitize_page_text(p.get("title", "Sem Título")),
                    "url": _redact_url(p.get("url", "")),
                    "devtoolsFrontendUrl": _redact_url(p.get("devtoolsFrontendUrl", ""))
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
    Só escaneia domínios da allowlist local do usuário (WEB_XRAY_ALLOWLIST / ~/.web-xray/allowlist.txt) ou
    localhost; esta ferramenta de propósito não expõe a confirmação de autorização (feita só pelo usuário).
    """
    if not ENGINE_JS.exists():
        return {
            "success": False,
            "error": f"Motor JavaScript não encontrado em: {ENGINE_JS}"
        }

    env = os.environ.copy()
    env["CDP_HOST"] = host
    env["CHROME_DEBUG_PORT"] = port

    # Flags ANTES de "--"; o filtro (controlado pelo chamador) depois dele, para que nunca seja lido como flag
    # (ex: --confirmo-autorizacao). A confirmação de autorização só vale vinda do usuário (env/allowlist).
    cmd = ["node", str(ENGINE_JS)]
    if not enable_storage:
        cmd.append("--no-storage")
    if not enable_console:
        cmd.append("--no-console")
    if enable_screenshot:
        cmd.append("--screenshot")
    cmd += ["--", target_filter]

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
    # report_path, screenshot_path e target_title chegam do chamador (e, indiretamente, do site escaneado):
    # entram nos prompts somente como dado não confiável delimitado.
    report = wrap_untrusted(report_path, 300)
    screenshot = wrap_untrusted(screenshot_path, 300)
    title = wrap_untrusted(target_title)
    manifest = [
        {
            "id": "autopsia_architect",
            "engine": "agy",
            "mode": "plan",
            "model": "gemini-3.8-flash-high",
            "effort": "high",
            "prompt": f"{UNTRUSTED_DATA_NOTICE} Analise o relatório de autópsia técnica (caminho: {report}) de {title}. Dissecte os endpoints de API, a arquitetura de backend observada e gere diagramas Mermaid do fluxo de dados e dos contratos de rotas."
        },
        {
            "id": "autopsia_ux_designer",
            "engine": "claude",
            "mode": "plan",
            "model": "sonnet",
            "effort": "high",
            "prompt": f"{UNTRUSTED_DATA_NOTICE} Analise os elementos de interface (relatório: {report}) e o screenshot visual (caminho: {screenshot}) de {title}. Mapeie os componentes correspondentes no Arsenal de Design (shadcn/ui, Tremor Raw, Origin UI, Aceternity) e avalie a densidade de tela."
        },
        {
            "id": "autopsia_security_auditor",
            "engine": "codex",
            "mode": "plan",
            "model": "gpt-6-sol",
            "effort": "high",
            "prompt": f"{UNTRUSTED_DATA_NOTICE} Audite a superfície de ataque e a exposição de segurança de {title} com base em (relatório: {report}). Classifique o nível DEFCON (1 a 4), aponte possíveis riscos de PII, parâmetros inseguros e rotas sensíveis."
        }
    ]
    return {
        "success": True,
        "tasksCount": len(manifest),
        "manifest": manifest
    }

if __name__ == "__main__":
    mcp.run()
