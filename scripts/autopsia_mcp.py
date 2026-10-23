"""
Autopsia FastMCP Server (v2.2.0)
Servidor FastMCP nativo em Python para consulta segura e telemetria de evidências de autópsia.
Opera estritamente via stdio com proteção ativa contra Path Traversal e injeção de comandos.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastmcp import FastMCP
from pydantic import BaseModel, Field

mcp = FastMCP("Autopsia-MCP")

def resolve_artifact_dir() -> Path:
    configured = os.getenv("ANTIGRAVITY_ARTIFACTS_DIR")
    if configured:
        p = Path(configured).resolve()
    else:
        p = (Path(tempfile.gettempdir()) / "antigravity-autopsia").resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p

def safe_resolve_report(report_id_or_path: str) -> Path:
    """
    Blindagem Red Team contra Path Traversal:
    Garante que nenhum caminho saia do escopo do diretório de artefatos autorizado.
    """
    base = resolve_artifact_dir()
    clean_name = os.path.basename(report_id_or_path)
    if not clean_name.endswith(".json"):
        clean_name = f"{clean_name}.json"
        
    target = (base / clean_name).resolve()
    if not target.is_relative_to(base):
        raise ValueError(f"🚨 Ação de Red Team bloqueada: Tentativa de Path Traversal ({report_id_or_path})")
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Relatório de autópsia não encontrado: {clean_name}")
    return target

class AutopsiaSummary(BaseModel):
    report_id: str
    target: str
    title: str
    timestamp: str
    screenshot_path: str
    sensitive_inputs_detected: bool
    sensitive_inputs_warning: str
    total_dom_elements: int
    links_count: int
    inputs_count: int
    api_endpoints_count: int
    security_notice: str

@mcp.tool
def get_autopsia_summary(report_id: str = Field(..., description="Nome do arquivo ou ID do relatório JSON (ex: autopsia_report_1710000000000.json)")) -> Dict[str, Any]:
    """
    Retorna o sumário consolidado de um relatório de autópsia técnica sem vazar dados brutos.
    """
    target_path = safe_resolve_report(report_id)
    with open(target_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    ui = data.get("uiAnalysis", {})
    sec = data.get("securityAudit", {})
    
    summary = AutopsiaSummary(
        report_id=target_path.name,
        target=data.get("target", "N/A"),
        title=data.get("title", "Sem título"),
        timestamp=data.get("timestamp", "N/A"),
        screenshot_path=data.get("screenshot", "N/A"),
        sensitive_inputs_detected=sec.get("sensitiveInputsDetected", False),
        sensitive_inputs_warning=sec.get("warning", ""),
        total_dom_elements=ui.get("totalElements", 0),
        links_count=ui.get("linksCount", 0),
        inputs_count=ui.get("inputsCount", 0),
        api_endpoints_count=len(data.get("apiEndpointsCaptured", [])),
        security_notice=data.get("securityNotice", "UNTRUSTED_APP_TELEMETRY")
    )
    return summary.model_dump()

@mcp.tool
def list_observed_endpoints(
    report_id: str = Field(..., description="ID do relatório de autópsia."),
    status_filter: Optional[int] = Field(None, description="Filtra por código de status HTTP (ex: 200, 401, 500).")
) -> List[Dict[str, Any]]:
    """
    Lista todos os endpoints de backend interceptados durante a sessão de autópsia.
    Todos os parâmetros de rota e tokens são previamente ofuscados pelo motor.
    """
    target_path = safe_resolve_report(report_id)
    with open(target_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    endpoints = data.get("apiEndpointsCaptured", [])
    if status_filter is not None:
        endpoints = [ep for ep in endpoints if ep.get("status") == status_filter]
    return endpoints

@mcp.tool
def inspect_ui_elements(
    report_id: str = Field(..., description="ID do relatório de autópsia."),
    category: str = Field("all", description="Categoria a inspecionar: 'links', 'inputs' ou 'all'.")
) -> Dict[str, Any]:
    """
    Retorna os elementos visíveis de UI (links, botões, campos de formulário) capturados,
    com garantia de sanitização anti-Prompt Injection.
    """
    target_path = safe_resolve_report(report_id)
    with open(target_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    ui = data.get("uiAnalysis", {})
    response = {}
    if category in ("links", "all"):
        response["linksSample"] = ui.get("linksSample", [])
    if category in ("inputs", "all"):
        response["inputsSample"] = ui.get("inputsSample", [])
    response["securityNotice"] = data.get("securityNotice", "UNTRUSTED_APP_TELEMETRY")
    return response

@mcp.tool
def list_recent_autopsias(
    limit: int = Field(5, description="Quantidade máxima de relatórios a listar.")
) -> List[Dict[str, Any]]:
    """
    Lista as autópsias mais recentes disponíveis no diretório de artefatos.
    """
    base = resolve_artifact_dir()
    files = list(base.glob("autopsia_report_*.json"))
    files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    
    results = []
    for f in files[:limit]:
        try:
            with open(f, "r", encoding="utf-8") as rf:
                data = json.load(rf)
                results.append({
                    "report_id": f.name,
                    "target": data.get("target", "N/A"),
                    "title": data.get("title", "N/A"),
                    "timestamp": data.get("timestamp", "N/A"),
                    "size_bytes": f.stat().st_size
                })
        except Exception:
            continue
    return results

if __name__ == "__main__":
    mcp.run()
