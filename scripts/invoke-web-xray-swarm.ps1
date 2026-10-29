[CmdletBinding()]
param(
    [string]$TargetFilter = '',
    [string]$Port = '9222',
    [string]$HostAddress = '127.0.0.1',
    [switch]$RunSwarmTriangulation,
    [switch]$ConfirmoAutorizacao,
    [ValidateSet('agy', 'claude', 'codex')]
    [string]$DefaultSwarmEngine = 'agy'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "`n⚡ [WEB-XRAY SOTA v3.1] Iniciando ciclo de investigação técnica..." -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$engineJs = Join-Path $scriptDir "web_xray_engine.mjs"

if (-not (Test-Path -LiteralPath $engineJs)) {
    throw "Motor JavaScript de web-xray não encontrado em: $engineJs"
}

# 1. Configurar variáveis de ambiente do runtime
$env:CHROME_DEBUG_PORT = $Port
$env:CDP_HOST = $HostAddress
# Domínios fora da allowlist local (WEB_XRAY_ALLOWLIST) exigem confirmação explícita de autorização
if ($ConfirmoAutorizacao) { $env:WEB_XRAY_CONFIRMO_AUTORIZACAO = '1' }

# 2. Executar o Motor de Autópsia
Write-Host "📡 Conectando ao Chrome DevTools Protocol na porta $Port..." -ForegroundColor Yellow
$outputLines = & node "$engineJs" "$TargetFilter"
$nodeExit = $LASTEXITCODE

$outputLines | ForEach-Object { Write-Host $_ }

if ($nodeExit -ne 0) {
    throw "Falha na execução do motor de autópsia (ExitCode: $nodeExit)."
}

Write-Host "✅ Ingestão técnica e evidências coletadas e sanitizadas com sucesso!" -ForegroundColor Green

# 3. Se solicitado, disparar a Triangulação Concorrente Swarmv2
if ($RunSwarmTriangulation) {
    Write-Host "`n🐝 [SWARMv2] Iniciando Triangulação Analítica Concorrente..." -ForegroundColor Cyan
    
    # Localizar o script canônico do Swarmv2
    $swarmv2Script = "C:\Users\User\.agents\skills\swarmv2\scripts\invoke-swarmv2-parallel.ps1"
    if (-not (Test-Path -LiteralPath $swarmv2Script)) {
        # Fallback para workspace local
        $swarmv2Script = Join-Path $scriptDir "..\..\swarmv2\scripts\invoke-swarmv2-parallel.ps1"
    }
    if (-not (Test-Path -LiteralPath $swarmv2Script)) {
        Write-Warning "Script do Swarmv2 não encontrado. Executando modo somente-ingestão."
        return
    }

    # Identificar o manifesto exato gerado nesta execução
    $manifestMatch = $outputLines | Select-String -Pattern 'Manifesto Swarmv2(?:\s*Pronto)?:\s*(.+)'
    $manifestPath = if ($manifestMatch) { $manifestMatch.Matches[0].Groups[1].Value.Trim() } else { $null }

    if (-not $manifestPath -or -not (Test-Path -LiteralPath $manifestPath)) {
        # Fallback de busca em caso de stdout truncado
        $artifactsBase = if ($env:ANTIGRAVITY_ARTIFACTS_DIR) { $env:ANTIGRAVITY_ARTIFACTS_DIR } else { [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "antigravity-autopsia") }
        $manifestFiles = Get-ChildItem -Path $artifactsBase -Filter "autopsia_swarmv2_manifest_*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
        if ($manifestFiles -and $manifestFiles.Count -gt 0) {
            $manifestPath = $manifestFiles[0].FullName
        }
    }
    
    if (-not $manifestPath -or -not (Test-Path -LiteralPath $manifestPath)) {
        Write-Warning "Nenhum manifesto Swarmv2 encontrado."
        return
    }

    Write-Host "📋 Usando manifesto da execução: $manifestPath" -ForegroundColor Gray

    # Executar Swarmv2 em modo Fan-Out
    & powershell.exe -NoProfile -File $swarmv2Script -ManifestPath $manifestPath -Engine $DefaultSwarmEngine -Json
}
