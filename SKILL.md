---
name: web-xray
version: 3.1.0
description: Produz raios-X e evidências técnicas reproduzíveis de aplicações web autorizadas via CDP, integrando análise paralela multi-perspectiva via Swarmv2, ferramentas FastMCP e blindagem de 5 camadas contra extração acidental de segredos.
category: devops
tags: [cdp, web-xray, browser-recon, swarmv2, fastmcp, investigacao-tecnica, anti-exfiltracao]
---

# Web-XRay Técnico SOTA por CDP (v3.1.0)

Protocolo canônico para dissecação técnica e produção de evidências de aplicações web conectadas via Chrome DevTools Protocol (CDP) ou Chromium headless efêmero.

Esta skill opera em três etapas:
1. **Ingestão Técnica Zero-Exfiltração:** Extrai Tech Stack, formulários, rotas SPA, endpoints de API correlacionados (com método HTTP e latência real) e chaves de storage em modo estritamente *Keys-Only* (zero valores gravados).
2. **Resiliência e Fallback Efêmero:** Opera na porta CDP ativa (`9222`) ou sobe automaticamente um Chromium headless efêmero se a porta estiver fechada, sem exigir ativação manual prévia.
3. **Triangulação Analítica Swarmv2:** Orquestra múltiplos motores concorrentes (`agy`, `claude`, `codex`) sob as perspectivas de Arquitetura, UX e Segurança com rotulagem epistêmica explícita (`[OBSERVADO]`, `[INFERIDO]`, `[NÃO VERIFICADO]`).

---

## 1. Diretrizes de Investigação Técnica Avançada

A investigação técnica nunca deve se limitar a um crawling superficial de HTML. Ela opera diretamente na instância ativa do navegador Chromium (Porta `9222` ou Chromium efêmero temporário):

```
                        ┌──> [1. Tech Stack Discovery] ───> React, Next.js, Vite, Tailwind, TanStack, Three.js
                        ├──> [2. DOM & Formulários] ──────> Botões, rotas SPA, inputs (senhas protegidas)
[Aplicação Autorizada] ─┼──> [3. Network Sniffer] ────────> Endpoints REST/GraphQL correlacionados por requestId
 (CDP :9222 / Efêmero)  ├──> [4. Web Storage Audit] ─────> Chaves e contagem (Keys-Only, ZERO valores)
                        ├──> [5. Console & WebSockets] ──> Erros/warnings e conexões sanitizadas
                        └──> [6. Evidência Visual] ──────> Screenshot opcional (--screenshot)
```

1. **Tech Stack & Frameworks Discovery:**
   - Detecta bibliotecas no escopo global (`window.React`, `window.next`, `window.Vue`, `window.angular`, `window.__svelte`, `window.THREE`, `window.__TANSTACK_QUERY__`, `window.__REDUX_DEVTOOLS_EXTENSION__`).
   - Mapeia meta-tags de renderização e frameworks CSS via classes utilitárias no DOM (Tailwind, Radix UI, Shadcn).
2. **Mapeamento de Rotas e Navegação SPA:**
   - Mapeia árvores de navegação em `<nav>`, `<aside>`, botões e links com atributos `href` e `data-href` sanitizados.
   - Distingue links internos de navegação SPA de links externos ou de transbordo.
3. **Sniffer de Rede Observável Correlacionado:**
   - Intercepta tráfego via `Network.requestWillBeSent` e `Network.responseReceived` agrupados por `requestId`.
   - Identifica rotas de backend `/api/`, `/graphql`, `/trpc/`, `/v1/`, `/v2/` com método HTTP exato (`GET`, `POST`, `PUT`, `DELETE`), status code e latência real.
   - Detecta canais em tempo real (`Network.webSocketCreated`).
4. **Auditoria Segura de Storage (Chaves-Apenas Estrito):**
   - Inspeciona `window.localStorage` e `window.sessionStorage` em modo **estritamente estrutural**: registra nomes de chaves higienizados, tamanho em bytes e tipo inferido (`json_object`, `string`), **sem nunca capturar ou persistir valores**.
5. **Console Events Scrubber:**
   - Captura erros e avisos de runtime (`Runtime.consoleAPICalled`) higienizando mensagens contra JWTs, chaves de API e e-mails.

---

## 2. Protocolo Blindado de 5 Camadas Anti-Exfiltração de Segredos

> [!CAUTION]
> **REGRA DE OURO ANTI-EXFILTRAÇÃO (REGRA 6 UNIVERSAL):**
> É estritamente proibido que o Web-XRay capture, persista em disco ou exponha no chat tokens JWT, cookies de sessão, Bearer headers, senhas digitadas ou dados pessoais (PII).

| Camada | Vetor de Risco | Ação Obrigatória do Engine |
|---|---|---|
| **1. Headers de Rede** | `Authorization: Bearer <jwt>`, `Cookie`, `Set-Cookie`, `X-Api-Key` | **Strict Allowlist:** Apenas headers seguros de transporte (`content-type`, `accept`, `host`, `user-agent`) são retidos. Qualquer outro header vira `[REDACTED_CUSTOM_HEADER]`. |
| **2. URLs & Query Strings** | `?token=...`, `?key=...`, `?signature=...`, `#access_token=...` | `redactUrl()` mascara 100% dos parâmetros de query, credenciais de URL (`user:pass`) e fragmentos OAuth de hash. |
| **3. Web Storage** | Tokens JWT de Supabase/Firebase gravados no `localStorage` | **Modo Keys-Only Estrito:** Extrai apenas chave, tamanho em bytes e tipo de dado. O campo de valor foi **completamente eliminado da coleta**. |
| **4. Inputs de Formulário** | Campos de senha, CVV, CPF preenchidos | Atributos `type="password"` ou campos com nomes sensíveis têm seus valores bloqueados; apenas presença e rótulo são catalogados. |
| **5. Diretório de Artefatos** | Salvar evidências na raiz do projeto e commitar via Git | Bloqueio forçado de `process.cwd()`: saídas vão exclusivamente para `ANTIGRAVITY_ARTIFACTS_DIR` ou pasta privada `%TEMP%/antigravity-web-xray-*` (0700/0600). |

---

## 3. Ferramental FastMCP (`web_xray_fastmcp.py`)

A skill implementa um servidor e toolkit **FastMCP** em Python para que outros agentes possam orquestrar o Web-XRay programaticamente:

```bash
# Execução direta do servidor FastMCP
fastmcp run scripts/web_xray_fastmcp.py:mcp --transport stdio
```

### Ferramentas Expostas:

1. `web_xray_run_scan(target_filter="", host="127.0.0.1", port="9222", enable_storage=True, enable_console=True, enable_screenshot=False, network_wait_ms=2500)`:
   - Executa o raio-X técnico completo e retorna o sumário estruturado e os caminhos dos relatórios gerados.
2. `web_xray_sanitize_payload(payload_json: str)`:
   - Sanitizador universal que higieniza qualquer JSON mascarando chaves ou valores sensíveis.
3. `autopsia_run_scan(...)`:
   - Alias retrocompatível com a versão anterior.

---

## 4. Integração aos Motores do Swarmv2 (Triangulação Paralela)

Uma vez concluída a ingestão técnica e gerado o relatório sanitizado (`web_xray_report_<id>.json`), o Swarmv2 pode dissecar a evidência em **3 perspectivas simultâneas (Fan-Out)** com modelos de fronteira:

```
                                  ┌──> [Motor 1 (agy)]: Arquiteto de Sistemas (gemini-4-argon-high)
[web_xray_report.json] ───────────┼──> [Motor 2 (claude)]: Designer UI/UX (claude-sonnet-5.5)
                                  └──> [Motor 3 (codex)]: Auditor de Segurança (gpt-6.1-sol)
                                                │
                                                ▼
                                  [Fan-In: Laudo Canônico 0X_WebXRay_<App>.md]
```

### Invocação via CLI Autônoma (PowerShell)

```powershell
powershell -NoProfile -File scripts/invoke-web-xray-swarm.ps1 `
  -TargetFilter "dashboard" -RunSwarmTriangulation -DefaultSwarmEngine agy
```

---

## 5. Formas de Execução

### Opção A: Execução Direta via Node.js
```bash
# Execução padrão (conecta na porta 9222 ou sobe Chromium efêmero se passada URL)
node scripts/web_xray_engine.mjs "https://app.exemplo.com"

# Execução com screenshot opcional
node scripts/web_xray_engine.mjs "meuapp" --screenshot
```

### Opção B: Execução Completa com Swarmv2 (PowerShell)
```powershell
powershell -NoProfile -File scripts/invoke-web-xray-swarm.ps1 -TargetFilter "<filtro>" -RunSwarmTriangulation
```

### Opção C: Execução via FastMCP (Python)
```python
from scripts.web_xray_fastmcp import web_xray_run_scan
resultado = web_xray_run_scan(target_filter="https://app.exemplo.com")
```

---

## 6. Rotulagem Epistêmica no Laudo

Todo laudo Web-XRay classifica suas conclusões explicitamente:
- **`[OBSERVADO EM RUNTIME]`**: Endpoints de API interceptados, chamadas de WebSocket, eventos de console e contagem de storage.
- **`[INFERIDO DO DOM/REDE]`**: Tech Stack, rotas SPA e formulários.
- **`[NÃO VERIFICADO / HIPÓTESE]`**: Bancos de dados, filas e serviços internos não visíveis pela camada cliente.
