# 🔬 Autópsia (`autopsia`)

[![GitHub Stars](https://img.shields.io/github/stars/Gabrielrtads/autopsia?style=social)](https://github.com/Gabrielrtads/autopsia)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node: >=18](https://img.shields.io/badge/Node-%3E%3D18.0.0-green.svg)](https://nodejs.org/)
[![Skills CLI](https://img.shields.io/badge/skills.sh-autopsia-purple.svg)](https://skills.sh/)

> **Zero-Exfiltration Technical Web App Autopsy & CDP Sniffer for AI Coding Agents.**  
> Non-destructive X-ray of any web application: Tech Stack, SPA routes, form structures, REST/GraphQL APIs and web storage with a strict 5-layer anti-leak shield.

---

## ⚡ Install with 1-Click

Install directly into your AI agent environment (Claude Code, Cursor, Codex, Antigravity, Cline) via the open **Skills CLI**:

```bash
npx skills add Gabrielrtads/autopsia
```

Or install globally:

```bash
npx skills add Gabrielrtads/autopsia -g -y
```

---

## 💡 Why Autopsia?

Most web scrapers (Puppeteer, Cheerio, raw CDP) are **blind hands**: they either extract flat text or leak sensitive authentication tokens, session cookies, and passwords directly into the LLM context.

**Autopsia is a clinical forensic microscope:**
1. **Tech Stack & Frameworks:** Discovers React, Next.js, Vite, Tailwind, Svelte, Vue, Angular, Three.js, TanStack Query, and Redux in runtime.
2. **SPA Routes & Navigation:** Maps the actual internal application tree from `<nav>`, `<aside>`, and interactive buttons.
3. **Correlated API Sniffer:** Intercepts REST/GraphQL/tRPC endpoints matched by `requestId` (HTTP method, status code, latency, and sanitized headers).
4. **Strict Keys-Only Storage Audit:** Audits `localStorage` and `sessionStorage` architecture (key names, byte sizes, inferred types) with **ZERO value extraction**.
5. **Ephemeral Headless Fallback:** Runs against open Chrome tabs (`port 9222`) or spins up an isolated, temporary Chromium instance automatically if none is running.
6. **Multi-Persona Triangulation:** Dispatches structured reports to 3 specialized LLM personas (Systems Architect, UI/UX Designer, and Security Auditor) with explicit epistemic confidence labels.

---

## 📊 Market Comparison

| Capability | Autopsia (`v3.1`) | `pasky/chrome-cdp` | `browserbase/trace` | Generic Scrapers |
|---|:---:|:---:|:---:|:---:|
| **Tech Stack Discovery** | ✅ **Native** | ❌ None | ❌ None | ⚠️ Static only |
| **SPA Routes & Forms** | ✅ **Native** | ❌ Raw DOM | ❌ None | ⚠️ Fragile |
| **Correlated REST/GraphQL APIs** | ✅ **Method + Latency** | ❌ None | ✅ Raw Events | ❌ None |
| **Anti-Exfiltration Shield** | 🛡️ **5-Layer Strict** | ❌ Leaks Cookies | ❌ Raw NDJSON | ❌ Leaks Auth |
| **Storage Audit (Keys-Only)** | ✅ **Zero Values** | ❌ Unprotected | ❌ None | ❌ Leaks JWT |
| **Ephemeral Headless Fallback** | ✅ **Auto-Launch** | ❌ Manual Setup | ❌ SaaS Required | ⚠️ Bulky |
| **Multi-Agent Triangulation** | ✅ **Swarmv2** | ❌ None | ❌ None | ❌ None |

---

## 🛡️ The 5-Layer Anti-Exfiltration Guarantee

```
[Target Web Application] 
           │
           ▼
[1. Strict Header Allowlist] ──> Only safe transport headers retained; auth/cookies redacted
           │
           ▼
[2. Structural URL Redaction] ─> Query params, embedded user:pass and OAuth hashes masked
           │
           ▼
[3. Keys-Only Web Storage] ────> Byte sizes & data types recorded; ZERO values stored
           │
           ▼
[4. Protected Form Inputs] ────> Password/sensitive fields censored; structure preserved
           │
           ▼
[5. Epistemic Output] ─────────> Explicit [OBSERVED] vs [INFERRED] vs [UNVERIFIED] labels
```

---

## 🚀 Usage

### 1. Direct CLI

```bash
# Basic inspection (connects to port 9222 or auto-launches headless Chromium)
node ./scripts/autopsia_engine.mjs "https://app.example.com"

# Inspection with visual viewport screenshot
node ./scripts/autopsia_engine.mjs "dashboard" --screenshot
```

### 2. FastMCP Server (Python)

Run the native Model Context Protocol server for agent integrations:

```bash
fastmcp run scripts/autopsia_fastmcp.py:mcp --transport stdio
```

Call from your agent:
```python
from scripts.autopsia_fastmcp import autopsia_run_scan

result = autopsia_run_scan(target_filter="https://app.example.com")
print(result["techStack"])
print(result["endpointsCount"])
```

### 3. Swarm Multi-Agent Triangulation (PowerShell)

Dispatches the sanitized autopsy report concurrently to 3 AI engines:

```powershell
powershell -NoProfile -File ./scripts/invoke-autopsia-swarm.ps1 -TargetFilter "dashboard" -RunSwarmTriangulation
```

---

## 🧪 Testing

Run the automated test suite verifying anti-exfiltration guards, storage isolation, and URL/header sanitization:

```bash
npm test
```

---

## 📄 License

MIT © [Gabriel Toledo (@Gabrielrtads)](https://github.com/Gabrielrtads).
