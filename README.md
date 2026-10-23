# ⚡ Web-XRay (`web-xray`)

[![GitHub Stars](https://img.shields.io/github/stars/Gabrielrtads/web-xray?style=social)](https://github.com/Gabrielrtads/web-xray)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node: >=18](https://img.shields.io/badge/Node-%3E%3D18.0.0-green.svg)](https://nodejs.org/)
[![Skills CLI](https://img.shields.io/badge/skills.sh-web--xray-purple.svg)](https://skills.sh/)

> **Zero-Exfiltration Technical Web App X-Ray, DOM Architecture & Correlated API Sniffer for AI Coding Agents.**  
> Non-destructive X-ray of any web application: Tech Stack, SPA routes, form structures, REST/GraphQL APIs and web storage with a strict 5-layer anti-leak shield.

---

## ⚡ Install with 1-Click

Install directly into your AI agent environment (Claude Code, Cursor, Codex, Antigravity, Cline) via the open **Skills CLI**:

```bash
npx skills add Gabrielrtads/web-xray
```

Or install globally:

```bash
npx skills add Gabrielrtads/web-xray -g -y
```

---

## 💡 Why Web-XRay?

Most web scrapers and browser tools (Puppeteer, Cheerio, raw CDP dumps) are **blind and leaky**: they either dump unstructured HTML or accidentally leak sensitive authentication tokens, session cookies, and passwords directly into the LLM context window.

**Web-XRay is a clinical, zero-leak forensic scanner designed specifically for AI Agents:**
1. **Tech Stack & Frameworks:** Discovers React, Next.js, Vite, Tailwind, Svelte, Vue, Angular, Three.js, TanStack Query, and Redux in live runtime.
2. **SPA Routes & Navigation:** Maps the actual internal application tree from `<nav>`, `<aside>`, and interactive buttons.
3. **Correlated API Sniffer:** Intercepts REST/GraphQL/tRPC endpoints matched by `requestId` (HTTP method, status code, latency, and sanitized headers).
4. **Strict Keys-Only Storage Audit:** Audits `localStorage` and `sessionStorage` architecture (key names, byte sizes, inferred types) with **ZERO value extraction**.
5. **Ephemeral Headless Fallback:** Runs against open Chrome tabs (`port 9222`) or spins up an isolated, temporary Chromium instance automatically if none is running.
6. **Multi-Persona Triangulation:** Dispatches structured reports to 3 specialized LLM personas (Systems Architect, UI/UX Designer, and Security Auditor) with explicit epistemic confidence labels.

---

## 🔄 The Synergistic Pipeline: `web-xray` + `morluto/rea`

Web-XRay works seamlessly as the **frontline reconnaissance scout** alongside deep forensic workbenches like **[morluto/rea](https://github.com/morluto/rea)** (Reverse Engineer Anything):

```
┌────────────────────────────────────────────────────────┐
│                   TARGET APPLICATION                   │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
 ┌──────────────────────────────────────────────────────┐
 │  STAGE 1: LIVE RECONNAISSANCE & SANITIZATION         │
 │  ⚡ Web-XRay (gabrielrtads/web-xray)                  │
 │                                                      │
 │  • 5-second non-destructive CDP / Chromium probe     │
 │  • Strict anti-exfiltration (0 leaked secrets/JWTs)  │
 │  • Maps live REST/GraphQL APIs & routes              │
 │  • Identifies loaded script chunks & bundle URLs     │
 └─────────────────────────┬────────────────────────────┘
                           │ Bundle URLs & API Maps
                           ▼
 ┌──────────────────────────────────────────────────────┐
 │  STAGE 2: DEEP FORENSICS & AST DEOBFUSCATION         │
 │  🔬 REA (morluto/rea)                                │
 │                                                      │
 │  • JavaScript source recovery from bundles & maps    │
 │  • AST parsing & module dependency graph             │
 │  • Runtime reconciliation & deobfuscation            │
 │  • Decompilation of native binaries / Electron apps  │
 └──────────────────────────────────────────────────────┘
```

- **Web-XRay** handles live runtime reconnaissance: it enters in 5 seconds, safely catalogs routes, APIs, storage schemas, and bundle asset URLs without crashing the target, triggering security bans, or leaking sensitive credentials into the LLM context.
- **REA** handles deep forensic decompilation: armed with the bundle URLs and entrypoints identified by Web-XRay, REA executes `recover_javascript_sources`, unpacks webpack/vite chunks, traces module ASTs, and reconstructs the client application graph.

---

## 📊 Market Comparison

| Capability | Web-XRay (`v3.1`) | `pasky/chrome-cdp` | `browserbase/trace` | Generic Scrapers |
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
node ./scripts/web_xray_engine.mjs "https://app.example.com"

# Inspection with visual viewport screenshot
node ./scripts/web_xray_engine.mjs "dashboard" --screenshot
```

### 2. FastMCP Server (Python)

Run the native Model Context Protocol server for agent integrations:

```bash
fastmcp run scripts/web_xray_fastmcp.py:mcp --transport stdio
```

Call from your agent:
- `web_xray_run_scan(target_filter="https://app.example.com")`
- `web_xray_sanitize_payload(payload_json)`

### 3. Multi-Agent Triangulation (PowerShell)

Dispatches parallel analysis across 3 specialized agent roles:

```powershell
powershell -NoProfile -File ./scripts/invoke-web-xray-swarm.ps1 `
  -TargetFilter "https://app.example.com" `
  -RunSwarmTriangulation `
  -DefaultSwarmEngine agy
```

---

## 🧪 Testing

Run the included unit test suite verifying strict header sanitization, URL redaction, and keys-only storage constraints:

```bash
npm test
```

---

## 📄 License

MIT © [Gabriel Toledo](https://github.com/Gabrielrtads).
