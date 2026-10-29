# ⚡ Web-XRay (`web-xray`)

[![GitHub Stars](https://img.shields.io/github/stars/Gabrielrtads/web-xray?style=social)](https://github.com/Gabrielrtads/web-xray)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node: >=18](https://img.shields.io/badge/Node-%3E%3D18.0.0-green.svg)](https://nodejs.org/)
[![Skills CLI](https://img.shields.io/badge/skills.sh-web--xray-purple.svg)](https://skills.sh/)

> **Zero-Exfiltration Technical Web App X-Ray, DOM Architecture & Correlated API Sniffer for AI Coding Agents.**  
> Passive, read-only X-ray of web applications **you own or are explicitly authorized to test**: Tech Stack, SPA routes, form structures, REST/GraphQL APIs and web storage with a strict 5-layer anti-leak shield.

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

**Web-XRay is a clinical, leak-hardened forensic scanner designed specifically for AI Agents:**
1. **Tech Stack & Frameworks:** Discovers React, Next.js, Vite, Tailwind, Svelte, Vue, Angular, Three.js, TanStack Query, and Redux in live runtime.
2. **SPA Routes & Navigation:** Maps the actual internal application tree from `<nav>`, `<aside>`, and interactive buttons.
3. **Correlated API Sniffer:** Intercepts REST/GraphQL/tRPC endpoints matched by `requestId` (HTTP method, status code, latency, and sanitized headers).
4. **Strict Keys-Only Storage Audit:** Audits `localStorage` and `sessionStorage` architecture (key names, byte sizes, inferred types) with **ZERO value extraction**.
5. **Ephemeral Headless Fallback:** Runs against open Chrome tabs (`port 9222`) or spins up an isolated, temporary Chromium instance automatically if none is running.
6. **Multi-Persona Triangulation:** Dispatches structured reports to 3 specialized LLM personas (Systems Architect, UI/UX Designer, and Security Auditor) with explicit epistemic confidence labels.

---

## ⚖️ Authorized Use Only

Web-XRay must only be pointed at applications **you own or have written permission to test**. The engine enforces this:

- Every scan prints an authorized-use warning.
- Scanning an `http(s)` host that is **not** `localhost`/loopback and **not** in your local allowlist is **blocked** unless you explicitly confirm authorization with `--confirmo-autorizacao` (or `WEB_XRAY_CONFIRMO_AUTORIZACAO=1`).
- Your allowlist lives in `WEB_XRAY_ALLOWLIST` (comma-separated) and/or `~/.web-xray/allowlist.txt` (override the path with `WEB_XRAY_ALLOWLIST_FILE`). One host per line; `*.example.com` matches subdomains; `#` starts a comment.
- The FastMCP tools deliberately do **not** expose the confirmation flag, so an agent cannot self-authorize: only you can, through the allowlist or the environment.

> Redaction is pattern-based (JWTs, API-key formats, e-mails, sensitive key names, URL parts). It lowers the risk of leaking secrets into an LLM context but cannot guarantee it: opaque tokens with no recognizable format (for example a random string inside a URL path) can still appear. Review reports before sharing them. Text copied from the scanned site is treated as **untrusted data** in the generated agent prompts.

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
 │  • Strict anti-exfiltration (pattern-based redaction) │
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

- **Web-XRay** handles live runtime reconnaissance: it enters in 5 seconds and catalogs routes, APIs, storage schemas, and bundle asset URLs of applications you are authorized to analyze, with a passive, read-only footprint and without leaking sensitive credentials into the LLM context. It is **not** a stealth tool: it makes no attempt to evade rate limits, WAFs, bot detection, or security monitoring.
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
[2. Structural URL Redaction] ─> Path, query params, embedded user:pass, OAuth hashes and mailto:/tel:/data: masked
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

# Domain not in your allowlist? Confirm authorization explicitly (only for apps you own / may test)
node ./scripts/web_xray_engine.mjs "https://app.example.com" --confirmo-autorizacao

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
