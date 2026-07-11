# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

SOC Analyst Toolkit — a Manifest V3 Chrome extension (v0.5) for SOC analysts. Extracts IOCs from selected text, generates OSINT lookup links, manages snippets, opens selected text in CyberChef. All processing is local; only user-initiated lookups hit the network.

There is no build/bundle step. A `package.json` exists but only to pull in Playwright for the store-screenshot script under `scripts/`; the extension source itself is plain JS/CSS served as-is.

## Commands

```bash
# Run the offline feature/parsing test suite (Node, ~no setup)
node tests/verify_features.js

# Load the extension in Chrome
#   chrome://extensions → enable Developer mode → "Load unpacked" → select this directory.
# Changes are picked up via the service-worker reload button; popup.js/html edits require closing+reopening the popup.
```

No linter, formatter, or bundler is configured. Tests live only in `tests/verify_features.js` and use a hand-rolled `SOCToolkitMock` — not the production class.

## File map

| File | Role |
|---|---|
| `manifest.json` | MV3 manifest: permissions, commands, content/background/popup wiring |
| `popup.html` / `popup.js` | The toolbar popup UI. The `SOCToolkit` class (popup.js:32) owns state, IOC parsing, OSINT link generation, graph rendering, snippets, settings, Ask-AI panel |
| `background.js` | MV3 service worker. Owns cross-origin fetch (popup can't fetch directly), `RateLimiter` (background.js:51), cache I/O, the central `chrome.runtime.onMessage` router (background.js:2199), context menus, notifications |
| `content.js` | Injected **on demand** via `chrome.scripting.executeScript` (`ensureContentScript` in background.js) — there is no `content_scripts` block in the manifest, so it is not auto-injected into every page. Handles `copyToClipboard`, `toggleSnippets`, `highlightIOCs`, `getSelectedText`, page-snippet UI. Listens via its own `chrome.runtime.onMessage` (content.js:16) |
| `tlds.js` | TLD allow-list used for domain extraction |
| `vis-network.min.js` | Vendored graph viz library (the popup's IOC graph) |
| `css/`, `icons/`, `webfonts/` | Static assets for the popup UI |
| `tests/verify_features.js` | Node-based IOC parser/regex smoke tests |
| `AGENTS.md` | Enrichment-agent design doc (architecture, rate limits, caching, per-IOC-type agent specs) — read before touching enrichment code |
| `FEATURES.md`, `UPGRADE_GUIDE.md`, `CHANGELOG.md` | User-facing/upgrade docs |
| `docs/superpowers/` | Design specs and implementation plans (e.g. Ask AI + QA/security/UX work) — current planned-but-not-shipped work lives here |

## Architecture

Three execution contexts, connected by `chrome.runtime` messages. Each context owns its own globals; nothing is shared in memory.

```
┌─────────────┐  chrome.runtime.sendMessage  ┌──────────────────┐
│   popup     │ ───────────────────────────► │   background.js  │
│  (SOCTool-  │ ◄─────────────────────────── │   service worker │
│   kit)      │       sendResponse           │  fetch / cache / │
└─────┬───────┘                               │  rate-limit      │
      │ chrome.tabs.sendMessage /            └─────────┬────────┘
      │ chrome.runtime.sendMessage to tab              │
      ▼                                                │
┌─────────────┐                                        │
│ content.js  │  page DOM access (selection, highlight)│
│  (selected  │ ◄───────────────────────────────────────┘
│   text)     │
└─────────────┘
```

**Why the background service worker owns the network**: MV3 popups cannot perform arbitrary cross-origin fetches, and CORS would block OSINT APIs anyway. All outbound HTTP goes through `background.js` (see `fetchWithBackoff`, background.js:102) so a single layer enforces rate limiting, retries, and caching.

**Message router pattern**: `background.js:2199` switches on `request.action`. Current actions: `getPendingAnalysis`, `agentEnrich`, `toggleFloat`, `getRateLimitStatus`, `passiveDnsEnrich`, `asnEnrich`. New cross-context actions should be added as new `action` strings on the router, not new channels.

**Async responses**: handlers that do I/O must `return true` from the listener to keep the message channel open until `sendResponse` fires.

## IOC processing flow

1. User selects text on a page, right-clicks → context menu → "Analyze SOC Toolkit" (background.js), or `Ctrl+Shift+S` to open the popup directly.
2. Popup receives the selected text via `getPendingAnalysis` from background (the context menu stashed it in `pendingAnalysis` / `chrome.storage.local`). content.js still exposes a `getSelectedText` handler, but nothing in popup/background currently calls it.
3. `SOCToolkit.analyzeIOCs` (popup.js:706) runs the regex bank against the input, dedupes, classifies (IP / domain / URL / hash / email / CVE / MITRE / crypto / MAC), and renders the result list + the vis-network graph.
4. `generateOSINTLinks` (popup.js:1908) builds per-IOC lookup URLs for ~20 providers; the popup's context menu and `openXxxLookup` family in background.js (`openVirusTotalLookup`, `openAlienVaultLookup`, `openAbuseIPDBLookup`, `openIpInfoLookup`, `openMitreLookup`, `openBlockchainLookup`) open them.
5. Enrichment agents (per `AGENTS.md`) are invoked via `agentEnrich` → `runAgent` in background, with per-provider caching (`agent_<id>_<type>_<ioc>` keys in `chrome.storage.local`) and `RateLimiter` guarding each provider.

## Persistence

State lives in `chrome.storage.local` under namespaced keys:

- `snippets`, `socSettings`, `savedIOCInput` — popup state
- `agent_<agentId>_<iocType>_<ioc>` — enrichment cache
- `pdns_cache_<domain>`, `asn_cache_<ip>` — passive DNS / ASN lookups
- `virustoolApiKey` (and similar `<provider>ApiKey`) — user-supplied API keys
- Custom OSINT sources, theme, agent config — all keys live in `chrome.storage.local`; grep there before adding new top-level keys.

API keys are user-supplied only; never hardcode one. Background fallbacks: when no key is present, many `*Enrich` handlers fall through to opening the provider's web UI rather than calling the API.

## Conventions for new code

- **Context placement**: state belongs in popup, fetches belong in background, DOM access belongs in content. Don't fetch from popup.js.
- **Adding a message**: add an `action` to the background router at `background.js:2199`, then send from popup/content. Return `true` from the listener when async.
- **Adding a new IOC type**: regex + classifier in `popup.js` (see existing `patterns.*` and `analyzeIOCs`), then per-type lookup function in background if there's an OSINT provider for it.
- **Adding an enrichment agent**: follow the per-IOC-type template in `AGENTS.md` (normalized result format, TTL, rate-limit entry, fallback to web UI). Tests for the agent logic live alongside `SOCToolkitMock` in `tests/verify_features.js` — extend the mock, not the production class, since the test harness does not load `popup.js`.
- **Visuals**: popup pulls `vis-network.min.js` and `webfonts/`; themes are defined as CSS classes on `<body>`. New theme = new class in `css/`.
- **Plan/spec docs under `docs/superpowers/`**: when a feature has a spec + plan there, treat them as authoritative for scope and naming before touching the code.

## Gotchas

- MV3 service worker can be killed at any time. Don't keep transient state in background globals you can't recover; anything important goes to `chrome.storage.local`.
- Several popup→background `sendMessage` call sites do not check `chrome.runtime.lastError` on the callback. If you add a new call, handle the disconnected-worker case (the `safeResponse` wrapper pattern from the 2026-07-07 plan is the established fix).
- `popup.html` and `popup.js` are large (~80KB / ~140KB); new features belong in the same files unless they introduce a clear new context.
- `tlds.js` is consumed by both popup.js and the test mock — keep the allow-list in one place.
- No runtime npm dependencies; `vis-network.min.js` is vendored locally. The only dev dependency is Playwright (store screenshots). Don't add runtime deps or external CDN references without a deliberate decision.