# QA / Security / UX Pass + Ask AI — Design

**Date:** 2026-07-07
**Scope:** SOC Analyst Toolkit browser extension (MV3). Edit main in place. No branch.
**Out of scope (queued as separate spec):** module-level refactor of `popup.js` and `background.js`.

---

## Goals

1. Replace the "Ask Claude" feature with "Ask AI": a configurable, streaming AI triage report generated inside the popup.
2. Fix outstanding security issues.
3. Fix bugs found during the QA sweep.
4. Polish UX hiccups.

## Non-goals

- Splitting `popup.js` (3794 lines) / `background.js` (2517) into modules. Deferred to a follow-up spec.
- Adding new OSINT providers or IOC extraction rules.
- Changing the existing storage scheme for non-AI keys.

---

## Architecture context (established)

- MV3 extension. Popup → `chrome.runtime.sendMessage` → background service worker performs all cross-origin fetches (popup cannot).
- Existing API keys (`ipinfoApiKey`, `abuseipdbApiKey`, `greynoiseApiKey`, `virustotalApiKey`) live in `chrome.storage.local`. Ask AI follows the same pattern.
- `background.js` owns `fetchWithBackoff`, `RateLimiter`, caching, and a message router (`chrome.runtime.onMessage` with a `switch` on `action`).
- `popup.js` has an `askClaude()` method (line 871) that builds a triage-report prompt and copies it to the clipboard while opening `https://claude.ai/new`. The prompt builder is reused verbatim by Ask AI.
- Settings UI already exists in `popup.html` with a key-grid layout and per-provider sections.

---

## 1. Ask AI feature

### 1.1 Config schema

Stored under `chrome.storage.local`, key `askAiConfig`:

```json
{
  "provider": "anthropic",
  "anthropic": {
    "apiKey": "",
    "model": "claude-opus-4-8",
    "baseUrl": "https://api.anthropic.com"
  },
  "openai": {
    "apiKey": "",
    "model": "gpt-4o",
    "baseUrl": "https://api.openai.com/v1"
  },
  "systemPrompt": ""
}
```

- `provider` ∈ `{"anthropic", "openai"}`. Selects which preset is active.
- `baseUrl` included for both so users can point at a proxy or self-host. Anthropic default omits trailing `/v1` (worker appends `/v1/messages`); OpenAI default includes `/v1` (worker appends `/chat/completions`).
- Empty `systemPrompt` → worker uses a built-in SOC analyst persona.
- Missing `askAiConfig` entirely → treated as unset; UI prompts user to configure.

### 1.2 Streaming transport

One-shot `chrome.runtime.sendMessage` cannot carry SSE chunks. Ask AI uses a long-lived **port** via `chrome.runtime.connect({name: 'ask-ai'})`.

**Lifecycle:**
- Popup opens port on "Ask AI" click. Worker begins fetch.
- Worker emits `{type:'token', text}` per parsed chunk.
- Worker emits `{type:'done'}` on natural completion.
- Worker emits `{type:'error', message}` on any failure (missing key, HTTP non-2xx, network, parse).
- Popup closing → port disconnects → worker's `port.onDisconnect` aborts the in-flight `fetch` via `AbortController`.
- User clicks "Stop" → popup posts `{type:'abort'}` → worker aborts.

### 1.3 Worker: `ask-ai-worker.js` (background)

Routes on `port.name === 'ask-ai'`. On `port.onMessage`:

1. Load `askAiConfig` from `chrome.storage.local`.
2. Build the prompt by reusing the existing `askClaude()` prompt builder logic. Extract that builder into a shared helper (`buildTriagePrompt(iocs, rawInput)`) imported by both the popup (for the legacy clipboard fallback, if retained) and the worker.
3. Validate config: chosen provider has a non-empty key and model. If invalid, emit `{type:'error', message:'Ask AI not configured — set key and model in Settings'}` and return.
4. Dispatch by provider. Streaming path does **not** use `fetchWithBackoff` (mid-stream retry is unsafe); it uses a single `fetch` with `AbortController`. Non-streaming fallback is not provided — streaming is the only path.

**Anthropic:**
- URL: `${baseUrl}/v1/messages`
- Headers: `content-type: application/json`, `x-api-key: <key>`, `anthropic-version: 2023-06-01`
- Body: `{ model, max_tokens: 4096, stream: true, system, messages: [{role:'user', content: prompt}] }`
- SSE parse: emit `delta.text` from `content_block_delta` events. Stop on `message_stop`.

**OpenAI-compatible:**
- URL: `${baseUrl}/chat/completions`
- Headers: `content-type: application/json`, `Authorization: Bearer <key>`
- Body: `{ model, stream: true, messages: [{role:'system', content: system}, {role:'user', content: prompt}] }`
- SSE parse: emit `choices[0].delta.content` where present. Stop on `data: [DONE]`.

**SSE parser:** shared `parseSSEStream(reader, onEvent)` that splits the byte stream on `\n\n`, parses `data:` lines, JSON-parses each payload, and yields to a callback. Provider handlers map payloads to `{type:'token', text}`.

### 1.4 Popup UI

- Replace `askClaudeBtn` with `askAiBtn` (icon: `fa-wand-magic-sparkles`).
- Click handler:
  - If no IOCs → toast "No IOCs to analyze — run analysis first" (existing behavior).
  - If `askAiConfig` missing/invalid → toast "Configure Ask AI in Settings" + switch to settings tab.
  - Else open the **Ask AI panel**.
- **Panel:** modal overlay (or new tab section — modal preferred to avoid losing the IOC list).
  - Header: provider name, model, Stop button.
  - Body: scrollable. Renders streamed text via `textContent` into a `<pre>` (auto-escaped, no XSS surface). No markdown rendering in v1. Cursor at end, auto-scroll while streaming.
  - Footer: "AI output may reflect content of analyzed indicators." + Copy button (enabled on done).
  - Close (×) disconnects the port.

### 1.5 Settings UI

New section in the existing settings panel: **Ask AI**.

- Provider radio: `Anthropic` / `OpenAI-compatible`.
- Anthropic row: API key (password, monospace), model (text, default `claude-opus-4-8`), optional base URL (default `https://api.anthropic.com`, hidden behind "Advanced").
- OpenAI row: API key, model (default `gpt-4o`), base URL (default `https://api.openai.com/v1`).
- System prompt textarea (collapsible; placeholder explains default persona).
- **Test** button: opens a one-shot (non-streaming) request with a trivial prompt ("Reply with OK") and shows ✓ green / ✗ red with the error message. Reuses the worker's validation + fetch logic with a `{test: true}` flag on the port message.

### 1.6 Manifest / permissions

No new permissions. `storage` already granted. `host_permissions: <all_urls>` already covers provider endpoints. No CSP changes (worker fetches are not CSP-restricted in MV3).

---

## 2. Security hardening

### 2.1 Clipboard API migration
- `popup.js:1837` and `content.js:72` use deprecated `document.execCommand('copy')`.
- Replace with `navigator.clipboard.writeText(text)`. Keep `clipboardWrite` permission (harmless, and some contexts still benefit).
- Fallback: if `navigator.clipboard` is undefined (rare, but possible in a non-secure context), fall back to the legacy `execCommand` path rather than dropping the copy. Wrap in a `copyText(text)` helper.

### 2.2 Streaming output rendering
- Streamed model output is inserted via `textContent` only. No `innerHTML` of model output anywhere. This eliminates prompt-injection-driven XSS (a malicious IOC can't ship HTML/script to the panel).
- Existing `innerHTML` usages elsewhere are static template strings with no user/model content interpolation that could carry markup — verified during design. No change required beyond a documented re-check during implementation.

### 2.3 API key handling
- Keys stored in `chrome.storage.local`, consistent with existing provider keys. Not synced, not encrypted at rest (Chrome's extension storage is profile-isolated, not encrypted — acceptable for this threat model, documented in README).
- Never log keys. Never include keys in error messages emitted to the popup. Worker strips auth headers from any error detail.

### 2.4 SSRF on custom baseUrl
- `baseUrl` is user-configured; the worker will fetch whatever the user enters. This is the intended behavior (custom provider / self-host / proxy).
- No mitigation applied beyond a settings-UI hint: "Base URL is fetched verbatim. Point only at providers you trust."
- Documented as accepted risk.

### 2.5 Prompt-injection awareness
- Analyzed indicator text is embedded in the triage prompt. A crafted IOC (e.g. "Ignore previous instructions…") can steer model output.
- Impact is bounded: the model only writes a triage report; it has no tool use, no side effects.
- Mitigation: footer notice in the Ask AI panel (§1.4). No technical block — any block would also mangle legitimate indicators.

---

## 3. QA / bug-fix sweep

Performed during implementation, per module. Known categories to investigate (not an exhaustive list — the sweep will surface more):

- `chrome.runtime.lastError` not checked in `sendMessage` callbacks (several call sites in `popup.js`). Add guards; surface failures via toast instead of silent drops.
- Promise rejections from `chrome.storage.local.get/set` wrappers — ensure all are caught.
- `RateLimiter` edge cases (cleanup loop, TTL expiry).
- Graph node ID collisions when the same IOC appears across types.
- `tests/verify_features.js`: extend with assertions for Ask AI config validation (provider, key, model, baseUrl shape). Keep the suite framework-free (plain asserts, no new test deps).

Bugs found are fixed in place; each non-trivial fix gets a one-line note in the commit body.

---

## 4. UX polish

Addressed opportunistically during the sweep. Triggers for a fix:
- Controls that don't show loading state during async work.
- Buttons that can be double-clicked into duplicate requests.
- Toast/error messages that don't tell the user what to do next.
- Focus loss when modals open/close.

Each UX change is one self-contained diff; no wholesale restyle.

---

## 5. Implementation order

1. **Ask AI** (highest value, self-contained). Worker first, then popup panel, then settings UI, then test button.
2. **Security hardening** (§2): clipboard helper, output rendering guards, key-handling audit.
3. **QA sweep** (§3): per-module bug fixes.
4. **UX polish** (§4).
5. **Tests**: extend `tests/verify_features.js` for Ask AI config; run full suite green at the end.

Each step ends with the extension loadable and the test suite passing.

---

## 6. Verification

- `node tests/verify_features.js` — must report `Failed: 0` after every step.
- Manual smoke check (documented, not automated): load unpacked, run an IOC extraction, click Ask AI with each provider preset, confirm streaming renders, abort mid-stream, test error path with a bad key.

---

## 7. Risks

- **MV3 service worker idle eviction.** A long stream may outlast the 30s SW idle timer. Mitigation: the open port counts as an active event; the worker stays alive while streaming. If Chrome still evicts, the popup sees a port disconnect and surfaces "Stream interrupted." Acceptable; revisit if reported.
- **Provider API drift.** Anthropic/OpenAI shapes are stable as of writing; if either changes, the parser breaks loudly (error emitted, no silent corruption).
- **Large reports.** `max_tokens: 4096` caps output. If users want longer, expose a setting later — YAGNI for v1.
