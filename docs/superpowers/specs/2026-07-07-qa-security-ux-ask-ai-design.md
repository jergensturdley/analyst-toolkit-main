# QA / Security / UX Pass + Ask AI — Design

**Date:** 2026-07-07 (updated 2026-07-08)
**Scope:** SOC Analyst Toolkit browser extension (MV3). Edit main in place. No branch.
**Out of scope (queued as separate spec):** module-level refactor of `popup.js` and `background.js`.

---

## Goals

1. Replace the "Ask Claude" feature with **Ask AI**: a clipboard-copy helper that builds a triage prompt from the user's IOCs + raw input, copies it to the clipboard, and opens the user's chosen AI chat URL. Configurable via settings (target URL + custom prompt template).
2. Fix outstanding security issues. *(Deferred — covered by follow-up spec.)*
3. Fix bugs found during the QA sweep. *(Deferred — covered by follow-up spec.)*
4. Polish UX hiccups. *(Deferred — covered by follow-up spec.)*

**This spec covers only Goal 1.** The streaming/API version of Ask AI (Anthropic / OpenAI streaming into a popup panel) is explicitly out of scope and is superseded by the clipboard-copy approach.

## Non-goals

- Splitting `popup.js` (3794 lines) / `background.js` (2517) into modules. Deferred to a follow-up spec.
- Adding new OSINT providers or IOC extraction rules.
- Changing the existing storage scheme for non-AI keys.
- Streaming responses from an AI provider into the popup. (Deferred; this v1 is clipboard-only.)
- Removing or modifying the existing QA/security/UX work tracked under Goals 2–4; that material (§2–§7 below) is preserved for future reference and is **not** part of this implementation.

---

## Architecture context (established)

- MV3 extension. Popup → `chrome.runtime.sendMessage` → background service worker performs all cross-origin fetches (popup cannot). *Not used by Ask AI v1 — the v1 clipboard flow performs no network calls in the extension.*
- Existing API keys (`ipinfoApiKey`, `abuseipdbApiKey`, `greynoiseApiKey`, `virustotalApiKey`) live in `chrome.storage.local`. Ask AI follows the same pattern for its target URL and prompt template.
- `background.js` owns `fetchWithBackoff`, `RateLimiter`, caching, and a message router. Unused by Ask AI v1.
- `popup.js` has an `askClaude()` method (line 871) that builds a triage-report prompt and copies it to the clipboard while opening `https://claude.ai/new`. The prompt body is the source of truth for the default template; Ask AI reuses it verbatim.
- Settings UI already exists in `popup.html` with a key-grid layout and per-provider sections.

---

## 1. Ask AI feature

This section supersedes the earlier streaming/API design. Ask AI is a clipboard-copy helper, not an API client: it builds a triage prompt from the user's IOCs + raw input, copies it to the clipboard, and opens the user's chosen AI chat URL. The streaming/API version (Anthropic / OpenAI) is deferred to a follow-up spec.

### 1.1 Replace Ask Claude with Ask AI

**Delete:**
- `popup.js` `askClaude()` method (line 871) and its click handler at line 339.
- `popup.html` `#askClaudeBtn` button (icon `fa-robot`, label "Ask Claude").

**Rename + relabel in place:**
- `#askClaudeBtn` → `#askAiBtn` (icon `fa-wand-magic-sparkles`, label "Ask AI").
- `askClaude()` → `askAi()`. Body is unchanged except `targetUrl` is now read from `askAiConfig.targetUrl` instead of being hardcoded to `https://claude.ai/new`.

### 1.2 Config schema

Stored under `chrome.storage.local`, key `askAiConfig`:

```json
{
  "targetUrl": "https://claude.ai/new",
  "promptTemplate": ""
}
```

- `targetUrl` — destination tab. Validated as a parseable `http(s)` URL on save.
- `promptTemplate` — user-supplied template. Empty string means "use the built-in default template" (the verbatim triage prompt currently hardcoded inside the old `askClaude()`). Non-empty strings support `{{iocs}}` and `{{rawInput}}` placeholders. A template that lacks `{{iocs}}` gets the IOC list appended after the template body so an accidentally-empty template never silently produces a request with no indicators.

### 1.3 Target URL dropdown

A `<select>` of common AI chat URLs sits next to the target URL text input in settings:

| Label | URL |
|---|---|
| Claude | `https://claude.ai/new` |
| ChatGPT | `https://chatgpt.com/` |
| Gemini | `https://gemini.google.com/app` |
| Copilot | `https://copilot.microsoft.com/` |
| Perplexity | `https://www.perplexity.ai/` |
| Mistral (Le Chat) | `https://chat.mistral.ai/chat` |
| Custom… | _(empty — frees the text input for a user-typed URL)_ |

Selecting a non-Custom entry writes its URL into the text input and clears focus from the input (no flicker / no overwrite). Selecting **Custom…** does not change the text input — the user types freely. On settings load, if the saved `targetUrl` matches a known preset's URL, that preset is selected; otherwise the dropdown is set to "Custom…" and the saved URL populates the text input. Matches the existing pattern in popup.html where storage-driven UI state is reconstructed on load.

### 1.4 Prompt builder

Extract the prompt-building logic out of the old `askClaude()` into a single pure helper:

```
buildTriagePrompt(iocs, rawInput, template?) => string
```

Behavior:
- `template` empty / undefined → return the hardcoded default template, with `iocs` formatted in and `rawInput` appended at the end (preserves existing behavior exactly).
- `template` non-empty → substitute `{{iocs}}` if present, append formatted IOCs at end if absent. Substitute `{{rawInput}}` if present, append at end if absent. Substitution is plain string replace, not regex, so a template with `{{iocs}}` does not interpret the IOC list.
- IOC list format stays the same as today (one line per IOC: `type: value`).

This helper is pure (no DOM, no chrome APIs) and lives alongside the test mock so it can be exercised from `tests/verify_features.js`.

### 1.5 Popup click handler

```
askAi() {
  if (!this.lastResults?.length) {
    this.showNotification('Run analysis first', 'error');
    return;
  }
  const cfg = await loadAskAiConfig();  // see §1.6
  if (!cfg.targetUrl) {
    this.showNotification('Set Ask AI target URL in Settings', 'error');
    this.switchTab('settings');
    return;
  }
  const prompt = buildTriagePrompt(this.lastResults, this.lastRawInput ?? '', cfg.promptTemplate);
  await this.copyToClipboard(prompt);   // existing helper
  this.showNotification('Prompt copied to clipboard', 'success');
  chrome.tabs.create({ url: cfg.targetUrl });
}
```

Reuses existing `copyToClipboard()` (which currently does `execCommand('copy')`; the spec'd `navigator.clipboard.writeText` migration lives in §2.1 and applies here automatically).

### 1.6 Settings UI

New section in the existing settings panel, titled **Ask AI**:

- **Target chat**: `<select>` of presets (§1.3) plus a freeform `<input type="url">` next to it.
- **Prompt template**: `<textarea>` with placeholder showing the built-in default, and a **Reset to default** button that clears `promptTemplate` and the textarea.
- A short help line under the section: "Ask AI copies a triage prompt to your clipboard and opens your chosen AI chat."

Save behavior: settings save handler reads the `select` + input together — if the select is anything other than "Custom…", the input is overwritten with that preset's URL before save. Custom URL is saved as typed. Empty URL on save is rejected with a toast and the previous value restored.

### 1.7 Manifest / permissions

No new permissions. `storage` already granted. `tabs.create` is implicitly available without a permission entry in MV3.

---

## 2. Security hardening *(deferred — see Goals 2–4)*

The material in §2, §3, §4, §5, §6, §7 is preserved for future reference and is **not** part of this implementation. Ask AI v1 is clipboard-only with no API calls and no worker; the security surface is exactly the same as the existing Ask Claude flow plus a user-editable template.

Concretely, for v1:

- **§2.1** (`copyText` migration to `navigator.clipboard.writeText`) — applies only if the existing `copyToClipboard()` helper is reused; the refactor is a one-line swap and falls inside the implementation plan as part of the Ask AI task.
- **§2.2** (streaming output rendering) — N/A, no streaming.
- **§2.3** (API key handling) — N/A, no API keys.
- **§2.4** (SSRF on custom baseUrl) — N/A, no `baseUrl` field. Target URL is restricted to `http(s)` scheme on save.
- **§2.5** (prompt-injection awareness) — partially applies. The default template renders IOCs inside a fenced "data, not instructions" section. The new `buildTriagePrompt()` helper preserves this. A user-supplied template that strips the fence is the user's responsibility — we do not parse or sanitize their template text..

---

## 3. QA / bug-fix sweep *(deferred — see Goals 2–4)*

Out of scope for this implementation. The plan in §5 covers only Ask AI v1; QA/security/UX work is filed under separate specs.

---

## 4. UX polish *(deferred — see Goals 2–4)*

Out of scope for this implementation.

---

## 5. Implementation order

This spec covers Ask AI v1 only. Steps in build order:

1. **`tests/verify_features.js`** — add `Ask AI config + prompt builder` test block first, asserting against the pure helper. Tests are the contract; the rest of the implementation is built to satisfy them.
2. **`buildTriagePrompt(iocs, rawInput, template?)`** in `popup.js` as a free function (or static method). Pure. Importable from the test mock or duplicated there.
3. **`askAi()`** method in `popup.js`. Rename of `askClaude()`; reads `askAiConfig`, calls `buildTriagePrompt`, copies prompt, opens tab.
4. **`popup.html`** — rename `#askClaudeBtn` → `#askAiBtn` (icon + label); add Ask AI settings section (select + URL input + textarea + Reset).
5. **Settings load/save** — `loadAskAiConfig()` / `saveAskAiConfig()`; wire into the existing settings save flow.
6. **Manual smoke** — see §6.
7. **`node tests/verify_features.js`** must report `Failed: 0` before commit.

Each step leaves the extension loadable and the test suite green.

---

## 6. Verification

- `node tests/verify_features.js` — must report `Failed: 0` after every step.
- Manual smoke (documented, not automated): load unpacked, paste IOCs, click Ask AI. Confirm: clipboard contains the expected prompt, the chosen target URL opens in a new tab, and changing the target URL in settings takes effect on the next click. With each preset in the dropdown, click Ask AI → opens the right URL.

---

## 7. Risks

- **Clipboard failure in non-secure popup contexts.** Rare in `chrome-extension://` popups, but `navigator.clipboard.writeText` may reject. Fallback to `execCommand('copy')` is already in `copyToClipboard()` (or will be after the §2.1 migration). Acceptable.
- **Custom target URL typo.** A user-typed URL that resolves to nothing leaves them with a copied prompt and an empty tab. We open the URL regardless; the user sees the failure in the tab and can paste the prompt manually. Acceptable.
- **Custom prompt template mistakes.** A template that strips the IOC list (e.g. forgets `{{iocs}}`) still gets the IOC list appended (§1.2). A template that forgets both placeholders ends up with IOCs + raw input appended — the prompt is larger than expected but still usable. A template with `{{iocs}}` but no `{{rawInput}}` still has raw input appended. Worst case is a verbose prompt, not a broken one. Acceptable.
