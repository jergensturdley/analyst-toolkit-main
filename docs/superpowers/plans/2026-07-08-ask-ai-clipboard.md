# Ask AI (clipboard-copy) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the "Ask Claude" feature and replace it with "Ask AI": a clipboard-copy helper that builds a triage prompt from the current IOCs + raw input, copies it to the clipboard, and opens a configurable AI chat URL. Add a settings panel with a preset dropdown (Claude / ChatGPT / Gemini / Copilot / Perplexity / Mistral / Custom) and an editable prompt template.

**Architecture:** v1 is entirely popup-local. No service-worker fetch, no API keys, no streaming. The prompt builder is a pure function (`buildTriagePrompt(iocs, rawInput, template?)`) extracted out of the old `askClaude()` so it's testable. `askAiConfig` lives in `chrome.storage.local` under the existing settings flow. Reuses the existing `copyToClipboard()` helper.

**Tech Stack:** Vanilla JS (no build step), Chrome Extension MV3, `chrome.storage.local`, Font Awesome icons, plain `node tests/verify_features.js` assert runner.

**Spec:** `docs/superpowers/specs/2026-07-07-qa-security-ux-ask-ai-design.md` §1.

## Global Constraints

- Edit main in place. No branch. Commit per task with conventional-commit messages.
- No new npm dependencies. No bundler. Files are plain `<script src>` (popup is NOT a module — `popup.html` uses `<script src="popup.js">`).
- Streaming/API version (Anthropic / OpenAI) is **out of scope** — v1 is clipboard-only.
- Module refactor of `popup.js` / `background.js` is **out of scope** — new code goes into the existing files at sensible section boundaries.
- No new manifest permissions. `storage`, `clipboardWrite`, `<all_urls>` host permissions already granted.
- `node tests/verify_features.js` must end with `Failed: 0` after every task.
- Conventional-commit format: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`. End commit bodies with `Co-Authored-By: Claude <noreply@anthropic.com>`.

## File Structure

**Modified:**
- `popup.js` — extract `buildTriagePrompt()` as a free function; rename `askClaude()` → `askAi()`; add `loadAskAiConfig()` / `saveAskAiConfig()`; update click handler at line 339; wire settings save.
- `popup.html` — rename `#askClaudeBtn` → `#askAiBtn` (icon + label); add Ask AI settings section (preset select + URL input + textarea + Reset).
- `tests/verify_features.js` — add `Ask AI Config + Prompt Builder` test block.

**Not touched:**
- `background.js` — no message router additions; the v1 clipboard flow does no network calls in the extension.
- `content.js` — no change.
- `manifest.json` — no permission additions.

---

### Task 1: Prompt builder helper + tests

**Files:**
- Modify: `popup.js` (add `buildTriagePrompt` near the top of the file, above `class SOCToolkit`, around line 32)
- Test: `tests/verify_features.js` (add new test block before the final summary)

**Interfaces:**
- Produces: free function `buildTriagePrompt(iocs, rawInput, template?)` returning a string.

`iocs` is an array of `{category, value, type}` objects (the same shape produced by `extractIOCs`). `rawInput` is the original user text. `template` is the user-supplied prompt template; empty / undefined means "use the built-in default".

The default template is the literal string the existing `askClaude()` body builds (group by category, IOC table, raw input). Reproduce it verbatim — do not rewrite the wording. The extracted function returns that exact string when `template` is empty.

**Substitution rules:**
- If `template` is empty / undefined: return the default prompt built from `iocs` + `rawInput`.
- If `template` is non-empty:
  - Replace `{{iocs}}` with the formatted IOC list if the placeholder is present; if absent, append the formatted IOC list at the end.
  - Replace `{{rawInput}}` with `rawInput` (or empty string if falsy) if the placeholder is present; if absent, append at the end.
  - Substitution is plain `String.prototype.replaceAll('{{iocs}}', ...)`, not regex. Curly braces are not escaped.

**IOC list format (used by both default and custom templates):**

```
[type]: value
```

One line per IOC, joined by `\n`. The IOC list rendering for the default template includes a markdown table grouped by category — extract that table-building logic out of `askClaude()` into a helper inside the same file (e.g. `buildDefaultIocTable(grouped)`) and call it from `buildTriagePrompt()` when no template is supplied. This keeps the default verbatim while making the helper fully testable.

- [ ] **Step 1: Add the new test block to `tests/verify_features.js`**

Open `tests/verify_features.js` and find the last `console.log('\n--- ... ---')` block before the summary. Insert before it (do not remove existing tests):

```js
// ==================== Ask AI Config + Prompt Builder Tests ====================
console.log('\n--- Ask AI Config + Prompt Builder Tests ---');

// These free functions are duplicated from popup.js for testing in plain Node.
// Keep them byte-for-byte identical to the popup.js versions.
function buildDefaultIocTable(grouped) {
  const labelMap = {
    ip: 'IP addresses', domain: 'Domains', url: 'URLs', hostname: 'Hostnames',
    hash: 'File hashes', email: 'Emails', cve: 'CVEs', mitre: 'MITRE ATT&CK techniques',
    crypto: 'Cryptocurrency addresses', mac: 'MAC addresses'
  };
  const linkMap = {
    ip: v => `[VT](https://www.virustotal.com/gui/ip-address/${v})`,
    domain: v => `[VT](https://www.virustotal.com/gui/domain/${v})`,
    url: v => `[urlscan](https://urlscan.io/search/${encodeURIComponent('task.url:"' + v + '"')})`,
    hostname: v => `[VT](https://www.virustotal.com/gui/domain/${v})`,
    hash: v => `[VT](https://www.virustotal.com/gui/file/${v})`,
    email: v => `[Hunter](https://hunter.io/email-verifier/${v})`,
    cve: v => `[NVD](https://nvd.nist.gov/vuln/detail/${v})`,
    mitre: v => `[MITRE](https://attack.mitre.org/techniques/${v.replace('.', '/')}/)`,
    crypto: v => `[Blockchain](https://www.blockchain.com/explorer/search?search=${v})`,
    mac: v => `[MAC Vendors](https://macvendors.com/query/${v})`
  };
  const sections = [];
  for (const key of Object.keys(labelMap)) {
    const values = grouped[key] || [];
    if (!values.length) continue;
    const rows = values.map(v => `| \`${v}\` | ${linkMap[key](v)} |`).join('\n');
    sections.push(`### ${labelMap[key]}\n\n| Indicator | Lookup |\n| --- | --- |\n${rows}`);
  }
  return sections.join('\n\n');
}

function buildTriagePrompt(iocs, rawInput, template) {
  const fmtIocs = iocs.map(i => `[${i.category}]: ${i.value}`).join('\n');
  const table = (() => {
    const grouped = {};
    for (const i of iocs) {
      const key = i.category in { ip:1, domain:1, url:1, hostname:1, hash:1, email:1, cve:1, mitre:1, crypto:1, mac:1 } ? i.category : 'hostname';
      (grouped[key] = grouped[key] || []).push(i.value);
    }
    return buildDefaultIocTable(grouped);
  })();

  if (!template) {
    return [
      'You are a SOC analyst triaging the following IOCs.',
      '',
      '## Indicators',
      '',
      table,
      '',
      '## Raw input',
      '',
      rawInput || '(none)'
    ].join('\n');
  }

  let out = template;
  if (out.includes('{{iocs}}')) {
    out = out.split('{{iocs}}').join(fmtIocs);
  } else {
    out += '\n\n## Indicators\n\n' + fmtIocs;
  }
  if (out.includes('{{rawInput}}')) {
    out = out.split('{{rawInput}}').join(rawInput || '');
  } else {
    if (rawInput) out += '\n\n## Raw input\n\n' + rawInput;
  }
  return out;
}

const askAiPresets = [
  { label: 'Claude',         url: 'https://claude.ai/new' },
  { label: 'ChatGPT',        url: 'https://chatgpt.com/' },
  { label: 'Gemini',         url: 'https://gemini.google.com/app' },
  { label: 'Copilot',        url: 'https://copilot.microsoft.com/' },
  { label: 'Perplexity',     url: 'https://www.perplexity.ai/' },
  { label: 'Mistral (Le Chat)', url: 'https://chat.mistral.ai/chat' }
];

const askAiDefaultConfig = () => ({ targetUrl: 'https://claude.ai/new', promptTemplate: '' });

function resolveAskAiPreset(url) {
  const match = askAiPresets.find(p => p.url === url);
  return match ? match.label : 'Custom…';
}

function validateAskAiTargetUrl(url) {
  if (!url || typeof url !== 'string') return { ok: false, error: 'Target URL required' };
  let u;
  try { u = new URL(url); } catch { return { ok: false, error: 'Invalid URL' }; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { ok: false, error: 'URL must be http(s)' };
  return { ok: true };
}

// Tests
test('buildTriagePrompt: default template includes IOC table and raw input', () => {
  const iocs = [
    { category: 'ip', value: '1.2.3.4', type: 'IP' },
    { category: 'domain', value: 'evil.example', type: 'Domain' }
  ];
  const out = buildTriagePrompt(iocs, 'found in alert XYZ', undefined);
  assert.ok(out.includes('IP addresses'), 'has IP section');
  assert.ok(out.includes('Domains'), 'has Domain section');
  assert.ok(out.includes('1.2.3.4'), 'includes IOC value');
  assert.ok(out.includes('evil.example'), 'includes second IOC');
  assert.ok(out.includes('found in alert XYZ'), 'includes raw input');
});

test('buildTriagePrompt: empty raw input renders "(none)"', () => {
  const out = buildTriagePrompt([{ category: 'ip', value: '5.6.7.8', type: 'IP' }], '', undefined);
  assert.ok(out.includes('(none)'), 'empty raw input renders (none)');
});

test('buildTriagePrompt: custom template substitutes {{iocs}} and {{rawInput}}', () => {
  const out = buildTriagePrompt(
    [{ category: 'ip', value: '9.9.9.9', type: 'IP' }],
    'raw text here',
    'Triage this:\n{{iocs}}\nContext: {{rawInput}}'
  );
  assert.ok(out.includes('9.9.9.9'), 'IOC substituted');
  assert.ok(out.includes('raw text here'), 'raw input substituted');
  assert.ok(!out.includes('{{iocs}}'), 'placeholder removed');
  assert.ok(!out.includes('{{rawInput}}'), 'placeholder removed');
});

test('buildTriagePrompt: template missing {{iocs}} still gets IOC list appended', () => {
  const out = buildTriagePrompt(
    [{ category: 'ip', value: '7.7.7.7', type: 'IP' }],
    'context',
    'Just analyze this:'
  );
  assert.ok(out.includes('Just analyze this:'), 'user template kept');
  assert.ok(out.includes('7.7.7.7'), 'IOC appended');
});

test('buildTriagePrompt: template missing {{rawInput}} still gets raw input appended', () => {
  const out = buildTriagePrompt(
    [{ category: 'ip', value: '7.7.7.7', type: 'IP' }],
    'context ABC',
    '{{iocs}}'
  );
  assert.ok(out.includes('7.7.7.7'), 'IOC substituted');
  assert.ok(out.includes('context ABC'), 'raw input appended');
});

test('resolveAskAiPreset: known URL resolves to label', () => {
  assert.strictEqual(resolveAskAiPreset('https://claude.ai/new'), 'Claude');
  assert.strictEqual(resolveAskAiPreset('https://chatgpt.com/'), 'ChatGPT');
  assert.strictEqual(resolveAskAiPreset('https://gemini.google.com/app'), 'Gemini');
  assert.strictEqual(resolveAskAiPreset('https://copilot.microsoft.com/'), 'Copilot');
  assert.strictEqual(resolveAskAiPreset('https://www.perplexity.ai/'), 'Perplexity');
  assert.strictEqual(resolveAskAiPreset('https://chat.mistral.ai/chat'), 'Mistral (Le Chat)');
});

test('resolveAskAiPreset: unknown URL resolves to Custom…', () => {
  assert.strictEqual(resolveAskAiPreset('https://example.com/chat'), 'Custom…');
  assert.strictEqual(resolveAskAiPreset(''), 'Custom…');
});

test('validateAskAiTargetUrl: accepts http(s)', () => {
  assert.deepStrictEqual(validateAskAiTargetUrl('https://claude.ai/new'), { ok: true });
  assert.deepStrictEqual(validateAskAiTargetUrl('http://example.com/x'), { ok: true });
});

test('validateAskAiTargetUrl: rejects empty / non-http(s)', () => {
  assert.strictEqual(validateAskAiTargetUrl('').ok, false);
  assert.strictEqual(validateAskAiTargetUrl('javascript:alert(1)').ok, false);
  assert.strictEqual(validateAskAiTargetUrl('ftp://x.com').ok, false);
  assert.strictEqual(validateAskAiTargetUrl('not a url').ok, false);
});

test('askAiDefaultConfig: defaults to claude.ai/new, empty template', () => {
  const c = askAiDefaultConfig();
  assert.strictEqual(c.targetUrl, 'https://claude.ai/new');
  assert.strictEqual(c.promptTemplate, '');
});

console.log(' [PASS] Ask AI config + prompt builder');
```

- [ ] **Step 2: Run the tests to confirm they pass against the duplicated functions**

Run: `node tests/verify_features.js`
Expected: `Failed: 0` and `[PASS] Ask AI config + prompt builder` printed. The duplicated helpers in the test file are self-contained; they pass on their own before any popup.js change.

- [ ] **Step 3: Commit**

```bash
git add tests/verify_features.js
git commit -m "test: Ask AI config + prompt builder helpers

Pure-function helpers duplicated into the test runner so we can drive
buildTriagePrompt / resolveAskAiPreset / validateAskAiTargetUrl without
loading popup.js. They will be replaced by real imports in the next task.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 2: Extract `buildTriagePrompt` into `popup.js`

**Files:**
- Modify: `popup.js` (insert `buildTriagePrompt` + `buildDefaultIocTable` + preset list + `resolveAskAiPreset` + `validateAskAiTargetUrl` + `askAiDefaultConfig` as free functions above `class SOCToolkit` around line 32)

**Interfaces:**
- Produces: free functions in `popup.js` matching the helpers added to `tests/verify_features.js` in Task 1 (byte-for-byte the same logic).

- [ ] **Step 1: Read the existing `askClaude()` body verbatim**

Read popup.js from line 871 to the end of the method (find the matching closing brace — search for `^}` indented two spaces from `askClaude`). Capture the IOC table-building logic and the surrounding template string.

- [ ] **Step 2: Replace `askClaude()` body with a delegation to `buildTriagePrompt`**

Cut the IOC table / template string construction out of `askClaude()` and put it inside the new `buildTriagePrompt(iocs, rawInput, template)` free function (defined at module scope). `askClaude()` keeps the URL open + clipboard copy + notification — only the prompt-construction work moves.

The new `askClaude()` body, line 871 onwards, becomes (no other change):

```js
  askClaude() {
    const iocs = this.lastIOCs;
    if (!iocs || iocs.length === 0) {
      this.showNotification('No IOCs to analyze — run analysis first', 'error');
      return;
    }
    const prompt = buildTriagePrompt(iocs, this.lastRawInput || '', '');
    this.copyToClipboard(prompt);
    this.showNotification('Prompt copied to clipboard', 'success');
    chrome.tabs.create({ url: 'https://claude.ai/new' });
  }
```

Add the helper functions above `class SOCToolkit` (around line 32). The duplicated helpers from Task 1's test file are moved here unchanged. Do NOT delete the helpers from `tests/verify_features.js` yet — keep them duplicated until Task 6 replaces them with shared-module imports (or keeps them duplicated if a shared-module split is out of scope).

- [ ] **Step 3: Verify the popup still loads and `askClaude()` still works**

Load unpacked in `chrome://extensions`, click the toolbar icon, paste IOCs, click "Ask Claude". Confirm: clipboard has the expected prompt, a new tab opens at `https://claude.ai/new`. If anything breaks, the body extraction missed a binding — restore the original verbatim and try again.

- [ ] **Step 4: Run the tests**

Run: `node tests/verify_features.js`
Expected: `Failed: 0`. The test file's helpers are still self-contained.

- [ ] **Step 5: Commit**

```bash
git add popup.js
git commit -m "refactor(popup): extract buildTriagePrompt from askClaude

The IOC table builder and the default template string move into a pure
free function so it can be unit-tested and reused by the upcoming Ask AI
flow. askClaude() now delegates prompt construction and keeps only the
clipboard + tab-open work.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 3: Rename `askClaude()` → `askAi()` and update the button

**Files:**
- Modify: `popup.js:339` (rename handler)
- Modify: `popup.js:871` (rename method)
- Modify: `popup.html:2042` (rename button id, label, icon)

- [ ] **Step 1: Rename the method in `popup.js`**

Edit `popup.js` line 339:

```js
    el('askClaudeBtn')?.addEventListener('click', () => this.askClaude());
```

→

```js
    el('askAiBtn')?.addEventListener('click', () => this.askAi());
```

Edit `popup.js` line 871: change `askClaude() {` to `askAi() {`. No body change.

- [ ] **Step 2: Rename the button in `popup.html`**

Edit `popup.html` line 2042:

```html
      <button class="btn btn-small" id="askClaudeBtn" title="Open Claude with a pre-built triage prompt for these IOCs">
```

→

```html
      <button class="btn btn-small" id="askAiBtn" title="Open your chosen AI chat with a pre-built triage prompt for these IOCs">
        <i class="fa-solid fa-wand-magic-sparkles"></i> Ask AI
      </button>
```

Find the matching closing `</button>` for `#askClaudeBtn` (just below) and remove the existing `Ask Claude` text + `fa-robot` icon inside it so only the new label remains.

- [ ] **Step 3: Verify in browser**

Load unpacked, click the toolbar icon, paste IOCs, click "Ask AI". Confirm: clipboard has the prompt, new tab opens at `https://claude.ai/new` (default still hardcoded — settings wiring happens in Task 4).

- [ ] **Step 4: Run the tests**

Run: `node tests/verify_features.js`
Expected: `Failed: 0`.

- [ ] **Step 5: Commit**

```bash
git add popup.js popup.html
git commit -m "feat: rename Ask Claude → Ask AI

Same clipboard flow, same default URL. Icon swapped to
fa-wand-magic-sparkles; label and tooltip updated.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 4: Settings load/save for `askAiConfig`

**Files:**
- Modify: `popup.js` (add `loadAskAiConfig()` + `saveAskAiConfig()` methods; update `askAi()` to read config)
- Modify: `popup.html` (add Ask AI settings section; selector + URL input + textarea + Reset button)
- Modify: `tests/verify_features.js` (no change — helpers already cover the data layer)

**Interfaces:**
- Produces: `async loadAskAiConfig()` → resolves to `{ targetUrl, promptTemplate }`. Missing or malformed storage → returns `askAiDefaultConfig()`.
- Produces: `async saveAskAiConfig(cfg)` → writes to `chrome.storage.local` under key `askAiConfig`. Empty / invalid `targetUrl` rejected (see `validateAskAiTargetUrl`); prior value preserved on rejection and a toast shown.
- Produces: `askAi()` updated to read `askAiConfig.targetUrl` and `askAiConfig.promptTemplate` (via `buildTriagePrompt`).

- [ ] **Step 1: Add `loadAskAiConfig()` and `saveAskAiConfig()` methods to `SOCToolkit`**

Add to the class (alongside the other config loaders — grep for `chrome.storage.local.get` to find the neighborhood):

```js
  async loadAskAiConfig() {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.get(['askAiConfig'], (res) => {
          const cfg = res && res.askAiConfig;
          if (!cfg || typeof cfg !== 'object') return resolve(askAiDefaultConfig());
          resolve({
            targetUrl: typeof cfg.targetUrl === 'string' ? cfg.targetUrl : 'https://claude.ai/new',
            promptTemplate: typeof cfg.promptTemplate === 'string' ? cfg.promptTemplate : ''
          });
        });
      } catch (e) {
        resolve(askAiDefaultConfig());
      }
    });
  }

  async saveAskAiConfig(cfg) {
    const v = validateAskAiTargetUrl(cfg.targetUrl);
    if (!v.ok) {
      this.showNotification(`Ask AI: ${v.error}`, 'error');
      return false;
    }
    return new Promise((resolve) => {
      try {
        chrome.storage.local.set({ askAiConfig: { targetUrl: cfg.targetUrl.trim(), promptTemplate: cfg.promptTemplate || '' } }, () => resolve(true));
      } catch (e) {
        this.showNotification('Failed to save Ask AI settings', 'error');
        resolve(false);
      }
    });
  }
```

- [ ] **Step 2: Update `askAi()` to use the config**

Replace the body of `askAi()`:

```js
  async askAi() {
    const iocs = this.lastIOCs;
    if (!iocs || iocs.length === 0) {
      this.showNotification('No IOCs to analyze — run analysis first', 'error');
      return;
    }
    const cfg = await this.loadAskAiConfig();
    const v = validateAskAiTargetUrl(cfg.targetUrl);
    if (!v.ok) {
      this.showNotification(`Ask AI: ${v.error}`, 'error');
      this.switchTab('settings');
      return;
    }
    const prompt = buildTriagePrompt(iocs, this.lastRawInput || '', cfg.promptTemplate);
    await this.copyToClipboard(prompt);
    this.showNotification('Prompt copied to clipboard', 'success');
    chrome.tabs.create({ url: cfg.targetUrl });
  }
```

- [ ] **Step 3: Add the Ask AI settings section to `popup.html`**

Find the existing settings panel's closing `</div>` and insert just before it (so the section sits inside the settings panel). The exact insertion point is the last `<div class="settings-section">` block — find the closing `</div>` of that section and add the new section after it.

```html
<div class="settings-section" id="askAiSettingsSection">
  <h3>Ask AI</h3>
  <p class="settings-help">Ask AI copies a triage prompt to your clipboard and opens your chosen AI chat.</p>

  <div class="form-row">
    <label for="askAiPreset">Target chat</label>
    <div class="ask-ai-target-row">
      <select id="askAiPreset">
        <option value="Claude">Claude</option>
        <option value="ChatGPT">ChatGPT</option>
        <option value="Gemini">Gemini</option>
        <option value="Copilot">Copilot</option>
        <option value="Perplexity">Perplexity</option>
        <option value="Mistral (Le Chat)">Mistral (Le Chat)</option>
        <option value="Custom…">Custom…</option>
      </select>
      <input type="url" id="askAiTargetUrl" placeholder="https://example.com/chat" />
    </div>
  </div>

  <div class="form-row">
    <label for="askAiPromptTemplate">Prompt template</label>
    <textarea id="askAiPromptTemplate" rows="6" placeholder="Leave empty to use the built-in default template. Supports {{iocs}} and {{rawInput}} placeholders."></textarea>
    <button type="button" class="btn btn-small" id="askAiResetTemplate">Reset to default</button>
  </div>
</div>
```

Match the styling class names already used in popup.html (`form-row`, `btn`, `btn-small`). If `settings-help` doesn't exist, use whatever paragraph class is already there.

- [ ] **Step 4: Wire the preset dropdown to the URL input**

Add to `popup.js` constructor or `init()` (whichever wires up event listeners — match the existing pattern for the other settings inputs):

```js
    // Ask AI settings wiring
    const presetSel = el('askAiPreset');
    const urlInput = el('askAiTargetUrl');
    const tplArea = el('askAiPromptTemplate');
    const resetBtn = el('askAiResetTemplate');

    presetSel?.addEventListener('change', () => {
      const v = presetSel.value;
      if (v === 'Custom…') return; // user types freely
      const match = askAiPresets.find(p => p.label === v);
      if (match) {
        urlInput.value = match.url;
        urlInput.focus();
        urlInput.blur(); // clear focus to avoid visual jump
      }
    });

    resetBtn?.addEventListener('click', () => {
      tplArea.value = '';
      this.showNotification('Prompt template reset to default', 'success');
    });
```

Add to the existing settings-load call (find the place that loads other config keys):

```js
    const askAiCfg = await this.loadAskAiConfig();
    if (urlInput) urlInput.value = askAiCfg.targetUrl;
    if (tplArea) tplArea.value = askAiCfg.promptTemplate;
    if (presetSel) presetSel.value = resolveAskAiPreset(askAiCfg.targetUrl);
```

Add to the existing settings-save call (find the place that saves other config keys):

```js
    if (presetSel && urlInput) {
      let targetUrl = urlInput.value.trim();
      if (presetSel.value !== 'Custom…') {
        const match = askAiPresets.find(p => p.label === presetSel.value);
        if (match) targetUrl = match.url;
      }
      const ok = await this.saveAskAiConfig({ targetUrl, promptTemplate: tplArea ? tplArea.value : '' });
      if (!ok && urlInput) urlInput.value = askAiCfg.targetUrl; // restore on rejection
    }
```

- [ ] **Step 5: Verify in browser**

Reload unpacked. Open settings tab:
- Dropdown defaults to "Claude", URL input shows `https://claude.ai/new`.
- Switch dropdown to "ChatGPT" → URL input updates to `https://chatgpt.com/`.
- Switch to "Custom…" → URL input stays editable.
- Paste a custom template into the textarea → click "Reset to default" → textarea clears.

Click "Ask AI" with the default config → clipboard has prompt, new tab opens at `https://claude.ai/new`.
Switch dropdown to "ChatGPT", save settings, click Ask AI again → new tab opens at `https://chatgpt.com/`.

- [ ] **Step 6: Run the tests**

Run: `node tests/verify_features.js`
Expected: `Failed: 0`.

- [ ] **Step 7: Commit**

```bash
git add popup.js popup.html
git commit -m "feat: Ask AI settings (target URL + prompt template)

Adds the Ask AI settings section: a preset dropdown (Claude, ChatGPT,
Gemini, Copilot, Perplexity, Mistral, Custom…) plus a freeform URL input
and a customizable prompt template textarea. Settings persist under
chrome.storage.local key askAiConfig. askAi() reads from the config and
falls back to a sane default.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 5: Remove duplicated helpers from `tests/verify_features.js`

**Files:**
- Modify: `tests/verify_features.js` (remove the helper definitions added in Task 1; keep the test cases)

The helpers were duplicated in Task 1 so the tests would pass without touching `popup.js`. Now that `popup.js` contains the real helpers, the test file should call the popup.js versions directly. Since `popup.js` is not a module, the cleanest path is to keep the helpers in the test file (single source of truth = the test file) and delete them from `popup.js`. This means `popup.js` calls the helpers via the same names — which works because the test file and `popup.js` are not loaded together.

**Decision: keep helpers in BOTH places for now.** The test file is a standalone Node script. `popup.js` is loaded by the browser. They cannot share source without a build step (out of scope). This task is therefore a NO-OP.

- [ ] **Step 1: Confirm the test file still passes**

Run: `node tests/verify_features.js`
Expected: `Failed: 0`. The duplicated helpers remain in both files; both stay in sync because they're checked by the same test cases.

- [ ] **Step 2: Commit (only if a drift occurred during refactor)**

If you find the test helpers drifted from the popup.js helpers during Tasks 2–4, fix them. Otherwise, no commit.

```bash
git add tests/verify_features.js popup.js
git commit -m "chore: keep Ask AI helpers in sync between test and popup

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 6: README update + final smoke

**Files:**
- Modify: `README.md` (replace the Ask-Claude mention with Ask AI; document the settings section)

- [ ] **Step 1: Update README**

Find any mention of "Ask Claude" in README.md and replace it with "Ask AI". Add a short paragraph under the appropriate feature section:

```markdown
### Ask AI

The Ask AI button copies a triage prompt — formatted from your current IOCs and the original raw input — to your clipboard and opens your chosen AI chat in a new tab. Configure the target URL and prompt template from the Ask AI section of Settings (preset dropdown covers Claude, ChatGPT, Gemini, Copilot, Perplexity, and Mistral; pick "Custom…" for any other URL). Custom templates support `{{iocs}}` and `{{rawInput}}` placeholders.
```

If README.md doesn't currently mention Ask Claude, just append the new section under a sensible heading.

- [ ] **Step 2: Final manual smoke**

Run: `node tests/verify_features.js`
Expected: `Failed: 0`.

Load unpacked. Smoke flow:
1. Click toolbar icon → paste text containing 2 IPs + 1 domain → "Analyze".
2. Click "Ask AI" → new tab opens at `https://claude.ai/new`, clipboard has prompt.
3. Open Settings → switch dropdown to "ChatGPT" → URL input updates → save.
4. Click "Ask AI" → new tab opens at `https://chatgpt.com/`.
5. Paste a custom template `Triage:\n{{iocs}}` into the prompt template textarea → save.
6. Click "Ask AI" → clipboard has `Triage:` followed by the formatted IOC list (no raw input section, because the template lacks `{{rawInput}}` and there's no raw input).
7. Switch dropdown to "Custom…" → URL input accepts `https://www.perplexity.ai/` → save → Ask AI opens Perplexity.
8. Switch dropdown to "Mistral (Le Chat)" → Ask AI opens Mistral.

All eight steps must pass.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: README — document Ask AI feature

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Self-Review Notes

- **Spec coverage**: §1.1 (rename) → Tasks 3; §1.2 (config schema) → Tasks 1 + 4; §1.3 (dropdown) → Tasks 1 + 4; §1.4 (prompt builder) → Tasks 1 + 2; §1.5 (click handler) → Tasks 3 + 4; §1.6 (settings UI) → Task 4; §1.7 (permissions) → no-op (none added).
- **No placeholders**: every code block is the literal file content the engineer writes. No "TBD" / "implement later" / "add appropriate error handling".
- **Type/signature consistency**: helpers are defined identically in Task 1 (test file) and Task 2 (popup.js). `askAi()` signature is consistent across Tasks 3 and 4. `loadAskAiConfig` / `saveAskAiConfig` defined once in Task 4 and reused.
- **Task 5 is deliberately a no-op**: the test file and `popup.js` cannot share source without a build step. Duplication is the explicit tradeoff documented in the spec's "Module refactor" non-goal.