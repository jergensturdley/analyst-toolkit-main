# Ask AI + QA/Security/UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the "Ask Claude" clipboard feature with a streaming, configurable "Ask AI" triage report generated inside the popup, then harden security, fix bugs, and polish UX.

**Architecture:** Ask AI runs as a streaming fetch in the MV3 background service worker (the only context with cross-origin fetch rights). The popup opens a long-lived `chrome.runtime.connect` port; the worker parses the provider's SSE stream and forwards token events. Output renders into the popup via `textContent` (no HTML injection). Provider config (Anthropic + OpenAI-compatible) lives in `chrome.storage.local` alongside the existing provider keys.

**Tech Stack:** Vanilla JS (no build step), Chrome Extension MV3, `chrome.runtime` ports + messaging, `chrome.storage.local`, existing `node tests/verify_features.js` plain-assert runner.

## Global Constraints

- Edit main in place. No branch. Commit per task with conventional-commit messages.
- No new npm dependencies. No bundler. Files are plain `<script src>` (popup is NOT a module — `popup.html:2540` uses `<script src="popup.js">`).
- Module refactor of `popup.js` / `background.js` is **out of scope** — new code goes into the existing files at sensible section boundaries.
- No `innerHTML` of model output anywhere; only `textContent`.
- Never log or surface API keys in error messages.
- `node tests/verify_features.js` must end with `Failed: 0` after every task.
- Conventional-commit format: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`. End commit bodies with `Co-Authored-By: Claude <noreply@anthropic.com>`.
- `clipboardWrite`, `storage`, `<all_urls>` host permissions already granted — no manifest changes in this plan.

## File Structure

**Modified:**
- `background.js` — add Ask AI streaming handler on the `ask-ai` port; add SSE parser + provider adapters.
- `popup.js` — extract prompt builder into a pure method; add Ask AI panel + port client; add settings load/save for `askAiConfig`.
- `popup.html` — rename Ask Claude → Ask AI button; add Ask AI panel markup; add Ask AI settings section.
- `content.js` — no code change expected (clipboard path already correct); verify only.
- `tests/verify_features.js` — add pure-function tests for prompt builder, SSE parser, config validation.
- `README.md` — document Ask AI feature + accepted security notes.

**Created:** none. (A `docs/` spec already exists.)

Each task below ends with the extension loadable (`chrome://extensions` → reload unpacked) and the test suite green.

---

### Task 1: Ask AI config schema + validation

**Files:**
- Modify: `popup.js` (add config defaults + validator near the settings section, ~line 2500)
- Test: `tests/verify_features.js` (add `AskAiConfig` test block)

**Interfaces:**
- Produces: `defaultAskAiConfig()` → returns the object below; `validateAskAiConfig(cfg)` → returns `{ok: true}` or `{ok: false, error: string}`.

```js
// defaultAskAiConfig()
{
  provider: 'anthropic',
  anthropic:  { apiKey: '', model: 'claude-opus-4-8', baseUrl: 'https://api.anthropic.com' },
  openai:     { apiKey: '', model: 'gpt-4o',          baseUrl: 'https://api.openai.com/v1' },
  systemPrompt: ''
}
```

**Validation rules** (enforced by `validateAskAiConfig`):
- `provider` ∈ `{'anthropic', 'openai'}`.
- Active provider block exists with non-empty `apiKey` (trimmed) and non-empty `model`.
- `baseUrl`, if set, must parse via `new URL(...)` and use `http:` or `https:`.
- Empty key on the inactive provider is allowed.

- [ ] **Step 1: Write the failing tests**

Append to `tests/verify_features.js`, before the final summary block:

```js
console.log('\n--- Ask AI Config Tests ---');

function defaultAskAiConfig() {
  return {
    provider: 'anthropic',
    anthropic:  { apiKey: '', model: 'claude-opus-4-8', baseUrl: 'https://api.anthropic.com' },
    openai:     { apiKey: '', model: 'gpt-4o',          baseUrl: 'https://api.openai.com/v1' },
    systemPrompt: ''
  };
}

function validateAskAiConfig(cfg) {
  if (!cfg || typeof cfg !== 'object') return { ok: false, error: 'Missing config' };
  const provider = cfg.provider;
  if (provider !== 'anthropic' && provider !== 'openai') {
    return { ok: false, error: 'Invalid provider' };
  }
  const block = cfg[provider];
  if (!block || typeof block !== 'object') return { ok: false, error: 'Missing provider block' };
  const key = (block.apiKey || '').trim();
  const model = (block.model || '').trim();
  if (!key) return { ok: false, error: 'API key required' };
  if (!model) return { ok: false, error: 'Model required' };
  if (block.baseUrl) {
    let u;
    try { u = new URL(block.baseUrl); } catch { return { ok: false, error: 'Invalid baseUrl' }; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return { ok: false, error: 'baseUrl must be http(s)' };
    }
  }
  return { ok: true };
}

function testAskAiConfig() {
  assert.deepStrictEqual(defaultAskAiConfig().provider, 'anthropic');
  assert.ok(validateAskAiConfig(defaultAskAiConfig()).ok === false, 'default (empty key) invalid');

  const good = defaultAskAiConfig();
  good.anthropic.apiKey = 'sk-x';
  assert.ok(validateAskAiConfig(good).ok, 'anthropic with key ok');

  const openai = defaultAskAiConfig();
  openai.provider = 'openai';
  openai.openai.apiKey = 'sk-y';
  assert.ok(validateAskAiConfig(openai).ok, 'openai with key ok');

  const badProvider = defaultAskAiConfig();
  badProvider.provider = 'gemini';
  badProvider.anthropic.apiKey = 'sk-x';
  assert.ok(/provider/i.test(validateAskAiConfig(badProvider).error), 'bad provider rejected');

  const badUrl = defaultAskAiConfig();
  badUrl.anthropic.apiKey = 'sk-x';
  badUrl.anthropic.baseUrl = 'ftp://nope';
  assert.ok(/baseUrl/i.test(validateAskAiConfig(badUrl).error), 'bad baseUrl rejected');

  const emptyModel = defaultAskAiConfig();
  emptyModel.anthropic.apiKey = 'sk-x';
  emptyModel.anthropic.model = '  ';
  assert.ok(/model/i.test(validateAskAiConfig(emptyModel).error), 'empty model rejected');
  console.log('  [PASS] Ask AI config validation');
}
testAskAiConfig();
```

- [ ] **Step 2: Run tests to verify they pass (functions defined in the test file itself)**

Run: `node tests/verify_features.js`
Expected: PASS, summary `Failed: 0`. (These functions will move into `popup.js` in Step 3; defining them in the test first locks the contract.)

- [ ] **Step 3: Add the real functions to popup.js**

Insert near the other settings helpers in `popup.js` (find the settings section; the grep target is `getStoredApiKey` or the `saveApiKey`-shaped helpers):

```js
  // --- Ask AI config ---
  defaultAskAiConfig() {
    return {
      provider: 'anthropic',
      anthropic:  { apiKey: '', model: 'claude-opus-4-8', baseUrl: 'https://api.anthropic.com' },
      openai:     { apiKey: '', model: 'gpt-4o',          baseUrl: 'https://api.openai.com/v1' },
      systemPrompt: ''
    };
  }

  validateAskAiConfig(cfg) {
    if (!cfg || typeof cfg !== 'object') return { ok: false, error: 'Missing config' };
    const provider = cfg.provider;
    if (provider !== 'anthropic' && provider !== 'openai') {
      return { ok: false, error: 'Invalid provider' };
    }
    const block = cfg[provider];
    if (!block || typeof block !== 'object') return { ok: false, error: 'Missing provider block' };
    const key = (block.apiKey || '').trim();
    const model = (block.model || '').trim();
    if (!key) return { ok: false, error: 'API key required' };
    if (!model) return { ok: false, error: 'Model required' };
    if (block.baseUrl) {
      let u;
      try { u = new URL(block.baseUrl); } catch { return { ok: false, error: 'Invalid baseUrl' }; }
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        return { ok: false, error: 'baseUrl must be http(s)' };
      }
    }
    return { ok: true };
  }
```

- [ ] **Step 4: Re-run tests**

Run: `node tests/verify_features.js`
Expected: `Failed: 0`.

- [ ] **Step 5: Commit**

```bash
git add popup.js tests/verify_features.js
git commit -m "feat(ask-ai): config schema + validation

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 2: Extract triage prompt builder as a pure function

**Files:**
- Modify: `popup.js` (refactor `askClaude()` at line 871 — extract body into `buildTriagePrompt()`)
- Test: `tests/verify_features.js`

**Interfaces:**
- Produces: `buildTriagePrompt({ iocs, rawInput })` → returns a `string`. `iocs` is an array of `{ category, value }` where `category` ∈ `ip|domain|url|hostname|hash|email|cve|mitre|crypto|mac` (other categories bucket into `hostname`).

The current `askClaude()` body (popup.js:871–974) builds exactly this string. This task lifts it verbatim into a parameterized method so the worker can reuse it without re-implementing.

- [ ] **Step 1: Write the failing test**

Append to `tests/verify_features.js`:

```js
console.log('\n--- Triage Prompt Builder Tests ---');

function buildTriagePrompt({ iocs, rawInput }) {
  const grouped = { ip: [], domain: [], url: [], hostname: [], hash: [], email: [], cve: [], mitre: [], crypto: [], mac: [] };
  for (const ioc of (iocs || [])) {
    const key = ioc.category in grouped ? ioc.category : 'hostname';
    grouped[key].push(ioc.value);
  }
  const buildIocTable = (label, values, linkFn) => {
    if (!values.length) return '';
    const rows = values.map(v => `| \`${v}\` | ${linkFn(v)} |`).join('\n');
    return `**${label}**\n| Indicator | Links |\n|-----------|-------|\n${rows}\n`;
  };
  const vtIp   = v => `[VirusTotal](https://www.virustotal.com/gui/ip-address/${encodeURIComponent(v)}) · [AbuseIPDB](https://www.abuseipdb.com/check/${encodeURIComponent(v)})`;
  const vtDom  = v => `[VirusTotal](https://www.virustotal.com/gui/domain/${encodeURIComponent(v)})`;
  const vtUrl  = v => `[VirusTotal](https://www.virustotal.com/gui/url/${btoa(v)})`;
  const vtHash = v => `[VirusTotal](https://www.virustotal.com/gui/file/${v})`;
  const noLinks = () => '—';
  const iocSection = [
    buildIocTable('IP Addresses', grouped.ip, vtIp),
    buildIocTable('Domains', grouped.domain, vtDom),
    buildIocTable('URLs', grouped.url, vtUrl),
    buildIocTable('Hostnames', grouped.hostname, noLinks),
    buildIocTable('File Hashes', grouped.hash, vtHash),
    buildIocTable('Email Addresses', grouped.email, noLinks),
    buildIocTable('CVEs', grouped.cve, v => `[NVD](https://nvd.nist.gov/vuln/detail/${v})`),
    buildIocTable('MITRE Techniques', grouped.mitre, v => `[ATT&CK](https://attack.mitre.org/techniques/${v.replace('.', '/')})`),
    buildIocTable('Crypto Addresses', grouped.crypto, noLinks),
    buildIocTable('MAC Addresses', grouped.mac, noLinks),
  ].filter(Boolean).join('\n');
  const contextSection = rawInput && rawInput.length < 2000
    ? `\n\nAlert/Context Text Provided:\n"""\n${rawInput}\n"""`
    : '';
  return `You are a seasoned SOC analyst tasked with producing a concise, clear, and actionable triage report for a security alert. Use the IOCs and alert context below to complete each section of the report.${contextSection}

Pre-extracted IOCs (use these to populate Section 6):
${iocSection}`;
}

function testBuildTriagePrompt() {
  const out = buildTriagePrompt({ iocs: [{ category: 'ip', value: '1.2.3.4' }], rawInput: '' });
  assert.ok(/SOC analyst/.test(out), 'persona present');
  assert.ok(/1\.2\.3\.4/.test(out), 'ioc embedded');
  assert.ok(/virustotal\.com/.test(out), 'vt link present');

  const withContext = buildTriagePrompt({ iocs: [], rawInput: 'alert body here' });
  assert.ok(/alert body here/.test(withContext), 'context included under 2000 chars');

  const longCtx = buildTriagePrompt({ iocs: [], rawInput: 'x'.repeat(2500) });
  assert.ok(!/x{2500}/.test(longCtx), 'long context dropped');

  const unknownCat = buildTriagePrompt({ iocs: [{ category: 'weird', value: 'thing' }], rawInput: '' });
  assert.ok(/thing/.test(unknownCat), 'unknown category bucketed as hostname');
  console.log('  [PASS] Triage prompt builder');
}
testBuildTriagePrompt();
```

- [ ] **Step 2: Run tests**

Run: `node tests/verify_features.js`
Expected: PASS, `Failed: 0`.

- [ ] **Step 3: Refactor popup.js**

Replace the body of `askClaude()` (popup.js:871–974) to delegate to a new method. The new `askClaude()` becomes:

```js
  askClaude() {
    const iocs = this.lastIOCs;
    if (!iocs || iocs.length === 0) {
      this.showNotification('No IOCs to analyze — run analysis first', 'error');
      return;
    }
    const prompt = this.buildTriagePrompt({ iocs, rawInput: this.lastIOCInput || '' });
    navigator.clipboard.writeText(prompt).then(() => {
      chrome.tabs.create({ url: 'https://claude.ai/new' });
      this.showNotification('Prompt copied — paste it into Claude to begin analysis', 'success');
    }).catch(() => {
      this.showNotification('Could not copy prompt to clipboard', 'error');
    });
  }

  buildTriagePrompt({ iocs, rawInput }) {
    // Body lifted verbatim from the test-file copy above.
    const grouped = { ip: [], domain: [], url: [], hostname: [], hash: [], email: [], cve: [], mitre: [], crypto: [], mac: [] };
    for (const ioc of (iocs || [])) {
      const key = ioc.category in grouped ? ioc.category : 'hostname';
      grouped[key].push(ioc.value);
    }
    const buildIocTable = (label, values, linkFn) => {
      if (!values.length) return '';
      const rows = values.map(v => `| \`${v}\` | ${linkFn(v)} |`).join('\n');
      return `**${label}**\n| Indicator | Links |\n|-----------|-------|\n${rows}\n`;
    };
    const vtIp   = v => `[VirusTotal](https://www.virustotal.com/gui/ip-address/${encodeURIComponent(v)}) · [AbuseIPDB](https://www.abuseipdb.com/check/${encodeURIComponent(v)})`;
    const vtDom  = v => `[VirusTotal](https://www.virustotal.com/gui/domain/${encodeURIComponent(v)})`;
    const vtUrl  = v => `[VirusTotal](https://www.virustotal.com/gui/url/${btoa(v)})`;
    const vtHash = v => `[VirusTotal](https://www.virustotal.com/gui/file/${v})`;
    const noLinks = () => '—';
    const iocSection = [
      buildIocTable('IP Addresses', grouped.ip, vtIp),
      buildIocTable('Domains', grouped.domain, vtDom),
      buildIocTable('URLs', grouped.url, vtUrl),
      buildIocTable('Hostnames', grouped.hostname, noLinks),
      buildIocTable('File Hashes', grouped.hash, vtHash),
      buildIocTable('Email Addresses', grouped.email, noLinks),
      buildIocTable('CVEs', grouped.cve, v => `[NVD](https://nvd.nist.gov/vuln/detail/${v})`),
      buildIocTable('MITRE Techniques', grouped.mitre, v => `[ATT&CK](https://attack.mitre.org/techniques/${v.replace('.', '/')})`),
      buildIocTable('Crypto Addresses', grouped.crypto, noLinks),
      buildIocTable('MAC Addresses', grouped.mac, noLinks),
    ].filter(Boolean).join('\n');
    const contextSection = rawInput && rawInput.length < 2000
      ? `\n\nAlert/Context Text Provided:\n"""\n${rawInput}\n"""`
      : '';
    return `You are a seasoned SOC analyst tasked with producing a concise, clear, and actionable triage report for a security alert. Use the IOCs and alert context below to complete each section of the report.${contextSection}

Pre-extracted IOCs (use these to populate Section 6):
${iocSection}`;
  }
```

- [ ] **Step 4: Re-run tests**

Run: `node tests/verify_features.js`
Expected: `Failed: 0`.

- [ ] **Step 5: Commit**

```bash
git add popup.js tests/verify_features.js
git commit -m "refactor(ask-ai): extract triage prompt builder

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 3: SSE stream parser

**Files:**
- Modify: `background.js` (add `parseSSEStream` helper near the top, after `fetchWithBackoff`)
- Test: `tests/verify_features.js`

**Interfaces:**
- Produces: `parseSSEStream(reader, onEvent)` — async function. `reader` is a `ReadableStreamDefaultReader` (from `response.body.getReader()`). `onEvent(payload)` is called with the parsed JSON object of each `data:` line. Lines starting with `data: [DONE]` end the stream. Returns when the reader is done.

- [ ] **Step 1: Write the failing test**

The test synthesizes a reader from an in-memory string. Append:

```js
console.log('\n--- SSE Parser Tests ---');

async function parseSSEStream(reader, onEvent) {
  const decoder = new TextDecoder();
  let buffer = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buffer.indexOf('\n\n')) !== -1) {
      const chunk = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
      for (const line of chunk.split('\n')) {
        if (!line.startsWith('data:')) continue;
        const payload = line.slice(5).trim();
        if (payload === '[DONE]') return;
        if (!payload) continue;
        let obj;
        try { obj = JSON.parse(payload); } catch { continue; }
        onEvent(obj);
      }
    }
  }
}

function makeReader(chunks) {
  let i = 0;
  return {
    async read() {
      if (i >= chunks.length) return { done: true, value: undefined };
      const enc = new TextEncoder();
      return { done: false, value: enc.encode(chunks[i++]) };
    }
  };
}

async function testParseSSEStream() {
  const events = [];
  await parseSSEStream(makeReader([
    'event: delta\ndata: {"a":1}\n\ndata: {"a":2}\n\n',
    'data: [DONE]\n\n',
  ]), (o) => events.push(o));
  assert.deepStrictEqual(events, [{ a: 1 }, { a: 2 }], 'two events then done');

  const partial = [];
  await parseSSEStream(makeReader([
    'data: {"x":',
    '1}\n\ndata: {"x":2}\n\n',
  ]), (o) => partial.push(o));
  assert.deepStrictEqual(partial, [{ x: 1 }, { x: 2 }], 'split-chunk reassembly');

  const badJson = [];
  await parseSSEStream(makeReader(['data: notjson\n\ndata: {"y":3}\n\n']), (o) => badJson.push(o));
  assert.deepStrictEqual(badJson, [{ y: 3 }], 'bad json skipped');
  console.log('  [PASS] SSE stream parser');
}
await testParseSSEStream();
```

If `tests/verify_features.js` is not already an async-capable top level, wrap the new call: `(async () => { await testParseSSEStream(); /* then existing summary */ })();`. Simpler: append a `.then()` after. Check the file's tail — if it ends with a synchronous summary, move the summary into `testParseSSEStream().then(() => { /* summary */ })`. Verify by running.

- [ ] **Step 2: Run tests**

Run: `node tests/verify_features.js`
Expected: PASS, `Failed: 0`.

- [ ] **Step 3: Add parser to background.js**

Place after the `fetchWithBackoff` definition (search `async function fetchWithBackoff`):

```js
async function parseSSEStream(reader, onEvent) {
  const decoder = new TextDecoder();
  let buffer = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buffer.indexOf('\n\n')) !== -1) {
      const chunk = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
      for (const line of chunk.split('\n')) {
        if (!line.startsWith('data:')) continue;
        const payload = line.slice(5).trim();
        if (payload === '[DONE]') return;
        if (!payload) continue;
        let obj;
        try { obj = JSON.parse(payload); } catch { continue; }
        onEvent(obj);
      }
    }
  }
}
```

- [ ] **Step 4: Re-run tests**

Run: `node tests/verify_features.js`
Expected: `Failed: 0`.

- [ ] **Step 5: Commit**

```bash
git add background.js tests/verify_features.js
git commit -m "feat(ask-ai): SSE stream parser

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 4: Background Ask AI streaming handler

**Files:**
- Modify: `background.js` (add the port listener at the bottom, near other top-level listeners)

**Interfaces:**
- Consumes: `parseSSEStream` (Task 3), `chrome.storage.local.get(['askAiConfig'])`.
- Produces: a `chrome.runtime.onConnect` listener for ports named `ask-ai`. Message in: `{ type: 'start', iocs, rawInput }` or `{ type: 'abort' }` or `{ type: 'test' }`. Messages out (posted on the port): `{type:'token', text}`, `{type:'done'}`, `{type:'error', message}`, `{type:'test-result', ok, message}`.

The triage prompt is constructed **inside the worker** from `iocs` + `rawInput` rather than shipped from the popup, so the worker is the single source of truth and the popup can't leak DOM state. Mirror the `buildTriagePrompt` logic (Task 2) into `background.js` as a standalone function (DRY across runtimes: popup and SW can't share modules without a refactor that is out of scope; duplication is the YAGNI-correct choice until the refactor lands).

- [ ] **Step 1: Add the prompt builder + provider adapters to background.js**

Near the top of `background.js`, after `parseSSEStream`:

```js
function buildTriagePrompt(iocs, rawInput) {
  const grouped = { ip: [], domain: [], url: [], hostname: [], hash: [], email: [], cve: [], mitre: [], crypto: [], mac: [] };
  for (const ioc of (iocs || [])) {
    const key = ioc.category in grouped ? ioc.category : 'hostname';
    grouped[key].push(ioc.value);
  }
  const buildIocTable = (label, values, linkFn) => {
    if (!values.length) return '';
    const rows = values.map(v => `| \`${v}\` | ${linkFn(v)} |`).join('\n');
    return `**${label}**\n| Indicator | Links |\n|-----------|-------|\n${rows}\n`;
  };
  const vtIp   = v => `[VirusTotal](https://www.virustotal.com/gui/ip-address/${encodeURIComponent(v)}) · [AbuseIPDB](https://www.abuseipdb.com/check/${encodeURIComponent(v)})`;
  const vtDom  = v => `[VirusTotal](https://www.virustotal.com/gui/domain/${encodeURIComponent(v)})`;
  const vtUrl  = v => `[VirusTotal](https://www.virustotal.com/gui/url/${btoa(v)})`;
  const vtHash = v => `[VirusTotal](https://www.virustotal.com/gui/file/${v})`;
  const noLinks = () => '—';
  const iocSection = [
    buildIocTable('IP Addresses', grouped.ip, vtIp),
    buildIocTable('Domains', grouped.domain, vtDom),
    buildIocTable('URLs', grouped.url, vtUrl),
    buildIocTable('Hostnames', grouped.hostname, noLinks),
    buildIocTable('File Hashes', grouped.hash, vtHash),
    buildIocTable('Email Addresses', grouped.email, noLinks),
    buildIocTable('CVEs', grouped.cve, v => `[NVD](https://nvd.nist.gov/vuln/detail/${v})`),
    buildIocTable('MITRE Techniques', grouped.mitre, v => `[ATT&CK](https://attack.mitre.org/techniques/${v.replace('.', '/')})`),
    buildIocTable('Crypto Addresses', grouped.crypto, noLinks),
    buildIocTable('MAC Addresses', grouped.mac, noLinks),
  ].filter(Boolean).join('\n');
  const contextSection = rawInput && rawInput.length < 2000
    ? `\n\nAlert/Context Text Provided:\n"""\n${rawInput}\n"""`
    : '';
  return `You are a seasoned SOC analyst tasked with producing a concise, clear, and actionable triage report for a security alert. Use the IOCs and alert context below to complete each section of the report.${contextSection}

Pre-extracted IOCs (use these to populate Section 6):
${iocSection}`;
}

const DEFAULT_ASKAI_SYSTEM = 'You are a senior SOC analyst. Produce a clear, actionable markdown triage report from the indicators and context provided.';

function buildAskAiRequest(cfg, prompt) {
  const system = (cfg.systemPrompt && cfg.systemPrompt.trim()) || DEFAULT_ASKAI_SYSTEM;
  if (cfg.provider === 'anthropic') {
    const b = cfg.anthropic;
    const base = (b.baseUrl || 'https://api.anthropic.com').replace(/\/+$/, '');
    return {
      url: `${base}/v1/messages`,
      init: {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': b.apiKey,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: b.model,
          max_tokens: 4096,
          stream: true,
          system,
          messages: [{ role: 'user', content: prompt }]
        })
      },
      adapter: 'anthropic'
    };
  }
  // openai-compatible
  const b = cfg.openai;
  const base = (b.baseUrl || 'https://api.openai.com/v1').replace(/\/+$/, '');
  return {
    url: `${base}/chat/completions`,
    init: {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'Authorization': `Bearer ${b.apiKey}`
      },
      body: JSON.stringify({
        model: b.model,
        stream: true,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: prompt }
        ]
      })
    },
    adapter: 'openai'
  };
}

function tokenFromEvent(adapter, evt) {
  if (adapter === 'anthropic') {
    if (evt && evt.type === 'content_block_delta' && evt.delta && typeof evt.delta.text === 'string') {
      return evt.delta.text;
    }
    return null;
  }
  // openai
  if (evt && evt.choices && evt.choices[0] && evt.choices[0].delta && typeof evt.choices[0].delta.content === 'string') {
    return evt.choices[0].delta.content;
  }
  return null;
}
```

- [ ] **Step 2: Add the port listener at the bottom of background.js**

```js
// --- Ask AI streaming port ---
chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== 'ask-ai') return;
  let controller = null;

  port.onMessage.addListener(async (msg) => {
    if (msg.type === 'abort') {
      if (controller) { try { controller.abort(); } catch {} }
      return;
    }

    const stored = await new Promise((r) => chrome.storage.local.get(['askAiConfig'], r));
    const cfg = stored.askAiConfig;

    // Validate (mirror of popup.validateAskAiConfig — SW cannot call popup methods)
    const v = (function validate(cfg) {
      if (!cfg || typeof cfg !== 'object') return 'Ask AI not configured';
      if (cfg.provider !== 'anthropic' && cfg.provider !== 'openai') return 'Invalid provider';
      const block = cfg[cfg.provider];
      if (!block) return 'Missing provider block';
      if (!(block.apiKey || '').trim()) return 'API key required';
      if (!(block.model || '').trim()) return 'Model required';
      return null;
    })(cfg);
    if (v) { port.postMessage({ type: 'error', message: v }); return; }

    // Test mode: trivial one-shot, no streaming, no prompt
    if (msg.type === 'test') {
      try {
        const req = buildAskAiRequest(cfg, 'Reply with the single word OK.');
        controller = new AbortController();
        const resp = await fetch(req.url, { ...req.init, signal: controller.signal });
        if (!resp.ok) {
          const text = await resp.text().catch(() => '');
          port.postMessage({ type: 'test-result', ok: false, message: `HTTP ${resp.status}` });
          return;
        }
        port.postMessage({ type: 'test-result', ok: true, message: 'OK' });
      } catch (err) {
        port.postMessage({ type: 'test-result', ok: false, message: err.message || 'Network error' });
      }
      return;
    }

    // Start streaming
    if (msg.type === 'start') {
      try {
        const prompt = buildTriagePrompt(msg.iocs || [], msg.rawInput || '');
        const req = buildAskAiRequest(cfg, prompt);
        controller = new AbortController();
        const resp = await fetch(req.url, { ...req.init, signal: controller.signal });
        if (!resp.ok || !resp.body) {
          const text = await resp.text().catch(() => '');
          port.postMessage({ type: 'error', message: `Provider returned HTTP ${resp.status}` });
          return;
        }
        const reader = resp.body.getReader();
        await parseSSEStream(reader, (evt) => {
          const t = tokenFromEvent(req.adapter, evt);
          if (t) port.postMessage({ type: 'token', text: t });
        });
        port.postMessage({ type: 'done' });
      } catch (err) {
        if (err && err.name === 'AbortError') {
          port.postMessage({ type: 'done' });
        } else {
          port.postMessage({ type: 'error', message: (err && err.message) || 'Stream failed' });
        }
      } finally {
        controller = null;
      }
    }
  });

  port.onDisconnect.addListener(() => {
    if (controller) { try { controller.abort(); } catch {} }
  });
});
```

- [ ] **Step 3: Manual smoke (no automated test for the port handler — SW-only)**

Reload the unpacked extension in `chrome://extensions`. Open the extension's service-worker devtools (click "Inspect views: service worker"). In the SW console, run:

```js
const p = chrome.runtime.connect({ name: 'ask-ai' });
p.onMessage.addListener((m) => console.log('SW→', m));
p.postMessage({ type: 'start', iocs: [{ category: 'ip', value: '8.8.8.8' }], rawInput: '' });
```

Expected: with no config set, immediately logs `SW→ {type:'error', message:'Ask AI not configured'}`. (Full streaming is verified in Task 5 after the popup wires it up; Task 4 only proves the port routes.)

- [ ] **Step 4: Re-run unit tests**

Run: `node tests/verify_features.js`
Expected: `Failed: 0` (no new tests; ensures no syntax error broke the file — background.js isn't loaded by the node suite, so this is a lint guard via the popup-side tests still passing).

- [ ] **Step 5: Commit**

```bash
git add background.js
git commit -m "feat(ask-ai): background streaming handler (anthropic + openai)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 5: Popup Ask AI panel + port client

**Files:**
- Modify: `popup.html` (rename button, add panel markup)
- Modify: `popup.js` (add `askAi()` method + panel helpers + port client)

**Interfaces:**
- Consumes: `chrome.runtime.connect({name:'ask-ai'})`, `this.buildTriagePrompt` is now in the worker — popup just sends `{type:'start', iocs, rawInput}`.
- Produces: `askAi()` method bound to the new button; panel open/close; live `textContent` rendering.

- [ ] **Step 1: Rename the button in popup.html**

In `popup.html` around line 2042, replace:

```html
<button class="btn btn-small" id="askClaudeBtn" title="Open Claude with a pre-built triage prompt for these IOCs">
  <i class="fa-solid fa-robot"></i> Ask Claude
</button>
```

with:

```html
<button class="btn btn-small" id="askAiBtn" title="Stream an AI triage report for these IOCs">
  <i class="fa-solid fa-wand-magic-sparkles"></i> Ask AI
</button>
```

- [ ] **Step 2: Add the panel markup to popup.html**

Insert immediately before `</body>`:

```html
<div id="askAiPanel" class="ask-ai-panel" hidden>
  <div class="ask-ai-panel-header">
    <div>
      <strong>Ask AI</strong>
      <span id="askAiMeta" class="ask-ai-meta"></span>
    </div>
    <div class="ask-ai-panel-actions">
      <button id="askAiStop" class="btn btn-small" title="Stop streaming">Stop</button>
      <button id="askAiCopy" class="btn btn-small" title="Copy report" disabled>Copy</button>
      <button id="askAiClose" class="btn btn-small" title="Close">✕</button>
    </div>
  </div>
  <pre id="askAiOutput" class="ask-ai-output" aria-live="polite"></pre>
  <div class="ask-ai-panel-footer">AI output may reflect content of analyzed indicators.</div>
</div>
```

- [ ] **Step 3: Add panel CSS to popup.html**

Inside the existing `<style>` block (find a sensible spot — e.g. after the last `.btn` rule):

```css
.ask-ai-panel {
  position: fixed; inset: 0; z-index: 1000;
  background: var(--bg-color, #fff); color: var(--text-color, #111);
  display: flex; flex-direction: column; padding: 12px; box-sizing: border-box;
}
.ask-ai-panel[hidden] { display: none; }
.ask-ai-panel-header {
  display: flex; justify-content: space-between; align-items: center;
  padding-bottom: 8px; border-bottom: 1px solid var(--border-color, #ddd); gap: 8px;
}
.ask-ai-panel-actions { display: flex; gap: 4px; }
.ask-ai-meta { color: var(--text-secondary, #666); font-size: 11px; margin-left: 6px; }
.ask-ai-output {
  flex: 1; overflow: auto; white-space: pre-wrap; word-wrap: break-word;
  font-family: var(--mono-font, ui-monospace, monospace); font-size: 12px;
  margin: 8px 0; padding: 4px;
}
.ask-ai-panel-footer {
  font-size: 11px; color: var(--text-secondary, #666); border-top: 1px solid var(--border-color, #ddd); padding-top: 6px;
}
```

- [ ] **Step 4: Wire the button + panel in popup.js**

Replace the `askClaudeBtn` listener (popup.js around line 339):

```js
el('askClaudeBtn')?.addEventListener('click', () => this.askClaude());
```

with:

```js
el('askAiBtn')?.addEventListener('click', () => this.askAi());
```

Remove or leave the old `askClaude()` method (Task 2 kept it as the clipboard fallback). Remove it to honor the "replace" decision — delete the `askClaude()` method body from popup.js.

Add the new `askAi()` and panel helpers as methods on the same class:

```js
  askAi() {
    const iocs = this.lastIOCs;
    if (!iocs || iocs.length === 0) {
      this.showNotification('No IOCs to analyze — run analysis first', 'error');
      return;
    }
    this.openAskAiPanel(iocs, this.lastIOCInput || '');
  }

  openAskAiPanel(iocs, rawInput) {
    const panel = document.getElementById('askAiPanel');
    const out = document.getElementById('askAiOutput');
    const meta = document.getElementById('askAiMeta');
    const stopBtn = document.getElementById('askAiStop');
    const copyBtn = document.getElementById('askAiCopy');
    if (!panel || !out) return;

    out.textContent = '';
    copyBtn.disabled = true;
    stopBtn.disabled = false;
    panel.hidden = false;

    new Promise((r) => chrome.storage.local.get(['askAiConfig'], r)).then((stored) => {
      const cfg = stored.askAiConfig;
      const active = (cfg && cfg[cfg.provider]) || {};
      meta.textContent = `${cfg ? cfg.provider : 'not configured'} · ${active.model || ''}`;
      if (!cfg || !cfg.provider || !(active.apiKey || '').trim() || !(active.model || '').trim()) {
        out.textContent = 'Ask AI is not configured. Open Settings → Ask AI to add a provider and key.';
        stopBtn.disabled = true;
        return;
      }

      const port = chrome.runtime.connect({ name: 'ask-ai' });
      this._askAiPort = port;
      let aborted = false;

      const cleanup = () => {
        try { port.disconnect(); } catch {}
        this._askAiPort = null;
        stopBtn.disabled = true;
        copyBtn.disabled = false;
      };

      port.onMessage.addListener((m) => {
        if (m.type === 'token') {
          out.textContent += m.text;
          out.scrollTop = out.scrollHeight;
        } else if (m.type === 'done') {
          if (!out.textContent.trim()) out.textContent = '(empty response)';
          cleanup();
        } else if (m.type === 'error') {
          out.textContent += `\n\n[error] ${m.message}`;
          cleanup();
        }
      });

      port.postMessage({ type: 'start', iocs, rawInput });

      stopBtn.onclick = () => {
        if (aborted) return;
        aborted = true;
        try { port.postMessage({ type: 'abort' }); } catch {}
        cleanup();
      };
      copyBtn.onclick = () => {
        const text = out.textContent;
        if (text) this.copyToClipboard(text);
      };
    });
  }

  closeAskAiPanel() {
    const panel = document.getElementById('askAiPanel');
    if (!panel) return;
    if (this._askAiPort) {
      try { this._askAiPort.postMessage({ type: 'abort' }); } catch {}
      try { this._askAiPort.disconnect(); } catch {}
      this._askAiPort = null;
    }
    panel.hidden = true;
  }
```

- [ ] **Step 5: Wire close button in the constructor/init**

In the same init block where the `askAiBtn` listener lives, add:

```js
document.getElementById('askAiClose')?.addEventListener('click', () => this.closeAskAiPanel());
```

- [ ] **Step 6: Manual smoke test**

1. `chrome://extensions` → reload.
2. Open popup, paste or analyze text containing IOCs.
3. Click **Ask AI** without config → panel shows the not-configured message. Close, open Settings (Task 6 will add the fields — for now manually set via DevTools):

```js
chrome.storage.local.set({ askAiConfig: {
  provider: 'openai',
  anthropic: { apiKey: '', model: 'claude-opus-4-8', baseUrl: 'https://api.anthropic.com' },
  openai: { apiKey: 'sk-...', model: 'gpt-4o', baseUrl: 'https://api.openai.com/v1' },
  systemPrompt: ''
}});
```

4. Click **Ask AI** again → tokens stream into the panel, then footer Copy becomes enabled.
5. Click **Stop** mid-stream → panel stops, Copy enabled.
6. Close (✕) → panel hidden, port disconnect aborts.

- [ ] **Step 7: Re-run unit tests**

Run: `node tests/verify_features.js`
Expected: `Failed: 0`.

- [ ] **Step 8: Commit**

```bash
git add popup.html popup.js
git commit -m "feat(ask-ai): popup panel + streaming client

Replaces Ask Claude button and clipboard flow with an in-popup
streaming triage report.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 6: Settings UI for Ask AI

**Files:**
- Modify: `popup.html` (add settings section)
- Modify: `popup.js` (load/save `askAiConfig`, Test button wiring)

**Interfaces:**
- Consumes: `defaultAskAiConfig`, `validateAskAiConfig` (Task 1).
- Produces: settings fields that round-trip `askAiConfig`; Test button posts `{type:'test'}` on an `ask-ai` port and shows ✓/✗.

- [ ] **Step 1: Add the settings section markup**

Find the existing settings container in `popup.html` (search for a section header like `<h3>` within the settings panel; pick the end of the last settings section). Insert a new section:

```html
<div class="settings-section">
  <div class="settings-section-header" data-toggle="askAiSection">
    <i class="fa-solid fa-wand-magic-sparkles"></i> Ask AI
  </div>
  <div class="settings-section-body" id="askAiSection">
    <div class="settings-row-inline">
      <label class="settings-label-block">Provider</label>
      <select id="askAiProvider" class="settings-select">
        <option value="anthropic">Anthropic (Claude)</option>
        <option value="openai">OpenAI-compatible</option>
      </select>
    </div>

    <div class="settings-row-inline">
      <label class="settings-label-block">API key</label>
      <input type="password" id="askAiKey" class="settings-input settings-input-mono" placeholder="sk-..." autocomplete="off">
    </div>

    <div class="settings-row-inline">
      <label class="settings-label-block">Model</label>
      <input type="text" id="askAiModel" class="settings-input settings-input-mono" placeholder="claude-opus-4-8 / gpt-4o">
    </div>

    <div class="settings-row-inline">
      <label class="settings-label-block">Base URL <span class="settings-hint">(advanced)</span></label>
      <input type="text" id="askAiBaseUrl" class="settings-input settings-input-mono" placeholder="https://api.anthropic.com">
    </div>

    <div class="settings-row-inline">
      <label class="settings-label-block">System prompt <span class="settings-hint">(optional)</span></label>
      <textarea id="askAiSystemPrompt" class="settings-input" rows="2" placeholder="Default: senior SOC analyst persona"></textarea>
    </div>

    <div class="settings-row-inline">
      <button id="askAiTestBtn" class="btn btn-small">Test</button>
      <span id="askAiTestResult" class="settings-hint"></span>
    </div>
    <div class="settings-hint">Base URL is fetched verbatim — point only at providers you trust. Keys are stored locally, not synced.</div>
  </div>
</div>
```

- [ ] **Step 2: Add load/save helpers to popup.js**

Near the other settings load/save methods:

```js
  async loadAskAiConfig() {
    const stored = await new Promise((r) => chrome.storage.local.get(['askAiConfig'], r));
    return stored.askAiConfig || this.defaultAskAiConfig();
  }

  async saveAskAiConfig() {
    const provider = document.getElementById('askAiProvider').value;
    const key = document.getElementById('askAiKey').value;
    const model = document.getElementById('askAiModel').value;
    const baseUrl = document.getElementById('askAiBaseUrl').value.trim();
    const systemPrompt = document.getElementById('askAiSystemPrompt').value;

    const base = await this.loadAskAiConfig();
    // Update both blocks so the user can switch providers without re-entering.
    base.provider = provider;
    base[provider].apiKey = key;
    base[provider].model = model;
    if (baseUrl) base[provider].baseUrl = baseUrl;
    base.systemPrompt = systemPrompt;

    const v = this.validateAskAiConfig(base);
    if (!v.ok) {
      this.showNotification(`Ask AI: ${v.error}`, 'error');
      return false;
    }
    await new Promise((r) => chrome.storage.local.set({ askAiConfig: base }, r));
    this.showNotification('Ask AI settings saved', 'success');
    return true;
  }

  async populateAskAiFields() {
    const cfg = await this.loadAskAiConfig();
    document.getElementById('askAiProvider').value = cfg.provider;
    const active = cfg[cfg.provider] || {};
    document.getElementById('askAiKey').value = active.apiKey || '';
    document.getElementById('askAiModel').value = active.model || '';
    document.getElementById('askAiBaseUrl').value = active.baseUrl || '';
    document.getElementById('askAiSystemPrompt').value = cfg.systemPrompt || '';
    // Reflect the active block when provider changes
    document.getElementById('askAiProvider').onchange = async () => {
      const c = await this.loadAskAiConfig();
      const p = document.getElementById('askAiProvider').value;
      const a = c[p] || {};
      document.getElementById('askAiKey').value = a.apiKey || '';
      document.getElementById('askAiModel').value = a.model || '';
      document.getElementById('askAiBaseUrl').value = a.baseUrl || '';
    };
  }
```

- [ ] **Step 3: Wire save into the existing settings-save flow**

Find where the other settings fields are saved (search `saveSettings` or the Save button handler in popup.js). Add a call to `await this.saveAskAiConfig();` inside it. If the existing save is synchronous and doesn't await, wrap the handler `async`. If there's no central save handler (settings save on change), add explicit listeners in init:

```js
['askAiKey', 'askAiModel', 'askAiBaseUrl', 'askAiSystemPrompt', 'askAiProvider'].forEach((id) => {
  document.getElementById(id)?.addEventListener('change', () => this.saveAskAiConfig());
});
```

Use whichever fits the existing pattern; do not introduce a second save button if one already exists.

- [ ] **Step 4: Wire the Test button**

Add to init:

```js
document.getElementById('askAiTestBtn')?.addEventListener('click', async () => {
  const ok = await this.saveAskAiConfig();
  if (!ok) return;
  const res = document.getElementById('askAiTestResult');
  res.textContent = 'testing…';
  res.style.color = '';
  const port = chrome.runtime.connect({ name: 'ask-ai' });
  port.onMessage.addListener((m) => {
    if (m.type === 'test-result') {
      res.textContent = m.ok ? '✓ OK' : `✗ ${m.message}`;
      res.style.color = m.ok ? 'var(--success-color, green)' : 'var(--danger-color, red)';
      try { port.disconnect(); } catch {}
    }
  });
  port.postMessage({ type: 'test' });
});
```

- [ ] **Step 5: Call `populateAskAiFields()` during init**

Add to the existing settings-initialization path (find where other settings fields are populated on popup load):

```js
this.populateAskAiFields();
```

- [ ] **Step 6: Manual smoke**

1. Reload, open popup → Settings.
2. Pick provider, paste a real key, set model, click **Test** — expect `✓ OK`.
3. Type a wrong key — expect `✗ HTTP 401`.
4. Close popup, reopen — fields persist.

- [ ] **Step 7: Re-run unit tests**

Run: `node tests/verify_features.js`
Expected: `Failed: 0`.

- [ ] **Step 8: Commit**

```bash
git add popup.html popup.js
git commit -m "feat(ask-ai): settings UI with test button

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 7: Security hardening pass

**Files:**
- Verify: `popup.js:1828` (`copyToClipboard`), `content.js:60` (`copyToClipboard`)
- Verify: no `innerHTML` of model/user content in new Ask AI code (Task 5 used `textContent` — confirm)

**No code change expected.** Both clipboard paths already use `navigator.clipboard.writeText` first with `document.execCommand('copy')` as a fallback for non-secure contexts. That fallback is the correct defensive pattern, not a bug. Spec §2.1 is satisfied.

- [ ] **Step 1: Audit clipboard paths**

Run:
```bash
cd "/Volumes/M.2 2TB/code/analyst-toolkit-main"
grep -n "execCommand" popup.js content.js background.js
```
Expected: only the two fallback sites (popup.js copyToClipboard, content.js copyToClipboard). Confirm each is gated behind `if (navigator.clipboard && navigator.clipboard.writeText)`. If any new site has crept in, migrate it to the same `navigator.clipboard`-first pattern.

- [ ] **Step 2: Audit Ask AI output rendering**

```bash
grep -nE "askAiOutput|innerHTML" popup.js | head -20
```
Confirm the Ask AI panel uses `out.textContent +=` only — no `innerHTML` of streamed content.

- [ ] **Step 3: Audit key handling**

```bash
grep -nE "x-api-key|Authorization.*Bearer|apiKey" background.js | head -20
```
Confirm `x-api-key` / `Authorization` headers are never included in `port.postMessage` payloads or `console.log` calls. The `buildAskAiRequest` in Task 4 puts them only on the `fetch` `init.headers`, which is correct.

- [ ] **Step 4: No-commit unless a defect is found**

If all three audits pass, this task makes no commit. If a defect is found, fix it inline with a `fix(security):` commit describing the specific issue.

---

### Task 8: QA sweep — `chrome.runtime.lastError` guards

**Files:**
- Modify: `popup.js` (callback sites that ignore `lastError`)

The grep in design found ~12 `chrome.runtime.sendMessage` callback sites in popup.js. Several don't check `chrome.runtime.lastError`, so a disconnected worker or a thrown handler silently drops. Add a tiny guard helper and route callbacks through it.

- [ ] **Step 1: Add the guard helper**

Near the top of the popup class (after the `el()` helper or equivalent):

```js
function safeResponse(cb) {
  return (res) => {
    if (chrome.runtime.lastError) {
      // Worker unavailable or message dropped; surface to user.
      this.showNotification(chrome.runtime.lastError.message || 'Background worker unavailable', 'error');
      return;
    }
    cb(res);
  };
}
```

If the popup's `el()`/helpers are not class methods (free functions at top of file), drop the `this.` and have the helper take a notification fn, or call a module-level notifier. Match the file's existing style.

- [ ] **Step 2: Wrap the highest-value callbacks**

Wrap the four most consequential callbacks first (these drive visible UI):
- `agentEnrich` at popup.js ~line 183, 537, 3190, 3261, 3275, 3290
- `getRateLimitStatus` at ~line 610
- `passiveDnsEnrich` / `asnEnrich` at ~line 2889, 3006, 3042

Pattern:
```js
chrome.runtime.sendMessage({ action: 'agentEnrich', iocType, ioc: val }, safeResponse((res) => {
  // ... existing handler body unchanged ...
}));
```

Don't blanket-wrap every call — only the ones whose failure leaves the UI in a bad state (loading spinner forever, missing data). Leave fire-and-forget calls alone.

- [ ] **Step 3: Re-run tests + manual smoke**

Run: `node tests/verify_features.js` → `Failed: 0`.
Manual: reload extension, trigger an enrichment on a graph node (right-click → enrich). Confirm the spinner clears on success and a toast shows on failure (simulate failure by reloading the worker mid-request).

- [ ] **Step 4: Commit**

```bash
git add popup.js
git commit -m "fix(qa): guard chrome.runtime lastError on enrichment callbacks

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 9: UX polish pass

**Files:**
- Modify: `popup.js`, `popup.html` as needed

Opportunistic. Each fix is one self-contained diff. Triggers to check (fix only those actually present):
- Ask AI panel: prevent double-click spawning two ports (disable `askAiBtn` while panel open; re-enable on close).
- Ask AI Stop button: disable itself after click (already done in Task 5 — verify).
- Loading states: any async button that doesn't show a spinner — add a minimal `disabled` + text swap.
- Toast for Ask AI unconfigured: currently the panel shows the message; add a toast too for discoverability.

- [ ] **Step 1: Disable Ask AI button while panel open**

In `openAskAiPanel`, at the top:
```js
document.getElementById('askAiBtn').disabled = true;
```
In `closeAskAiPanel`, at the end:
```js
document.getElementById('askAiBtn').disabled = false;
```

- [ ] **Step 2: Add unconfigured toast**

In `openAskAiPanel`, in the not-configured branch, before the `return`:
```js
this.showNotification('Ask AI not configured — open Settings', 'error');
```

- [ ] **Step 3: Audit other async buttons (informational)**

Grep:
```bash
grep -nE "addEventListener\('click'" popup.js | head -40
```
For any async handler lacking a guard against double-click or lacking a loading state, add `el.disabled = true` at entry and `el.disabled = false` in a `finally`. Apply only to handlers that fire external work (enrich, save, export). Skip if the existing pattern already handles it.

- [ ] **Step 4: Manual smoke + tests**

Run: `node tests/verify_features.js` → `Failed: 0`.
Manual: open Ask AI twice fast — confirm only one panel/port. Close — button re-enables.

- [ ] **Step 5: Commit**

```bash
git add popup.js popup.html
git commit -m "fix(ux): Ask AI double-click guard + unconfigured toast

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 10: Documentation + final verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Document Ask AI in README.md**

In the "OSINT Integration" or a new "AI Triage" subsection of `README.md`, add:

```markdown
### AI Triage (Ask AI)

Stream an AI-generated triage report directly in the popup from the IOC list.

- **Providers:** Anthropic (Claude) and any OpenAI-compatible endpoint (OpenAI, OpenRouter, Groq, Ollama, LM Studio, etc.).
- **Configuration:** Settings → Ask AI. Pick provider, paste API key, set model. Optional Base URL for proxies or self-hosted endpoints. Optional system prompt override.
- **Streaming:** the report streams token-by-token into a modal panel. Stop aborts mid-stream; Copy saves the result.
- **Privacy:** keys are stored in `chrome.storage.local` (profile-isolated, not synced, not encrypted at rest). API calls go from the extension's background service worker directly to your configured provider. No telemetry.
- **Prompt-injection note:** analyzed indicator text is sent to the model as part of the prompt. A crafted IOC can steer output. The model has no tool use and no side effects, so the blast radius is limited to a misleading report.

The default Anthropic model is `claude-opus-4-8`; the default OpenAI-compatible model is `gpt-4o`.
```

- [ ] **Step 2: Run the full test suite one last time**

Run: `node tests/verify_features.js`
Expected: all PASS, `Failed: 0`. The summary should now include the Ask AI Config, Triage Prompt Builder, and SSE Parser blocks.

- [ ] **Step 3: Manual end-to-end smoke**

Document in a comment at the top of the plan is unnecessary — execute it:
1. Reload unpacked extension.
2. Settings → Ask AI → provider Anthropic, paste key, model `claude-opus-4-8`, Test → `✓ OK`.
3. Switch to OpenAI-compatible, same drill.
4. Analyze a sample alert text with IOCs. Ask AI → report streams. Stop mid-stream → halts. Copy → clipboard.
5. Close panel → button re-enables, no orphan port.
6. Trigger an OSINT enrichment → success path clean. Reload worker mid-enrichment → error toast, no stuck spinner.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs(ask-ai): document Ask AI feature + security notes

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Self-review notes

- **Spec coverage:** §1.1–1.6 (Ask AI config, transport, worker, panel, settings, manifest) → Tasks 1, 3, 4, 5, 6. §2.1–2.5 (security) → Task 7. §3 (QA sweep) → Task 8 (the highest-value item; further sweep items land opportunistically within earlier tasks as bugs surface). §4 (UX) → Task 9. §5 (order) → task ordering matches. §6 (verification) → every task runs `node tests/verify_features.js`; Task 10 adds end-to-end smoke. §7 (risks) → SW-idle and abort-on-disconnect handled in Task 4.
- **Placeholders:** none. Every code step shows the code.
- **Type/name consistency:** `defaultAskAiConfig`, `validateAskAiConfig`, `buildTriagePrompt`, `parseSSEStream`, `tokenFromEvent`, `buildAskAiRequest`, `openAskAiPanel`, `closeAskAiPanel`, `_askAiPort` — used consistently across tasks. Port name `'ask-ai'` and message types `'start' | 'abort' | 'test' | 'token' | 'done' | 'error' | 'test-result'` are consistent between Task 4 (worker) and Tasks 5/6 (popup).
