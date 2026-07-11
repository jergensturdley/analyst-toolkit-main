// SOC Analyst Toolkit - Popup JavaScript
"use strict";

// Note: HTML escaping is provided by SOCToolkit#escapeHtml (popup.js:2010).
// Call sites in this file use `this.escapeHtml(...)` so the class method is
// resolved; do not introduce a top-level `escapeHtml` that would shadow it.

// Helper function for UTF-8 to Base64 encoding
function utf8ToBase64(text) {
  const utf8Bytes = new TextEncoder().encode(text);
  let binary = '';
  for (let i = 0; i < utf8Bytes.length; i++) {
    binary += String.fromCharCode(utf8Bytes[i]);
  }
  return btoa(binary);
}

// Encode one CSV field. IOC values are attacker-controlled, so this both quotes
// correctly (double embedded quotes, wrap the field) and neutralizes spreadsheet
// formula injection by prefixing a leading =,+,-,@,tab or CR with an apostrophe.
// NOTE: a byte-for-byte copy lives in tests/verify_features.js — keep in sync.
function toCsvCell(value) {
  let v = String(value == null ? '' : value);
  if (/^[=+\-@\t\r]/.test(v)) v = "'" + v;
  return '"' + v.replace(/"/g, '""') + '"';
}

// Lightweight synchronous hash replacement for MD5 (keeps API)
// Not cryptographic — used as a deterministic identifier within the popup.
const MD5 = {
  hash(s) {
    let h = 2166136261 >>> 0;
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
    return ('00000000' + (h >>> 0).toString(16)).slice(-8);
  },
  hashArray(uint8Array) {
    let s = '';
    for (let i = 0; i < uint8Array.length; i++) s += String.fromCharCode(uint8Array[i]);
    return this.hash(s);
  }
};

// ==================== Ask AI: free helpers ====================
// Source of truth: tests/verify_features.js keeps byte-for-byte copies of these
// for plain-Node testing (popup.js is not a module — no build step in scope).
// buildDefaultIocTable + the default-template branch of buildTriagePrompt are
// lifted verbatim from the original askClaude() body (popup.js pre-refactor).

// Builds the IOC section using the same labels/links the original askClaude()
// used. Takes a grouped object { ip: [..], domain: [..], ... } and returns a
// markdown string of sections joined by blank lines.
function buildDefaultIocTable(grouped) {
  const labelMap = {
    ip: 'IP Addresses', domain: 'Domains', url: 'URLs', hostname: 'Hostnames',
    hash: 'File Hashes', email: 'Email Addresses', cve: 'CVEs',
    mitre: 'MITRE Techniques', crypto: 'Crypto Addresses', mac: 'MAC Addresses'
  };
  const vtIp    = v => `[VirusTotal](https://www.virustotal.com/gui/ip-address/${encodeURIComponent(v)}) · [AbuseIPDB](https://www.abuseipdb.com/check/${encodeURIComponent(v)})`;
  const vtDom   = v => `[VirusTotal](https://www.virustotal.com/gui/domain/${encodeURIComponent(v)})`;
  const vtUrl   = v => `[VirusTotal](https://www.virustotal.com/gui/url/${utf8ToBase64(v).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')})`;
  const vtHash  = v => `[VirusTotal](https://www.virustotal.com/gui/file/${v})`;
  const noLinks = () => '—';
  const cveLinks    = v => `[NVD](https://nvd.nist.gov/vuln/detail/${v}) · [MITRE CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=${v})`;
  const mitreLinks  = v => `[ATT&CK](https://attack.mitre.org/techniques/${v.replace('.', '/')})`;
  const linkMap = {
    ip: vtIp, domain: vtDom, url: vtUrl, hostname: noLinks, hash: vtHash,
    email: noLinks, cve: cveLinks, mitre: mitreLinks, crypto: noLinks, mac: noLinks
  };
  const sections = [];
  for (const key of Object.keys(labelMap)) {
    const values = grouped[key] || [];
    if (!values.length) continue;
    const rows = values.map(v => `| \`${v}\` | ${linkMap[key](v)} |`).join('\n');
    sections.push(`**${labelMap[key]}**\n| Indicator | Links |\n|-----------|-------|\n${rows}\n`);
  }
  return sections.join('\n');
}

function buildTriagePrompt(iocs, rawInput, template) {
  const grouped = {};
  for (const i of iocs) {
    const key = i.category in { ip:1, domain:1, url:1, hostname:1, hash:1, email:1, cve:1, mitre:1, crypto:1, mac:1 } ? i.category : 'hostname';
    (grouped[key] = grouped[key] || []).push(i.value);
  }
  const table = buildDefaultIocTable(grouped);
  const fmtIocs = iocs.map(i => `[${i.category}]: ${i.value}`).join('\n');
  const contextSection = rawInput && rawInput.length < 2000
    ? `\n\nAlert/Context Text Provided:\n"""\n${rawInput}\n"""`
    : '';

  if (!template) {
    return `You are a seasoned SOC analyst tasked with producing a concise, clear, and actionable triage report for a security alert. Use the IOCs and alert context below to complete each section of the report.${contextSection}

Pre-extracted IOCs (use these to populate Section 6):
${table}

---

Produce a triage report using **exactly** the following structure and markdown formatting:

# Security Alert Triage Report

## 1. Priority and Severity
State the alert priority (Critical / High / Medium / Low) clearly, with a one-sentence justification.

---

## 2. What Was Observed
- **Alert Source & Name:**
- **Affected Host(s) & IP(s):**
- **Suspicious Activity / Indicators Detected:**
- **Relevant Time Window:**
- **Detection Logic Summary:**

---

## 3. What Is the Risk
- **True Positive or False Positive:**
- **Potential Impact:**
- **Attacker Behaviour Context:**

---

## 4. Threat Context
- **Vulnerability / Malware Details:**
- **Attacker TTPs (with [MITRE ATT&CK](https://attack.mitre.org) links where applicable):**
- **Relevant Threat Intelligence:**

---

## 5. What Is Recommended
- **Immediate Actions:**
- **Longer-Term Remediation:**
- **Monitoring / Hunting Follow-Up:**

---

## 6. Extracted IOCs
Use the pre-extracted IOC tables provided above. Preserve the VirusTotal, AbuseIPDB, NVD, and ATT&CK links. If a section has no indicators, omit it.

---

Formatting rules:
- Use markdown headings and \`---\` horizontal rules between sections.
- Use tables with clickable links for IOC listings.
- Keep language professional, clear, and concise — suitable for both technical teams and management.
- When referencing CVEs, MITRE techniques, or tools, include official links.
- Avoid unexplained technical jargon.`;
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

class SOCToolkit {
  constructor() {
    this.currentTab = 'ioc';
    this.snippets = [];
    this.autoAnalyze = true;
    // Prefixes are now fixed and not user-editable
    this.snippetPrefixes = ['$', ':'];
    this.floatMode = false;
    this.customOsintSources = [];
    this.enableGraph = true;
    this.iocGraph = null;
    this.currentTheme = 'arc'; // Default theme
    this.tlds = new Set();
    // Cache for debounce timeouts
    this._debounceTimers = {};
    // Cache for OSINT links to avoid regenerating
    this._osintLinksCache = new Map();
    this.init();
  }

  // Utility function for debouncing
  debounce(key, callback, delay) {
    clearTimeout(this._debounceTimers[key]);
    this._debounceTimers[key] = setTimeout(callback, delay);
  }

  async init() {
    this.setupEventListeners();
    this.setupSystemThemeListener(); // Listen for system theme changes
    
    // Initialize patterns
    this.patterns = {
      url: /\bhttps?:\/\/[\w.-]+(?::\d+)?(?:\/[\w\-._~:/?#[\]@!$&'()*+,;=%]*)?/gi,
      ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
      // IPv6 pattern - handles full, compressed, and mixed formats. 
      // Removed leading \b to better handle addresses following colons or brackets.
      ipv6: /(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9]))\b/gi,
      cve: /\bCVE-\d{4}-\d{4,}\b/gi,
      mitre: /\bT\d{4}(?:\.\d{3})?\b/gi,
      btc: /\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b/g,
      eth: /\b0x[a-fA-F0-9]{40}\b/g,
      mac: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,
      email: /\b[\w.+-]+@([\w-]+\.)+[\w-]{2,}\b/gi,
      domain: /\b(?!https?:\/\/)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi,
      md5: /\b[a-f0-9]{32}\b/gi,
      sha1: /\b[a-f0-9]{40}\b/gi,
      sha256: /\b[a-f0-9]{64}\b/gi,
      sha512: /\b[a-f0-9]{128}\b/gi
    };

    // Load critical settings first, TLDs lazily
    await Promise.all([
      this.loadSettings(),
      this.loadSnippets(),
      this.loadCustomOsintSources(),
      this.loadAskAiConfig().then(cfg => this.applyAskAiConfigToUI(cfg))
    ]);

    this.displaySnippets();
    this.displayCustomOsintSources();

    // Check for pending actions from context menu or background
    await this.checkPendingAnalysis();

    // Handle any legacy pending actions
    chrome.storage.local.get(['pendingAction', 'pendingText'], (result) => {
      if (result.pendingAction && result.pendingText) {
        this.handlePendingAction(result.pendingAction, result.pendingText);
        chrome.storage.local.remove(['pendingAction', 'pendingText']);
      }
    });

    // Load TLDs lazily in the background
    this.loadTlds();
  }

  async loadTlds() {
    // Return immediately if already loaded
    if (this.tlds && this.tlds.size > 100) return;

    try {
      const { validTlds } = await import('./tlds.js');
      this.tlds = validTlds;
    } catch (error) {
      console.error('Failed to load TLDs:', error);
      // Fallback to a small, common set if loading fails
      this.tlds = new Set(['com', 'net', 'org', 'edu', 'gov', 'mil', 'io', 'co', 'uk', 'de', 'jp', 'fr', 'au', 'ru', 'ch', 'it', 'nl', 'ca', 'cn', 'br', 'us', 'info', 'biz']);
    }
  }

  async checkPendingAnalysis() {
    try {
      const response = await chrome.runtime.sendMessage({ action: 'getPendingAnalysis' });
      if (response && response.text) {
        document.getElementById('iocInput').value = response.text;
        this.switchTab('ioc');
        if (this.autoAnalyze) {
          this.analyzeIOCs();
        }
      }
    } catch (err) {
      console.log('No pending analysis or error:', err);
    }
  }

  handlePendingAction(action, text) {
    switch (action) {
      case 'extract-iocs':
        this.extractIOCsFromText(text);
        break;
      default:
        console.log('Unknown pending action:', action);
    }
  }

  extractIOCsFromText(text) {
    const iocs = this.extractIOCs(text);
    const iocText = iocs.map(ioc => ioc.value).join('\n');

    // Just display the IOCs, no automatic copy
    document.getElementById('iocInput').value = iocText;
    this.switchTab('ioc');
    this.analyzeIOCs();
    this.showStatus('IOCs extracted and displayed', 'success');
  }

  // Helper for batch enrichment with a single tracking notification
  async _batchEnrich(type, values) {
    if (!values.length) return;
    const ok = await this._ensureConsent('enrichment'); if (!ok) return;
    
    const total = values.length;
    let completed = 0;
    let failed = 0;
    
    // Create a persistent progress notification
    const note = document.createElement('div');
    note.className = 'notification info persistent';
    document.body.appendChild(note);
    
    const updateProgress = () => {
      note.textContent = `Enriching ${type}s: ${completed}/${total}...`;
    };
    
    updateProgress();

    // Use a delay between requests to respect rate limits
    const delay = type === 'url' ? 800 : 600;

    for (let i = 0; i < values.length; i++) {
      const val = values[i];
      await new Promise(resolve => setTimeout(resolve, i === 0 ? 0 : delay));
      
      chrome.runtime.sendMessage({ action: 'agentEnrich', iocType: type, ioc: val }, (res) => {
        void chrome.runtime.lastError;
        completed++;
        if (!res || res.status === 'error') {
          failed++;
        } else if (res.nodes || res.edges) {
          let nodeId = null;
          if (this.graphNodes) {
            this.graphNodes.forEach((n) => { if (this.getNodeValue(n) === val) nodeId = n.id; });
          }
          if (nodeId) this.applyAgentResultToGraph(res, nodeId, val);
        }
        
        if (completed === total) {
          note.remove();
          this.showNotification(`Enriched ${total - failed}/${total} ${type}s`, failed > 0 ? 'info' : 'success');
        } else {
          updateProgress();
        }


      });
    }
  }

  // === First-use consent gates (privacy disclosure, store-readiness item 7) ===
  // Both "enrichment" (provider API calls) and "askAi" (clipboard -> third-party
  // LLM) send user data off-device. We prompt the first time and persist consent
  // in chrome.storage.local under `socConsent`. Users can revoke from Settings.

  _readConsent() {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.get(['socConsent'], (res) => {
          const c = res && res.socConsent;
          if (!c || typeof c !== 'object') return resolve({ enrichment: false, askAi: false });
          resolve({
            enrichment: c.enrichment === true,
            askAi: c.askAi === true
          });
        });
      } catch (e) {
        resolve({ enrichment: false, askAi: false });
      }
    });
  }

  _writeConsent(partial) {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.get(['socConsent'], (res) => {
          const cur = (res && typeof res.socConsent === 'object' && res.socConsent) || {};
          const next = Object.assign({}, cur, partial || {});
          chrome.storage.local.set({ socConsent: next }, () => resolve(true));
        });
      } catch (e) {
        resolve(false);
      }
    });
  }

  async _ensureConsent(kind) {
    if (kind !== 'enrichment' && kind !== 'askAi') return true;
    const cur = await this._readConsent();
    if (cur[kind]) return true;
    const ok = await this._showConsentModal(kind);
    if (ok) await this._writeConsent({ [kind]: true });
    return ok;
  }

  _showConsentModal(kind) {
    return new Promise((resolve) => {
      const modal = document.getElementById('consentModal');
      const title = document.getElementById('consentModalTitle');
      const body = document.getElementById('consentModalBody');
      const allow = document.getElementById('consentAllowBtn');
      const deny = document.getElementById('consentDenyBtn');
      const close = document.getElementById('consentCloseBtn');
      if (!modal || !title || !body || !allow || !deny) { resolve(false); return; }
      if (kind === 'askAi') {
        title.textContent = 'Send IOC triage prompt to a third-party AI chat?';
        body.innerHTML = [
          '<p>Ask AI will:</p>',
          '<ol>',
          '<li>Generate a markdown prompt containing every IOC currently shown (IPs, domains, URLs, hashes, CVEs, MITRE techniques, emails, etc.) plus any alert text you pasted.</li>',
          '<li>Copy that prompt to your clipboard.</li>',
          '<li>Open the AI chat target you configured in Settings (Claude, ChatGPT, Gemini, Copilot, Perplexity, Mistral, or any custom HTTPS URL).</li>',
          '</ol>',
          '<p>Nothing is sent by the extension itself &mdash; you paste the prompt yourself &mdash; but the IOC content will be visible to the third-party service you have chosen.</p>'
        ].join('');
      } else {
        title.textContent = 'Enrich IOCs using third-party services?';
        body.innerHTML = [
          '<p>Enrichment will send the selected IOC to the third-party providers enabled in Settings (e.g. VirusTotal, AbuseIPDB, ipinfo, GreyNoise, urlscan, MalwareBazaar). Each enabled provider returns data that the extension renders into the popup graph.</p>',
          '<p>No API keys are uploaded &mdash; they are configured locally and used only in your browser to call those services.</p>',
          '<p>You can disable specific providers in Settings &gt; Enrichment Providers.</p>'
        ].join('');
      }
      const cleanup = (decision) => {
        try { modal.style.display = 'none'; } catch (e) {}
        try { allow.removeEventListener('click', allowHandler); } catch (e) {}
        try { deny.removeEventListener('click', denyHandler); } catch (e) {}
        try { close && close.removeEventListener('click', denyHandler); } catch (e) {}
        document.removeEventListener('keydown', keyHandler, true);
        resolve(decision);
      };
      const allowHandler = () => cleanup(true);
      const denyHandler = () => cleanup(false);
      const keyHandler = (ev) => {
        // stopPropagation so the global Escape handler (which clears IOC input)
        // does not also fire when the user dismisses this modal with Escape.
        if (ev.key === 'Escape') { ev.preventDefault(); ev.stopPropagation(); cleanup(false); }
        else if (ev.key === 'Enter') { ev.preventDefault(); ev.stopPropagation(); cleanup(true); }
      };
      allow.addEventListener('click', allowHandler);
      deny.addEventListener('click', denyHandler);
      if (close) close.addEventListener('click', denyHandler);
      document.addEventListener('keydown', keyHandler, true);
      modal.style.display = 'flex';
      try { allow.focus(); } catch (e) {}
    });
  }

  resetConsent() {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.remove(['socConsent'], () => {
          if (typeof this._refreshConsentStatus === 'function') this._refreshConsentStatus();
          this.showNotification('Consent prompts reset', 'success');
          resolve(true);
        });
      } catch (e) {
        resolve(false);
      }
    });
  }

  _refreshConsentStatus() {
    return this._readConsent().then((c) => {
      const enrichEl = document.getElementById('consentStatusEnrichment');
      const aiEl = document.getElementById('consentStatusAskAi');
      const fmt = (granted) => granted ? 'granted' : 'not yet granted (will be requested on first use)';
      if (enrichEl) enrichEl.textContent = fmt(c.enrichment);
      if (aiEl) aiEl.textContent = fmt(c.askAi);
    });
  }

  setupEventListeners() {
    // Tab switching

    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        this.switchTab(btn.dataset.tab);
        if (btn.dataset.tab === 'settings') this._refreshConsentStatus();
      });
    });

    // Privacy & Consent — reset prompts
    document.getElementById('resetConsentBtn')?.addEventListener('click', () => this.resetConsent());

    // IOC Analysis buttons
    const el = (id) => document.getElementById(id);
    el('analyzeBtn')?.addEventListener('click', () => this.analyzeIOCs());
    el('clearBtn')?.addEventListener('click', () => this.clearIOCs());
    el('pasteBtn')?.addEventListener('click', () => this.pasteFromClipboard());
    el('defangBtn')?.addEventListener('click', () => this.defangIOCsInInput());
    el('fangBtn')?.addEventListener('click', () => this.fangIOCsInInput());
    el('dedupeBtn')?.addEventListener('click', () => this.deduplicateIOCs());
    el('sortBtn')?.addEventListener('click', () => this.sortIOCs());

    // Auto-analysis on input
    const iocInput = document.getElementById('iocInput');
    const autoAnalyzeToggle = document.getElementById('autoAnalyzeToggle');

    if (autoAnalyzeToggle) {
      autoAnalyzeToggle.checked = this.autoAnalyze;
      autoAnalyzeToggle.addEventListener('change', (e) => {
        this.autoAnalyze = e.target.checked;
        this.saveSettings();
      });
    }

    // Initialize graph toggle
    const enableGraphToggle = document.getElementById('enableGraphToggle');
    if (enableGraphToggle) {
      enableGraphToggle.checked = this.enableGraph;
    }



    // Snippet editor buttons (save/cancel)
    const saveBtn = document.getElementById('snippetSaveBtn');
    const cancelBtn = document.getElementById('snippetCancelBtn');
    if (saveBtn) saveBtn.addEventListener('click', () => this.saveSnippetFromEditor());
    if (cancelBtn) cancelBtn.addEventListener('click', () => this.closeSnippetEditor());

    if (iocInput) {
      iocInput.addEventListener('input', () => {
        // Debounced save to storage
        this.debounce('saveIOCInput', () => {
          chrome.storage.local.set({ savedIOCInput: iocInput.value });
        }, 1000);

        // Auto-analysis (debounced)
        if (this.autoAnalyze) {
          this.debounce('autoAnalyze', () => {
            if (iocInput.value.trim()) {
              this.analyzeIOCs();
            } else {
              this.clearIOCs();
            }
          }, 500);
        }
      });
    }

    // Snippet functionality
    el('snippetSearch')?.addEventListener('input', (e) => this.searchSnippets(e.target.value));
    el('addSnippetBtn')?.addEventListener('click', () => this.addSnippet());
    // Note: importBtn/exportBtn are wired by the preset controls in the
    // DOMContentLoaded block (exportSnippetsPreset/importSnippetsPreset), which
    // support format + merge options. Do not add duplicate listeners here or the
    // buttons fire twice (double download / double file picker).

    // Investigation Notes functionality
    el('addNoteBtn')?.addEventListener('click', () => this.showAddNoteModal());
    el('exportNotesBtn')?.addEventListener('click', () => this.exportNotes());
    el('clearNotesBtn')?.addEventListener('click', () => this.clearAllNotes());
    el('saveNoteBtn')?.addEventListener('click', () => this.saveNote());
    el('cancelNoteBtn')?.addEventListener('click', () => this.hideAddNoteModal());

    // File Hash functionality
    el('selectFileBtn')?.addEventListener('click', () => this.selectFile());
    el('hashFileBtn')?.addEventListener('click', () => this.hashSelectedFile());
    el('copyFileHashBtn')?.addEventListener('click', () => this.copyFileHashes());
    el('fileHashInput')?.addEventListener('change', (e) => this.handleFileSelection(e));

    // Header controls
    el('floatBtn')?.addEventListener('click', () => this.toggleFloat());
    el('closeBtn')?.addEventListener('click', () => this.closeWindow());

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      if (e.ctrlKey && e.key === 'Enter') this.analyzeIOCs();
      if (e.key === 'Escape') {
        this.clearIOCs();
        this.hideKeyboardShortcuts();
      }
      // Show keyboard shortcuts with ?
      if (e.key === '?' && !e.target.matches('input, textarea')) {
        e.preventDefault();
        this.showKeyboardShortcuts();
      }
      // Quick navigation with numbers
      if (e.altKey && !e.target.matches('input, textarea')) {
        if (e.key === '1') { e.preventDefault(); this.switchTab('ioc'); }
        if (e.key === '2') { e.preventDefault(); this.switchTab('snippets'); }
        if (e.key === '3') { e.preventDefault(); this.switchTab('notes'); }
        if (e.key === '4') { e.preventDefault(); this.switchTab('settings'); }
      }
    });

    // Quick copy buttons
    el('copyAllIPs')?.addEventListener('click', () => this.copyIOCsByType('ip'));
    el('copyAllDomains')?.addEventListener('click', () => this.copyIOCsByType('domain'));
    el('copyAllHashes')?.addEventListener('click', () => this.copyIOCsByType('hash'));
    el('copyAllURLs')?.addEventListener('click', () => this.copyIOCsByType('url'));
    el('copyAllCVEs')?.addEventListener('click', () => this.copyIOCsByType('cve'));
    el('copyAllMITRE')?.addEventListener('click', () => this.copyIOCsByType('mitre'));
    el('copyAllCrypto')?.addEventListener('click', () => this.copyIOCsByType('crypto'));
    el('copyAllMACs')?.addEventListener('click', () => this.copyIOCsByType('mac'));

    // Keyboard shortcuts modal
    el('showKeyboardShortcuts')?.addEventListener('click', () => this.showKeyboardShortcuts());
    el('closeKeyboardShortcuts')?.addEventListener('click', () => this.hideKeyboardShortcuts());

    // Storage management
    el('clearOldDataBtn')?.addEventListener('click', () => {
      const days = parseInt(document.getElementById('clearOldDataDays')?.value || '30', 10);
      if (confirm(`Clear all data older than ${days} days?`)) {
        this.clearOldData(days);
      }
    });

    // Update storage indicator on settings tab switch
    // Will be called when settings tab opens

    // --- IOC Results Panel controls ---
    el('copyAllBtn')?.addEventListener('click', () => this.copyAllIOCs());
    el('clearGraphBtn')?.addEventListener('click', () => this.clearGraph());
    el('askAiBtn')?.addEventListener('click', () => this.askAi());

    document.querySelectorAll('#exportMenu .dropdown-item').forEach(item => {
      item.addEventListener('click', (e) => {
        const format = e.target.getAttribute('data-export');
        this.exportIOCs(format);
      });
    });

    document.querySelectorAll('#filterMenu .dropdown-item').forEach(item => {
      item.addEventListener('click', (e) => {
        const filter = e.target.getAttribute('data-filter');
        this.filterIOCs(filter);
      });
    });

    el('selectAllIOCs')?.addEventListener('change', (e) => {
      const checked = e.target.checked;
      document.querySelectorAll('.ioc-item input[type="checkbox"]').forEach(cb => {
        cb.checked = checked;
      });
    });

    // Bulk action buttons (footer)
    const copySel = el('copySelectedBtn');
    const exportSel = el('exportSelectedBtn');
    const openVTSel = el('openVTSelectedBtn');
    if (copySel) copySel.addEventListener('click', () => this.handleBulkAction('copy'));
    const copySelMd = el('copySelectedMdBtn');
    if (copySelMd) copySelMd.addEventListener('click', () => this.handleBulkAction('copy-md'));
    if (exportSel) exportSel.addEventListener('click', () => this.handleBulkAction('export'));
    if (openVTSel) openVTSel.addEventListener('click', () => this.handleBulkAction('osint'));

    // Bulk link preference save button
    const saveBulkBtn = el('saveBulkLinkPref');
    if (saveBulkBtn) saveBulkBtn.addEventListener('click', () => {
      const sel = document.getElementById('bulkLinkPreference');
      if (!sel) return;
      const val = sel.value;
      // persist into socSettings
      chrome.storage.local.get(['socSettings'], (res) => {
        const s = res.socSettings || {};
        s.bulkLinkPreference = val;
        chrome.storage.local.set({ socSettings: s }, () => {
          this.showNotification('Bulk link preference saved', 'success');
        });
      });
    });

    // Settings tab functionality
    el('addOsintBtn')?.addEventListener('click', () => this.addCustomOsintSource());
    el('osintSaveBtn')?.addEventListener('click', () => this.saveCustomOsintSource());
    el('osintCancelBtn')?.addEventListener('click', () => this.closeOsintEditor());
    el('enableGraphToggle')?.addEventListener('change', (e) => {
      this.enableGraph = e.target.checked;
      this.saveSettings();
      this.updateGraphVisibility();
    });

    // Theme selector
    el('themeSelect')?.addEventListener('change', (e) => {
      this.currentTheme = e.target.value;
      this.applyTheme(this.currentTheme);
      this.saveSettings();
    });

    // CyberChef URL input
    el('cyberchefUrl')?.addEventListener('change', (e) => {
      const url = e.target.value.trim() || 'https://gchq.github.io/CyberChef';
      chrome.storage.local.set({ cyberchefUrl: url });
      this.showNotification('CyberChef URL saved', 'success');
    });

    // Ask AI settings: preset dropdown, URL, prompt template, reset
    const askAiPreset = el('askAiPreset');
    const askAiTargetUrl = el('askAiTargetUrl');
    const askAiPromptTemplate = el('askAiPromptTemplate');
    const askAiResetBtn = el('askAiResetBtn');
    askAiPreset?.addEventListener('change', async (e) => {
      const v = e.target.value;
      if (v === 'Custom…') {
        if (askAiTargetUrl) askAiTargetUrl.focus();
        return;
      }
      const match = askAiPresets.find(p => p.label === v);
      if (match && askAiTargetUrl) {
        askAiTargetUrl.value = match.url;
        await this.saveAskAiConfig({ targetUrl: match.url, promptTemplate: askAiPromptTemplate ? askAiPromptTemplate.value : '' });
        this.showNotification('Ask AI target saved', 'success');
      }
    });
    askAiTargetUrl?.addEventListener('change', async (e) => {
      const targetUrl = e.target.value.trim();
      const ok = await this.saveAskAiConfig({ targetUrl, promptTemplate: askAiPromptTemplate ? askAiPromptTemplate.value : '' });
      if (!ok) {
        const cfg = await this.loadAskAiConfig();
        e.target.value = cfg.targetUrl; // restore on rejection
      } else {
        this.showNotification('Ask AI target saved', 'success');
        if (askAiPreset) askAiPreset.value = resolveAskAiPreset(targetUrl);
      }
    });
    askAiPromptTemplate?.addEventListener('change', async (e) => {
      const ok = await this.saveAskAiConfig({ targetUrl: askAiTargetUrl ? askAiTargetUrl.value.trim() : '', promptTemplate: e.target.value });
      if (ok) this.showNotification('Ask AI prompt template saved', 'success');
    });
    askAiResetBtn?.addEventListener('click', async () => {
      const ok = await this.saveAskAiConfig({ targetUrl: askAiTargetUrl ? askAiTargetUrl.value.trim() : '', promptTemplate: '' });
      if (ok) {
        if (askAiPromptTemplate) askAiPromptTemplate.value = '';
        this.showNotification('Prompt template reset to default', 'success');
      }
    });

    // VirusTotal API key input
    el('virustotalApiKey')?.addEventListener('change', (e) => {
      const key = e.target.value.trim();
      chrome.storage.local.set({ virustotalApiKey: key });
      this.showNotification('VirusTotal API key saved', 'success');
    });

    // VirusTotal show/hide and clear buttons
    el('vtToggleShow')?.addEventListener('click', (e) => {
      const input = document.getElementById('virustotalApiKey');
      if (!input) return;
      if (input.type === 'password') {
        input.type = 'text';
        e.target.textContent = 'Hide';
      } else {
        input.type = 'password';
        e.target.textContent = 'Show';
      }
    });

    // Auto-save VirusTotal key on input (debounced) and allow manual Save
    el('virustotalApiKey')?.addEventListener('input', (e) => {
      const target = e.target;
      this.debounce('saveVTKey', () => {
        const key = (target && target.value) ? target.value.trim() : '';
        chrome.storage.local.set({ virustotalApiKey: key }, () => {
          try { toolkit.showNotification('VirusTotal API key saved', 'success'); } catch (err) { }
        });
      }, 700);
    });

    el('vtSaveKey')?.addEventListener('click', () => {
      const input = document.getElementById('virustotalApiKey');
      const key = input ? input.value.trim() : '';
      chrome.storage.local.set({ virustotalApiKey: key }, () => {
        try { toolkit.showNotification('VirusTotal API key saved', 'success'); } catch (err) { }
      });
    });

    el('vtClearKey')?.addEventListener('click', (e) => {
      const input = document.getElementById('virustotalApiKey');
      if (input) input.value = '';
      chrome.storage.local.remove(['virustotalApiKey']);
      toolkit.showNotification('VirusTotal API key cleared', 'success');
    });

    const ipEnrichmentApiInputs = [
      { id: 'ipinfoApiKey', storageKey: 'ipinfoApiKey', label: 'ipinfo token' },
      { id: 'abuseipdbApiKey', storageKey: 'abuseipdbApiKey', label: 'AbuseIPDB key' },
      { id: 'greynoiseApiKey', storageKey: 'greynoiseApiKey', label: 'GreyNoise key' },
      { id: 'urlscanApiKey', storageKey: 'urlscanApiKey', label: 'urlscan.io key' }
    ];
    ipEnrichmentApiInputs.forEach((entry) => {
      const input = document.getElementById(entry.id);
      if (input) {
        input.addEventListener('change', (e) => {
          const val = (e.target?.value || '').trim();
          const payload = {};
          payload[entry.storageKey] = val;
          chrome.storage.local.set(payload, () => {
            this.showNotification(`${entry.label} saved`, 'success');
          });
        });
      }
    });

    // Clear PDNS / ASN cache button
    el('clearPdnsAsnCacheBtn')?.addEventListener('click', async () => {
      try {
        const all = await new Promise(resolve => chrome.storage.local.get(null, resolve));
        const keys = Object.keys(all || {});
        const toRemove = keys.filter(k => k.startsWith('pdns_cache_') || k.startsWith('asn_cache_'));
        if (toRemove.length === 0) {
          toolkit.showNotification('Cache Clear', 'No PDNS/ASN cache entries found');
          return;
        }
        await new Promise(resolve => chrome.storage.local.remove(toRemove, resolve));
        toolkit.showNotification('Cache Cleared', `${toRemove.length} PDNS/ASN cache entries removed`);
      } catch (e) {
        console.error('Failed to clear PDNS/ASN cache', e);
        toolkit.showNotification('Cache Clear Error', 'Failed to clear cache');
      }
    });

    // View PDNS / ASN cache button -> opens modal and lists entries
    el('viewPdnsAsnCacheBtn')?.addEventListener('click', async () => {
      await toolkit.loadAndShowPdnsAsnCache();
    });

    // Modal controls
    el('pdnsCacheClose')?.addEventListener('click', () => {
      const m = document.getElementById('pdnsAsnCacheModal'); if (m) m.style.display = 'none';
    });
    el('pdnsCacheRefresh')?.addEventListener('click', async () => { await toolkit.loadAndShowPdnsAsnCache(); });
    el('pdnsCacheDeleteAll')?.addEventListener('click', async () => {
      try {
        const all = await new Promise(resolve => chrome.storage.local.get(null, resolve));
        const keys = Object.keys(all || {});
        const toRemove = keys.filter(k => k.startsWith('pdns_cache_') || k.startsWith('asn_cache_'));
        if (toRemove.length === 0) { toolkit.showNotification('Cache Delete', 'No entries to delete'); return; }
        await new Promise(resolve => chrome.storage.local.remove(toRemove, resolve));
        toolkit.showNotification('Cache Deleted', `${toRemove.length} entries removed`);
        await toolkit.loadAndShowPdnsAsnCache();
      } catch (e) {
        console.error('Failed to delete all cache', e);
        this.showNotification('Cache Delete Error', 'Failed to delete cache');
      }
    });

    // Backdrop click closes modal
    const bd = document.getElementById('pdnsAsnCacheBackdrop');
    if (bd) bd.addEventListener('click', () => { const m = document.getElementById('pdnsAsnCacheModal'); if (m) m.style.display = 'none'; });

    el('enrichmentPanelHeader')?.addEventListener('click', () => {
      const body = document.getElementById('enrichmentPanelBody');
      const chevron = document.getElementById('enrichmentPanelChevron');
      if (body) body.classList.toggle('open');
      if (chevron) chevron.style.transform = body?.classList.contains('open') ? 'rotate(90deg)' : 'rotate(0deg)';
    });

    el('refreshEnrichmentBtn')?.addEventListener('click', (e) => {
      e.stopPropagation();
      const panel = document.getElementById('enrichmentDetailPanel');
      const lastResult = panel?._lastResult;
      if (!lastResult?.ioc || !lastResult?.iocType) return;
      chrome.runtime.sendMessage({ action: 'agentEnrich', iocType: lastResult.iocType, ioc: lastResult.ioc }, (res) => {
        void chrome.runtime.lastError;
        if (!res || res.status === 'error') {
          this.showNotification(this.buildEnrichmentErrorMessage(res), 'error');
          return;
        }
        this.showEnrichmentPanel(res);
        this.showNotification('Enrichment refreshed', 'success');
      });
    });

    el('enrichAllIPsBtn')?.addEventListener('click', () => {
      const ipItems = Array.from(document.querySelectorAll('.ioc-item[data-type="ip"], .ioc-item[data-type="ipv4"], .ioc-item[data-type="ipv6"]'));
      if (!ipItems.length) {
        this.showNotification('No IPs found in results', 'info');
        return;
      }
      const ipValues = [...new Set(ipItems.map(el => el.dataset.value).filter(Boolean))];
      if (!ipValues.length) {
        this.showNotification('No IP values found', 'info');
        return;
      }
      this._batchEnrich('ip', ipValues);
    });

    el('enrichAllHashesBtn')?.addEventListener('click', () => {
      const items = Array.from(document.querySelectorAll(
        '.ioc-item[data-type="hash"], .ioc-item[data-type="md5"], .ioc-item[data-type="sha1"], .ioc-item[data-type="sha256"], .ioc-item[data-type="sha512"]'
      ));
      if (!items.length) {
        this.showNotification('No hashes found in results', 'info');
        return;
      }
      const values = [...new Set(items.map(el => el.dataset.value).filter(Boolean))];
      if (!values.length) {
        this.showNotification('No hash values found', 'info');
        return;
      }
      this._batchEnrich('hash', values);
    });

    el('enrichAllDomainsBtn')?.addEventListener('click', () => {
      const items = Array.from(document.querySelectorAll('.ioc-item[data-type="domain"]'));
      if (!items.length) {
        this.showNotification('No domains found in results', 'info');
        return;
      }
      const values = [...new Set(items.map(el => el.dataset.value).filter(Boolean))];
      if (!values.length) {
        this.showNotification('No domain values found', 'info');
        return;
      }
      this._batchEnrich('domain', values);
    });

    el('enrichAllUrlsBtn')?.addEventListener('click', () => {
      const items = Array.from(document.querySelectorAll('.ioc-item[data-type="url"]'));
      if (!items.length) {
        this.showNotification('No URLs found in results', 'info');
        return;
      }
      const values = [...new Set(items.map(el => el.dataset.value).filter(Boolean))];
      if (!values.length) {
        this.showNotification('No URL values found', 'info');
        return;
      }
      this._batchEnrich('url', values);
    });

    el('rateLimitDetails')?.addEventListener('toggle', (e) => {
      if (!e.target.open) return;
      const container = document.getElementById('rateLimitStatusContainer');
      if (!container) return;
      container.innerHTML = '<div style="color:var(--text-secondary);font-size:11px;">Loading...</div>';
      chrome.runtime.sendMessage({ action: 'getRateLimitStatus' }, (res) => {
        void chrome.runtime.lastError;
        if (!res?.status) {
          container.innerHTML = '<div style="color:var(--danger-color);font-size:11px;">Failed to load rate limit data.</div>';
          return;
        }
        const rows = Object.entries(res.status).map(([provider, info]) => {
          const pct = info.limit > 0 ? Math.round((info.used / info.limit) * 100) : 0;
          const barClass = pct >= 90 ? 'danger' : '';
          const resetStr = info.resetInMs > 0 ? `resets in ${Math.ceil(info.resetInMs / 60000)}m` : 'reset available';
          return `<div class="rate-limit-row">
  <span class="rate-limit-provider">${provider}</span>
  <div class="rate-limit-bar-wrap"><div class="rate-limit-bar-fill ${barClass}" style="width:${pct}%"></div></div>
  <span class="rate-limit-used">${info.used}/${info.limit}</span>
  <span class="rate-limit-reset">${resetStr}</span>
</div>`;
        }).join('');
        container.innerHTML = rows || '<div style="color:var(--text-secondary);font-size:11px;">No data.</div>';
      });
    });

    const providerIds = ['ipinfo', 'abuseipdb', 'greynoise', 'virustotal', 'malwarebazaar', 'crtsh', 'urlscan', 'urlhaus', 'phishtank'];
    chrome.storage.local.get(['enrichmentProviders'], (res) => {
      const saved = res.enrichmentProviders || {};
      providerIds.forEach((pid) => {
        const input = document.getElementById(`providerToggle_${pid}`);
        if (!input) return;
        input.checked = saved[pid] !== false;
        input.addEventListener('change', () => {
          chrome.storage.local.get(['enrichmentProviders'], (r2) => {
            const prefs = r2.enrichmentProviders || {};
            prefs[pid] = input.checked;
            chrome.storage.local.set({ enrichmentProviders: prefs });
          });
        });
      });
    });

    // Floating window button
    el('toggleFloatingBtn')?.addEventListener('click', () => this.toggleFloat());

    // Simple dropdown toggles for Export / Filter headers
    document.querySelectorAll('.dropdown > .btn').forEach(btn => {
      const dd = btn.parentElement;
      const menu = dd.querySelector('.dropdown-menu');
      if (!menu) return;
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        document.querySelectorAll('.dropdown.open').forEach(d => d !== dd && d.classList.remove('open'));
        dd.classList.toggle('open');
      });
    });
    document.addEventListener('click', () => {
      document.querySelectorAll('.dropdown.open').forEach(d => d.classList.remove('open'));
    });
  }

  switchTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.tab === tabName);
    });

    let targetId;
    if (tabName === 'snippets') {
      targetId = 'snippets-tab';
    } else if (tabName === 'notes') {
      targetId = 'notes-tab';
    } else if (tabName === 'settings') {
      targetId = 'settings-tab';
    } else {
      targetId = 'ioc-tab';
    }

    document.querySelectorAll('.tab-content').forEach(content => {
      const isTarget = content.id === targetId;
      content.classList.toggle('active', isTarget);
      content.style.display = isTarget ? 'block' : 'none';
    });

    this.currentTab = tabName;
    if (tabName === 'snippets') {
      // Ensure snippets list is rendered/refreshed when opening the tab
      const snippetsTab = document.getElementById('snippets-tab');
      if (snippetsTab) {
        this.displaySnippets();
      } else {
        console.error('snippets-tab element not found!');
      }
    } else if (tabName === 'notes') {
      this.displayNotes();
    } else if (tabName === 'settings') {
      this.displayCustomOsintSources();
      this.updateStorageIndicator();
    }
  }

  // IOC Analysis Functions
  analyzeIOCs() {
    let input = document.getElementById('iocInput').value.trim();
    if (!input) {
      this.showNotification('Please enter text to analyze', 'error');
      return;
    }
    // Automatically refang defanged IOCs before analysis
    input = this.fangText(input);
    // Clear OSINT links cache when analyzing new IOCs
    this._osintLinksCache.clear();
    const iocs = this.extractIOCs(input);
    this.lastIOCs = iocs;
    this.lastIOCInput = input;
    this.displayIOCResults(iocs);

    // Persist last analysis results
    try {
      chrome.storage.local.set({ 
        lastAnalysisResults: iocs,
        savedIOCInput: input
      });
    } catch (e) {
      console.error('Failed to persist analysis results:', e);
    }
  }

  displayIOCResults(iocs) {
    const resultsContainer = document.getElementById('iocResults');
    const listEl = resultsContainer.querySelector('.ioc-list');
    if (!listEl) return;

    if (iocs.length === 0) {
      listEl.innerHTML = `<div class="ioc-item empty-state"><i class="fa-solid fa-search"></i><div>No IOCs found. Run analysis above.</div></div>`;
      // Update count to 0 and keep header/footer intact
      const countEl = resultsContainer.querySelector('.ioc-count');
      if (countEl) countEl.textContent = `IOC Results [0]`;
      // Hide stats
      const statsEl = document.getElementById('iocStats');
      if (statsEl) statsEl.style.display = 'none';
      return;
    }

    // Calculate statistics
    this.displayIOCStatistics(iocs);

    // Build HTML in memory first, then update DOM once
    const htmlParts = [];
    for (const ioc of iocs) {
      const osintLinks = this.generateOSINTLinks(ioc.value, ioc.category);
      const escapedValue = this.escapeHtml(ioc.value);

      htmlParts.push(`
        <div class="ioc-item" data-value="${escapedValue}" data-type="${this.escapeHtml(ioc.category.toLowerCase())}">
          <input type="checkbox" class="ioc-select" />
          <div style="flex: 1;">
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
              <div class="ioc-value" data-copy="${escapedValue}" title="Click to copy">
                ${escapedValue}
              </div>
              <span class="ioc-type type-${this.escapeHtml(ioc.category.toLowerCase())}">${this.escapeHtml(ioc.type || '')}</span>
              <div class="ioc-actions" style="margin-left: auto; display: flex; gap: 4px;">
                <button class="defang-item-btn" title="Defang this IOC"><i class="fa-solid fa-shield-halved"></i></button>
                <button class="refang-item-btn" title="Refang this IOC"><i class="fa-solid fa-link"></i></button>
              </div>
            </div>
            <div class="osint-links">
              ${osintLinks.map(link => `
                <div class="osint-link-container">
                  <a href="${this.escapeHtml(link.url)}" target="_blank" rel="noopener noreferrer" class="osint-link" title="${this.escapeHtml(link.name)}">${this.escapeHtml(link.name)}</a>
                  <button class="copy-link-btn" data-copy="${this.escapeHtml(link.url)}" title="Copy Link"><i class="fa-regular fa-copy"></i></button>
                  <button class="copy-md-btn" title="Copy Markdown"><i class="fa-brands fa-markdown"></i>&nbsp;MD</button>
                </div>
              `).join('')}
            </div>
          </div>
        </div>`);
    }
    listEl.innerHTML = htmlParts.join('');

    // Update count
    const countEl = resultsContainer.querySelector('.ioc-count');
    if (countEl) countEl.textContent = `IOC Results [${iocs.length}]`;

    // Add event listeners for results
    this.setupResultEventListeners();

    // Generate and display IOC correlation graph
    if (this.enableGraph) {
      this.generateIOCGraph(iocs);
    }
  }

  displayIOCStatistics(iocs) {
    const statsEl = document.getElementById('iocStats');
    if (!statsEl) return;

    // Count by category
    const stats = {};
    for (const ioc of iocs) {
      const cat = ioc.category || 'unknown';
      stats[cat] = (stats[cat] || 0) + 1;
    }

    // Build stats HTML
    const statItems = [];
    const categoryOrder = ['ip', 'domain', 'url', 'email', 'hash', 'cve', 'mitre', 'crypto', 'mac'];
    const categoryLabels = {
      'ip': 'IPs',
      'domain': 'Domains',
      'url': 'URLs',
      'email': 'Emails',
      'hash': 'Hashes',
      'cve': 'CVEs',
      'mitre': 'MITRE',
      'crypto': 'Crypto',
      'mac': 'MACs'
    };

    for (const cat of categoryOrder) {
      if (stats[cat]) {
        statItems.push(`
          <div class="stat-item">
            <span class="stat-value">${stats[cat]}</span>
            <span class="stat-label">${categoryLabels[cat] || cat}</span>
          </div>
        `);
      }
    }

    // Add any remaining categories not in the order list
    for (const cat in stats) {
      if (!categoryOrder.includes(cat)) {
        statItems.push(`
          <div class="stat-item">
            <span class="stat-value">${stats[cat]}</span>
            <span class="stat-label">${categoryLabels[cat] || cat}</span>
          </div>
        `);
      }
    }

    // Add total
    statItems.push(`
      <div class="stat-item">
        <span class="stat-value">${iocs.length}</span>
        <span class="stat-label">Total</span>
      </div>
    `);

    statsEl.innerHTML = statItems.join('');
    statsEl.style.display = 'grid';
  }

  // --- New Helpers ---
  copyAllIOCs() {
    const values = Array.from(document.querySelectorAll('.ioc-item .ioc-value'))
      .map(el => el.textContent.trim());
    if (values.length === 0) {
      this.showNotification('No IOCs to copy', 'error');
      return;
    }
    this.copyToClipboard(values.join('\n'));
  }

  async askAi() {
    const ok = await this._ensureConsent('askAi'); if (!ok) return;
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
    const prompt = TriagePrompt.buildTriagePrompt(iocs, this.lastIOCInput || '', cfg.promptTemplate);
    // Await the clipboard write before opening the tab. Opening a new tab blurs
    // the popup, which then closes and can abort an in-flight clipboard write —
    // leaving the user on the AI site with nothing to paste.
    try {
      await navigator.clipboard.writeText(prompt);
      this.showNotification('Prompt copied to clipboard', 'success');
    } catch (e) {
      this.showNotification('Could not copy prompt — clipboard blocked', 'error');
    }
    chrome.tabs.create({ url: cfg.targetUrl });
  }

  // Quick copy methods for specific IOC types
  copyIOCsByType(type) {
    const items = Array.from(document.querySelectorAll('.ioc-item')).filter(item => {
      const typeEl = item.querySelector('.ioc-type');
      if (!typeEl) return false;
      const itemType = typeEl.textContent.toLowerCase();
      if (type === 'ip') return itemType === 'ipv4' || itemType === 'ipv6';
      if (type === 'hash') return itemType === 'md5' || itemType === 'sha1' || itemType === 'sha256' || itemType === 'sha512';
      return itemType === type.toLowerCase();
    });

    const values = items.map(item => item.querySelector('.ioc-value')?.textContent.trim()).filter(Boolean);

    if (values.length === 0) {
      this.showNotification(`No ${type}s found`, 'error');
      return;
    }

    this.copyToClipboard(values.join('\n'));
    this.showNotification(`Copied ${values.length} ${type}${values.length > 1 ? 's' : ''}`, 'success');
  }

  // Get IOC statistics
  getIOCStats() {
    const items = Array.from(document.querySelectorAll('.ioc-item:not(.empty-state)'));
    const stats = {
      total: items.length,
      ipv4: 0,
      ipv6: 0,
      domain: 0,
      url: 0,
      email: 0,
      hash: 0,
      cve: 0
    };

    items.forEach(item => {
      const typeEl = item.querySelector('.ioc-type');
      if (!typeEl) return;
      const type = typeEl.textContent.toLowerCase();
      if (type === 'ipv4') stats.ipv4++;
      else if (type === 'ipv6') stats.ipv6++;
      else if (type === 'domain') stats.domain++;
      else if (type === 'url') stats.url++;
      else if (type === 'email') stats.email++;
      else if (type === 'md5' || type === 'sha1' || type === 'sha256') stats.hash++;
      else if (type === 'cve') stats.cve++;
    });

    return stats;
  }

  // Show keyboard shortcuts modal
  showKeyboardShortcuts() {
    const modal = document.getElementById('keyboardShortcutsModal');
    if (modal) {
      modal.style.display = 'flex';
    }
  }

  hideKeyboardShortcuts() {
    const modal = document.getElementById('keyboardShortcutsModal');
    if (modal) {
      modal.style.display = 'none';
    }
  }

  // Get storage usage info
  async getStorageUsage() {
    return new Promise((resolve) => {
      chrome.storage.local.getBytesInUse(null, (bytes) => {
        const maxBytes = chrome.storage.local.QUOTA_BYTES || 5242880; // 5MB default
        resolve({
          used: bytes,
          max: maxBytes,
          percent: Math.round((bytes / maxBytes) * 100),
          usedFormatted: this.formatBytes(bytes),
          maxFormatted: this.formatBytes(maxBytes)
        });
      });
    });
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  async updateStorageIndicator() {
    const indicator = document.getElementById('storageIndicator');
    const bar = document.getElementById('storageBar');
    const text = document.getElementById('storageText');

    if (!indicator) return;

    const usage = await this.getStorageUsage();
    if (bar) bar.style.width = `${usage.percent}%`;
    if (text) text.textContent = `${usage.usedFormatted} / ${usage.maxFormatted} (${usage.percent}%)`;

    // Color based on usage
    if (bar) {
      const style = getComputedStyle(document.documentElement);
      if (usage.percent > 90) bar.style.background = style.getPropertyValue('--danger-color').trim() || '#ef4444';
      else if (usage.percent > 70) bar.style.background = style.getPropertyValue('--warning-color').trim() || '#f59e0b';
      else bar.style.background = 'var(--button-active)';
    }
  }

  async clearOldData(daysOld = 30) {
    const cutoff = Date.now() - (daysOld * 24 * 60 * 60 * 1000);

    // 1. Prune timestamped investigation notes
    const notes = await this.loadNotes();
    const filteredNotes = notes.filter(note => {
      const match = note.match(/^\[([^\]]+)\]/);
      if (match) {
        try {
          const noteDate = new Date(match[1]).getTime();
          return noteDate > cutoff;
        } catch {
          return true;
        }
      }
      return true;
    });
    const removedNotes = notes.length - filteredNotes.length;
    await this.saveNotes(filteredNotes);

    // 2. Prune stale caches. The button says "clear all data older than N days",
    // so also sweep enrichment (agent_*), passive-DNS (pdns_cache_*) and ASN
    // (asn_cache_*) entries — each stores a numeric .timestamp.
    const all = await new Promise(resolve => chrome.storage.local.get(null, resolve));
    const staleKeys = Object.keys(all || {}).filter(k => {
      if (!/^(agent_|pdns_cache_|asn_cache_)/.test(k)) return false;
      const ts = all[k] && all[k].timestamp;
      return typeof ts === 'number' && ts < cutoff;
    });
    if (staleKeys.length) {
      await new Promise(resolve => chrome.storage.local.remove(staleKeys, resolve));
    }

    await this.updateStorageIndicator();
    this.showNotification(`Cleared ${removedNotes} old notes, ${staleKeys.length} cache entries`, 'success');
  }

  exportIOCs(format = 'csv') {
    const iocs = Array.from(document.querySelectorAll('.ioc-item')).map(item => {
      const value = item.querySelector('.ioc-value')?.textContent.trim() || '';
      const type = item.querySelector('.ioc-type')?.textContent.trim() || '';
      return { value, type };
    });

    if (iocs.length === 0) {
      this.showNotification('No IOCs to export', 'error');
      return;
    }

    // Handle graph image exports
    if (format === 'graph-png' || format === 'graph-svg') {
      this.exportGraphImage(format);
      return;
    }

    let content = '';
    let mime = 'text/plain';
    let ext = 'txt';

    if (format === 'csv') {
      content = 'Value,Type\n' + iocs.map(i => `${toCsvCell(i.value)},${toCsvCell(i.type)}`).join('\n');
      mime = 'text/csv';
      ext = 'csv';
    } else if (format === 'json') {
      content = JSON.stringify(iocs, null, 2);
      mime = 'application/json';
      ext = 'json';
    } else if (format === 'md') {
      content = iocs.map(i => `- **${i.type}**: ${i.value}`).join('\n');
      mime = 'text/markdown';
      ext = 'md';
    } else if (format === 'md-links') {
      // Use preferred OSINT link for each IOC when available
      const mdLines = iocs.map(i => {
        const category = this.inferCategoryFromType(i.type || '');
        const chosen = this.getPreferredOsintLink(i.value, category);
        if (chosen && chosen.url) {
          return `- [${chosen.name || i.value}](${chosen.url})`;
        }
        // fallback to VirusTotal search
        const enc = encodeURIComponent(i.value);
        const vtUrl = `https://www.virustotal.com/gui/search/${enc}`;
        return `- [${i.value}](${vtUrl})`;
      });
      content = mdLines.join('\n');
      mime = 'text/markdown';
      ext = 'md';
    } else if (format === 'obsidian') {
      content = this.generateObsidianGraph(iocs);
      mime = 'text/markdown';
      ext = 'md';
    }

    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const filename = format === 'obsidian' ? `ioc-graph-${new Date().toISOString().split('T')[0]}.${ext}` : `ioc-results-${new Date().toISOString().split('T')[0]}.${ext}`;
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);

    this.showNotification(`Exported ${iocs.length} IOCs as ${format.toUpperCase()}`, 'success');
  }

  // Generate Obsidian-compatible graph markdown
  generateObsidianGraph(iocs) {
    const timestamp = new Date().toISOString().split('T')[0];
    let content = `# IOC Analysis Graph - ${timestamp}\n\n`;

    // Add metadata
    content += `---\n`;
    content += `tags: [ioc, analysis, graph]\n`;
    content += `date: ${timestamp}\n`;
    content += `---\n\n`;

    // Add IOC nodes as markdown links
    content += `## IOC Nodes\n\n`;
    const nodeMap = new Map();

    iocs.forEach((ioc, index) => {
      const nodeName = `IOC_${ioc.type}_${index + 1}`;
      nodeMap.set(ioc.value, nodeName);
      content += `### [[${nodeName}]]\n`;
      content += `- **Type**: ${ioc.type}\n`;
      content += `- **Value**: \`${ioc.value}\`\n`;
      content += `- **Category**: ${ioc.category || 'unknown'}\n\n`;
    });

    // Add relationships
    content += `## Relationships\n\n`;
    const relationships = this.detectIOCRelationships(iocs);

    if (relationships.length > 0) {
      relationships.forEach(rel => {
        const sourceNode = nodeMap.get(rel.source);
        const targetNode = nodeMap.get(rel.target);
        if (sourceNode && targetNode) {
          content += `- [[${sourceNode}]] --${rel.type}--> [[${targetNode}]]\n`;
        }
      });
    } else {
      content += `No relationships detected between IOCs.\n`;
    }

    // Add canvas view for Obsidian
    content += `\n## Graph View\n\n`;
    content += `This analysis contains ${iocs.length} IOCs with ${relationships.length} relationships.\n`;
    content += `Use Obsidian's Graph View to visualize the connections between these indicators.\n\n`;

    // Add individual IOC files as suggestions
    content += `## Individual IOC Files\n\n`;
    content += `Consider creating individual files for each IOC:\n\n`;
    iocs.forEach((ioc, index) => {
      const nodeName = `IOC_${ioc.type}_${index + 1}`;
      content += `- Create file: \`${nodeName}.md\` with content:\n`;
      content += `  \`\`\`markdown\n`;
      content += `  # ${ioc.value}\n`;
      content += `  \n`;
      content += `  **Type**: ${ioc.type}\n`;
      content += `  **Value**: \`${ioc.value}\`\n`;
      content += `  **Analysis Date**: ${timestamp}\n`;
      content += `  \n`;
      content += `  ## Analysis Notes\n`;
      content += `  \n`;
      content += `  ## Related IOCs\n`;
      content += `  \`\`\`\n\n`;
    });

    return content;
  }

  // Export graph visualization as image
  exportGraphImage(format) {
    if (!this.iocGraph) {
      this.showNotification('No graph visualization available. Enable graph visualization first.', 'error');
      return;
    }

    try {
      const canvas = this.iocGraph.canvas.frame.canvas;
      const graphContainer = document.getElementById('iocGraph');

      if (!canvas) {
        this.showNotification('Canvas not available for export', 'error');
        return;
      }

      if (format === 'graph-png') {
        // Export as PNG
        canvas.toBlob((blob) => {
          if (blob) {
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ioc-graph-${new Date().toISOString().split('T')[0]}.png`;
            a.click();
            URL.revokeObjectURL(url);
            this.showNotification('Graph exported as PNG', 'success');
          } else {
            this.showNotification('Failed to export graph as PNG', 'error');
          }
        }, 'image/png');
      } else if (format === 'graph-svg') {
        // Export as SVG (vis.js doesn't directly support SVG, so we'll create a canvas-to-SVG conversion)
        const svgData = this.canvasToSVG(canvas);
        const blob = new Blob([svgData], { type: 'image/svg+xml' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `ioc-graph-${new Date().toISOString().split('T')[0]}.svg`;
        a.click();
        URL.revokeObjectURL(url);
        this.showNotification('Graph exported as SVG', 'success');
      }
    } catch (error) {
      console.error('Graph export error:', error);
      this.showNotification('Failed to export graph image', 'error');
    }
  }

  // Convert canvas to SVG (basic implementation)
  canvasToSVG(canvas) {
    const { width, height } = canvas;
    const imageData = canvas.toDataURL('image/png');

    return `<?xml version="1.0" encoding="UTF-8"?>
<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <title>IOC Relationship Graph</title>
  <desc>Generated from SOC Analyst Toolkit</desc>
  <image x="0" y="0" width="${width}" height="${height}" xlink:href="${imageData}"/>
</svg>`;
  }

  filterIOCs(category) {
    const items = document.querySelectorAll('.ioc-item');
    let visibleCount = 0;
    items.forEach(item => {
      // Filter on the item's category (data-type), not the type-label text.
      // Labels are md5/sha1/ipv4/… so text matching never matched "hash" and
      // was fragile for "ip".
      const type = item.dataset.type || '';
      if (category === 'all' || type === category) {
        item.style.display = '';
        visibleCount++;
      } else {
        item.style.display = 'none';
      }
    });
    document.querySelector('.ioc-count').textContent = `IOC Results [${visibleCount}]`;
  }

  handleBulkAction(action) {
    const selected = Array.from(document.querySelectorAll('.ioc-item input[type="checkbox"]:checked'))
      .map(cb => cb.closest('.ioc-item'));
    if (selected.length === 0) {
      this.showNotification('No IOCs selected', 'error');
      return;
    }

    const values = selected.map(item => item.querySelector('.ioc-value')?.textContent.trim() || '');

    if (action === 'copy') {
      this.copyToClipboard(values.join('\n'));
    } else if (action === 'copy-md') {
      // Build markdown links for selected items using preferred OSINT link
      const mdLines = selected.map(item => {
        const val = item.querySelector('.ioc-value')?.textContent.trim() || '';
        const typeText = item.querySelector('.ioc-type')?.textContent.trim() || '';
        const category = this.inferCategoryFromType(typeText);
        const chosen = this.getPreferredOsintLink(val, category);
        if (chosen && chosen.url) {
          const label = chosen.name || val;
          return `[${label}](${chosen.url})`;
        }
        // fallback to raw value
        return `[${val}](${encodeURI(val)})`;
      });
      this.copyToClipboard(mdLines.join('\n'));
      this.showNotification(`Copied ${mdLines.length} markdown links`, 'success');
    } else if (action === 'export') {
      this.exportIOCs('csv'); // bulk default as CSV
    } else if (action === 'osint') {
      selected.forEach(item => {
        const vtLink = item.querySelector('.osint-link[href*="virustotal.com"]');
        if (vtLink) window.open(vtLink.href, '_blank');
      });
    }
  }

  // --- Rest of your original class methods (snippets, copyToClipboard, etc.) ---

  // === Settings ===
  applyAskAiConfigToUI(cfg) {
    const urlInput = document.getElementById('askAiTargetUrl');
    const tplArea = document.getElementById('askAiPromptTemplate');
    const presetSel = document.getElementById('askAiPreset');
    if (urlInput) urlInput.value = cfg.targetUrl;
    if (tplArea) tplArea.value = cfg.promptTemplate;
    if (presetSel) presetSel.value = resolveAskAiPreset(cfg.targetUrl);
  }

  async loadSettings() {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.get(['socSettings', 'savedIOCInput', 'lastAnalysisResults', 'cyberchefUrl', 'virustotalApiKey', 'ipinfoApiKey', 'abuseipdbApiKey', 'greynoiseApiKey', 'urlscanApiKey'], (res) => {
          const defaults = { autoAnalyze: true, enableGraph: true, theme: 'arc' };
          const s = res.socSettings || defaults;
          this.autoAnalyze = s.autoAnalyze ?? true;
          this.enableGraph = s.enableGraph ?? true;
          this.currentTheme = s.theme ?? 'arc';
          // load snippetPrefixes if present
          if (s.snippetPrefixes && Array.isArray(s.snippetPrefixes)) this.snippetPrefixes = s.snippetPrefixes;

          // Apply the theme
          this.applyTheme(this.currentTheme);

          // Set the theme selector value
          const themeSelect = document.getElementById('themeSelect');
          if (themeSelect) {
            themeSelect.value = this.currentTheme;
          }

          // Load CyberChef URL
          const cyberchefUrl = res.cyberchefUrl || 'https://gchq.github.io/CyberChef';
          const cyberchefInput = document.getElementById('cyberchefUrl');
          if (cyberchefInput) {
            cyberchefInput.value = cyberchefUrl;
          }

          // Load VirusTotal API key (do not show value if empty)
          const vtInput = document.getElementById('virustotalApiKey');
          if (vtInput && res.virustotalApiKey) {
            vtInput.value = res.virustotalApiKey;
          }

          const ipinfoInput = document.getElementById('ipinfoApiKey');
          if (ipinfoInput && res.ipinfoApiKey) ipinfoInput.value = res.ipinfoApiKey;
          const abuseInput = document.getElementById('abuseipdbApiKey');
          if (abuseInput && res.abuseipdbApiKey) abuseInput.value = res.abuseipdbApiKey;
          const greynoiseInput = document.getElementById('greynoiseApiKey');
          if (greynoiseInput && res.greynoiseApiKey) greynoiseInput.value = res.greynoiseApiKey;
          const urlscanInput = document.getElementById('urlscanApiKey');
          if (urlscanInput && res.urlscanApiKey) urlscanInput.value = res.urlscanApiKey;

          // Restore saved IOC input
          if (res.savedIOCInput) {
            const iocInput = document.getElementById('iocInput');
            if (iocInput) {
              iocInput.value = res.savedIOCInput;
            }
          }

          // Restore last analysis results if present
          if (res.lastAnalysisResults && Array.isArray(res.lastAnalysisResults) && res.lastAnalysisResults.length > 0) {
            this.lastIOCs = res.lastAnalysisResults;
            this.lastIOCInput = res.savedIOCInput || '';
            this.displayIOCResults(this.lastIOCs);
          }

          // Load bulk link preference
          const bulkPref = (res.socSettings && res.socSettings.bulkLinkPreference) || 'VirusTotal';
          const bulkSelect = document.getElementById('bulkLinkPreference');
          if (bulkSelect) bulkSelect.value = bulkPref;

          resolve();
        });
      } catch (e) {
        console.error('Failed to load settings:', e);
        this.autoAnalyze = true;
        this.enableGraph = true;
        this.currentTheme = 'arc';
        this.applyTheme(this.currentTheme);
        resolve();
      }
    });
  }

  // Helper: infer category from IOC type label text
  inferCategoryFromType(typeText) {
    if (!typeText) return 'domain';
    const t = typeText.toLowerCase();
    if (t.includes('ipv4') || t.includes('ipv6') || t.includes('ip')) return 'ip';
    if (t.includes('url')) return 'url';
    if (t.includes('domain')) return 'domain';
    if (t.includes('sha256') || t.includes('sha1') || t.includes('md5') || t.includes('hash')) return 'hash';
    if (t.includes('cve')) return 'cve';
    if (t.includes('mitre')) return 'mitre';
    if (t.includes('bitcoin') || t.includes('ethereum') || t.includes('crypto')) return 'crypto';
    if (t.includes('mac')) return 'mac';
    if (t.includes('email')) return 'email';
    return 'domain';
  }

  // Get preferred OSINT link for a value using stored preference
  getPreferredOsintLink(value, category) {
    const pref = (document.getElementById('bulkLinkPreference')?.value) || 'VirusTotal';
    const links = this.generateOSINTLinks(value, category || 'domain');
    if (!links || links.length === 0) return null;

    if (pref === 'CustomFirst') {
      // prefer custom sources defined in this.customOsintSources
      if (this.customOsintSources && this.customOsintSources.length > 0) {
        const name = this.customOsintSources[0].name;
        const found = links.find(l => l.name === name);
        if (found) return found;
      }
    }

    // Try to find exact match by name
    const found = links.find(l => l.name && l.name.toLowerCase() === pref.toLowerCase());
    if (found) return found;

    // Try partial match
    const partial = links.find(l => l.name && l.name.toLowerCase().includes(pref.toLowerCase()));
    if (partial) return partial;

    // Fallback to first
    return links[0];
  }

  saveSettings() {
    try {
      const socSettings = {
        autoAnalyze: this.autoAnalyze,
        enableGraph: this.enableGraph,
        snippetPrefixes: this.snippetPrefixes,
        theme: this.currentTheme
      };
      chrome.storage.local.set({ socSettings });
    } catch (e) {
      console.error('Failed to save settings:', e);
    }
  }

  // --- Ask AI config ---
  async loadAskAiConfig() {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.get(['askAiConfig'], (res) => {
          const cfg = res && res.askAiConfig;
          if (!cfg || typeof cfg !== 'object') return resolve(askAiDefaultConfig());
          resolve({
            targetUrl: typeof cfg.targetUrl === 'string' ? cfg.targetUrl : askAiDefaultConfig().targetUrl,
            promptTemplate: typeof cfg.promptTemplate === 'string' ? cfg.promptTemplate : ''
          });
        });
      } catch (e) {
        resolve(askAiDefaultConfig());
      }
    });
  }

  async saveAskAiConfig(cfg) {
    const v = validateAskAiTargetUrl(cfg && cfg.targetUrl);
    if (!v.ok) {
      this.showNotification(`Ask AI: ${v.error}`, 'error');
      return false;
    }
    return new Promise((resolve) => {
      try {
        chrome.storage.local.set({ askAiConfig: cfg }, () => resolve(true));
      } catch (e) {
        resolve(false);
      }
    });
  }

  // === Theme Management ===
  applyTheme(themeName) {
    // Remove existing theme data attributes
    document.body.removeAttribute('data-theme');

    // Handle system theme preference
    if (themeName === 'system') {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      // Use arc for dark mode, coffee for light mode
      themeName = prefersDark ? 'arc' : 'coffee';
    }

    // Apply new theme (if not arc/default)
    if (themeName !== 'arc') {
      document.body.setAttribute('data-theme', themeName);
    }

    this.currentTheme = themeName;
  }

  // Setup system theme change listener
  setupSystemThemeListener() {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    mediaQuery.addEventListener('change', () => {
      // Only react if user has selected 'system' theme
      chrome.storage.local.get(['socSettings'], (res) => {
        if (res.socSettings?.theme === 'system') {
          this.applyTheme('system');
        }
      });
    });
  }

  // === Snippets ===
  async loadSnippets() {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.get(['snippets'], (res) => {
          this.snippets = Array.isArray(res.snippets) ? res.snippets : [];
          resolve();
        });
      } catch (e) {
        console.error('Failed to load snippets:', e);
        this.snippets = [];
        resolve();
      }
    });
  }

  async saveSnippets() {
    try {
      await chrome.storage.local.set({ snippets: this.snippets });
    } catch (e) {
      console.error('Failed to save snippets:', e);
    }
  }

  displaySnippets(filtered = null) {
    const list = document.getElementById('snippetList');
    if (!list) return;
    const data = filtered ?? this.snippets;
    if (!data.length) {
      const emptyStateHTML = `
        <div class="empty-state">
          <i class="fa-solid fa-code"></i>
          <div>No snippets found</div>
          <div style="font-size: 11px; margin-top: 4px;">Create your first snippet to get started</div>
        </div>`;
      list.innerHTML = emptyStateHTML;
      return;
    }

    // Build HTML in memory first
    const htmlParts = [];
    for (let idx = 0; idx < data.length; idx++) {
      const snip = data[idx];
      htmlParts.push(`
      <div class="snippet-item" data-index="${idx}">
        <div class="snippet-header">
          <div class="snippet-name">${this.escapeHtml(snip.name || 'Untitled')}</div>
        </div>
        <div class="snippet-content">
          <div class="snippet-text">${this.escapeHtml(snip.content || '')}</div>
          <div class="snippet-actions">
            <button class="btn btn-primary btn-small action-copy"><i class="fa-regular fa-copy"></i> Copy</button>
            <button class="btn btn-secondary btn-small action-edit"><i class="fa-regular fa-pen-to-square"></i> Edit</button>
            <button class="btn btn-secondary btn-small action-delete"><i class="fa-regular fa-trash-can"></i> Delete</button>
          </div>
        </div>
      </div>`);
    }
    list.innerHTML = htmlParts.join('');

    // Remove existing event listener if present to prevent duplicates
    if (this._snippetListClickHandler) {
      list.removeEventListener('click', this._snippetListClickHandler);
    }

    // Use event delegation for better performance
    this._snippetListClickHandler = (e) => {
      const target = e.target;
      const item = target.closest('.snippet-item');
      if (!item) return;

      const idx = Number(item.dataset.index);
      const snip = data[idx];

      if (target.closest('.snippet-header')) {
        item.querySelector('.snippet-content').classList.toggle('expanded');
      } else if (target.closest('.action-copy')) {
        this.copyToClipboard(snip.content || '');
      } else if (target.closest('.action-edit')) {
        this.openSnippetEditor(idx);
      } else if (target.closest('.action-delete')) {
        if (confirm(`Delete snippet "${snip.name || 'Untitled'}"?`)) {
          const realIndex = this.snippets.indexOf(snip);
          if (realIndex >= 0) {
            this.snippets.splice(realIndex, 1);
            this.saveSnippets();
            this.displaySnippets();
          }
        }
      }
    };
    list.addEventListener('click', this._snippetListClickHandler);
  }

  searchSnippets(query) {
    const q = (query || '').toLowerCase();
    if (!q) return this.displaySnippets();
    const filtered = this.snippets.filter(s =>
      (s.name || '').toLowerCase().includes(q) ||
      (s.content || '').toLowerCase().includes(q)
    );
    this.displaySnippets(filtered);
  }

  async addSnippet() {
    // Open editor for a new snippet
    this.openSnippetEditor();
  }

  openSnippetEditor(index = null) {
    const editor = document.getElementById('snippetEditor');
    const nameIn = document.getElementById('snippetNameInput');
    const contentIn = document.getElementById('snippetContentInput');
    if (!editor || !nameIn || !contentIn) return;
    // If index provided, load existing
    if (index !== null && this.snippets[index]) {
      const s = this.snippets[index];
      nameIn.value = s.name || '';
      contentIn.value = s.content || '';
      editor.dataset.editIndex = String(index);
    } else {
      nameIn.value = '';
      contentIn.value = '';
      delete editor.dataset.editIndex;
    }
    editor.style.display = 'block';
    nameIn.focus();
  }

  closeSnippetEditor() {
    const editor = document.getElementById('snippetEditor');
    if (!editor) return;
    editor.style.display = 'none';
  }

  async saveSnippetFromEditor() {
    const editor = document.getElementById('snippetEditor');
    const nameIn = document.getElementById('snippetNameInput');
    const contentIn = document.getElementById('snippetContentInput');
    if (!nameIn || !contentIn) return;
    const name = (nameIn.value || '').trim();
    const content = contentIn.value || '';
    if (!name) { this.showNotification('Please provide a name', 'error'); return; }
    const idx = editor.dataset.editIndex !== undefined ? Number(editor.dataset.editIndex) : -1;
    if (idx >= 0 && this.snippets[idx]) {
      this.snippets[idx] = { name, content };
    } else {
      this.snippets.push({ name, content });
    }
    await this.saveSnippets();
    this.displaySnippets();
    this.closeSnippetEditor();
    this.showNotification('Snippet saved', 'success');
  }

  // === IOC helpers ===
  setupResultEventListeners() {
    document.querySelectorAll('.ioc-value').forEach(el => {
      el.addEventListener('click', () => {
        const text = el.getAttribute('data-copy') || el.textContent.trim();
        this.copyToClipboard(text);
      });
    });
    document.querySelectorAll('.copy-link-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const text = btn.getAttribute('data-copy') || '';
        this.copyToClipboard(text);
      });
    });
    // Copy Markdown button: copies [SourceName](link)
    document.querySelectorAll('.copy-md-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        try {
          const container = btn.closest('.osint-link-container');
          if (!container) return;
          const a = container.querySelector('a.osint-link');
          if (!a) return;
          const name = (a.textContent || a.getAttribute('title') || '').trim();
          const href = a.href || a.getAttribute('href') || '';
          const md = `[${name}](${href})`;
          this.copyToClipboard(md);
        } catch (e) {
          console.error('Copy Markdown failed', e);
          this.showNotification('Copy Markdown failed', 'error');
        }
      });
    });

    // Defang/Refang single item handlers
    document.querySelectorAll('.defang-item-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const item = btn.closest('.ioc-item');
        if (!item) return;
        const value = item.getAttribute('data-value') || '';
        this.defangSingleIOC(value, item);
      });
    });
    document.querySelectorAll('.refang-item-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const item = btn.closest('.ioc-item');
        if (!item) return;
        const value = item.getAttribute('data-value') || '';
        this.refangSingleIOC(value, item);
      });
    });
  }

  clearIOCs() {
    // Clear the input field
    const input = document.getElementById('iocInput');
    if (input) {
      input.value = '';
      // Clear saved IOC input and last results from storage
      chrome.storage.local.remove(['savedIOCInput', 'lastAnalysisResults']);
    }

    // Clear the graph visualization
    this.clearGraph();

    // Clear the results display
    const resultsContainer = document.getElementById('iocResults');
    const listEl = resultsContainer?.querySelector('.ioc-list');
    if (listEl) {
      listEl.innerHTML = `
        <div class="ioc-item empty-state">
          <i class="fa-solid fa-search"></i>
          <div>No IOCs found. Run analysis above.</div>
        </div>`;
    }
    const countEl = resultsContainer?.querySelector('.ioc-count');
    if (countEl) countEl.textContent = 'IOC Results [0]';
    const selectAll = document.getElementById('selectAllIOCs');
    if (selectAll) selectAll.checked = false;
  }

  async pasteFromClipboard() {
    try {
      const text = await navigator.clipboard.readText();
      const input = document.getElementById('iocInput');
      if (input) {
        input.value = text || '';
        // Save to storage for persistence
        chrome.storage.local.set({ savedIOCInput: input.value });
        if (this.autoAnalyze && input.value.trim()) {
          this.analyzeIOCs();
        }
      }
    } catch (e) {
      this.showNotification('Unable to read clipboard', 'error');
    }
  }

  copyToClipboard(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => this.showNotification('Copied to clipboard', 'success'));
      } else {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        this.showNotification('Copied to clipboard', 'success');
      }
    } catch (e) {
      this.showNotification('Copy failed', 'error');
    }
  }

  showStatus(message, type = 'info') {
    this.showNotification(message, type);
  }

  showNotification(message, type = 'success') {
    const note = document.createElement('div');
    note.className = `notification ${type}`;
    note.textContent = message;
    document.body.appendChild(note);
    setTimeout(() => note.remove(), 2000);
  }

  truncateText(text, max = 40) {
    if (!text) return '';
    return text.length > max ? text.slice(0, max - 1) + '…' : text;
  }

  escapeHtml(str) {
    if (!str) return '';
    // Use a single regex with a lookup map for better performance
    const htmlEscapeMap = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    return str.replace(/[&<>"']/g, (char) => htmlEscapeMap[char]);
  }

  generateOSINTLinks(value, category) {
    // Check cache first
    const cacheKey = `${value}:${category}`;
    if (this._osintLinksCache.has(cacheKey)) {
      return this._osintLinksCache.get(cacheKey);
    }

    const enc = encodeURIComponent(value);
    // utf8ToBase64 (not raw btoa) so non-Latin1 IOCs (IDN domains, unicode URLs)
    // don't throw and abort the whole result render.
    const b64 = encodeURIComponent(utf8ToBase64(value));
    const links = [];

    // Default OSINT Sources
    // VirusTotal
    links.push({ name: 'VirusTotal', url: `https://www.virustotal.com/gui/search/${enc}` });
    // urlscan
    if (category === 'url' || category === 'domain') {
      links.push({ name: 'urlscan', url: `https://urlscan.io/search/#${enc}` });
    }
    // AbuseIPDB for IPs
    if (category === 'ip') {
      links.push({ name: 'AbuseIPDB', url: `https://www.abuseipdb.com/check/${enc}` });
      links.push({ name: 'ipinfo', url: `https://ipinfo.io/${enc}` });
      // Pulsedive for IPs
      links.push({ name: 'Pulsedive', url: `https://pulsedive.com/indicator/?ioc=${b64}` });
    }
    // Domains: Pulsedive as well
    if (category === 'domain') {
      links.push({ name: 'Pulsedive', url: `https://pulsedive.com/indicator/?ioc=${b64}` });
      links.push({ name: 'ThreatFox', url: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${enc}` });
    }
    // Hashes: threat.rip and more
    if (category === 'hash') {
      // threat.rip: Use standard single encoding for "hash:<value>"
      const trQuery = encodeURIComponent(`hash:${value}`);
      links.push({ name: 'threat.rip', url: `https://threat.rip/search?q=${trQuery}` });

      links.push({ name: 'MalwareBazaar', url: `https://bazaar.abuse.ch/browse.php?search=${enc}` });

      // Hybrid Analysis: Direct sample link is more precise
      links.push({ name: 'Hybrid Analysis', url: `https://www.hybrid-analysis.com/sample/${enc}` });
    }
    // URLs: URLhaus and additional checks
    if (category === 'url') {
      links.push({ name: 'URLhaus', url: `https://urlhaus.abuse.ch/browse.php?search=${enc}` });
    }
    // IPs: Add GreyNoise
    if (category === 'ip') {
      links.push({ name: 'GreyNoise', url: `https://viz.greynoise.com/ip/${enc}` });
      links.push({ name: 'Shodan', url: `https://www.shodan.io/host/${enc}` });
    }

    // CVE lookups
    if (category === 'cve') {
      links.push({ name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${enc}` });
      links.push({ name: 'MITRE', url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${enc}` });
      links.push({ name: 'CVE Details', url: `https://www.cvedetails.com/cve/${enc}/` });
      links.push({ name: 'Exploit-DB', url: `https://www.exploit-db.com/search?cve=${enc}` });
    }

    // MITRE ATT&CK Technique lookups
    if (category === 'mitre') {
      // Sub-techniques live at /techniques/T1055/001/, not /techniques/T1055.001/
      links.push({ name: 'MITRE ATT&CK', url: `https://attack.mitre.org/techniques/${enc.replace('.', '/')}/` });
      links.push({ name: 'D3FEND', url: `https://d3fend.mitre.org/offensive-technique/attack/${enc}/` });
    }

    // Cryptocurrency address lookups
    if (category === 'crypto') {
      // Bitcoin
      if (value.match(/^[13]/)) {
        links.push({ name: 'Blockchain.com', url: `https://www.blockchain.com/explorer/addresses/btc/${enc}` });
        links.push({ name: 'BlockCypher', url: `https://live.blockcypher.com/btc/address/${enc}/` });
      }
      // Ethereum
      if (value.toLowerCase().startsWith('0x')) {
        links.push({ name: 'Etherscan', url: `https://etherscan.io/address/${enc}` });
        links.push({ name: 'Ethplorer', url: `https://ethplorer.io/address/${enc}` });
      }
    }

    // MAC address lookup
    if (category === 'mac') {
      links.push({ name: 'MAC Vendor', url: `https://macvendors.com/query/${enc}` });
      links.push({ name: 'MAC Address Lookup', url: `https://www.macvendorlookup.com/search/${enc}` });
    }

    // Add custom OSINT sources
    for (const source of this.customOsintSources) {
      if (source.types === 'all' || source.types === category) {
        const customUrl = source.url.replace(/\{\{IOC\}\}/g, enc);
        links.push({ name: source.name, url: customUrl, custom: true });
      }
    }

    // Cache the result
    this._osintLinksCache.set(cacheKey, links);
    return links;
  }

  // === Defang / Fang ===
  // Defang a single IOC value
  defangSingleIOC(iocValue, itemEl) {
    if (!iocValue || !itemEl) return;
    const defanged = this.defangText(iocValue);
    this._updateIOCValueInItem(itemEl, defanged);
    this.showNotification('IOC defanged', 'success');
  }

  // Refang a single IOC value
  refangSingleIOC(iocValue, itemEl) {
    if (!iocValue || !itemEl) return;
    const fanged = this.fangText(iocValue);
    this._updateIOCValueInItem(itemEl, fanged);
    this.showNotification('IOC refanged', 'success');
  }

  // Internal helper to update the UI for a single IOC item
  _updateIOCValueInItem(itemEl, newValue) {
    const valueEl = itemEl.querySelector('.ioc-value');
    if (!valueEl) return;

    // Store the RAW value. setAttribute and textContent do not HTML-parse their
    // input, so escaping here would corrupt copies (a URL "&" would become
    // "&amp;" on the clipboard) and truncating textContent would corrupt
    // copy-all / export, which read .ioc-value textContent for the full value.
    valueEl.setAttribute('data-copy', newValue);
    valueEl.textContent = newValue;
    valueEl.title = 'Click to copy';

    itemEl.setAttribute('data-value', newValue);
  }

  defangIOCsInInput() {
    const ta = document.getElementById('iocInput');
    if (!ta) return;
    const original = ta.value;
    if (!original) return;
    const defanged = this.defangText(original);
    ta.value = defanged;
  }

  fangIOCsInInput() {
    const ta = document.getElementById('iocInput');
    if (!ta) return;
    const original = ta.value;
    if (!original) return;
    const fanged = this.fangText(original);
    ta.value = fanged;
  }

  deduplicateIOCs() {
    const ta = document.getElementById('iocInput');
    if (!ta) return;
    const lines = ta.value.split('\n');
    // Use Set to remove duplicates (case-insensitive comparison)
    // Note: Preserves the case of the first occurrence, which is standard behavior
    const seen = new Set();
    const unique = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const normalized = trimmed.toLowerCase();
      if (!seen.has(normalized)) {
        seen.add(normalized);
        unique.push(trimmed); // Keep original case of first occurrence
      }
    }

    ta.value = unique.join('\n');
    this.showNotification(`Removed ${lines.length - unique.length} duplicate(s)`, 'success');
    if (this.autoAnalyze) {
      this.analyzeIOCs();
    }
  }

  sortIOCs() {
    const ta = document.getElementById('iocInput');
    if (!ta) return;
    const lines = ta.value.split('\n').filter(line => line.trim());
    lines.sort((a, b) => a.trim().localeCompare(b.trim()));
    ta.value = lines.join('\n');
    this.showNotification('IOCs sorted alphabetically', 'success');
    if (this.autoAnalyze) {
      this.analyzeIOCs();
    }
  }

  defangText(text) {
    if (!text) return text;
    let t = text;
    // Protocols - use explicit replacements for accuracy
    t = t.replace(/https:\/\//gi, 'hxxps://');
    t = t.replace(/http:\/\//gi, 'hxxp://');
    t = t.replace(/ftp:\/\//gi, 'fxp://');
    // Dots in hostnames/emails
    t = t.replace(/\./g, '[.]');
    // @ in emails
    t = t.replace(/@/g, '[at]');
    return t;
  }

  deobfuscateText(text) {
    if (!text) return text;
    let t = text;
    // Strip CMD caret escaping: t^h^i^s -> this
    t = t.replace(/\^/g, '');
    // Strip PowerShell backtick escaping: po`wer -> power
    t = t.replace(/`/g, '');
    // Collapse string concatenation: 'a'+'b' or "a"+"b" -> ab
    t = t.replace(/['"]\s*\+\s*['"]/g, '');
    return t;
  }

  fangText(text) {
    if (!text) return text;
    let t = text;
    // reverse of defang variants
    t = t.replace(/hxxps?:\/\//gi, s => s.replace('xx', 'tt'));
    t = t.replace(/\[(?:dot|\.)\]|\(dot\)|\{dot\}/gi, '.');
    t = t.replace(/\[(?:at)\]|\(at\)|\{at\}/gi, '@');
    // Also handle generic [.]
    t = t.replace(/\[\.\]/g, '.');
    return t;
  }

  extractIOCs(text) {
    const results = [];
    if (!text) return results;
    text = this.deobfuscateText(text);

    // Modularized extraction
    this._extractUrls(text, results);
    this._extractNetworkIOCs(text, results);
    this._extractSecurityIOCs(text, results);
    this._extractFinancialIOCs(text, results);
    this._extractHardwareIOCs(text, results);
    this._extractHashes(text, results);
    this._extractDomains(text, results);

    return results;
  }

  _addResult(results, type, value, category) {
    if (!value) return;
    
    // Additional validation for specific categories
    if (category === 'domain') {
      if (this.isValidDomain(value)) {
        results.push({ type, value, category });
      }
    } else if (category === 'ip') {
      if (this.isValidIP(value)) {
        results.push({ type, value, category });
      }
    } else {
      results.push({ type, value, category });
    }
  }

  _extractUrls(text, results) {
    (text.match(this.patterns.url) || []).forEach(v => {
      this._addResult(results, 'URL', v, 'url');
    });
  }

  _extractNetworkIOCs(text, results) {
    // IPv4
    (text.match(this.patterns.ipv4) || []).forEach(v => {
      this._addResult(results, 'IPv4', v, 'ip');
    });

    // IPv6
    (text.match(this.patterns.ipv6) || []).forEach(v => {
      if (this.isValidIPv6(v)) {
        this._addResult(results, 'IPv6', v.toLowerCase(), 'ip');
      }
    });

    // Emails
    (text.match(this.patterns.email) || []).forEach(v => {
      this._addResult(results, 'Email', v, 'email');
    });
  }

  _extractSecurityIOCs(text, results) {
    // CVEs
    (text.match(this.patterns.cve) || []).forEach(v => {
      this._addResult(results, 'CVE', v.toUpperCase(), 'cve');
    });

    // MITRE ATT&CK
    (text.match(this.patterns.mitre) || []).forEach(v => {
      this._addResult(results, 'MITRE', v.toUpperCase(), 'mitre');
    });
  }

  _extractFinancialIOCs(text, results) {
    // Bitcoin
    (text.match(this.patterns.btc) || []).forEach(v => {
      this._addResult(results, 'Bitcoin', v, 'crypto');
    });

    // Ethereum
    (text.match(this.patterns.eth) || []).forEach(v => {
      this._addResult(results, 'Ethereum', v.toLowerCase(), 'crypto');
    });
  }

  _extractHardwareIOCs(text, results) {
    (text.match(this.patterns.mac) || []).forEach(v => {
      this._addResult(results, 'MAC', v.toUpperCase(), 'mac');
    });
  }

  _extractHashes(text, results) {
    const hashMatches = new Set();
    
    // Order: longest to shortest to avoid partial matches
    const hashTypes = [
      { type: 'SHA512', pattern: this.patterns.sha512 },
      { type: 'SHA256', pattern: this.patterns.sha256 },
      { type: 'SHA1', pattern: this.patterns.sha1 },
      { type: 'MD5', pattern: this.patterns.md5 }
    ];

    for (const h of hashTypes) {
      (text.match(h.pattern) || []).forEach(v => {
        const lower = v.toLowerCase();
        if (!hashMatches.has(lower)) {
          this._addResult(results, h.type, lower, 'hash');
          hashMatches.add(lower);
        }
      });
    }
  }

  _extractDomains(text, results) {
    const existing = new Set(results.map(r => r.value.toLowerCase()));
    
    (text.match(this.patterns.domain) || []).forEach(v => {
      const lower = v.toLowerCase();
      
      // Improved deduplication: check if domain is part of an already extracted URL or Email
      const isDuplicate = results.some(r => 
        (r.category === 'url' || r.category === 'email') && 
        r.value.toLowerCase().includes(lower)
      );

      if (!existing.has(lower) && !isDuplicate) {
        this._addResult(results, 'Domain', lower, 'domain');
        existing.add(lower);
      }
    });
  }

  // Helper function to validate domains and reduce false positives
  isValidDomain(domain) {
    if (!domain || domain.length > 253) return false;

    // Cache compiled regex patterns as class properties
    if (!this._domainExcludePatterns) {
      this._domainExcludePatterns = [
        /^[a-z]\.[a-z]$/i, // Single char domains like "a.b"
        /\.(local|localhost|internal|corp|lan)$/i, // Internal domains
        /^\d+\.\d+$/, // Version numbers like 1.2
        /^\d+\.\d+\.\d+$/, // Version numbers like 1.2.3
        /\.(jpg|png|gif|svg|pdf|doc|docx|xls|xlsx|zip|rar|tar|gz)$/i, // File extensions
      ];
      this._labelPattern = /^[a-z0-9-]+$/i;
    }

    const labels = domain.toLowerCase().split('.');
    if (labels.length < 2) return false;
    const tld = labels[labels.length - 1];

    // Check against TLD list - use fallback for common TLDs if full list not loaded
    if (this.tlds && this.tlds.size > 100) {
      if (!this.tlds.has(tld)) {
        return false;
      }
    } else {
      // Fallback: accept common TLDs if full list not yet loaded
      const commonTlds = new Set(['com', 'net', 'org', 'edu', 'gov', 'mil', 'io', 'co', 'uk', 'de', 'jp', 'fr', 'au', 'ru', 'ch', 'it', 'nl', 'ca', 'cn', 'br', 'us', 'info', 'biz']);
      if (!commonTlds.has(tld)) {
        return false;
      }
    }

    // Check exclusion patterns
    for (const pattern of this._domainExcludePatterns) {
      if (pattern.test(domain)) {
        return false;
      }
    }

    // Validate each label
    for (const label of labels) {
      if (!label || label.length > 63) return false;
      if (label.startsWith('-') || label.endsWith('-')) return false;
      if (!this._labelPattern.test(label)) return false;
    }

    return true;
  }

  // Helper function to validate IP addresses (IPv4 and IPv6)
  isValidIP(ip) {
    if (!ip) return false;

    // Check if it's an IPv4 address
    if (ip.includes('.')) {
      const parts = ip.split('.');
      if (parts.length !== 4) return false;

      for (const part of parts) {
        const num = parseInt(part, 10);
        if (isNaN(num) || num < 0 || num > 255) return false;
        if (part.length > 1 && part.startsWith('0')) return false;
      }

      if (ip === '0.0.0.0' || ip === '255.255.255.255') return false;
      return true;
    }

    // Check if it's an IPv6 address
    if (ip.includes(':')) {
      return this.isValidIPv6(ip);
    }

    return false;
  }

  // Helper function to validate IPv6 addresses
  isValidIPv6(ip) {
    if (!ip || typeof ip !== 'string') return false;

    // Basic format checks
    if (!ip.includes(':')) return false;
    if (ip.length < 2) return false;

    // Check for zone index (e.g., %eth0) - remove it for validation
    const zoneIndex = ip.indexOf('%');
    const addr = zoneIndex > 0 ? ip.substring(0, zoneIndex) : ip;

    // Handle IPv4-mapped IPv6 addresses (::ffff:192.168.1.1)
    if (addr.includes('.')) {
      const ipv4Part = addr.substring(addr.lastIndexOf(':') + 1);
      if (!this.isValidIP(ipv4Part)) return false;

      // Replace IPv4 part with placeholder for further validation
      const ipv6Part = addr.substring(0, addr.lastIndexOf(':') + 1) + '0:0';
      return this.validateIPv6Hex(ipv6Part);
    }

    return this.validateIPv6Hex(addr);
  }

  // Validate the hex portions of an IPv6 address
  validateIPv6Hex(addr) {
    // Must have exactly one :: or exactly 7 colons
    const doubleColonCount = (addr.match(/::/g) || []).length;
    const colonCount = (addr.match(/:/g) || []).length;

    if (doubleColonCount > 1) return false;  // Can't have more than one ::

    if (doubleColonCount === 1) {
      // With ::, we can have 1-7 colons total
      if (colonCount < 1 || colonCount > 7) return false;
    } else {
      // Without ::, must have exactly 7 colons
      if (colonCount !== 7) return false;
    }

    // Validate each hex group
    const groups = addr.split(':');
    let nonEmptyGroups = 0;

    for (const group of groups) {
      if (group === '') continue;  // Empty group is part of ::
      if (group.length > 4) return false;  // Max 4 hex digits
      if (!/^[0-9a-fA-F]+$/.test(group)) return false;  // Must be hex
      nonEmptyGroups++;
    }

    // With ::, total groups (including implied) must be 8
    if (doubleColonCount === 1) {
      if (nonEmptyGroups >= 8) return false;
    } else {
      // Without ::, must have exactly 8 groups
      if (groups.length !== 8) return false;
    }

    return true;
  }

  // === Window controls ===
  async toggleFloat() {
    try {
      const response = await chrome.runtime.sendMessage({ action: 'toggleFloat' });
      if (response && response.success) {
        if (response.action === 'opened') {
          this.showStatus('Floating window opened', 'success');
          // Close the popup after a short delay
          setTimeout(() => window.close(), 500);
        } else if (response.action === 'closed') {
          this.showStatus('Floating window closed', 'info');
        }
      }
    } catch (e) {
      this.showStatus('Error toggling floating window', 'error');
    }
  }

  closeWindow() {
    window.close();
  }

  // === Custom OSINT Sources Management ===
  async loadCustomOsintSources() {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.get(['customOsintSources'], (res) => {
          this.customOsintSources = Array.isArray(res.customOsintSources) ? res.customOsintSources : [];
          resolve();
        });
      } catch (e) {
        console.error('Failed to load custom OSINT sources:', e);
        this.customOsintSources = [];
        resolve();
      }
    });
  }

  saveCustomOsintSources() {
    try {
      chrome.storage.local.set({ customOsintSources: this.customOsintSources });
      // Clear OSINT links cache when custom sources change
      this._osintLinksCache.clear();
      // Update bulk preference selector to reflect current custom sources
      this.updateBulkPreferenceOptions();
    } catch (e) {
      console.error('Failed to save custom OSINT sources:', e);
    }
  }

  // Move a custom OSINT source up or down in the list
  moveCustomOsintSource(index, direction) {
    const newIndex = index + direction;
    if (newIndex < 0 || newIndex >= this.customOsintSources.length) return;
    const item = this.customOsintSources.splice(index, 1)[0];
    this.customOsintSources.splice(newIndex, 0, item);
    this.saveCustomOsintSources();
    this.displayCustomOsintSources();
    this.showNotification('OSINT source order updated', 'success');
  }

  // Make a custom OSINT source the default bulk preference
  makeCustomDefault(index) {
    const source = this.customOsintSources[index];
    if (!source) return;
    const name = source.name;
    // Persist as bulkLinkPreference
    chrome.storage.local.get(['socSettings'], (res) => {
      const s = res.socSettings || {};
      s.bulkLinkPreference = name;
      chrome.storage.local.set({ socSettings: s }, () => {
        // Update select if present
        const sel = document.getElementById('bulkLinkPreference');
        if (sel) sel.value = name;
        this.showNotification(`${name} set as preferred link`, 'success');
      });
    });
  }

  // Update the bulk preference select element to include current custom sources
  updateBulkPreferenceOptions() {
    const sel = document.getElementById('bulkLinkPreference');
    if (!sel) return;

    // Preserve current selection
    const current = sel.value;

    // Keep base/default options (first group)
    const baseOptions = [
      { v: 'VirusTotal', t: 'VirusTotal' },
      { v: 'urlscan', t: 'urlscan' },
      { v: 'AbuseIPDB', t: 'AbuseIPDB' },
      { v: 'Pulsedive', t: 'Pulsedive' },
      { v: 'GreyNoise', t: 'GreyNoise' },
      { v: 'Shodan', t: 'Shodan' },
      { v: 'ThreatFox', t: 'ThreatFox' },
      { v: 'MalwareBazaar', t: 'MalwareBazaar' },
      { v: 'URLhaus', t: 'URLhaus' },
      { v: 'Hybrid Analysis', t: 'Hybrid Analysis' },
      { v: 'CustomFirst', t: 'Custom (first)' }
    ];

    // Build new options list
    sel.innerHTML = '';
    for (const o of baseOptions) {
      const opt = document.createElement('option');
      opt.value = o.v;
      opt.textContent = o.t;
      sel.appendChild(opt);
    }

    if (this.customOsintSources && this.customOsintSources.length > 0) {
      // Separator (disabled)
      const sep = document.createElement('option');
      sep.disabled = true;
      sep.textContent = '--- Custom Sources ---';
      sel.appendChild(sep);

      // Add each custom source by name in current order
      for (const src of this.customOsintSources) {
        const opt = document.createElement('option');
        opt.value = src.name;
        opt.textContent = `Custom: ${src.name}`;
        sel.appendChild(opt);
      }
    }

    // Restore previous selection if possible
    try { sel.value = current; } catch (e) { /* ignore */ }
  }

  displayCustomOsintSources() {
    const container = document.getElementById('osintSourcesList');
    if (!container) return;

    if (this.customOsintSources.length === 0) {
      container.innerHTML = `
        <div class="empty-state" style="padding: 20px; text-align: center;">
          <i class="fa-solid fa-globe"></i>
          <div>No custom OSINT sources configured</div>
          <div style="font-size: 11px; margin-top: 4px;">Add your first source to get started</div>
        </div>
      `;
      return;
    }

    const html = this.customOsintSources.map((source, index) => `
      <div class="osint-source-item" draggable="true" data-osint-index="${index}">
        <div class="osint-source-header">
          <div class="osint-source-name">${this.escapeHtml(source.name)}</div>
          <div class="osint-source-type">${this.escapeHtml(source.types)}</div>
        </div>
        <div class="osint-source-url">${this.escapeHtml(source.url)}</div>
        <div class="osint-source-actions">
          <button class="btn btn-secondary btn-small" data-osint-action="edit"><i class="fa-solid fa-edit"></i> Edit</button>
          <button class="btn btn-secondary btn-small" data-osint-action="up"><i class="fa-solid fa-arrow-up"></i> Up</button>
          <button class="btn btn-secondary btn-small" data-osint-action="down"><i class="fa-solid fa-arrow-down"></i> Down</button>
          <button class="btn btn-secondary btn-small" data-osint-action="default"><i class="fa-solid fa-star"></i> Make default</button>
          <button class="btn btn-secondary btn-small" data-osint-action="delete"><i class="fa-solid fa-trash"></i> Delete</button>
        </div>
      </div>
    `).join('');

    container.innerHTML = html;

    // Event delegation — MV3 extension-page CSP blocks inline onclick handlers.
    if (this._osintListClickHandler) {
      container.removeEventListener('click', this._osintListClickHandler);
    }
    this._osintListClickHandler = (e) => {
      const btn = e.target.closest('[data-osint-action]');
      if (!btn) return;
      const item = btn.closest('.osint-source-item');
      if (!item) return;
      const index = parseInt(item.dataset.osintIndex, 10);
      if (!Number.isFinite(index)) return;
      switch (btn.dataset.osintAction) {
        case 'edit': this.editCustomOsintSource(index); break;
        case 'up': this.moveCustomOsintSource(index, -1); break;
        case 'down': this.moveCustomOsintSource(index, 1); break;
        case 'default': this.makeCustomDefault(index); break;
        case 'delete': this.deleteCustomOsintSource(index); break;
      }
    };
    container.addEventListener('click', this._osintListClickHandler);

    // Also refresh bulk preference options to include current custom sources
    this.updateBulkPreferenceOptions();

    // Setup drag-and-drop handlers for items
    const items = Array.from(container.querySelectorAll('.osint-source-item'));
    items.forEach(item => {
      item.addEventListener('dragstart', (e) => {
        item.classList.add('dragging');
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/osint-index', item.dataset.osintIndex || '');
      });

      item.addEventListener('dragover', (e) => {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
      });

      item.addEventListener('drop', (e) => {
        e.preventDefault();
        const srcIdx = parseInt(e.dataTransfer.getData('text/osint-index'), 10);
        const dstIdx = parseInt(item.dataset.osintIndex, 10);
        if (!Number.isFinite(srcIdx) || !Number.isFinite(dstIdx)) return;
        if (srcIdx === dstIdx) return;
        // Reorder array: move src to position of dst
        const srcItem = this.customOsintSources.splice(srcIdx, 1)[0];
        // If source comes before destination and we removed it, destination index decreases by 1
        const insertIndex = (srcIdx < dstIdx) ? dstIdx : dstIdx;
        this.customOsintSources.splice(insertIndex, 0, srcItem);
        this.saveCustomOsintSources();
        this.displayCustomOsintSources();
      });

      item.addEventListener('dragend', () => {
        item.classList.remove('dragging');
      });
    });
  }

  addCustomOsintSource() {
    this.showOsintEditor();
  }

  editCustomOsintSource(index) {
    const source = this.customOsintSources[index];
    if (!source) return;

    this.showOsintEditor(source, index);
  }

  deleteCustomOsintSource(index) {
    if (confirm('Are you sure you want to delete this OSINT source?')) {
      this.customOsintSources.splice(index, 1);
      this.saveCustomOsintSources();
      this.displayCustomOsintSources();
      this.showNotification('OSINT source deleted', 'success');
    }
  }

  showOsintEditor(source = null, editIndex = null) {
    const editor = document.getElementById('osintEditor');
    const nameInput = document.getElementById('osintNameInput');
    const typesInput = document.getElementById('osintTypesInput');
    const urlInput = document.getElementById('osintUrlInput');

    if (source) {
      nameInput.value = source.name;
      typesInput.value = source.types;
      urlInput.value = source.url;
    } else {
      nameInput.value = '';
      typesInput.value = 'all';
      urlInput.value = '';
    }

    editor.style.display = 'block';
    editor.dataset.editIndex = editIndex !== null ? editIndex : '';
    nameInput.focus();
  }

  closeOsintEditor() {
    const editor = document.getElementById('osintEditor');
    editor.style.display = 'none';
    delete editor.dataset.editIndex;
  }

  saveCustomOsintSource() {
    const nameInput = document.getElementById('osintNameInput');
    const typesInput = document.getElementById('osintTypesInput');
    const urlInput = document.getElementById('osintUrlInput');
    const editor = document.getElementById('osintEditor');

    const name = nameInput.value.trim();
    const types = typesInput.value;
    const url = urlInput.value.trim();

    if (!name || !url) {
      this.showNotification('Name and URL are required', 'error');
      return;
    }

    if (!url.includes('{{IOC}}')) {
      this.showNotification('URL must contain {{IOC}} placeholder', 'error');
      return;
    }

    // Only http(s) schemes — block javascript:/data: and other unexpected schemes
    // from being stored and later turned into a clickable link.
    if (!/^https?:\/\//i.test(url)) {
      this.showNotification('URL must start with http:// or https://', 'error');
      return;
    }

    const source = { name, types, url };
    const editIndex = editor.dataset.editIndex;

    if (editIndex !== '') {
      // Edit existing source
      this.customOsintSources[parseInt(editIndex)] = source;
      this.showNotification('OSINT source updated', 'success');
    } else {
      // Add new source
      this.customOsintSources.push(source);
      this.showNotification('OSINT source added', 'success');
    }

    this.saveCustomOsintSources();
    this.displayCustomOsintSources();
    this.closeOsintEditor();
  }

  // === IOC Graph Visualization ===
  generateIOCGraph(iocs) {
    const graphContainer = document.getElementById('iocGraph');
    if (!graphContainer || !this.enableGraph) return;

    // Destroy existing graph to prevent memory leaks
    if (this.iocGraph) {
      this.iocGraph.destroy();
      this.iocGraph = null;
    }

    // Build nodes and edges for visualization
    const nodes = new vis.DataSet();
    const edges = new vis.DataSet();
    const nodeMap = new Map();

    // Create nodes for each IOC
    iocs.forEach((ioc, index) => {
      const nodeId = `ioc_${index}`;
      nodeMap.set(ioc.value, nodeId);

      nodes.add({
        id: nodeId,
        label: this.truncateText(ioc.value, 20),
        group: ioc.category,
        title: `${ioc.type}: ${ioc.value}`,
        font: { size: 12 }
      });
    });

    // Create edges based on relationships
    this.detectIOCRelationships(iocs).forEach(relationship => {
      const sourceNode = nodeMap.get(relationship.source);
      const targetNode = nodeMap.get(relationship.target);

      if (sourceNode && targetNode) {
        edges.add({
          from: sourceNode,
          to: targetNode,
          label: relationship.type,
          font: { size: 10 }
        });
      }
    });

    // Configure visualization options
    const cssVars = getComputedStyle(document.documentElement);
    const cssVar = (name, fallback) => cssVars.getPropertyValue(name).trim() || fallback;
    const options = {
      nodes: {
        shape: 'dot',
        size: 16,
        font: { color: '#ffffff' },
        borderWidth: 2
      },
      edges: {
        color: { color: '#9ca3af' },
        width: 2,
        arrows: { to: { enabled: true, scaleFactor: 0.5 } }
      },
      groups: {
        ip:             { color: { background: cssVar('--type-ip-border',         '#3b82f6'), border: cssVar('--type-ip-border',         '#2563eb') } },
        domain:         { color: { background: cssVar('--type-domain-border',     '#10b981'), border: cssVar('--type-domain-border',     '#059669') } },
        url:            { color: { background: cssVar('--type-url-border',        '#8b5cf6'), border: cssVar('--type-url-border',        '#7c3aed') } },
        email:          { color: { background: cssVar('--type-email-border',      '#f59e0b'), border: cssVar('--type-email-border',      '#d97706') } },
        hash:           { color: { background: cssVar('--type-hash-border',       '#ef4444'), border: cssVar('--type-hash-border',       '#dc2626') } },
        asn:            { color: { background: cssVar('--type-ip-text',           '#14b8a6'), border: cssVar('--type-ip-border',         '#0d9488') } },
        geo:            { color: { background: cssVar('--osint-link-color',       '#38bdf8'), border: cssVar('--button-active',          '#0ea5e9') } },
        reputation:     { color: { background: cssVar('--type-hash-border',       '#f43f5e'), border: cssVar('--danger-color',           '#be123c') } },
        classification: { color: { background: cssVar('--type-mitre-border',      '#a855f7'), border: cssVar('--type-mitre-border',      '#7c3aed') } },
        unknown:        { color: { background: cssVar('--border-primary',         '#6b7280'), border: cssVar('--bg-accent-dark',         '#4b5563') } }
      },
      physics: {
        enabled: true,
        stabilization: { iterations: 100 }
      },
      interaction: {
        hover: true,
        tooltipDelay: 200
      }
    };

    // Show graph container and render
    graphContainer.classList.add('active');
    this.graphNodes = nodes;
    this.graphEdges = edges;
    this.iocGraph = new vis.Network(graphContainer, { nodes, edges }, options);

    // Add double-click handler to enrich passive DNS for domain nodes
    this.iocGraph.on('doubleClick', (params) => {
      try {
        if (params.nodes && params.nodes.length) {
          const nodeId = params.nodes[0];
          const node = this.graphNodes.get(nodeId);
          if (node && node.group === 'domain') {
            const domainValue = (node.title && node.title.includes(':')) ? node.title.split(':').slice(1).join(':').trim() : node.label;
            // Ask background to enrich passive DNS (VirusTotal fallback)
            chrome.runtime.sendMessage({ action: 'passiveDnsEnrich', domain: domainValue }, (response) => {
              void chrome.runtime.lastError;
              if (!response) return;
              if (response.fallback === 'web') {
                this.showNotification('Passive DNS', 'Opened VirusTotal web UI for manual lookup');
                return;
              }

              const records = response.records || [];
              // Add resulting IP nodes and edges
              records.forEach((rec) => {
                if (!rec || !rec.ip) return;
                const ipId = `ip_${rec.ip.replace(/[^0-9a-fA-F\.:]/g, '_')}`;
                if (!this.graphNodes.get(ipId)) {
                  this.graphNodes.add({ id: ipId, label: rec.ip, group: 'ip', title: `ip: ${rec.ip}` });
                }

                // Edge metadata: lastSeen if available
                const edgeId = `edge_${nodeId}_${ipId}`;
                if (!this.graphEdges.get(edgeId)) {
                  const edgeObj = { id: edgeId, from: nodeId, to: ipId, label: 'passive-dns', title: rec.lastSeen ? `lastSeen: ${rec.lastSeen}` : '' };
                  // Use dashed line for historical data
                  if (rec.lastSeen) edgeObj.dashes = true;
                  this.graphEdges.add(edgeObj);
                }
              });

              this.showNotification('Passive DNS Enriched', `${records.length} records added to graph`);
            });
          }
        }
      } catch (e) {
        console.error('Passive DNS handler error:', e);
      }
    });

    // Right-click (button===2) handler to show a small context menu for nodes
    this._removeGraphContextIfExists = () => {
      const existing = document.getElementById('graphNodeContextMenu');
      if (existing && existing.parentElement) existing.parentElement.removeChild(existing);
    };

    this.iocGraph.on('click', (params) => {
      try {
        // Detect right-click via srcEvent.button === 2
        const ev = params.event && params.event.srcEvent;
        if (!ev || ev.button !== 2) return;

        // Remove any existing menu first
        this._removeGraphContextIfExists();

        if (!(params.nodes && params.nodes.length)) return;
        const nodeId = params.nodes[0];
        const node = this.graphNodes.get(nodeId);
        if (!node) return;

        // Build menu items based on node type
        const items = [];
        if (node.group === 'domain') {
          items.push({ id: 'domain-agent-enrich', label: 'Enrich Domain (Agents)' });
          items.push({ id: 'pdns', label: 'Enrich Passive DNS' });
          items.push({ id: 'open-vt', label: 'Open in VirusTotal' });
          items.push({ id: 'open-cyberchef', label: 'Open in CyberChef' });
        } else if (node.group === 'ip') {
          items.push({ id: 'ip-agent-enrich', label: 'Enrich IP (Agents)' });
          items.push({ id: 'asn', label: 'Lookup ASN' });
          items.push({ id: 'open-vt', label: 'Open in VirusTotal' });
          items.push({ id: 'open-cyberchef', label: 'Open in CyberChef' });
        } else if (['hash', 'md5', 'sha1', 'sha256', 'sha512'].includes(node.group)) {
          items.push({ id: 'hash-agent-enrich', label: 'Enrich Hash (Agents)' });
          items.push({ id: 'open-vt', label: 'Open in VirusTotal' });
          items.push({ id: 'open-cyberchef', label: 'Open in CyberChef' });
        } else if (node.group === 'url') {
          items.push({ id: 'url-agent-enrich', label: 'Enrich URL (Agents)' });
          items.push({ id: 'open-vt', label: 'Open in VirusTotal' });
          items.push({ id: 'open-cyberchef', label: 'Open in CyberChef' });
        } else {
          items.push({ id: 'open-cyberchef', label: 'Open in CyberChef' });
        }

        // Create menu element (viewport-safe placement and keyboard accessible)
        const menu = document.createElement('div');
        menu.id = 'graphNodeContextMenu';
        menu.setAttribute('role', 'menu');
        menu.tabIndex = -1;
        menu.style.position = 'fixed';
        menu.style.zIndex = 9999;
        menu.style.background = 'var(--bg-accent)';
        menu.style.border = '1px solid var(--border-primary)';
        menu.style.padding = '6px';
        menu.style.borderRadius = '6px';
        menu.style.boxShadow = '0 6px 18px rgba(0,0,0,0.4)';
        // initial placement
        let left = ev.clientX;
        let top = ev.clientY;
        const vw = Math.max(document.documentElement.clientWidth || 0, window.innerWidth || 0);
        const vh = Math.max(document.documentElement.clientHeight || 0, window.innerHeight || 0);
        const estimatedWidth = 220;
        const estimatedHeight = items.length * 36 + 12;
        if (left + estimatedWidth > vw) left = Math.max(8, vw - estimatedWidth - 8);
        if (top + estimatedHeight > vh) top = Math.max(8, vh - estimatedHeight - 8);
        menu.style.left = `${left}px`;
        menu.style.top = `${top}px`;

        items.forEach((it, idx) => {
          const el = document.createElement('div');
          el.textContent = it.label;
          el.style.padding = '6px 10px';
          el.style.cursor = 'pointer';
          el.style.color = 'var(--text-primary)';
          el.tabIndex = 0;
          el.setAttribute('role', 'menuitem');
          el.dataset.menuIndex = idx;
          el.addEventListener('click', (e) => {
            e.stopPropagation();
            this._removeGraphContextIfExists();
            if (it.id === 'pdns') {
              const domainValue = (node.title && node.title.includes(':')) ? node.title.split(':').slice(1).join(':').trim() : node.label;
              chrome.runtime.sendMessage({ action: 'passiveDnsEnrich', domain: domainValue }, (response) => {
                void chrome.runtime.lastError;
                if (!response) return;
                if (response.fallback === 'web') {
                  this.showNotification('Passive DNS', 'Opened VirusTotal web UI for manual lookup');
                  return;
                }
                const records = response.records || [];
                records.forEach((rec) => {
                  if (!rec || !rec.ip) return;
                  const ipId = `ip_${rec.ip.replace(/[^0-9a-fA-F\.:]/g, '_')}`;
                  if (!this.graphNodes.get(ipId)) {
                    this.graphNodes.add({ id: ipId, label: rec.ip, group: 'ip', title: `ip: ${rec.ip}` });
                  }
                  const edgeId = `edge_${nodeId}_${ipId}`;
                  if (!this.graphEdges.get(edgeId)) {
                    const edgeObj = { id: edgeId, from: nodeId, to: ipId, label: 'passive-dns', title: rec.lastSeen ? `lastSeen: ${rec.lastSeen}` : '' };
                    if (rec.lastSeen) edgeObj.dashes = true;
                    this.graphEdges.add(edgeObj);
                  }
                });
                this.showNotification('Passive DNS Enriched', `${records.length} records added to graph`);
              });
            } else if (it.id === 'ip-agent-enrich') {
              const ipValue = this.getNodeValue(node);
              this.triggerIpEnrichment(ipValue, nodeId);
            } else if (it.id === 'hash-agent-enrich') {
              const hashValue = this.getNodeValue(node);
              this.triggerHashEnrichment(hashValue, nodeId);
            } else if (it.id === 'domain-agent-enrich') {
              const domainValue = this.getNodeValue(node);
              this.triggerDomainEnrichment(domainValue, nodeId);
            } else if (it.id === 'url-agent-enrich') {
              const urlValue = this.getNodeValue(node);
              this.triggerUrlEnrichment(urlValue, nodeId);
            } else if (it.id === 'asn') {
              const ipValue = this.getNodeValue(node);
              chrome.runtime.sendMessage({ action: 'asnEnrich', ip: ipValue }, (resp) => {
                void chrome.runtime.lastError;
                if (!resp) return;
                if (resp.fallback === 'web') {
                  this.showNotification('ASN', 'Opened ipinfo web UI for manual lookup');
                  return;
                }
                const asn = resp.asn;
                if (asn && (asn.number || asn.name)) {
                  const idLabel = asn.number || ('ASN_' + (asn.name || '').replace(/\s+/g, '_'));
                  const asnId = `asn_${idLabel}`;
                  if (!this.graphNodes.get(asnId)) {
                    const titleParts = [];
                    if (asn.number) titleParts.push(asn.number);
                    if (asn.name) titleParts.push(asn.name);
                    if (asn.prefix) titleParts.push(asn.prefix);
                    if (asn.registry) titleParts.push(asn.registry);
                    this.graphNodes.add({ id: asnId, label: asn.number || (asn.name || 'ASN'), group: 'asn', title: `ASN: ${titleParts.join(' | ')}` });
                  }
                  const edgeId = `edge_${nodeId}_${asnId}`;
                  if (!this.graphEdges.get(edgeId)) {
                    this.graphEdges.add({ id: edgeId, from: nodeId, to: asnId, label: 'belongs-to' });
                  }
                  this.showNotification('ASN Added', `${asn.number || ''} ${asn.name || ''}`);
                } else {
                  this.showNotification('ASN Lookup', 'No ASN info found');
                }
              });
            } else if (it.id === 'open-vt') {
              const val = (node.title && node.title.includes(':')) ? node.title.split(':').slice(1).join(':').trim() : node.label;
              window.open(`https://www.virustotal.com/gui/search/${encodeURIComponent(val)}`, '_blank');
            } else if (it.id === 'open-cyberchef') {
              const val = (node.title && node.title.includes(':')) ? node.title.split(':').slice(1).join(':').trim() : node.label;
              chrome.storage.local.get(['cyberchefUrl'], (res) => {
                const cyberchefUrl = res.cyberchefUrl || 'https://gchq.github.io/CyberChef';
                // CyberChef expects Base64 encoded UTF-8 input
                const encodedInput = utf8ToBase64(val);
                window.open(`${cyberchefUrl}/#input=${encodedInput}`, '_blank');
              });
            }
          });
          menu.appendChild(el);
        });

        document.body.appendChild(menu);

        // Keyboard navigation for menu
        const itemsEls = Array.from(menu.querySelectorAll('[role="menuitem"]'));
        let focusedIndex = 0;
        const focusItem = (i) => {
          if (i < 0) i = itemsEls.length - 1;
          if (i >= itemsEls.length) i = 0;
          itemsEls.forEach((el, idx) => el.style.background = idx === i ? 'var(--bg-accent-dark)' : 'transparent');
          itemsEls[i].focus();
          focusedIndex = i;
        };
        if (itemsEls.length) focusItem(0);
        const keyHandler = (e) => {
          if (e.key === 'ArrowDown') { e.preventDefault(); focusItem(focusedIndex + 1); }
          else if (e.key === 'ArrowUp') { e.preventDefault(); focusItem(focusedIndex - 1); }
          else if (e.key === 'Enter') { e.preventDefault(); itemsEls[focusedIndex].click(); }
          else if (e.key === 'Escape') { this._removeGraphContextIfExists(); }
        };
        menu.addEventListener('keydown', keyHandler);

        // Close on next click anywhere
        setTimeout(() => {
          document.addEventListener('click', this._removeGraphContextIfExists, { once: true });
        }, 10);
      } catch (e) {
        console.error('Graph context menu error:', e);
      }
    });
  }

  detectIOCRelationships(iocs) {
    const relationships = [];

    // Group IOCs by category for more efficient matching
    const urlIOCs = [];
    const domainIOCs = [];
    const emailIOCs = [];

    for (const ioc of iocs) {
      if (ioc.category === 'url') urlIOCs.push(ioc);
      else if (ioc.category === 'domain') domainIOCs.push(ioc);
      else if (ioc.category === 'email') emailIOCs.push(ioc);
    }

    // URL to domain relationships
    for (const url of urlIOCs) {
      for (const domain of domainIOCs) {
        if (url.value.includes(domain.value)) {
          relationships.push({
            source: url.value,
            target: domain.value,
            type: 'contains'
          });
        }
      }
    }

    // Email to domain relationships
    for (const email of emailIOCs) {
      for (const domain of domainIOCs) {
        if (email.value.includes(domain.value)) {
          relationships.push({
            source: email.value,
            target: domain.value,
            type: 'uses'
          });
        }
      }
    }

    return relationships;
  }

  getNodeValue(node) {
    if (!node) return '';
    if (node.title && node.title.includes(':')) {
      const parts = node.title.split(':');
      parts.shift();
      const candidate = parts.join(':').trim();
      if (candidate) return candidate;
    }
    return (node.label || '').toString().trim();
  }

  buildEnrichmentErrorMessage(res) {
    if (!res) return 'Enrichment failed: no response received (possible network or extension error).';
    const details = [];
    if (typeof res.errorMessage === 'string' && res.errorMessage.trim()) details.push(res.errorMessage.trim());
    if (res.errorCode) details.push(`code: ${res.errorCode}`);
    if (res.statusCode) details.push(`status: ${res.statusCode}`);
    if (!details.length && typeof res.status === 'string' && res.status.trim() && res.status !== 'error') {
      details.push(`status: ${res.status.trim()}`);
    }
    if (!details.length) return 'Enrichment failed due to an unknown error.';
    return `Enrichment failed: ${details.join(' | ')}`;
  }

  async triggerIpEnrichment(ipValue, nodeId) {
    const ok = await this._ensureConsent('enrichment'); if (!ok) return;
    try {
      this.showNotification('Enriching IP...', 'info');
    } catch (e) {
      // Continue enrichment even if the initial notification fails, but log for diagnostics.
      console.error('Failed to show "Enriching IP..." notification', e);
    }
    chrome.runtime.sendMessage({ action: 'agentEnrich', iocType: 'ip', ioc: ipValue }, (res) => {
      void chrome.runtime.lastError;
      if (!res || res.status === 'error') {
        const message = this.buildEnrichmentErrorMessage(res);
        this.showNotification(message, 'error');
        return;
      }
      this.applyAgentResultToGraph(res, nodeId, ipValue);
      this.showEnrichmentPanel(res);
      const risk = res.summary?.riskScore !== undefined ? res.summary.riskScore : 'n/a';
      this.showNotification(`IP enriched (risk: ${risk})`, 'success');
    });
  }

  applyAgentResultToGraph(result, ipNodeId, ipValue) {
    if (!this.graphNodes || !this.graphEdges) return;
    const nodes = Array.isArray(result.nodes) ? result.nodes : [];
    const edges = Array.isArray(result.edges) ? result.edges : [];

    const canonicalIoc = result && typeof result.ioc === 'string'
      ? result.ioc.trim()
      : (result && result.ioc != null ? String(result.ioc).trim() : null);
    const canonicalIpValue = typeof ipValue === 'string'
      ? ipValue.trim()
      : (ipValue != null ? String(ipValue).trim() : null);

    nodes.forEach((n) => {
      if (!n || !n.id) return;
      if (!this.graphNodes.get(n.id)) {
        this.graphNodes.add({
          id: n.id,
          label: n.label || n.id,
          group: n.type || 'unknown',
          title: n.type ? `${n.type}: ${n.label || n.id}` : n.label || n.id
        });
      }
    });

    edges.forEach((edge) => {
      if (!edge) return;
      const fromMatchesCanonical =
        (canonicalIoc != null && edge.from === canonicalIoc) ||
        (canonicalIpValue != null && edge.from === canonicalIpValue);
      const toMatchesCanonical =
        (canonicalIoc != null && edge.to === canonicalIoc) ||
        (canonicalIpValue != null && edge.to === canonicalIpValue);
      const fromId = fromMatchesCanonical ? ipNodeId : edge.from;
      const toId = toMatchesCanonical ? ipNodeId : edge.to;
      const effectiveLabel = edge.label || 'enrich';
      const edgeDescriptor = {
        from: fromId,
        to: toId,
        label: effectiveLabel,
        source: edge.properties?.source || ''
      };
      const computedEdgeId = 'edge_' + MD5.hash(JSON.stringify(edgeDescriptor));
      const edgeId = edge.id || computedEdgeId;
      if (!this.graphEdges.get(edgeId)) {
        this.graphEdges.add({
          id: edgeId,
          from: fromId,
          to: toId,
          label: effectiveLabel,
          title: edge.properties?.source || effectiveLabel,
          dashes: edge.dashes || false
        });
      }
    });
  }

  async triggerHashEnrichment(hashValue, nodeId) {
    const ok = await this._ensureConsent('enrichment'); if (!ok) return;
    this.showNotification('Enriching hash...', 'info');
    chrome.runtime.sendMessage({ action: 'agentEnrich', iocType: 'hash', ioc: hashValue }, (res) => {
      void chrome.runtime.lastError;
      if (!res || res.status === 'error') {
        this.showNotification(this.buildEnrichmentErrorMessage(res), 'error');
        return;
      }
      this.applyAgentResultToGraph(res, nodeId, hashValue);
      this.showEnrichmentPanel(res);
      const risk = res.summary?.riskScore !== undefined ? res.summary.riskScore : 'n/a';
      this.showNotification(`Hash enriched (risk: ${risk})`, 'success');
    });
  }

  async triggerDomainEnrichment(domainValue, nodeId) {
    const ok = await this._ensureConsent('enrichment'); if (!ok) return;
    this.showNotification('Enriching domain...', 'info');
    chrome.runtime.sendMessage({ action: 'agentEnrich', iocType: 'domain', ioc: domainValue }, (res) => {
      void chrome.runtime.lastError;
      if (!res || res.status === 'error') {
        this.showNotification(this.buildEnrichmentErrorMessage(res), 'error');
        return;
      }
      this.applyAgentResultToGraph(res, nodeId, domainValue);
      this.showEnrichmentPanel(res);
      const subs = res.summary?.subdomains || 0;
      const ips = res.summary?.resolvedIPs || 0;
      this.showNotification(`Domain enriched (${ips} IPs, ${subs} subdomains)`, 'success');
    });
  }

  async triggerUrlEnrichment(urlValue, nodeId) {
    const ok = await this._ensureConsent('enrichment'); if (!ok) return;
    this.showNotification('Enriching URL...', 'info');
    chrome.runtime.sendMessage({ action: 'agentEnrich', iocType: 'url', ioc: urlValue }, (res) => {
      void chrome.runtime.lastError;
      if (!res || res.status === 'error') {
        this.showNotification(this.buildEnrichmentErrorMessage(res), 'error');
        return;
      }
      this.applyAgentResultToGraph(res, nodeId, urlValue);
      this.showEnrichmentPanel(res);
      const verdict = res.summary?.verdict || 'unknown';
      const risk = res.summary?.riskScore !== undefined ? res.summary.riskScore : 'n/a';
      this.showNotification(`URL enriched — verdict: ${verdict} (risk: ${risk})`, 'success');
    });
  }

  showEnrichmentPanel(result) {
    const panel = document.getElementById('enrichmentDetailPanel');
    const iocLabel = document.getElementById('enrichmentPanelIoc');
    const verdictBadge = document.getElementById('enrichmentVerdictBadge');
    const riskFill = document.getElementById('enrichmentRiskFill');
    const riskScore = document.getElementById('enrichmentRiskScore');
    const sourceCards = document.getElementById('enrichmentSourceCards');
    const timestamp = document.getElementById('enrichmentTimestamp');
    const body = document.getElementById('enrichmentPanelBody');
    const chevron = document.getElementById('enrichmentPanelChevron');
    if (!panel) return;

    if (iocLabel) iocLabel.textContent = `${result.iocType?.toUpperCase() || 'IOC'}: ${result.ioc || ''}`;
    const verdict = result.summary?.verdict || 'unknown';
    if (verdictBadge) {
      verdictBadge.textContent = verdict;
      verdictBadge.className = `enrichment-verdict-badge ${verdict}`;
    }

    const risk = result.summary?.riskScore ?? 0;
    if (riskFill) {
      riskFill.style.width = `${Math.min(100, risk)}%`;
      riskFill.className = `enrichment-risk-fill ${risk >= 75 ? 'high' : risk >= 40 ? 'medium' : 'low'}`;
    }
    if (riskScore) riskScore.textContent = risk;

    if (timestamp) {
      const t = result.timestamp ? new Date(result.timestamp) : new Date();
      timestamp.textContent = t.toLocaleTimeString();
    }

    if (sourceCards) {
      const sources = Array.isArray(result.sources) ? result.sources : [];
      sourceCards.innerHTML = sources.map((s) => {
        const statusClass = s.status || 'error';
        const dataLines = s.data ? Object.entries(s.data)
          .filter(([, v]) => v !== null && v !== undefined && v !== '')
          .slice(0, 6)
          .map(([k, v]) => `<span><b>${this.escapeHtml(k)}:</b> ${typeof v === 'object' ? this.escapeHtml(JSON.stringify(v)) : this.escapeHtml(String(v).slice(0, 80))}</span>`)
          .join('') : '';
        // Defense-in-depth: only render apiUrl if it is an https:// deep link, so a
        // future provider cannot accidentally turn the Source button into a
        // javascript: URL via attribute interpolation.
        const safeApiUrl = (typeof s.apiUrl === 'string' && s.apiUrl.startsWith('https://'))
          ? s.apiUrl
          : '';
        const apiLink = safeApiUrl
          ? `<a class="source-link" href="${this.escapeHtml(safeApiUrl)}" target="_blank" rel="noopener noreferrer" title="${this.escapeHtml(safeApiUrl)}"><i class="fa-solid fa-arrow-up-right-from-square"></i> Source</a>`
          : '';
        const cachedBadge = s.cached ? '<span class="source-cached-badge">cached</span>' : '';
        const safeProvider = String(s.provider || 'src').replace(/[^a-z0-9]/gi, '_');
        const rawId = `raw_${safeProvider}_${Date.now()}`;
        const rawJson = JSON.stringify(s.data || {}, null, 2).slice(0, 2000);
        return `
<div class="enrichment-source-card">
  <div class="source-header">
    <span class="source-name">${this.escapeHtml(s.displayName || s.provider || 'Unknown')}</span>
    <span class="source-status ${this.escapeHtml(statusClass)}">${this.escapeHtml(statusClass)}</span>
  </div>
  ${s.status === 'error' ? `<div style="color:var(--danger-color);font-size:11px;">${this.escapeHtml(s.errorMessage || 'Unknown error')}</div>` : ''}
  <div class="source-data">${dataLines || '<span style="color:var(--text-secondary);">No data</span>'}</div>
  <div class="source-meta">
    ${apiLink}
    ${cachedBadge}
    <button class="enrichment-raw-toggle" data-raw-target="${this.escapeHtml(rawId)}">View JSON</button>
  </div>
  <pre class="enrichment-raw-json" id="${this.escapeHtml(rawId)}">${this.escapeHtml(rawJson)}</pre>
</div>`;
      }).join('');

      // Wire up the View JSON toggle buttons via addEventListener instead of
      // inline onclick attributes — keeps CSP-friendly and removes any XSS risk
      // from attribute interpolation.
      sourceCards.querySelectorAll('.enrichment-raw-toggle').forEach((btn) => {
        btn.addEventListener('click', () => {
          const targetId = btn.getAttribute('data-raw-target');
          if (!targetId) return;
          const el = document.getElementById(targetId);
          if (!el) return;
          el.classList.toggle('open');
          btn.textContent = el.classList.contains('open') ? 'Hide JSON' : 'View JSON';
        });
      });
    }

    panel.style.display = 'block';
    if (body) body.classList.add('open');
    if (chevron) chevron.style.transform = 'rotate(90deg)';

    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    panel._lastResult = result;
  }

  updateGraphVisibility() {
    const graphContainer = document.getElementById('iocGraph');
    const enableGraphToggle = document.getElementById('enableGraphToggle');

    if (enableGraphToggle) {
      enableGraphToggle.checked = this.enableGraph;
    }

    if (graphContainer) {
      if (this.enableGraph) {
        graphContainer.classList.add('active');
      } else {
        graphContainer.classList.remove('active');
      }
    }
  }

  clearGraph() {
    const graphContainer = document.getElementById('iocGraph');

    // Destroy the existing graph instance
    if (this.iocGraph) {
      this.iocGraph.destroy();
      this.iocGraph = null;
    }

    // Clear the graph container
    if (graphContainer) {
      graphContainer.innerHTML = '';
      graphContainer.classList.remove('active');
    }

    this.showNotification('Graph visualization cleared', 'success');
  }

  // === Investigation Notes ===
  async loadNotes() {
    try {
      const result = await new Promise(resolve => {
        chrome.storage.local.get(['investigationNotes'], resolve);
      });
      return result.investigationNotes || [];
    } catch (error) {
      console.error('Failed to load notes:', error);
      return [];
    }
  }

  async saveNotes(notes) {
    try {
      await new Promise(resolve => {
        chrome.storage.local.set({ investigationNotes: notes }, resolve);
      });
    } catch (error) {
      console.error('Failed to save notes:', error);
    }
  }

  async displayNotes() {
    const notes = await this.loadNotes();
    const notesList = document.getElementById('notesList');

    if (!notesList) return;

    if (notes.length === 0) {
      notesList.innerHTML = '<div style="color: var(--muted-text); text-align: center; padding: 20px;">No investigation notes yet</div>';
      return;
    }

    notesList.innerHTML = notes.map((note, index) => {
      // Parse timestamp and content safely
      const timestampMatch = note.match(/^\[([^\]]+)\]\s*(.*)$/s);
      let dateStr = '';
      let noteContent = note;
      if (timestampMatch) {
        try {
          dateStr = new Date(timestampMatch[1]).toLocaleString();
          noteContent = timestampMatch[2] || '';
        } catch {
          dateStr = 'Invalid date';
        }
      }
      // Escape HTML to prevent XSS
      const escapedContent = this.escapeHtml(noteContent);
      return `
      <div class="note-item" style="border-bottom: 1px solid #374151; padding: 8px; margin-bottom: 8px;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 8px;">
          <div style="flex: 1;">
            <div style="color: var(--muted-text); font-size: 11px; margin-bottom: 4px;">
              ${this.escapeHtml(dateStr)}
            </div>
            <div style="color: var(--text-color); font-size: 13px; white-space: pre-wrap;">
              ${escapedContent}
            </div>
          </div>
          <button class="note-delete-btn" data-note-index="${index}" style="background: var(--danger-color); color: white; border: none; border-radius: 3px; padding: 2px 6px; font-size: 10px; cursor: pointer;">
            <i class="fa-solid fa-trash"></i>
          </button>
        </div>
      </div>`;
    }).join('');

    // Event delegation — MV3 extension-page CSP blocks inline onclick handlers.
    if (this._notesListClickHandler) {
      notesList.removeEventListener('click', this._notesListClickHandler);
    }
    this._notesListClickHandler = (e) => {
      const btn = e.target.closest('.note-delete-btn');
      if (!btn) return;
      const index = parseInt(btn.dataset.noteIndex, 10);
      if (Number.isFinite(index)) this.deleteNote(index);
    };
    notesList.addEventListener('click', this._notesListClickHandler);
  }

  showAddNoteModal() {
    const modal = document.getElementById('noteModal');
    const textarea = document.getElementById('newNoteText');
    if (modal && textarea) {
      modal.style.display = 'block';
      textarea.value = '';
      textarea.focus();
    }
  }

  hideAddNoteModal() {
    const modal = document.getElementById('noteModal');
    if (modal) {
      modal.style.display = 'none';
    }
  }

  async saveNote() {
    const textarea = document.getElementById('newNoteText');
    if (!textarea || !textarea.value.trim()) return;

    const notes = await this.loadNotes();
    const timestamp = new Date().toISOString();
    const newNote = `[${timestamp}] ${textarea.value.trim()}`;

    notes.push(newNote);
    await this.saveNotes(notes);
    await this.displayNotes();
    this.hideAddNoteModal();
    this.showStatus('Note added successfully', 'success');
  }

  async deleteNote(index) {
    const notes = await this.loadNotes();
    notes.splice(index, 1);
    await this.saveNotes(notes);
    await this.displayNotes();
    this.showStatus('Note deleted', 'success');
  }

  async exportNotes() {
    const notes = await this.loadNotes();
    if (notes.length === 0) {
      this.showStatus('No notes to export', 'warning');
      return;
    }

    const exportData = {
      exportDate: new Date().toISOString(),
      notesCount: notes.length,
      notes: notes
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
      type: 'application/json'
    });

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `investigation-notes-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);

    this.showStatus('Notes exported successfully', 'success');
  }

  async clearAllNotes() {
    if (confirm('Are you sure you want to delete all investigation notes? This cannot be undone.')) {
      await this.saveNotes([]);
      await this.displayNotes();
      this.showStatus('All notes cleared', 'success');
    }
  }

  // === File Hash Analysis ===
  selectFile() {
    const fileInput = document.getElementById('fileHashInput');
    if (fileInput) {
      fileInput.click();
    }
  }

  handleFileSelection(event) {
    const file = event.target.files[0];
    const fileNameSpan = document.getElementById('selectedFileName');
    const hashBtn = document.getElementById('hashFileBtn');
    const resultsDiv = document.getElementById('fileHashResults');

    if (file) {
      fileNameSpan.textContent = `${file.name} (${this.formatFileSize(file.size)})`;
      hashBtn.style.display = 'inline-block';
      resultsDiv.style.display = 'none';
      this.selectedFile = file;
    } else {
      fileNameSpan.textContent = '';
      hashBtn.style.display = 'none';
      resultsDiv.style.display = 'none';
      this.selectedFile = null;
    }
  }

  formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  async hashSelectedFile() {
    if (!this.selectedFile) return;

    const hashBtn = document.getElementById('hashFileBtn');
    const resultsDiv = document.getElementById('fileHashResults');
    const outputDiv = document.getElementById('fileHashOutput');

    // Show loading state
    hashBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Calculating...';
    hashBtn.disabled = true;

    try {
      const arrayBuffer = await this.selectedFile.arrayBuffer();

      // Calculate hashes. MD5 is intentionally omitted: the Web Crypto API does
      // not implement it, and the popup's FNV-1a `MD5` helper is a 32-bit
      // identifier — not a real MD5 — so surfacing it as a file MD5 would emit a
      // bogus IOC.
      const [sha1Hash, sha256Hash] = await Promise.all([
        this.calculateHash(arrayBuffer, 'SHA-1'),
        this.calculateHash(arrayBuffer, 'SHA-256')
      ]);

      const results = `File: ${this.selectedFile.name}
Size: ${this.formatFileSize(this.selectedFile.size)}
SHA1:   ${sha1Hash}
SHA256: ${sha256Hash}
Type:   ${this.selectedFile.type || 'Unknown'}`;

      outputDiv.textContent = results;
      resultsDiv.style.display = 'block';
      this.fileHashResults = results;

      this.showStatus('File hashes calculated successfully', 'success');
    } catch (error) {
      console.error('Error calculating file hashes:', error);
      this.showStatus('Failed to calculate file hashes', 'error');
    } finally {
      // Restore button state
      hashBtn.innerHTML = '<i class="fa-solid fa-calculator"></i> Calculate Hashes';
      hashBtn.disabled = false;
    }
  }

  async calculateHash(arrayBuffer, algorithm) {
    try {
      const hashBuffer = await crypto.subtle.digest(algorithm, arrayBuffer);
      return this.bufferToHex(hashBuffer);
    } catch (error) {
      console.error(`Error calculating ${algorithm}:`, error);
      return 'Error calculating hash';
    }
  }

  // Helper function to convert buffer to hex string efficiently
  bufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    const hexParts = [];
    for (let i = 0; i < bytes.length; i++) {
      hexParts.push(bytes[i].toString(16).padStart(2, '0'));
    }
    return hexParts.join('');
  }

  copyFileHashes() {
    if (this.fileHashResults) {
      navigator.clipboard.writeText(this.fileHashResults).then(() => {
        this.showStatus('File hashes copied to clipboard', 'success');
      }).catch(() => {
        this.showStatus('Failed to copy to clipboard', 'error');
      });
    }
  }
}

// Initialize the toolkit
// Initialize the toolkit
const toolkit = new SOCToolkit();

// --- Snippet preset helpers (module scope) ---
const SNIPPET_PRESETS = {
  internal: {
    ext: 'json',
    export: (snips) => JSON.stringify(snips, null, 2),
    import: (data) => Array.isArray(data) ? data : []
  },
  vscode: {
    ext: 'code-snippets.json',
    export: (snips) => {
      const out = {};
      snips.forEach(s => {
        out[s.name || `snippet_${s.id || Date.now()}`] = {
          prefix: s.trigger || '',
          body: (typeof s.content === 'string') ? s.content.split('\n') : s.content,
          description: s.description || ''
        };
      });
      return JSON.stringify(out, null, 2);
    },
    import: (data) => {
      if (!data || typeof data !== 'object' || Array.isArray(data)) return [];
      return Object.keys(data).map(key => {
        const v = data[key] || {};
        return {
          id: `import-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          name: key,
          trigger: v.prefix || '',
          content: Array.isArray(v.body) ? v.body.join('\n') : (v.body || ''),
          description: v.description || ''
        };
      });
    }
  }
};

function downloadFile(filename, text) {
  const blob = new Blob([text], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function exportSnippetsPreset(presetKey = 'internal') {
  const preset = SNIPPET_PRESETS[presetKey] || SNIPPET_PRESETS.internal;
  chrome.storage.local.get('snippets', (res) => {
    const snippets = Array.isArray(res.snippets) ? res.snippets : [];
    const payload = preset.export(snippets);
    const filename = `soc-snippets-${presetKey}.${preset.ext}`;
    downloadFile(filename, payload);
  });
}

function importSnippetsPreset(presetKey = 'internal', options = { merge: true }) {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json,application/json';
  input.onchange = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (evt) => {
      try {
        const raw = evt.target.result;
        const parsed = JSON.parse(raw);
        const preset = SNIPPET_PRESETS[presetKey] || SNIPPET_PRESETS.internal;
        const imported = preset.import(parsed);
        const normalized = imported.map(s => ({
          id: s.id || `imp-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          name: s.name || 'Unnamed',
          trigger: s.trigger || '',
          content: s.content || '',
          description: s.description || ''
        }));
        chrome.storage.local.get('snippets', (res) => {
          const existing = Array.isArray(res.snippets) ? res.snippets : [];
          const combined = options.merge ? existing.concat(normalized) : normalized;
          chrome.storage.local.set({ snippets: combined }, () => {
            // refresh the UI if toolkit exists
            try { toolkit.displaySnippets(); } catch (e) { }
            try { toolkit.showNotification('Snippets imported', 'success'); } catch (e) { }
          });
        });
      } catch (err) {
        console.error('Import failed', err);
        try { toolkit.showNotification('Failed to import snippets: invalid file', 'error'); } catch (e) { }
      }
    };
    reader.readAsText(file);
  };
  input.click();
}

// Wire up preset controls for the existing Import/Export buttons (will run in page scope)
document.addEventListener('DOMContentLoaded', () => {
  const presetSelect = document.getElementById('snippetPresetSelect');
  const importModeSelect = document.getElementById('importModeSelect');
  if (presetSelect) {
    document.getElementById('exportBtn')?.addEventListener('click', () => {
      const p = presetSelect.value || 'internal';
      exportSnippetsPreset(p);
    });
    document.getElementById('importBtn')?.addEventListener('click', () => {
      const p = presetSelect.value || 'internal';
      const mode = importModeSelect?.value === 'replace' ? { merge: false } : { merge: true };
      importSnippetsPreset(p, mode);
    });
  }
});
