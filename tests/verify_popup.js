'use strict';
/**
 * SOC Analyst Toolkit - popup.js VM Harness Tests (IOC dedupe)
 *
 * Loads the real popup.js via tests/popup_harness.js — no mocks of the
 * extraction pipeline. Run with: node tests/verify_popup.js
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { loadPopupToolkit } = require('./popup_harness.js');

let passed = 0;
let failed = 0;

// Same runner shape as verify_features.js, awaitable so tests that share the
// stubbed textarea run in order.
function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      console.log('[PASS]', name);
      passed++;
    })
    .catch((e) => {
      console.error('[FAIL]', name);
      console.error('  ', e.message);
      failed++;
    });
}

async function main() {
  const { toolkit, document, storage, globals, tabCreates, closeCalls, sidePanelOpens, sidePanelBehavior } = await loadPopupToolkit(path.join(__dirname, '..'));

  const makeRow = (value, type) => ({
    dataset: {},
    querySelector(sel) {
      if (sel === '.ioc-value') return { textContent: value };
      if (sel === '.ioc-type') return { textContent: type };
      return null;
    },
  });

  const withNotes = (fn) => {
    const notes = [];
    const original = toolkit.showNotification;
    toolkit.showNotification = (msg) => notes.push(msg);
    return Promise.resolve()
      .then(fn)
      .finally(() => { toolkit.showNotification = original; })
      .then(() => notes);
  };

  console.log('=== SOC Analyst Toolkit - popup.js IOC Dedupe Tests ===\n');

  await test('canary: patterns initialized and real TLD set loaded', () => {
    assert.ok(toolkit.patterns, 'toolkit.patterns missing');
    assert.ok(toolkit.tlds && toolkit.tlds.size > 100,
      'tlds.size=' + (toolkit.tlds && toolkit.tlds.size));
  });

  await test('same IPv4 twice on one line yields exactly 1 result', () => {
    const iocs = toolkit.extractIOCs('Connection from 192.168.1.1 and again 192.168.1.1');
    const count = iocs.filter(i => i.type === 'IPv4' && i.value === '192.168.1.1').length;
    assert.strictEqual(count, 1, `expected 1, got ${count}: ` + JSON.stringify(iocs));
  });

  await test('same IPv4 on two lines yields exactly 1 result', () => {
    const iocs = toolkit.extractIOCs('src 192.168.1.1\ndst 192.168.1.1');
    const count = iocs.filter(i => i.type === 'IPv4' && i.value === '192.168.1.1').length;
    assert.strictEqual(count, 1, `expected 1, got ${count}: ` + JSON.stringify(iocs));
  });

  await test('case-differing IPv6 duplicates yield exactly 1 IPv6 row', () => {
    const iocs = toolkit.extractIOCs('2001:DB8::1 and 2001:db8::1');
    const v6 = iocs.filter(i => i.type === 'IPv6');
    assert.strictEqual(v6.length, 1, `expected 1, got ${v6.length}: ` + JSON.stringify(iocs));
  });

  await test('distinct IOCs survive: URL row and its host IP both present', () => {
    const iocs = toolkit.extractIOCs('https://example.com/path from 1.2.3.4');
    assert.ok(iocs.some(i => i.type === 'URL' && i.value === 'https://example.com/path'),
      'URL row missing: ' + JSON.stringify(iocs));
    assert.ok(iocs.some(i => i.type === 'IPv4' && i.value === '1.2.3.4'),
      'IPv4 row missing: ' + JSON.stringify(iocs));
  });

  await test('hash repeated twice yields exactly 1 result', () => {
    const md5 = 'd41d8cd98f00b204e9800998ecf8427e';
    const iocs = toolkit.extractIOCs(`Hash: ${md5} and again ${md5}`);
    const count = iocs.filter(i => i.type === 'MD5' && i.value === md5).length;
    assert.strictEqual(count, 1, `expected 1, got ${count}: ` + JSON.stringify(iocs));
  });

  await test('domain containment preserved: no standalone Domain row for URL host', () => {
    const iocs = toolkit.extractIOCs('Visit https://example.com/path');
    const domain = iocs.find(i => i.type === 'Domain' && i.value === 'example.com');
    assert.ok(!domain, 'standalone Domain row must not appear: ' + JSON.stringify(iocs));
  });

  await test('dedupe button collapses identical lines, keeping first occurrence case', () => {
    const ta = document.getElementById('iocInput');
    ta.value = 'EVIL.com\nevil.com';
    toolkit.autoAnalyze = false;
    toolkit.deduplicateIOCs();
    assert.strictEqual(ta.value, 'EVIL.com', 'got ' + JSON.stringify(ta.value));
  });

  await test('dedupe button notification counts only real duplicates', () => {
    const ta = document.getElementById('iocInput');
    ta.value = 'evil.com\n\n';
    toolkit.autoAnalyze = false;
    const notes = [];
    const original = toolkit.showNotification;
    toolkit.showNotification = (msg) => notes.push(msg);
    try {
      toolkit.deduplicateIOCs();
    } finally {
      toolkit.showNotification = original;
    }
    assert.ok(/Removed 0 duplicate/.test(notes[0] || ''),
      'message should report 0 removed, got: ' + notes[0]);
  });

  await test('IPv6 acceptance table extracts full addresses', () => {
    const table = [
      ['ip 2001:db8::1', '2001:db8::1'],
      ['ip fe80::1', 'fe80::1'],
      ['host ::ffff:192.168.1.1 seen', '::ffff:192.168.1.1'],
      ['ip 2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'],
      ['ip 2001:db8:0:1:1:1:1:1', '2001:db8:0:1:1:1:1:1'],
      ['loopback ::1 ok', '::1'],
    ];
    for (const [text, expected] of table) {
      const rows = toolkit.extractIOCs(text).filter(i => i.type === 'IPv6');
      assert.strictEqual(rows.length, 1, `${text}: expected 1 IPv6 row, got ` + JSON.stringify(rows));
      assert.strictEqual(rows[0].value, expected, `${text}: got ${rows[0].value}`);
    }
  });

  await test('IPv6 uppercase input normalizes to lowercase', () => {
    const rows = toolkit.extractIOCs('IP 2001:DB8::1 end').filter(i => i.type === 'IPv6');
    assert.strictEqual(rows.length, 1, JSON.stringify(rows));
    assert.strictEqual(rows[0].value, '2001:db8::1');
  });

  await test('IPv6 non-addresses produce no IPv6 row', () => {
    for (const text of ['time 12:34:56', 'mac 00:1B:44:11:3A:B7', 'see example.com:8080 now', 'go https://x.com/a:b ok']) {
      const rows = toolkit.extractIOCs(text).filter(i => i.type === 'IPv6');
      assert.strictEqual(rows.length, 0, `${text}: expected 0 IPv6 rows, got ` + JSON.stringify(rows));
    }
  });

  await test('loadSettings syncs restored toggles to their checkboxes', async () => {
    const autoAnalyzeToggle = document.getElementById('autoAnalyzeToggle');
    const autoEnrichToggle = document.getElementById('autoEnrichToggle');
    const graphToggle = document.getElementById('enableGraphToggle');
    autoAnalyzeToggle.checked = true;
    autoEnrichToggle.checked = false;
    graphToggle.checked = true;
    storage.set({ socSettings: { autoAnalyze: false, autoEnrich: true, enableGraph: false, theme: 'arc' } });
    await toolkit.loadSettings();
    assert.strictEqual(autoAnalyzeToggle.checked, false, 'autoAnalyzeToggle not synced');
    assert.strictEqual(autoEnrichToggle.checked, true, 'autoEnrichToggle not synced');
    assert.strictEqual(graphToggle.checked, false, 'enableGraphToggle not synced');
    storage.remove(['socSettings']);
  });

  await test('row enrich sends the refanged value after row defang', () => {
    const listEl = document.getElementById('iocList');
    document.__setQuerySelector('.ioc-list', listEl);
    toolkit.setupResultEventListeners();
    const handler = listEl._listeners.click;
    assert.ok(handler, 'delegated row click handler not bound');
    const sent = [];
    const original = toolkit._batchEnrich;
    toolkit._batchEnrich = (type, values) => sent.push([type, Array.from(values)]);
    const iocItem = {
      getAttribute: (k) => (k === 'data-value' ? '192[.]168[.]1[.]1' : k === 'data-type' ? 'ip' : null),
    };
    const enrichBtn = { closest: (sel) => (sel === '.ioc-item' ? iocItem : null) };
    handler({ target: { closest: (sel) => (sel === '.row-enrich-btn' ? enrichBtn : null) } });
    toolkit._batchEnrich = original;
    document.__setQuerySelector('.ioc-list', null);
    assert.deepStrictEqual(sent, [['ip', ['192.168.1.1']]]);
  });

  await test('row details lookup refangs the defanged row value', () => {
    const listEl = document.getElementById('iocList');
    document.__setQuerySelector('.ioc-list', listEl);
    toolkit.setupResultEventListeners();
    const handler = listEl._listeners.click;
    const stored = { type: 'ip', result: { summary: { verdict: 'malicious' } } };
    toolkit.enrichmentByIoc.set('192.168.1.1', stored);
    const shown = [];
    const original = toolkit.showEnrichmentPanel;
    toolkit.showEnrichmentPanel = (r) => shown.push(r);
    const iocItem = { dataset: { value: '192[.]168[.]1[.]1' } };
    const detailsBtn = { closest: (sel) => (sel === '.ioc-item' ? iocItem : null) };
    handler({ target: { closest: (sel) => (sel === '.row-details-btn' ? detailsBtn : null) } });
    toolkit.showEnrichmentPanel = original;
    document.__setQuerySelector('.ioc-list', null);
    assert.strictEqual(shown[0], stored.result, 'panel should open for the fanged value');
  });

  await test('row enrichment status matches defanged rows by fanged value', () => {
    const cell = { innerHTML: '' };
    const row = {
      dataset: { value: '192[.]168[.]1[.]1' },
      querySelector: (sel) => (sel === '.row-status-cell' ? cell : null),
    };
    document.__setQuerySelectorAll('.ioc-item', [row]);
    toolkit._recordEnrichment('ip', '192.168.1.1', { status: 'success', sources: [] });
    document.__setQuerySelectorAll('.ioc-item', []);
    assert.ok(cell.innerHTML.length > 0, 'status cell should render for the defanged row');
  });

  await test('clearIOCs resets lastIOCs/lastIOCInput and blocks Ask AI', async () => {
    storage.set({ socConsent: { askAi: true } });
    toolkit.lastIOCs = [{ type: 'IPv4', value: '1.2.3.4', category: 'ip' }];
    toolkit.lastIOCInput = '1.2.3.4';
    toolkit._enrichmentRemainder = { ip: ['2.2.2.2'] };
    toolkit._refreshEnrichRemainingItem();
    assert.strictEqual(document.getElementById('enrichRemainingItem').hidden, false);
    const notes = await withNotes(() => {
      toolkit.clearIOCs();
      return toolkit.askAi();
    });
    assert.strictEqual(toolkit.lastIOCs, null, 'lastIOCs must be null after Clear');
    assert.strictEqual(toolkit.lastIOCInput, '', 'lastIOCInput must be empty after Clear');
    assert.strictEqual(JSON.stringify(toolkit._enrichmentRemainder), '{}', 'remainder must reset after Clear');
    assert.strictEqual(document.getElementById('enrichRemainingItem').hidden, true, 'enrich-remaining must hide');
    assert.ok(/No IOCs to analyze/.test(notes.join(' | ')),
      'Ask AI must be blocked after Clear, got: ' + notes.join(' | '));
    storage.remove(['socConsent']);
  });

  await test('new analysis resets the enrichment remainder and hides its menu item', () => {
    toolkit.autoAnalyze = false;
    toolkit.autoEnrich = false;
    document.getElementById('iocInput').value = 'evil.com';
    toolkit._enrichmentRemainder = { domain: ['stale.example.com'] };
    toolkit._refreshEnrichRemainingItem();
    assert.strictEqual(document.getElementById('enrichRemainingItem').hidden, false);
    toolkit.analyzeIOCs();
    assert.strictEqual(JSON.stringify(toolkit._enrichmentRemainder), '{}', 'remainder must reset on new analysis');
    assert.strictEqual(document.getElementById('enrichRemainingItem').hidden, true, 'menu item must hide when empty');
    document.getElementById('iocInput').value = '';
    storage.remove(['lastAnalysisResults', 'savedIOCInput']);
  });

  await test('Export Selected exports only the selected rows', async () => {
    const rows = [makeRow('1.2.3.4', 'IPv4'), makeRow('evil.com', 'Domain'), makeRow('5.6.7.8', 'IPv4')];
    document.__setQuerySelectorAll('.ioc-item', rows);
    document.__setQuerySelectorAll('.ioc-item:not(.empty-state)', rows);
    document.__setQuerySelectorAll('.ioc-item input[type="checkbox"]:checked', [
      { closest: () => rows[0] },
      { closest: () => rows[2] },
    ]);
    const notes = await withNotes(() => toolkit.handleBulkAction('export'));
    assert.ok(/Exported 2 IOCs as CSV/.test(notes.join(' | ')), 'got: ' + notes.join(' | '));
  });

  await test('export skips the empty-state row and warns when nothing to export', async () => {
    document.__setQuerySelectorAll('.ioc-item', [{ dataset: {}, querySelector: () => null }]);
    document.__setQuerySelectorAll('.ioc-item:not(.empty-state)', []);
    document.__setQuerySelectorAll('.ioc-item input[type="checkbox"]:checked', []);
    const notes = await withNotes(() => toolkit.exportIOCs('csv'));
    assert.ok(/No IOCs to export/.test(notes.join(' | ')), 'got: ' + notes.join(' | '));
  });

  await test('snippet Edit under a filter loads the filtered snippet, not array position', () => {
    toolkit.snippets = [
      { name: 'Alpha', content: 'aaa' },
      { name: 'Beta', content: 'bbb' },
    ];
    toolkit.displaySnippets([toolkit.snippets[1]]);
    const handler = document.getElementById('snippetList')._listeners.click;
    assert.ok(handler, 'snippet list click handler not bound');
    const item = {
      dataset: { index: '0' },
      querySelector: () => ({ classList: { toggle() {} } }),
    };
    handler({ target: { closest: (sel) => (sel === '.snippet-item' ? item : sel === '.action-edit' ? {} : null) } });
    assert.strictEqual(document.getElementById('snippetNameInput').value, 'Beta');
    assert.strictEqual(document.getElementById('snippetContentInput').value, 'bbb');
    assert.strictEqual(document.getElementById('snippetEditor').dataset.editIndex, '1');
  });

  await test('snippet Save under a filter overwrites the edited snippet only', async () => {
    document.getElementById('snippetNameInput').value = 'BetaEdited';
    document.getElementById('snippetContentInput').value = 'bbb-edited';
    await toolkit.saveSnippetFromEditor();
    assert.strictEqual(toolkit.snippets[0].name, 'Alpha');
    assert.strictEqual(toolkit.snippets[0].content, 'aaa');
    assert.strictEqual(toolkit.snippets[1].name, 'BetaEdited');
    assert.strictEqual(toolkit.snippets[1].content, 'bbb-edited');
    storage.remove(['snippets']);
  });

  await test("theme 'system' persists as 'system' and applies the resolved theme", async () => {
    const themeSelect = document.getElementById('themeSelect');
    const change = themeSelect._listeners.change;
    assert.ok(change, 'theme select change handler not bound');
    change({ target: { value: 'system' } });
    await new Promise((resolve) => setTimeout(resolve, 10));
    const stored = await new Promise((resolve) => storage.get(['socSettings'], resolve));
    assert.strictEqual(stored.socSettings && stored.socSettings.theme, 'system',
      'persisted theme: ' + JSON.stringify(stored.socSettings));
    assert.strictEqual(document.body.getAttribute('data-theme'), 'coffee',
      'body must carry the resolved theme');
    assert.strictEqual(toolkit.currentTheme, 'system');
    await toolkit.loadSettings();
    assert.strictEqual(themeSelect.value, 'system', 'select must show system after reload');
    storage.remove(['socSettings']);
  });

  await test('Copy Crypto matches bitcoin/ethereum rows', async () => {
    document.__setQuerySelectorAll('.ioc-item', [
      makeRow('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', 'bitcoin'),
      makeRow('0x742d35cc6634c0532925a3b844bc9e7595f0beb0', 'ethereum'),
    ]);
    const notes = await withNotes(() => toolkit.copyIOCsByType('crypto'));
    assert.ok(/^Copied 2 cryptos/.test(notes[0] || ''), 'got: ' + (notes[0] || 'none'));
  });

  await test('snippet import reloads snippets from storage before rendering', async () => {
    storage.set({ snippets: [{ name: 'Existing', content: 'x' }] });
    await toolkit.loadSnippets();
    assert.strictEqual(toolkit.snippets.length, 1);
    assert.strictEqual(typeof globals.importSnippetsPreset, 'function');
    globals.importSnippetsPreset('internal', { merge: true });
    const input = document.__lastCreated;
    assert.ok(input && typeof input.onchange === 'function', 'import input not created');
    input.onchange({ target: { files: [{ __text: JSON.stringify([{ name: 'Imported', content: 'y' }]) }] } });
    await new Promise((resolve) => setTimeout(resolve, 30));
    assert.ok(toolkit.snippets.some((s) => s.name === 'Imported'),
      'toolkit.snippets should reload from storage: ' + JSON.stringify(toolkit.snippets));
    assert.ok(document.getElementById('snippetList').innerHTML.includes('Imported'),
      'snippet list should render the imported snippet');
    storage.remove(['snippets']);
  });

  await test('OSINT drag-reorder moves items to the drop target', () => {
    const sources = () => [
      { name: 'A', types: 'domain', url: 'https://a.test/?q=%s' },
      { name: 'B', types: 'domain', url: 'https://b.test/?q=%s' },
      { name: 'C', types: 'domain', url: 'https://c.test/?q=%s' },
    ];
    toolkit.customOsintSources = sources();
    const items = [0, 1, 2].map((i) => ({
      dataset: { osintIndex: String(i) },
      classList: { add() {}, remove() {} },
      _handlers: {},
      addEventListener(type, fn) { this._handlers[type] = fn; },
      removeEventListener(type) { delete this._handlers[type]; },
    }));
    const container = document.getElementById('osintSourcesList');
    container.__setQuerySelectorAll('.osint-source-item', items);
    toolkit.displayCustomOsintSources();
    const drop = (dst, src) => items[dst]._handlers.drop({
      preventDefault() {},
      dataTransfer: { getData: () => String(src) },
    });
    drop(2, 0);
    assert.deepStrictEqual(toolkit.customOsintSources.map((s) => s.name), ['B', 'A', 'C'],
      'downward move: ' + JSON.stringify(toolkit.customOsintSources.map((s) => s.name)));
    toolkit.customOsintSources = sources();
    toolkit.displayCustomOsintSources();
    drop(0, 2);
    assert.deepStrictEqual(toolkit.customOsintSources.map((s) => s.name), ['C', 'A', 'B'],
      'upward move: ' + JSON.stringify(toolkit.customOsintSources.map((s) => s.name)));
    storage.remove(['customOsintSources']);
  });

  await test('displayIOCResults resets the Select All checkbox on a new render', () => {
    const resultsContainer = document.getElementById('iocResults');
    const listEl = document.getElementById('iocList');
    resultsContainer.__setQuerySelector('.ioc-list', listEl);
    document.__setQuerySelector('.ioc-count', document.getElementById('iocCount'));
    document.__setQuerySelectorAll('.ioc-item', []);
    const selectAll = document.getElementById('selectAllIOCs');
    selectAll.checked = true;
    toolkit.enableGraph = false;
    toolkit.displayIOCResults([{ type: 'IPv4', value: '1.2.3.4', category: 'ip' }]);
    resultsContainer.__setQuerySelector('.ioc-list', null);
    document.__setQuerySelector('.ioc-count', null);
    toolkit.enableGraph = true;
    assert.strictEqual(selectAll.checked, false, 'Select All must reset when rows render unchecked');
  });

  await test('loadAndShowPdnsAsnCache lists entries and opens the modal', async () => {
    const now = Date.now();
    storage.set({
      'pdns_cache_evil.com': { provider: 'virustotal', records: [{ ip: '1.2.3.4' }, { ip: '5.6.7.8' }], timestamp: now - 2 * 3600000 },
      'asn_cache_8.8.8.8': { asn: { number: 'AS15169', name: 'GOOGLE' }, timestamp: now },
      'pdns_cache_evil&co.example': { records: [], timestamp: now },
    });
    await toolkit.loadAndShowPdnsAsnCache();
    const modal = document.getElementById('pdnsAsnCacheModal');
    const list = document.getElementById('pdnsCacheList');
    assert.strictEqual(modal.style.display, 'flex', 'modal must be shown');
    const html = list.innerHTML;
    assert.ok(html.includes('PDNS') && html.includes('evil.com'), 'pdns entry missing: ' + html);
    assert.ok(html.includes('2 records'), 'record count missing: ' + html);
    assert.ok(html.includes('2h ago'), 'pdns age missing: ' + html);
    assert.ok(html.includes('ASN') && html.includes('8.8.8.8'), 'asn entry missing: ' + html);
    assert.ok(html.includes('AS15169') && html.includes('GOOGLE'), 'asn summary missing: ' + html);
    assert.ok(html.includes('just now'), 'asn age missing: ' + html);
    assert.ok(html.includes('evil&amp;co.example') && !html.includes('evil&co.example'),
      'IOC value must be escaped: ' + html);
    storage.remove(['pdns_cache_evil.com', 'asn_cache_8.8.8.8', 'pdns_cache_evil&co.example']);
  });

  await test('loadAndShowPdnsAsnCache shows the empty message when nothing is cached', async () => {
    await toolkit.loadAndShowPdnsAsnCache();
    const list = document.getElementById('pdnsCacheList');
    assert.ok(/No cached entries/.test(list.innerHTML), 'empty message missing: ' + list.innerHTML);
    assert.strictEqual(document.getElementById('pdnsAsnCacheModal').style.display, 'flex');
  });

  await test('extractIOCsFromText refangs defanged input before extraction', () => {
    toolkit.autoAnalyze = false;
    toolkit.extractIOCsFromText('hxxps://evil[.]example[.]com/login from 185.220.101.34');
    const value = document.getElementById('iocInput').value;
    assert.ok(value.includes('https://evil.example.com/login'), 'URL missing: ' + JSON.stringify(value));
    assert.ok(value.includes('185.220.101.34'), 'IP missing: ' + JSON.stringify(value));
    document.getElementById('iocInput').value = '';
    storage.remove(['lastAnalysisResults', 'savedIOCInput']);
  });

  console.log('\n--- OSINT links keep the popup open ---');

  await test('osint link left-click opens a background tab instead of navigating', () => {
    const handler = document._listeners.click;
    assert.ok(handler, 'delegated document click handler not bound');
    let prevented = false;
    const anchor = { href: 'https://www.virustotal.com/gui/ip/1.2.3.4' };
    handler({
      button: 0,
      ctrlKey: false, metaKey: false, shiftKey: false, altKey: false,
      target: { closest: (sel) => (sel === 'a[target="_blank"]' ? anchor : null) },
      preventDefault: () => { prevented = true; },
    });
    assert.strictEqual(prevented, true, 'native navigation must be prevented');
    assert.strictEqual(tabCreates.length, 1, 'exactly one tab: ' + JSON.stringify(tabCreates));
    assert.strictEqual(tabCreates[0].url, 'https://www.virustotal.com/gui/ip/1.2.3.4');
    assert.strictEqual(tabCreates[0].active, false, 'default must open in the background');
    tabCreates.length = 0;
  });

  await test('osint link opens in the foreground when the setting is off', () => {
    const handler = document._listeners.click;
    toolkit.osintLinksBackground = false;
    try {
      handler({
        button: 0,
        target: { closest: () => ({ href: 'https://urlscan.io/search/#evil.com' }) },
        preventDefault() {},
      });
    } finally {
      toolkit.osintLinksBackground = true;
    }
    assert.strictEqual(tabCreates.length, 1);
    assert.strictEqual(tabCreates[0].active, true, 'setting off must focus the tab');
    tabCreates.length = 0;
  });

  await test('modifier clicks keep native browser behavior', () => {
    const handler = document._listeners.click;
    let prevented = false;
    const ev = (mods) => ({
      button: 0, ...mods,
      target: { closest: () => ({ href: 'https://www.shodan.io/host/1.2.3.4' }) },
      preventDefault: () => { prevented = true; },
    });
    handler(ev({ ctrlKey: true }));
    handler(ev({ metaKey: true }));
    handler(ev({ shiftKey: true }));
    handler(ev({ altKey: true }));
    assert.strictEqual(prevented, false, 'modifiers must not be intercepted');
    assert.strictEqual(tabCreates.length, 0, 'no programmatic tab opens: ' + JSON.stringify(tabCreates));
  });

  await test("bulk 'osint' action routes selected rows through the same setting", () => {
    const vtLink = { href: 'https://www.virustotal.com/gui/domain/evil.com' };
    const row = {
      querySelector: (sel) => (sel === '.osint-link[href*="virustotal.com"]'
        ? vtLink
        : sel === '.ioc-value' ? { textContent: 'evil.com' } : null),
    };
    document.__setQuerySelectorAll('.ioc-item input[type="checkbox"]:checked', [{ closest: () => row }]);
    toolkit.handleBulkAction('osint');
    document.__setQuerySelectorAll('.ioc-item input[type="checkbox"]:checked', []);
    assert.strictEqual(tabCreates.length, 1, 'one tab per selected row: ' + JSON.stringify(tabCreates));
    assert.strictEqual(tabCreates[0].url, 'https://www.virustotal.com/gui/domain/evil.com');
    assert.strictEqual(tabCreates[0].active, false, 'bulk opens must honor the background default');
    tabCreates.length = 0;
  });

  await test('osintLinksBackground persists through saveSettings/loadSettings', async () => {
    storage.set({ socSettings: { osintLinksBackground: false } });
    await toolkit.loadSettings();
    assert.strictEqual(toolkit.osintLinksBackground, false, 'stored false must load');
    assert.strictEqual(document.getElementById('osintLinksBackgroundToggle').checked, false,
      'checkbox must sync to the restored state');
    const change = document.getElementById('osintLinksBackgroundToggle')._listeners.change;
    assert.ok(change, 'osint background toggle change handler not bound');
    change({ target: { checked: true } });
    const stored = await new Promise((resolve) => storage.get(['socSettings'], resolve));
    assert.strictEqual(stored.socSettings.osintLinksBackground, true, 'toggle must persist');
    storage.remove(['socSettings']);
  });

  console.log('\n--- floating window ---');

  const floatKit = await loadPopupToolkit(path.join(__dirname, '..'), { float: true });

  await test('loading with ?float=1 sets floatMode, the body class and the window id', () => {
    assert.strictEqual(floatKit.toolkit.floatMode, true, 'float flag must set floatMode');
    assert.strictEqual(floatKit.document.body.classList.contains('floating'), true, 'body must carry floating');
    assert.strictEqual(floatKit.toolkit._floatWindowId, 42, 'window id cached from chrome.windows.getCurrent');
  });

  await test('toolbar load keeps floating off the body and the grip unwired', () => {
    assert.strictEqual(toolkit.floatMode, false);
    assert.strictEqual(document.body.classList.contains('floating'), false, 'toolbar body must not carry floating');
    assert.strictEqual(document.getElementById('floatResizeGrip')._listeners.pointerdown, undefined,
      'grip must not be wired outside floating mode');
  });

  await test('clampWindowSize enforces the min and max table', () => {
    // Field-wise: deepStrictEqual fails cross-realm (vm prototypes).
    const belowMin = toolkit.clampWindowSize(100, 100);
    assert.strictEqual(belowMin.width, 380);
    assert.strictEqual(belowMin.height, 420);
    const aboveMax = toolkit.clampWindowSize(3000, 2000);
    assert.strictEqual(aboveMax.width, 2400);
    assert.strictEqual(aboveMax.height, 1600);
    const inRange = toolkit.clampWindowSize(800, 600);
    assert.strictEqual(inRange.width, 800);
    assert.strictEqual(inRange.height, 600);
  });

  await test('Escape in toolbar clears IOCs; in floating it closes the window', () => {
    const keydown = document._listeners.keydown;
    assert.ok(keydown, 'global keydown handler not bound');
    let cleared = 0;
    const originalClear = toolkit.clearIOCs;
    toolkit.clearIOCs = () => { cleared++; };
    try {
      keydown({ key: 'Escape' });
    } finally {
      toolkit.clearIOCs = originalClear;
    }
    assert.strictEqual(cleared, 1, 'toolbar Esc must clear the analysis');
    assert.strictEqual(closeCalls.length, 0, 'toolbar Esc must not close the window');

    let floatCleared = 0;
    const originalFloatClear = floatKit.toolkit.clearIOCs;
    floatKit.toolkit.clearIOCs = () => { floatCleared++; };
    try {
      floatKit.document._listeners.keydown({ key: 'Escape' });
    } finally {
      floatKit.toolkit.clearIOCs = originalFloatClear;
    }
    assert.strictEqual(floatKit.closeCalls.length, 1, 'floating Esc must close the window');
    assert.strictEqual(floatCleared, 0, 'floating Esc must not clear the analysis');
  });

  await test('Escape in floating dismisses an open shortcuts modal instead of closing', () => {
    const modal = floatKit.document.getElementById('keyboardShortcutsModal');
    const closesBefore = floatKit.closeCalls.length;
    modal.style.display = 'flex';
    floatKit.document._listeners.keydown({ key: 'Escape' });
    assert.strictEqual(modal.style.display, 'none', 'modal must close');
    assert.strictEqual(floatKit.closeCalls.length, closesBefore, 'window must stay open while a modal shows');
  });

  await test('dragging the resize grip updates the window with clamped, throttled sizes', async () => {
    const grip = floatKit.document.getElementById('floatResizeGrip');
    const { pointerdown: down, pointermove: move, pointerup: up } = grip._listeners;
    assert.ok(down && move && up, 'grip pointer handlers not bound');
    floatKit.globals.innerWidth = 800;
    floatKit.globals.innerHeight = 600;
    floatKit.toolkit._floatWindowId = 42;
    down({ button: 0, pointerId: 7, clientX: 200, clientY: 150, preventDefault() {} });
    move({ pointerId: 7, clientX: -300, clientY: -500 });
    assert.strictEqual(floatKit.windowUpdates.length, 1, 'one update per move');
    assert.deepStrictEqual(floatKit.windowUpdates[0], { id: 42, width: 380, height: 420 },
      'sizes must clamp to the minimum: ' + JSON.stringify(floatKit.windowUpdates[0]));
    move({ pointerId: 7, clientX: 0, clientY: 0 });
    assert.strictEqual(floatKit.windowUpdates.length, 1, 'a move while in flight is deferred, not sent');
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.strictEqual(floatKit.windowUpdates.length, 2, 'the deferred size coalesces into exactly one update');
    assert.deepStrictEqual(floatKit.windowUpdates[1], { id: 42, width: 600, height: 450 },
      'the coalesced update carries the latest clamped size');
    up({ pointerId: 7 });
    move({ pointerId: 7, clientX: 0, clientY: 0 });
    assert.strictEqual(floatKit.windowUpdates.length, 2, 'no updates after pointerup');
    floatKit.windowUpdates.length = 0;
  });

  console.log('\n--- sidebar navigation ---');

  await test('navLayout: seeded sidebar adds the body class, default stays absent', async () => {
    assert.strictEqual(document.body.classList.contains('nav-sidebar'), false, 'default must be tabs');
    storage.set({ socSettings: { navLayout: 'sidebar' } });
    await toolkit.loadSettings();
    assert.strictEqual(toolkit.navLayout, 'sidebar');
    assert.strictEqual(document.body.classList.contains('nav-sidebar'), true, 'sidebar must tag the body');
    storage.set({ socSettings: { navLayout: 'tabs' } });
    await toolkit.loadSettings();
    assert.strictEqual(toolkit.navLayout, 'tabs');
    assert.strictEqual(document.body.classList.contains('nav-sidebar'), false, 'tabs must drop the class');
    storage.remove(['socSettings']);
  });

  await test('flipping the nav radio persists the choice and toggles the class', async () => {
    const sidebarRadio = document.getElementById('navLayoutSidebar');
    const tabsRadio = document.getElementById('navLayoutTabs');
    const sidebarChange = sidebarRadio._listeners.change;
    assert.ok(sidebarChange, 'nav sidebar radio change handler not bound');
    // A real browser checks the radio before dispatching change.
    sidebarRadio.checked = true;
    tabsRadio.checked = false;
    sidebarChange({ target: sidebarRadio });
    assert.strictEqual(toolkit.navLayout, 'sidebar');
    assert.strictEqual(document.body.classList.contains('nav-sidebar'), true);
    const stored = await new Promise((resolve) => storage.get(['socSettings'], resolve));
    assert.strictEqual(stored.socSettings.navLayout, 'sidebar', 'choice must persist');

    const tabsChange = tabsRadio._listeners.change;
    assert.ok(tabsChange, 'nav tabs radio change handler not bound');
    tabsRadio.checked = true;
    sidebarRadio.checked = false;
    tabsChange({ target: tabsRadio });
    assert.strictEqual(toolkit.navLayout, 'tabs');
    assert.strictEqual(document.body.classList.contains('nav-sidebar'), false, 'class must drop on tabs');
    storage.remove(['socSettings']);
  });

  await test('applyWindowLayout keeps floating and nav classes independent', () => {
    toolkit.navLayout = 'sidebar';
    toolkit.applyWindowLayout();
    assert.strictEqual(document.body.classList.contains('nav-sidebar'), true);
    assert.strictEqual(document.body.classList.contains('floating'), false, 'toolbar stays non-floating');
    toolkit.navLayout = 'tabs';
    toolkit.applyWindowLayout();
    assert.strictEqual(document.body.classList.contains('nav-sidebar'), false);
  });

  console.log('\n--- side panel ---');

  const panelKit = await loadPopupToolkit(path.join(__dirname, '..'), { panel: true });

  await test('loading with ?panel=1 sets panelMode and the body class', () => {
    assert.strictEqual(panelKit.toolkit.panelMode, true, 'panel flag must set panelMode');
    assert.strictEqual(panelKit.document.body.classList.contains('panel'), true, 'body must carry panel');
    assert.strictEqual(toolkit.panelMode, false, 'toolbar load stays non-panel');
    assert.strictEqual(document.body.classList.contains('panel'), false, 'toolbar body must not carry panel');
  });

  await test('_openSidePanel opens the side panel for the current window', async () => {
    await toolkit._openSidePanel();
    assert.strictEqual(sidePanelOpens.length, 1,
      'exactly one open call, got: ' + JSON.stringify(sidePanelOpens));
    // Field-wise: deepStrictEqual fails cross-realm (vm prototypes).
    assert.strictEqual(sidePanelOpens[0].windowId, 42, 'must pass the current window id');
  });

  await test('the sidePanel header button is wired to _openSidePanel', async () => {
    const click = document.getElementById('sidePanelBtn')._listeners.click;
    assert.ok(click, 'sidePanelBtn click handler not bound');
    await click();
    assert.strictEqual(sidePanelOpens.length, 2, 'click must open the panel');
  });

  await test('actionOpensPanel toggle persists and switches the action behavior', async () => {
    const change = document.getElementById('actionOpensPanelToggle')._listeners.change;
    assert.ok(change, 'actionOpensPanel change handler not bound');
    change({ target: { checked: true } });
    assert.strictEqual(toolkit.actionOpensPanel, true, 'state must update');
    assert.strictEqual(sidePanelBehavior[sidePanelBehavior.length - 1].openPanelOnActionClick, true,
      'setPanelBehavior must follow the checkbox');
    const stored = await new Promise((resolve) => storage.get(['socSettings'], resolve));
    assert.strictEqual(stored.socSettings.actionOpensPanel, true, 'choice must persist');
    change({ target: { checked: false } });
    assert.strictEqual(toolkit.actionOpensPanel, false);
    assert.strictEqual(sidePanelBehavior[sidePanelBehavior.length - 1].openPanelOnActionClick, false);
    storage.remove(['socSettings']);
  });

  await test('side panel entries hide when chrome.sidePanel is missing (Firefox)', async () => {
    const ffKit = await loadPopupToolkit(path.join(__dirname, '..'), { noSidePanel: true });
    for (const id of ['sidePanelBtn', 'sidePanelRow', 'actionOpensPanelRow']) {
      assert.strictEqual(ffKit.document.getElementById(id).style.display, 'none', id + ' must hide');
    }
  });

  console.log('\n--- tools tab ---');

  const textTool = (id) => {
    const tool = toolkit.TEXT_TOOLS && toolkit.TEXT_TOOLS.find(t => t.id === id);
    assert.ok(tool, 'TEXT_TOOLS must define ' + id);
    return tool;
  };
  const makeTab = (id) => {
    const classes = new Set();
    return {
      id,
      style: {},
      classList: {
        toggle(name, force) {
          const on = force === undefined ? !classes.has(name) : Boolean(force);
          if (on) classes.add(name); else classes.delete(name);
        },
        contains: (name) => classes.has(name),
      },
    };
  };

  await test('TEXT_TOOLS base64 encode/decode round-trips unicode input', async () => {
    const sample = 'héllo wörld ✓ 日本語';
    const encoded = await textTool('base64_encode').fn(sample);
    assert.notStrictEqual(encoded, sample, 'sample must actually be encoded');
    assert.strictEqual(await textTool('base64_decode').fn(encoded), sample);
  });

  await test('TEXT_TOOLS defang/refang round-trips URLs and emails', async () => {
    const sample = 'https://evil.example.com/login?a=b user@evil.example.com';
    const defanged = await textTool('defang').fn(sample);
    assert.ok(defanged.includes('hxxps://') && defanged.includes('[.]'), defanged);
    assert.strictEqual(await textTool('refang').fn(defanged), sample);
  });

  await test('TEXT_TOOLS sha1/sha256 of "abc" match the known digests', async () => {
    assert.strictEqual(await textTool('sha256_text').fn('abc'),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    assert.strictEqual(await textTool('sha1_text').fn('abc'),
      'a9993e364706816aba3e25717850c26c9cd0d89d');
  });

  await test('TEXT_TOOLS jwt_decode pretty-prints header and payload', async () => {
    const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const token = `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url({ sub: '1234567890', name: 'John Doe', iat: 1516239022 })}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`;
    const out = await textTool('jwt_decode').fn(token);
    assert.ok(/Header:/.test(out) && /Payload:/.test(out), out);
    assert.ok(out.includes('"alg": "HS256"'), out);
    assert.ok(out.includes('"name": "John Doe"'), out);
    await assert.rejects(() => textTool('jwt_decode').fn('not-a-jwt'), /JWT/);
  });

  await test('TEXT_TOOLS unix_to_utc auto-detects seconds and milliseconds', async () => {
    assert.strictEqual(await textTool('unix_to_utc').fn('1700000000'), '2023-11-14T22:13:20.000Z');
    assert.strictEqual(await textTool('unix_to_utc').fn('1700000000000'), '2023-11-14T22:13:20.000Z');
  });

  await test('TEXT_TOOLS utc_to_unix emits both seconds and milliseconds', async () => {
    const out = await textTool('utc_to_unix').fn('2023-11-14T22:13:20Z');
    assert.ok(out.includes('1700000000'), out);
    assert.ok(out.includes('1700000000000'), out);
  });

  await test('TEXT_TOOLS rot13 round-trips and leaves non-letters alone', async () => {
    const sample = 'Attack at Dawn! 123';
    const once = await textTool('rot13').fn(sample);
    assert.strictEqual(once, 'Nggnpx ng Qnja! 123');
    assert.strictEqual(await textTool('rot13').fn(once), sample);
  });

  await test('runTextTool surfaces a decode error instead of throwing', async () => {
    document.getElementById('transformInput').value = '!!!';
    document.getElementById('transformOp').value = 'base64_decode';
    await toolkit.runTextTool();
    const errorEl = document.getElementById('transformError');
    assert.ok(errorEl.textContent.length > 0, 'error message must be shown');
    assert.strictEqual(errorEl.style.display, 'block', 'error must be visible');
    assert.strictEqual(document.getElementById('transformOutput').textContent, '');
  });

  await test('runTextTool renders output and clears a previous error on success', async () => {
    document.getElementById('transformInput').value = 'a<b>&c';
    document.getElementById('transformOp').value = 'base64_encode';
    await toolkit.runTextTool();
    const errorEl = document.getElementById('transformError');
    assert.strictEqual(errorEl.textContent, '');
    assert.strictEqual(errorEl.style.display, 'none');
    assert.ok(document.getElementById('transformOutput').textContent.length > 0);
  });

  await test('runRegex returns matches with index and capture groups', () => {
    const r = toolkit.runRegex('(\\w+)@(\\w+\\.com)', 'g', 'mail foo@bar.com and baz@qux.com end');
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.matches.length, 2);
    assert.strictEqual(r.matches[0].text, 'foo@bar.com');
    assert.strictEqual(r.matches[0].index, 5);
    assert.strictEqual(r.matches[0].groups.length, 2);
    assert.strictEqual(r.matches[0].groups[0], 'foo');
    assert.strictEqual(r.matches[0].groups[1], 'bar.com');
    assert.strictEqual(r.matches[1].text, 'baz@qux.com');
    assert.strictEqual(r.matches[1].index, 21);
  });

  await test('runRegex reports invalid patterns without throwing', () => {
    const r = toolkit.runRegex('[unclosed', 'g', 'sample text');
    assert.strictEqual(r.matches.length, 0);
    assert.ok(typeof r.error === 'string' && r.error.length > 0, 'expected an error string');
  });

  await test('unfurlUrl decodes encoded query parameter values', () => {
    const u = toolkit.unfurlUrl('https://example.com:8443/a/b.php?x=1%20plus&q=a%26b%3Dc#frag');
    assert.strictEqual(u.error, null);
    assert.strictEqual(u.parts.scheme, 'https');
    assert.strictEqual(u.parts.host, 'example.com');
    assert.strictEqual(u.parts.port, '8443');
    assert.strictEqual(u.parts.path, '/a/b.php');
    assert.strictEqual(u.parts.fragment, 'frag');
    assert.strictEqual(u.params.find((p) => p[0] === 'x')[1], '1 plus');
    assert.strictEqual(u.params.find((p) => p[0] === 'q')[1], 'a&b=c');
  });

  await test('unfurlUrl reports a parse error for non-URLs', () => {
    const u = toolkit.unfurlUrl('not a url');
    assert.ok(typeof u.error === 'string' && u.error.length > 0);
    assert.strictEqual(u.parts, null);
  });

  await test('extract-URLs lists every URL found in the text, refanging first', () => {
    document.getElementById('urlUnfurlInput').value =
      'see https://a.com/x?t=1 and hxxp://b[.]com/y plus plain words';
    toolkit.renderExtractedUrls();
    const html = document.getElementById('urlUnfurlResults').innerHTML;
    assert.ok(html.includes('https://a.com/x?t=1'), html);
    assert.ok(html.includes('http://b.com/y'), html);
    assert.ok(html.includes('<span>2</span>'), 'count must report 2 URLs: ' + html);
  });

  await test('transform and preset selects are populated from the registries', () => {
    const opSel = document.getElementById('transformOp');
    for (const t of toolkit.TEXT_TOOLS) {
      assert.ok(opSel.innerHTML.includes(`value="${t.id}"`), t.id + ' missing from the operation select');
    }
    const presetSel = document.getElementById('regexPresetSelect');
    for (const p of toolkit.REGEX_PRESETS) {
      assert.ok(presetSel.innerHTML.includes(`value="${p.id}"`), p.id + ' missing from the preset select');
    }
  });

  await test('switchTab("tools") activates the tools tab panel', () => {
    const iocTab = makeTab('ioc-tab');
    const toolsTab = makeTab('tools-tab');
    document.__setQuerySelectorAll('.tab-content', [iocTab, toolsTab]);
    document.__setQuerySelectorAll('.tab-btn', []);
    toolkit.switchTab('tools');
    document.__setQuerySelectorAll('.tab-content', []);
    document.__setQuerySelectorAll('.tab-btn', []);
    assert.strictEqual(toolkit.currentTab, 'tools');
    assert.strictEqual(toolsTab.classList.contains('active'), true, 'tools-tab must activate');
    assert.strictEqual(toolsTab.style.display, 'block');
    assert.strictEqual(iocTab.classList.contains('active'), false, 'ioc-tab must deactivate');
  });

  await test('Alt+3 keydown switches to the tools tab', () => {
    const keydown = document._listeners.keydown;
    assert.ok(keydown, 'global keydown handler not bound');
    keydown({ altKey: true, key: '3', target: { matches: () => false }, preventDefault() {} });
    assert.strictEqual(toolkit.currentTab, 'tools', 'Alt+3 must open the tools tab');
  });

  await test('file-hash buttons stay bound after the move to the tools tab', () => {
    assert.ok(document.getElementById('selectFileBtn')._listeners.click, 'selectFileBtn click handler not bound');
    assert.ok(document.getElementById('hashFileBtn')._listeners.click, 'hashFileBtn click handler not bound');
    assert.ok(document.getElementById('fileHashInput')._listeners.change, 'fileHashInput change handler not bound');
  });

  await test('popup.html: notes markup removed, tools markup present, file hash inside tools', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'popup.html'), 'utf8');
    for (const gone of ['notes-tab', 'notesContainer', 'notesList', 'noteModal', 'newNoteText',
      'addNoteBtn', 'exportNotesBtn', 'clearNotesBtn', 'cancelNoteBtn', 'saveNoteBtn', 'data-tab="notes"']) {
      assert.ok(!html.includes(gone), gone + ' must be gone from popup.html');
    }
    assert.ok(html.includes('data-tab="tools"'));
    assert.ok(html.includes('aria-controls="tools-tab"'));
    assert.ok(html.includes('fa-screwdriver-wrench'));
    assert.ok(html.includes('id="tools-tab"'));
    const toolsAt = html.indexOf('id="tools-tab"');
    const hashAt = html.indexOf('id="fileHashInput"');
    const settingsAt = html.indexOf('id="settings-tab"');
    assert.ok(toolsAt !== -1 && hashAt !== -1 && settingsAt !== -1);
    assert.ok(toolsAt < hashAt && hashAt < settingsAt, 'file-hash block must live inside the tools tab');
    assert.ok(!/>Notes tab</.test(html), 'shortcuts must no longer reference a Notes tab');
    assert.ok(/>Tools tab</.test(html), 'shortcuts must reference the Tools tab');
  });

  await test('one-time cleanup drops a stored investigationNotes key on init', async () => {
    const seeded = await loadPopupToolkit(path.join(__dirname, '..'), {
      seed: { investigationNotes: ['[2026-01-01T00:00:00.000Z] orphaned note'] },
    });
    const stored = await new Promise((resolve) => seeded.storage.get(['investigationNotes'], resolve));
    assert.strictEqual(stored.investigationNotes, undefined, 'notes key must be removed after init');
  });

  console.log('\nTest Summary:');
  console.log('  Passed:', passed);
  console.log('  Failed:', failed);
  console.log('========================================');
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error('Harness failure:', e);
  process.exit(1);
});
