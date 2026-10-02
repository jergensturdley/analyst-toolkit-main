'use strict';
/**
 * SOC Analyst Toolkit - popup.js VM Harness Tests (IOC dedupe)
 *
 * Loads the real popup.js via tests/popup_harness.js — no mocks of the
 * extraction pipeline. Run with: node tests/verify_popup.js
 */

const assert = require('assert');
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
  const { toolkit, document, storage, globals } = await loadPopupToolkit(path.join(__dirname, '..'));

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
