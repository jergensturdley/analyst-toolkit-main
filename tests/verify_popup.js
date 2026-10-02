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
  const { toolkit, document } = await loadPopupToolkit(path.join(__dirname, '..'));

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
