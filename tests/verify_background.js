/**
 * SOC Analyst Toolkit - Background Service Worker Tests
 *
 * Loads the REAL background.js via tests/background_harness.js and verifies
 * the enrichment bug fixes (edge ids, error classification, VT attribute
 * shapes, URLhaus statuses, cache eviction, and rate-limit fallbacks).
 * Run with: node tests/verify_background.js
 */

const assert = require('assert');
const path = require('path');
const { loadBackgroundToolkit, jsonResponse } = require('./background_harness');

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log('[PASS]', name);
    passed++;
  } catch (e) {
    console.error('[FAIL]', name);
    console.error('  ', e && e.message ? e.message : e);
    failed++;
  }
}

(async () => {
  const root = path.join(__dirname, '..');
  const bg = await loadBackgroundToolkit(root);
  const { fns, storageData, RATE_LIMITS } = bg;

  console.log('=== Background Service Worker Tests ===\n');

  console.log('--- dedupeById ---');

  await test('dedupeById keeps id-bearing items and drops id-less ones (current behavior)', () => {
    // Field-wise assertions: deepStrictEqual fails cross-realm (vm prototypes).
    const out = fns.dedupeById([{ id: 'edge_1_geo', label: 'x' }, { label: 'no-id' }, { id: 'edge_1_geo', label: 'dup' }]);
    assert.strictEqual(out.length, 1);
    assert.strictEqual(out[0].id, 'edge_1_geo');
    assert.strictEqual(out[0].label, 'x');
  });

  console.log('\n--- urlscan.io edge ids ---');

  await test('fetchURLscan: urlscan edges carry deterministic ids and survive dedupeById', async () => {
    bg.resetState();
    const url = 'https://example.com/';
    bg.setFetchImpl((input) => {
      const u = String(input);
      if (u === 'https://urlscan.io/api/v1/scan/') {
        return jsonResponse({
          api: 'https://urlscan.io/api/v1/',
          result: 'https://urlscan.io/api/v1/result/uuid/',
          uuid: 'uuid'
        });
      }
      if (u.startsWith('https://urlscan.io/api/v1/result/')) {
        return jsonResponse({
          page: { domain: 'example.com', ip: '1.2.3.4' },
          verdicts: { overall: { score: 0, malicious: false, categories: [] } },
          data: { requests: [] }
        });
      }
      throw new Error('unexpected fetch: ' + u);
    });
    const res = await fns.fetchURLscan(url, 'test-key');
    assert.strictEqual(res.status, 'success');
    assert.strictEqual(res.edges.length, 2, 'expected domain + ip edges');
    for (const e of res.edges) {
      assert.ok(typeof e.id === 'string' && e.id, 'edge missing deterministic id');
    }
    assert.ok(res.edges.some((e) => e.id === `edge_${fns.vtUrlId(url)}_domain`), 'domain edge id');
    assert.ok(res.edges.some((e) => e.id === `edge_${fns.vtUrlId(url)}_ip`), 'ip edge id');
    assert.strictEqual(fns.dedupeById(res.edges).length, 2, 'edges must survive dedupeById');
  });

  console.log('\n--- VirusTotal URL id ---');

  await test('fetchVirusTotalUrl: non-latin1 URL encodes via vtUrlId without throwing', async () => {
    bg.resetState();
    const url = 'https://例.com/a';
    let requested = null;
    bg.setFetchImpl((input) => {
      requested = String(input);
      return jsonResponse({ data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 } } } });
    });
    const res = await fns.fetchVirusTotalUrl(url, 'test-key');
    assert.ok(requested && requested.includes(fns.vtUrlId(url)), 'requested URL must contain vtUrlId, got ' + requested);
    assert.strictEqual(res.status, 'success');
  });

  await test('fetchVirusTotalUrl: ASCII URL encodes to the VT base64url id', async () => {
    bg.resetState();
    let requested = null;
    bg.setFetchImpl((input) => { requested = String(input); return jsonResponse({ data: { attributes: {} } }); });
    await fns.fetchVirusTotalUrl('http://www.google.com/', 'test-key');
    assert.ok(requested.includes('aHR0cDovL3d3dy5nb29nbGUuY29tLw'), 'unexpected url: ' + requested);
  });

  console.log('\n--- VirusTotal IP attributes ---');

  await test('fetchVirusTotalIp: network is the CIDR string and rir comes from regional_internet_registry', async () => {
    bg.resetState();
    bg.setFetchImpl(() => jsonResponse({
      data: { attributes: { asn: 15169, as_owner: 'Google LLC', network: '81.169.128.0/17', regional_internet_registry: 'RIPE NCC' } }
    }));
    const res = await fns.fetchVirusTotalIp('8.8.8.8', 'test-key');
    assert.strictEqual(res.status, 'success');
    const asnNode = res.nodes.find((n) => n.type === 'asn');
    assert.ok(asnNode, 'asn node expected');
    assert.strictEqual(asnNode.properties.network, '81.169.128.0/17');
    assert.strictEqual(asnNode.properties.rir, 'RIPE NCC');
  });

  console.log('\n--- HTTP error classification ---');

  await test('fetchVirusTotalIp: 401 maps to API_KEY_INVALID (not NETWORK_ERROR)', async () => {
    bg.resetState();
    bg.setFetchImpl(() => jsonResponse({}, { status: 401, statusText: 'Unauthorized' }));
    const res = await fns.fetchVirusTotalIp('8.8.8.8', 'test-key');
    assert.strictEqual(res.status, 'error');
    assert.strictEqual(res.errorCode, 'API_KEY_INVALID');
    assert.ok(/HTTP 401/.test(res.errorMessage || ''), 'message keeps HTTP status: ' + res.errorMessage);
  });

  await test('fetchVirusTotalIp: 429 maps to RATE_LIMIT_EXCEEDED', async () => {
    bg.resetState();
    bg.setFetchImpl(() => jsonResponse({}, { status: 429, statusText: 'Too Many Requests' }));
    const res = await fns.fetchVirusTotalIp('8.8.8.8', 'test-key');
    assert.strictEqual(res.status, 'error');
    assert.strictEqual(res.errorCode, 'RATE_LIMIT_EXCEEDED');
  });

  console.log('\n--- URLhaus query_status ---');

  await test('fetchURLhaus: query_status ok with threat is success', async () => {
    bg.resetState();
    bg.setFetchImpl(() => jsonResponse({ query_status: 'ok', threat: 'malware_download', url_status: 'online', tags: ['elf'] }));
    const res = await fns.fetchURLhaus('https://evil.example/payload');
    assert.strictEqual(res.status, 'success');
    assert.strictEqual(res.data.threat, 'malware_download');
  });

  await test('fetchURLhaus: no_results stays no_data', async () => {
    bg.resetState();
    bg.setFetchImpl(() => jsonResponse({ query_status: 'no_results' }));
    const res = await fns.fetchURLhaus('https://clean.example/');
    assert.strictEqual(res.status, 'no_data');
  });

  await test('fetchURLhaus: offline query_status is an error, not a false all-clear', async () => {
    bg.resetState();
    bg.setFetchImpl(() => jsonResponse({ query_status: 'offline' }));
    const res = await fns.fetchURLhaus('https://evil.example/');
    assert.strictEqual(res.status, 'error');
    assert.ok(/offline/.test(res.errorMessage || ''), 'message includes query_status: ' + res.errorMessage);
  });

  console.log('\n--- agent cache eviction ---');

  await test('agentCacheKeysToPrune: returns exactly the oldest keys beyond the cap, ignores non-agent2_ keys', () => {
    assert.ok(typeof fns.agentCacheKeysToPrune === 'function', 'agentCacheKeysToPrune must exist');
    const data = {};
    for (let i = 1; i <= 1001; i++) data[`agent2_ip_10.0.0.${i}`] = { timestamp: i };
    data['socSettings'] = { timestamp: 0 };
    data['agent_ip_1.2.3.4'] = { timestamp: 99999 };
    const pruned = fns.agentCacheKeysToPrune(data, 1000);
    assert.strictEqual(pruned.length, 1, 'exactly one key beyond the cap');
    assert.strictEqual(pruned[0], 'agent2_ip_10.0.0.1', 'the oldest agent2_ key');
  });

  await test('agentCacheKeysToPrune: fewer than max entries yields nothing', () => {
    assert.strictEqual(fns.agentCacheKeysToPrune({ 'agent2_ip_1.1.1.1': { timestamp: 5 } }, 1000).length, 0);
  });

  await test('setCachedAgentResult: writing past the 1000-entry cap evicts the oldest agent2_ key', async () => {
    bg.resetState();
    for (let i = 1; i <= 1000; i++) {
      storageData[`agent2_ip_10.0.0.${i}`] = { timestamp: i };
    }
    storageData['socSettings'] = { timestamp: 1 };
    await fns.setCachedAgentResult('ip', 'ip', '8.8.8.8', { status: 'success' });
    assert.ok('agent2_ip_ip_8.8.8.8' in storageData, 'new entry must be written');
    assert.ok(!('agent2_ip_10.0.0.1' in storageData), 'oldest entry must be evicted');
    assert.ok('agent2_ip_10.0.0.2' in storageData, 'second-oldest entry kept');
    assert.ok('socSettings' in storageData, 'non-agent keys untouched');
  });

  console.log('\n--- asnEnrich (onMessage listener) ---');

  await test('asnEnrich: ipinfo fallback sets prefix/registry to null (ipinfo has neither field)', async () => {
    bg.resetState();
    storageData['virustotalApiKey'] = 'test-key';
    bg.setFetchImpl((input) => {
      const u = String(input);
      if (u.startsWith('https://www.virustotal.com/api/v3/ip_addresses/')) {
        return jsonResponse({ data: { attributes: {} } });
      }
      if (u.startsWith('https://ipinfo.io/')) {
        return jsonResponse({ org: 'AS15169 Google LLC', ip: '8.8.8.8', country: 'US' });
      }
      throw new Error('unexpected fetch: ' + u);
    });
    const { payload } = await bg.dispatch({ action: 'asnEnrich', ip: '8.8.8.8' });
    assert.ok(payload && payload.asn, 'asn expected: ' + JSON.stringify(payload));
    assert.strictEqual(payload.asn.number, 'AS15169');
    assert.strictEqual(payload.asn.prefix, null, 'prefix must not be faked from the IP');
    assert.strictEqual(payload.asn.registry, null, 'registry must not be faked from the country');
  });

  await test('asnEnrich: VT lookup maps the network CIDR string and sibling registry', async () => {
    bg.resetState();
    storageData['virustotalApiKey'] = 'test-key';
    bg.setFetchImpl((input) => {
      const u = String(input);
      if (u.startsWith('https://www.virustotal.com/api/v3/ip_addresses/')) {
        return jsonResponse({ data: { attributes: { asn: 15169, as_owner: 'Google LLC', network: '8.8.8.0/24', regional_internet_registry: 'ARIN' } } });
      }
      throw new Error('unexpected fetch: ' + u);
    });
    const { payload } = await bg.dispatch({ action: 'asnEnrich', ip: '8.8.4.4' });
    assert.ok(payload && payload.asn, 'asn expected: ' + JSON.stringify(payload));
    assert.strictEqual(payload.asn.number, 'AS15169');
    assert.strictEqual(payload.asn.prefix, '8.8.8.0/24', 'prefix is the network CIDR string');
    assert.strictEqual(payload.asn.registry, 'ARIN', 'registry is regional_internet_registry');
  });

  await test('asnEnrich: no ASN from any source must not write the asn_cache entry', async () => {
    bg.resetState();
    storageData['virustotalApiKey'] = 'test-key';
    bg.setFetchImpl((input) => {
      const u = String(input);
      if (u.startsWith('https://www.virustotal.com/')) return jsonResponse({ data: { attributes: {} } });
      if (u.startsWith('https://ipinfo.io/')) return jsonResponse({ city: 'Mountain View' });
      throw new Error('unexpected fetch: ' + u);
    });
    const { payload } = await bg.dispatch({ action: 'asnEnrich', ip: '9.9.9.9' });
    assert.ok(payload, 'response expected');
    assert.strictEqual(payload.asn, null);
    assert.ok(!('asn_cache_9.9.9.9' in storageData), 'a transient miss must not be cached for 24h');
  });

  await test('asnEnrich: pre-exhausted VT budget falls back to the web UI without issuing a VT fetch', async () => {
    bg.resetState();
    storageData['virustotalApiKey'] = 'test-key';
    bg.exhaustRateLimit('virustotal', RATE_LIMITS.virustotal.requests);
    bg.setFetchImpl(() => { throw new Error('no fetch should be issued when rate-limited'); });
    const { payload } = await bg.dispatch({ action: 'asnEnrich', ip: '8.8.8.8' });
    assert.strictEqual(payload.fallback, 'web');
    assert.strictEqual(payload.opened, true);
    assert.strictEqual(payload.reason, 'rate_limited');
    assert.ok(bg.tabsCreated.some((t) => /virustotal\.com/.test(t.url)), 'VT web UI must open');
    assert.ok(!bg.fetchCalls.some((u) => u.includes('virustotal.com/api/')), 'no VT API fetch expected');
  });

  await test('passiveDnsEnrich: pre-exhausted VT budget falls back to the web UI without issuing a VT fetch', async () => {
    bg.resetState();
    storageData['virustotalApiKey'] = 'test-key';
    bg.exhaustRateLimit('virustotal', RATE_LIMITS.virustotal.requests);
    bg.setFetchImpl(() => { throw new Error('no fetch should be issued when rate-limited'); });
    const { payload } = await bg.dispatch({ action: 'passiveDnsEnrich', domain: 'example.com' });
    assert.strictEqual(payload.fallback, 'web');
    assert.strictEqual(payload.opened, true);
    assert.strictEqual(payload.reason, 'rate_limited');
    assert.ok(!bg.fetchCalls.some((u) => u.includes('virustotal.com/api/')), 'no VT API fetch expected');
  });

  console.log('\n--- onMessage fall-through ---');

  await test('onMessage: unmatched action returns false so the channel closes synchronously', async () => {
    const res = await bg.dispatch({ action: 'definitelyNotAHandler' });
    assert.strictEqual(res.returnValue, false);
    assert.strictEqual(res.payload, undefined);
  });

  console.log('\n--- floating window ---');

  await test('toggleFloat creates the window at popup.html?float=1', async () => {
    const created = [];
    bg.sandbox.chrome.windows.create = async (options) => { created.push(options); return { id: 1 }; };
    await bg.dispatch({ action: 'toggleFloat' });
    assert.ok(created[0] && /popup\.html\?float=1$/.test(created[0].url),
      'window must open the float-flagged URL, got: ' + (created[0] && created[0].url));
  });

  console.log('\nTest Summary:');
  console.log('  Passed:', passed);
  console.log('  Failed:', failed);
  console.log('========================================');

  process.exit(failed > 0 ? 1 : 0);
})().catch((err) => {
  console.error('verify_background crashed:', err);
  process.exit(1);
});
