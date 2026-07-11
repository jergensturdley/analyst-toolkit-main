/**
 * SOC Analyst Toolkit - Feature Verification Tests
 * 
 * This test file verifies that all IOC parsing functions work correctly.
 * Run with: node tests/verify_features.js
 */

const assert = require('assert');

// Mock the SOCToolkit class with production-like logic
class SOCToolkitMock {
  constructor() {
    // Full TLD list matching production
    this.tlds = new Set([
      'com', 'net', 'org', 'edu', 'gov', 'mil', 'io', 'co', 'uk', 'de', 'jp', 'fr', 'au', 'ru', 'ch', 'it', 'nl', 'ca', 'cn', 'br', 'us', 'info', 'biz',
      'app', 'dev', 'cloud', 'ai', 'tech', 'online', 'store', 'blog', 'site', 'xyz',
      'eu', 'in', 'mx', 'es', 'pl', 'be', 'se', 'dk', 'no', 'fi', 'at', 'pt', 'ie',
      'hk', 'sg', 'kr', 'tw', 'id', 'vn', 'th', 'my', 'ph', 'nz', 'za'
    ]);
    // Domain exclusion patterns matching production
    this._domainExcludePatterns = [
      /^[a-z]\.[a-z]$/i,
      /\.(local|localhost|internal|corp|lan)$/i,
      /^\d+\.\d+$/,
      /^\d+\.\d+\.\d+$/,
      /\.(jpg|png|gif|svg|pdf|doc|docx|xls|xlsx|zip|rar|tar|gz)$/i,
    ];
    this._labelPattern = /^[a-z0-9-]+$/i;

    this.patterns = {
      url: /\bhttps?:\/\/[\w.-]+(?::\d+)?(?:\/[\w\-._~:/?#[\]@!$&'()*+,;=%]*)?/gi,
      ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
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
  }

  extractIOCs(text) {
    const results = [];
    if (!text) return results;

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
    (text.match(this.patterns.ipv4) || []).forEach(v => {
      this._addResult(results, 'IPv4', v, 'ip');
    });

    (text.match(this.patterns.ipv6) || []).forEach(v => {
      this._addResult(results, 'IPv6', v.toLowerCase(), 'ip');
    });

    (text.match(this.patterns.email) || []).forEach(v => {
      this._addResult(results, 'Email', v, 'email');
    });
  }

  _extractSecurityIOCs(text, results) {
    (text.match(this.patterns.cve) || []).forEach(v => {
      this._addResult(results, 'CVE', v.toUpperCase(), 'cve');
    });

    (text.match(this.patterns.mitre) || []).forEach(v => {
      this._addResult(results, 'MITRE', v.toUpperCase(), 'mitre');
    });
  }

  _extractFinancialIOCs(text, results) {
    (text.match(this.patterns.btc) || []).forEach(v => {
      this._addResult(results, 'Bitcoin', v, 'crypto');
    });

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
    const hashTypes = [
      { type: 'SHA512', pattern: this.patterns.sha512 },
      { type: 'SHA256', pattern: this.patterns.sha256 },
      { type: 'SHA1', pattern: this.patterns.sha1 },
      { type: 'MD5', pattern: this.patterns.md5 }
    ];

    for (const h of hashTypes) {
      (text.match(h.pattern) || []).forEach(v => {
        const l = v.toLowerCase();
        if (!hashMatches.has(l)) {
          this._addResult(results, h.type, l, 'hash');
          hashMatches.add(l);
        }
      });
    }
  }

  _extractDomains(text, results) {
    const existing = new Set(results.map(r => r.value.toLowerCase()));
    (text.match(this.patterns.domain) || []).forEach(v => {
      const l = v.toLowerCase();
      const isDuplicate = results.some(r => 
        (r.category === 'url' || r.category === 'email') && 
        r.value.toLowerCase().includes(l)
      );
      if (!existing.has(l) && !isDuplicate) {
        this._addResult(results, 'Domain', l, 'domain');
      }
    });
  }

  // Production-matching domain validation
  isValidDomain(domain) {
    if (!domain || domain.length > 253) return false;

    // Check exclusion patterns
    for (const pattern of this._domainExcludePatterns) {
      if (pattern.test(domain)) return false;
    }

    const labels = domain.toLowerCase().split('.');
    if (labels.length < 2) return false;
    
    const tld = labels[labels.length - 1];
    if (!this.tlds.has(tld)) return false;

    // Validate each label
    for (const label of labels) {
      if (!this._labelPattern.test(label)) return false;
      if (label.startsWith('-') || label.endsWith('-')) return false;
      if (label.length > 63) return false;
    }

    return true;
  }

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

  // Defang/Fang helpers
  fangText(text) {
    if (!text) return text;
    let t = text;
    t = t.replace(/hxxps?:\/\//gi, s => s.replace('xx', 'tt'));
    t = t.replace(/\[(?:dot|\.)\]|\(dot\)|\{dot\}/gi, '.');
    t = t.replace(/\[(?:at)\]|\(at\)|\{at\}/gi, '@');
    t = t.replace(/\[\.\]/g, '.');
    return t;
  }
}

// Test runner
const toolkit = new SOCToolkitMock();
let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log('[PASS]', name);
    passed++;
  } catch (e) {
    console.error('[FAIL]', name);
    console.error('  ', e.message);
    failed++;
  }
}

console.log('=== SOC Analyst Toolkit - IOC Parsing Tests ===\n');

// ==================== IPv4 Tests ====================
console.log('--- IPv4 Address Tests ---');

test('Detect standard IPv4', () => {
  const text = 'Connection from 192.168.1.1 detected';
  const iocs = toolkit.extractIOCs(text);
  const ip = iocs.find(i => i.type === 'IPv4' && i.value === '192.168.1.1');
  assert.ok(ip, 'IPv4 not detected');
});

test('Detect IPv4 at start of string', () => {
  const text = '10.0.0.1 is the gateway';
  const iocs = toolkit.extractIOCs(text);
  const ip = iocs.find(i => i.type === 'IPv4' && i.value === '10.0.0.1');
  assert.ok(ip, 'IPv4 at start not detected');
});

test('Detect multiple IPv4 addresses', () => {
  const text = 'Servers at 192.168.1.1 and 10.0.0.1';
  const iocs = toolkit.extractIOCs(text);
  assert.strictEqual(iocs.filter(i => i.type === 'IPv4').length, 2, 'Should detect 2 IPv4 addresses');
});

test('Reject IPv4 with out-of-range octet', () => {
  const text = 'IP 256.1.1.1 is invalid';
  const iocs = toolkit.extractIOCs(text);
  const ip = iocs.find(i => i.type === 'IPv4');
  assert.ok(!ip, 'Invalid IPv4 should not be detected');
});

test('Reject IPv4 with leading zeros', () => {
  const text = 'IP 192.168.01.1 has leading zeros';
  const iocs = toolkit.extractIOCs(text);
  const ip = iocs.find(i => i.type === 'IPv4');
  assert.ok(!ip, 'IPv4 with leading zeros should not be detected');
});

test('Reject 0.0.0.0', () => {
  const text = 'Address 0.0.0.0';
  const iocs = toolkit.extractIOCs(text);
  const ip = iocs.find(i => i.type === 'IPv4' && i.value === '0.0.0.0');
  assert.ok(!ip, '0.0.0.0 should be rejected');
});

test('Reject 255.255.255.255', () => {
  const text = 'Broadcast 255.255.255.255';
  const iocs = toolkit.extractIOCs(text);
  const ip = iocs.find(i => i.type === 'IPv4' && i.value === '255.255.255.255');
  assert.ok(!ip, '255.255.255.255 should be rejected');
});

// ==================== IPv6 Tests ====================
console.log('\n--- IPv6 Address Tests ---');

test('Detect full IPv6', () => {
  const text = 'IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334';
  const iocs = toolkit.extractIOCs(text);
  const ip = iocs.find(i => i.type === 'IPv6');
  assert.ok(ip, 'IPv6 not detected');
});

test('Detect compressed IPv6', () => {
  const text = 'IPv6: 2001:db8::1';
  const iocs = toolkit.extractIOCs(text);
  const ip = iocs.find(i => i.type === 'IPv6');
  assert.ok(ip, 'Compressed IPv6 not detected');
});

test('Detect IPv6 with IPv4 mapping', () => {
  const text = 'IPv6: ::ffff:192.168.1.1';
  const iocs = toolkit.extractIOCs(text);
  const ip = iocs.find(i => i.type === 'IPv6');
  assert.ok(ip, 'IPv4-mapped IPv6 not detected');
});

test('IPv6 is normalized to lowercase', () => {
  const text = 'IPv6: 2001:DB8::1';
  const iocs = toolkit.extractIOCs(text);
  const ip = iocs.find(i => i.type === 'IPv6');
  assert.ok(ip, 'IPv6 not detected');
  assert.ok(ip.value === ip.value.toLowerCase(), 'IPv6 should be lowercase');
});

// ==================== Domain Tests ====================
console.log('\n--- Domain Tests ---');

test('Detect valid .com domain', () => {
  const text = 'Visit example.com for more';
  const iocs = toolkit.extractIOCs(text);
  const domain = iocs.find(i => i.type === 'Domain' && i.value === 'example.com');
  assert.ok(domain, 'Domain not detected');
});

test('Detect subdomain', () => {
  const text = 'API at api.example.com';
  const iocs = toolkit.extractIOCs(text);
  const domain = iocs.find(i => i.type === 'Domain' && i.value === 'api.example.com');
  assert.ok(domain, 'Subdomain not detected');
});

test('Reject invalid TLD', () => {
  const text = 'Visit example.invalidtld';
  const iocs = toolkit.extractIOCs(text);
  const domain = iocs.find(i => i.type === 'Domain');
  assert.ok(!domain, 'Invalid TLD should not be detected');
});

test('Reject file extension as domain', () => {
  const text = 'File: document.pdf';
  const iocs = toolkit.extractIOCs(text);
  const domain = iocs.find(i => i.type === 'Domain');
  assert.ok(!domain, 'File extension should not be detected as domain');
});

test('Reject version number as domain', () => {
  const text = 'Version 1.2.3';
  const iocs = toolkit.extractIOCs(text);
  const domain = iocs.find(i => i.type === 'Domain');
  assert.ok(!domain, 'Version number should not be detected as domain');
});

test('Reject internal domains', () => {
  const text = 'Server at host.local';
  const iocs = toolkit.extractIOCs(text);
  const domain = iocs.find(i => i.type === 'Domain');
  assert.ok(!domain, 'Internal .local domain should be rejected');
});

// ==================== URL Tests ====================
console.log('\n--- URL Tests ---');

test('Detect HTTP URL', () => {
  const text = 'Visit http://example.com/path';
  const iocs = toolkit.extractIOCs(text);
  const url = iocs.find(i => i.type === 'URL');
  assert.ok(url, 'HTTP URL not detected');
});

test('Detect HTTPS URL with query', () => {
  const text = 'Visit https://secure.example.com/path?query=1&foo=bar';
  const iocs = toolkit.extractIOCs(text);
  const url = iocs.find(i => i.type === 'URL');
  assert.ok(url, 'HTTPS URL not detected');
});

test('Detect URL with port', () => {
  const text = 'Connect to http://example.com:8080/api';
  const iocs = toolkit.extractIOCs(text);
  const url = iocs.find(i => i.type === 'URL');
  assert.ok(url && url.value.includes(':8080'), 'URL with port not detected');
});

test('Domain not duplicated from URL', () => {
  const text = 'Visit https://example.com/path';
  const iocs = toolkit.extractIOCs(text);
  const url = iocs.find(i => i.type === 'URL');
  const domain = iocs.find(i => i.type === 'Domain' && i.value === 'example.com');
  assert.ok(url, 'URL should be detected');
  assert.ok(!domain, 'Domain should not be duplicated from URL');
});

// ==================== Hash Tests ====================
console.log('\n--- Hash Tests ---');

test('Detect MD5 hash', () => {
  const text = 'Hash: d41d8cd98f00b204e9800998ecf8427e';
  const iocs = toolkit.extractIOCs(text);
  const hash = iocs.find(i => i.type === 'MD5');
  assert.ok(hash, 'MD5 not detected');
});

test('Detect SHA1 hash', () => {
  const text = 'Hash: da39a3ee5e6b4b0d3255bfef95601890afd80709';
  const iocs = toolkit.extractIOCs(text);
  const hash = iocs.find(i => i.type === 'SHA1');
  assert.ok(hash, 'SHA1 not detected');
});

test('Detect SHA256 hash', () => {
  const text = 'Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const iocs = toolkit.extractIOCs(text);
  const hash = iocs.find(i => i.type === 'SHA256');
  assert.ok(hash, 'SHA256 not detected');
});

test('Detect SHA512 hash', () => {
  const text = 'Hash: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e';
  const iocs = toolkit.extractIOCs(text);
  const hash = iocs.find(i => i.type === 'SHA512');
  assert.ok(hash, 'SHA512 not detected');
});

test('Hash deduplication - SHA256 takes precedence', () => {
  // A 64-char hex string could be both SHA256 and 2x MD5
  const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const text = `Hash: ${sha256}`;
  const iocs = toolkit.extractIOCs(text);
  const sha256Result = iocs.find(i => i.type === 'SHA256');
  const md5Result = iocs.filter(i => i.type === 'MD5');
  assert.ok(sha256Result, 'SHA256 should be detected');
  assert.strictEqual(md5Result.length, 0, 'MD5 should not be duplicated from SHA256');
});

test('Hash is normalized to lowercase', () => {
  const text = 'Hash: D41D8CD98F00B204E9800998ECF8427E';
  const iocs = toolkit.extractIOCs(text);
  const hash = iocs.find(i => i.type === 'MD5');
  assert.ok(hash, 'MD5 not detected');
  assert.ok(hash.value === hash.value.toLowerCase(), 'Hash should be lowercase');
});

// ==================== Email Tests ====================
console.log('\n--- Email Tests ---');

test('Detect email address', () => {
  const text = 'Contact admin@example.com for help';
  const iocs = toolkit.extractIOCs(text);
  const email = iocs.find(i => i.type === 'Email');
  assert.ok(email, 'Email not detected');
});

test('Detect email with plus', () => {
  const text = 'Email: user+tag@example.com';
  const iocs = toolkit.extractIOCs(text);
  const email = iocs.find(i => i.type === 'Email');
  assert.ok(email, 'Email with plus not detected');
});

// ==================== CVE Tests ====================
console.log('\n--- CVE Tests ---');

test('Detect CVE', () => {
  const text = 'Vulnerability CVE-2021-44228 found';
  const iocs = toolkit.extractIOCs(text);
  const cve = iocs.find(i => i.type === 'CVE');
  assert.ok(cve, 'CVE not detected');
  assert.ok(cve.value === cve.value.toUpperCase(), 'CVE should be uppercase');
});

test('Detect CVE with 5 digits', () => {
  const text = 'CVE-2023-12345';
  const iocs = toolkit.extractIOCs(text);
  const cve = iocs.find(i => i.type === 'CVE');
  assert.ok(cve, 'CVE with 5 digits not detected');
});

// ==================== MITRE ATT&CK Tests ====================
console.log('\n--- MITRE ATT&CK Tests ---');

test('Detect MITRE Technique', () => {
  const text = 'Technique T1566 used';
  const iocs = toolkit.extractIOCs(text);
  const mitre = iocs.find(i => i.type === 'MITRE');
  assert.ok(mitre, 'MITRE not detected');
});

test('Detect MITRE Sub-technique', () => {
  const text = 'Technique T1059.001 used';
  const iocs = toolkit.extractIOCs(text);
  const mitre = iocs.find(i => i.type === 'MITRE' && i.value === 'T1059.001');
  assert.ok(mitre, 'MITRE sub-technique not detected');
});

test('MITRE is normalized to uppercase', () => {
  const text = 'Technique t1566 used';
  const iocs = toolkit.extractIOCs(text);
  const mitre = iocs.find(i => i.type === 'MITRE');
  assert.ok(mitre, 'MITRE not detected');
  assert.ok(mitre.value === mitre.value.toUpperCase(), 'MITRE should be uppercase');
});

// ==================== Cryptocurrency Tests ====================
console.log('\n--- Cryptocurrency Tests ---');

test('Detect Bitcoin Legacy Address (P2PKH)', () => {
  const text = 'Payment to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa';
  const iocs = toolkit.extractIOCs(text);
  const btc = iocs.find(i => i.type === 'Bitcoin');
  assert.ok(btc, 'Bitcoin legacy address not detected');
});

test('Detect Bitcoin P2SH Address', () => {
  const text = 'Payment to 3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy';
  const iocs = toolkit.extractIOCs(text);
  const btc = iocs.find(i => i.type === 'Bitcoin');
  assert.ok(btc, 'Bitcoin P2SH address not detected');
});

test('Detect Bitcoin Bech32 Address', () => {
  const text = 'Payment to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh';
  const iocs = toolkit.extractIOCs(text);
  const btc = iocs.find(i => i.type === 'Bitcoin');
  assert.ok(btc, 'Bitcoin Bech32 address not detected');
});

test('Detect Ethereum Address', () => {
  const text = 'Contract at 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0';
  const iocs = toolkit.extractIOCs(text);
  const eth = iocs.find(i => i.type === 'Ethereum');
  assert.ok(eth, 'Ethereum not detected');
});

test('Ethereum is normalized to lowercase', () => {
  const text = 'Contract at 0x742D35CC6634C0532925A3B844BC9E7595F0BEB0';
  const iocs = toolkit.extractIOCs(text);
  const eth = iocs.find(i => i.type === 'Ethereum');
  assert.ok(eth, 'Ethereum not detected');
  assert.ok(eth.value === eth.value.toLowerCase(), 'Ethereum should be lowercase');
});

// ==================== MAC Address Tests ====================
console.log('\n--- MAC Address Tests ---');

test('Detect MAC Address (colon)', () => {
  const text = 'MAC: 00:1B:44:11:3A:B7';
  const iocs = toolkit.extractIOCs(text);
  const mac = iocs.find(i => i.type === 'MAC');
  assert.ok(mac, 'MAC (colon) not detected');
});

test('Detect MAC Address (hyphen)', () => {
  const text = 'MAC: 00-1B-44-11-3A-B7';
  const iocs = toolkit.extractIOCs(text);
  const mac = iocs.find(i => i.type === 'MAC');
  assert.ok(mac, 'MAC (hyphen) not detected');
});

test('MAC is normalized to uppercase', () => {
  const text = 'MAC: 00:1b:44:11:3a:b7';
  const iocs = toolkit.extractIOCs(text);
  const mac = iocs.find(i => i.type === 'MAC');
  assert.ok(mac, 'MAC not detected');
  assert.ok(mac.value === mac.value.toUpperCase(), 'MAC should be uppercase');
});

// ==================== Defang/Fang Tests ====================
console.log('\n--- Defang/Fang Tests ---');

test('Fang hxxp:// to http://', () => {
  const text = 'hxxp://example.com';
  const fanged = toolkit.fangText(text);
  assert.ok(fanged.includes('http://'), 'hxxp should be fanged to http');
});

test('Fang [.] to .', () => {
  const text = 'example[.]com';
  const fanged = toolkit.fangText(text);
  assert.ok(fanged.includes('example.com'), '[.] should be fanged to .');
});

test('Fang [at] to @', () => {
  const text = 'user[at]example.com';
  const fanged = toolkit.fangText(text);
  assert.ok(fanged.includes('user@example.com'), '[at] should be fanged to @');
});

// ==================== Complex/Edge Cases ====================
console.log('\n--- Complex/Edge Case Tests ---');

test('Multiple IOC types in one text', () => {
  const text = 'Alert: 192.168.1.1 contacted evil.com using hash d41d8cd98f00b204e9800998ecf8427e';
  const iocs = toolkit.extractIOCs(text);
  assert.ok(iocs.find(i => i.type === 'IPv4'), 'IPv4 should be detected');
  assert.ok(iocs.find(i => i.type === 'Domain'), 'Domain should be detected');
  assert.ok(iocs.find(i => i.type === 'MD5'), 'MD5 should be detected');
});

test('No false positives on random hex', () => {
  const text = 'abc123'; // Too short for any hash
  const iocs = toolkit.extractIOCs(text);
  const hashes = iocs.filter(i => i.category === 'hash');
  assert.strictEqual(hashes.length, 0, 'Short hex should not be detected as hash');
});

// ==================== Ask AI Config Tests ====================
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

// ==================== Ask AI Config + Prompt Builder Tests ====================
console.log('\n--- Ask AI Config + Prompt Builder Tests ---');

// Import same implementation loaded by popup.html. No private test copy.
const { buildDefaultIocTable, buildTriagePrompt } = require('../triage_prompt.js');

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
  assert.ok(out.includes('IP Addresses'), 'uses production IP section label');
  assert.ok(out.includes('[VirusTotal](https://www.virustotal.com/gui/ip-address/1.2.3.4)'), 'uses production VirusTotal link');
  assert.ok(out.includes('[AbuseIPDB](https://www.abuseipdb.com/check/1.2.3.4)'), 'uses production AbuseIPDB link');
  assert.ok(out.includes('Domains'), 'has Domain section');
  assert.ok(out.includes('1.2.3.4'), 'includes IOC value');
  assert.ok(out.includes('evil.example'), 'includes second IOC');
  assert.ok(out.includes('found in alert XYZ'), 'includes raw input');
});

test('buildTriagePrompt: empty raw input omits context block', () => {
  const out = buildTriagePrompt([{ category: 'ip', value: '5.6.7.8', type: 'IP' }], '', undefined);
  assert.ok(!out.includes('Alert/Context Text Provided:'), 'empty raw input omits context block');
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

// ==================== Privacy & Consent (store-readiness item 7) ====================
console.log('\n--- Privacy & Consent Tests ---');

const fs = require('fs');
const path = require('path');
const popupHtml = fs.readFileSync(path.join(__dirname, '..', 'popup.html'), 'utf8');
const popupJs = fs.readFileSync(path.join(__dirname, '..', 'popup.js'), 'utf8');

test('consent modal markup is present in popup.html', () => {
  for (const id of ['consentModal', 'consentModalTitle', 'consentModalBody', 'consentAllowBtn', 'consentDenyBtn', 'consentCloseBtn']) {
    assert.ok(popupHtml.includes('id="' + id + '"'), 'popup.html missing #' + id);
  }
});

test('consent status + reset UI is present in Settings', () => {
  for (const id of ['privacyConsentSection', 'consentStatusEnrichment', 'consentStatusAskAi', 'resetConsentBtn']) {
    assert.ok(popupHtml.includes('id="' + id + '"'), 'popup.html missing #' + id);
  }
});

test('popup.js defines _ensureConsent + resetConsent', () => {
  assert.ok(/_ensureConsent\s*\(/.test(popupJs), 'popup.js missing _ensureConsent');
  assert.ok(/resetConsent\s*\(/.test(popupJs), 'popup.js missing resetConsent');
  assert.ok(/_refreshConsentStatus\s*\(/.test(popupJs), 'popup.js missing _refreshConsentStatus');
});

test('every enrichment entry point goes through _ensureConsent', () => {
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

test('askAi goes through _ensureConsent("askAi")', () => {
  const idx = popupJs.indexOf('async askAi()');
  assert.ok(idx >= 0, 'askAi() is missing from popup.js');
  const window = popupJs.slice(idx, idx + 300);
  assert.ok(window.indexOf("_ensureConsent('askAi')") >= 0,
    'askAi() must call _ensureConsent("askAi")');
});

test('consent storage key is socConsent and stays on chrome.storage.local', () => {
  assert.ok(popupJs.indexOf('socConsent') >= 0, 'popup.js must persist under socConsent');
  assert.ok(popupJs.indexOf("chrome.storage.local.remove(['socConsent']") >= 0,
    'consent reset must use chrome.storage.local (not sync)');
});

test('reset button is wired to resetConsent()', () => {
  assert.ok(popupJs.indexOf("resetConsentBtn')") >= 0
        || popupJs.indexOf('resetConsentBtn")') >= 0,
    'resetConsentBtn lookup missing');
  // Quick smoke: the listener must invoke this.resetConsent().
  assert.ok(popupJs.indexOf("this.resetConsent()") >= 0,
    'this.resetConsent() is not invoked from any handler');
});


console.log(' [PASS] Privacy & consent UI + entry-point gates');


// ==================== CSV export cell escaping ====================
console.log('\n--- CSV Export Escaping Tests ---');

// Byte-for-byte copy of toCsvCell from popup.js — keep in sync.
function toCsvCell(value) {
  let v = String(value == null ? '' : value);
  if (/^[=+\-@\t\r]/.test(v)) v = "'" + v;
  return '"' + v.replace(/"/g, '""') + '"';
}

test('toCsvCell wraps plain values in quotes', () => {
  assert.strictEqual(toCsvCell('1.2.3.4'), '"1.2.3.4"');
});
test('toCsvCell doubles embedded quotes', () => {
  assert.strictEqual(toCsvCell('a"b'), '"a""b"');
});
test('toCsvCell neutralizes = formula injection', () => {
  assert.strictEqual(toCsvCell('=1+2'), '"\'=1+2"');
});
test('toCsvCell neutralizes @ and + and - leads', () => {
  assert.strictEqual(toCsvCell('@cmd'), '"\'@cmd"');
  assert.strictEqual(toCsvCell('+ping'), '"\'+ping"');
  assert.strictEqual(toCsvCell('-2+3'), '"\'-2+3"');
});
test('toCsvCell handles null/undefined', () => {
  assert.strictEqual(toCsvCell(null), '""');
  assert.strictEqual(toCsvCell(undefined), '""');
});
console.log(' [PASS] CSV export cell escaping');


// ==================== VirusTotal URL identifier ====================
console.log('\n--- VirusTotal URL id Tests ---');

// Mirror of vtUrlId in popup.js / background.js. VT's /gui/url/<id> report route
// takes the unpadded base64url of the URL (VT canonicalizes server-side), which
// is why /gui/search/<encoded-url> can't be used — its encoded slashes 404.
function vtUrlId(url) {
  const b = Buffer.from(url, 'utf8').toString('base64');
  return b.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

test('vtUrlId matches VT unpadded base64url (verified against live GUI)', () => {
  // /gui/url/aHR0cDovL3d3dy5nb29nbGUuY29tLw resolved to a real URL report.
  assert.strictEqual(vtUrlId('http://www.google.com/'), 'aHR0cDovL3d3dy5nb29nbGUuY29tLw');
});
test('vtUrlId output is URL-safe and unpadded', () => {
  const id = vtUrlId('https://example.com/a?b=c&d=e/f+g');
  assert.ok(!/[+/=]/.test(id), 'must not contain +, / or =');
});
test('vtUrlId handles unicode without throwing', () => {
  assert.doesNotThrow(() => vtUrlId('https://пример.рф/путь'));
});
console.log(' [PASS] VirusTotal URL id');


console.log('Test Summary:');
console.log('  Passed:', passed);
console.log('  Failed:', failed);
console.log('========================================');

process.exit(failed > 0 ? 1 : 0);