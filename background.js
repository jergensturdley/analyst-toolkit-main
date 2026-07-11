"use strict";

// Helper function for UTF-8 to Base64 encoding
function utf8ToBase64(text) {
  const utf8Bytes = new TextEncoder().encode(text);
  let binary = '';
  for (let i = 0; i < utf8Bytes.length; i++) {
    binary += String.fromCharCode(utf8Bytes[i]);
  }
  return btoa(binary);
}

// Global variables
let socSettings = {
  autoAnalyze: true,
  contextMenu: true,
  installedDate: new Date().toISOString()
};
let pendingAnalysis = null;
let floatingWindow = null;
let floatingWindowState = {
  isOpen: false,
  width: 850,
  height: 700,
  left: 100,
  top: 100
};

// --- Enrichment infrastructure (AGENTS.md alignment) ---
const CACHE_TTL = {
  ip: 24 * 60 * 60 * 1000,
  domain: 7 * 24 * 60 * 60 * 1000,
  hash: 7 * 24 * 60 * 60 * 1000,
  url: 6 * 60 * 60 * 1000,
  email: 7 * 24 * 60 * 60 * 1000,
  certificate: 30 * 24 * 60 * 60 * 1000
};

const RATE_LIMITS = {
  abuseipdb: { requests: 1000, window: 24 * 60 * 60 * 1000, backoff: 5 * 60 * 1000 },
  ipinfo: { requests: 50000, window: 24 * 60 * 60 * 1000, backoff: 60 * 1000 },
  greynoise: { requests: 100, window: 24 * 60 * 60 * 1000, backoff: 5 * 60 * 1000 },
  virustotal: { requests: 4, window: 60 * 1000, backoff: 15 * 60 * 1000 },
  urlscan: { requests: 100, window: 24 * 60 * 60 * 1000, backoff: 60 * 1000 },
  urlhaus: { requests: 500, window: 24 * 60 * 60 * 1000, backoff: 60 * 1000 },
  phishtank: { requests: 500, window: 24 * 60 * 60 * 1000, backoff: 60 * 1000 }
};

const MAX_RATE_LIMIT_PROVIDERS = 1000;

class RateLimiter {
  constructor() {
    this.requestLog = new Map();
  }

  _cleanupRequestLog() {
    const maxProviders = MAX_RATE_LIMIT_PROVIDERS;
    if (this.requestLog.size <= maxProviders) {
      return;
    }
    // Convert keys to array to avoid iterator exhaustion issues
    const keysArray = Array.from(this.requestLog.keys());
    let index = 0;
    while (this.requestLog.size > maxProviders && index < keysArray.length) {
      this.requestLog.delete(keysArray[index]);
      index++;
    }
  }

  canMakeRequest(provider) {
    const limit = RATE_LIMITS[provider];
    if (!limit) return true;
    const now = Date.now();
    const existing = this.requestLog.get(provider) || [];
    const recent = existing.filter((ts) => now - ts < limit.window);
    if (recent.length > 0) {
      this.requestLog.set(provider, recent);
    } else {
      this.requestLog.delete(provider);
    }
    this._cleanupRequestLog();
    return recent.length < limit.requests;
  }

  recordRequest(provider) {
    const existing = this.requestLog.get(provider) || [];
    existing.push(Date.now());
    this.requestLog.set(provider, existing);
    this._cleanupRequestLog();
  }
  timeUntilAvailable(provider) {
    const limit = RATE_LIMITS[provider];
    if (!limit) return 0;
    const existing = this.requestLog.get(provider) || [];
    if (!existing.length) return 0;
    const oldest = Math.min(...existing);
    return Math.max(0, oldest + limit.window - Date.now());
  }
}
const rateLimiter = new RateLimiter();

async function fetchWithBackoff(url, options = {}, maxRetries = 3) {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const resp = await fetch(url, options);
      if (resp.ok) return resp;
      if (resp.status === 429) {
        // Retry-After may be a number of seconds OR an HTTP-date. Number(date) is
        // NaN, which would make setTimeout fire immediately and hammer the server,
        // so fall back to exponential backoff when it isn't a finite number.
        const retryAfter = resp.headers.get('Retry-After');
        const seconds = retryAfter ? Number(retryAfter) : NaN;
        const delay = Number.isFinite(seconds) ? seconds * 1000 : Math.min(1000 * 2 ** attempt, 30000);
        await new Promise((resolve) => setTimeout(resolve, delay));
        continue;
      }
      throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    } catch (err) {
      if (attempt === maxRetries - 1) throw err;
      const delay = Math.min(1000 * 2 ** attempt, 30000);
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
  throw new Error('fetchWithBackoff: exhausted retries');
}

async function getCachedAgentResult(agentId, iocType, ioc) {
  const cacheKey = `agent_${agentId}_${iocType}_${ioc}`;
  const stored = await new Promise((resolve) => chrome.storage.local.get([cacheKey], resolve));
  const cached = stored[cacheKey];
  if (!cached) return null;
  const ttl = cached.metadata?.ttlSeconds ? cached.metadata.ttlSeconds * 1000 : CACHE_TTL[iocType] || 0;
  if (ttl && Date.now() - (cached.timestamp || 0) > ttl) {
    await new Promise((resolve) => chrome.storage.local.remove([cacheKey], resolve));
    return null;
  }
  const clone = typeof structuredClone === 'function'
    ? structuredClone(cached)
    : JSON.parse(JSON.stringify(cached));
  clone.cached = true;
  return clone;
}

async function setCachedAgentResult(agentId, iocType, ioc, result) {
  const cacheKey = `agent_${agentId}_${iocType}_${ioc}`;
  const payload = { ...result, timestamp: result.timestamp || Date.now() };
  await new Promise((resolve) => chrome.storage.local.set({ [cacheKey]: payload }, resolve));
}

function isValidIP(ip) {
  // IPv4 quick check
  const ipv4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
  if (ipv4.test(ip)) return true;

  // Basic IPv6 validation: try parsing via URL bracket notation which
  // will throw for clearly invalid addresses (covers most common forms)
  try {
    if (ip.includes(':')) {
      // Wrap in brackets as an IPv6 host in a URL
      // Newer Chrome engines accept this and will throw on invalid addresses
      new URL(`http://[${ip}]/`);
      return true;
    }
  } catch (e) {
    // fall through
  }

  return false;
}

function dedupeById(items = []) {
  const seen = new Set();
  const out = [];
  for (const item of items) {
    if (!item || !item.id) continue;
    if (seen.has(item.id)) continue;
    seen.add(item.id);
    out.push(item);
  }
  return out;
}

function isPrivateIP(ip) {
  // IPv4 RFC1918, loopback, link-local, and CGNAT ranges
  if (/^127\./.test(ip)) return true;                          // 127.0.0.0/8  loopback
  if (/^10\./.test(ip)) return true;                           // 10.0.0.0/8   RFC1918
  if (/^192\.168\./.test(ip)) return true;                     // 192.168.0.0/16 RFC1918
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;     // 172.16.0.0/12 RFC1918
  if (/^169\.254\./.test(ip)) return true;                     // 169.254.0.0/16 link-local
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip)) return true; // 100.64.0.0/10 CGNAT
  if (/^0\./.test(ip)) return true;                            // 0.0.0.0/8 "this" network
  if (/^(255\.255\.255\.255)$/.test(ip)) return true;          // broadcast
  // IPv6 loopback and ULA
  if (/^(::1|::ffff:|fe80:|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:)/i.test(ip)) return true;
  return false;
}

function isValidHash(hash) {
  return /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(hash);
}

function isValidDomain(domain) {
  return /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/.test(domain);
}

function isValidUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

async function runAgent(iocType, ioc, options = {}) {
  const normalizedType = iocType === 'ipv4' || iocType === 'ipv6'
    ? 'ip'
    : ['md5', 'sha1', 'sha256', 'sha512'].includes(iocType)
      ? 'hash'
      : iocType;
  const normalizedIoc = normalizedType === 'domain' ? String(ioc || '').trim().toLowerCase() : String(ioc || '').trim();

  if (normalizedType === 'ip') {
    if (!isValidIP(normalizedIoc)) {
      return { status: 'error', errorCode: 'INVALID_IOC', errorMessage: 'Invalid IP address' };
    }
    if (isPrivateIP(normalizedIoc)) {
      return {
        status: 'error',
        errorCode: 'PRIVATE_IP',
        errorMessage: 'Private/internal IP addresses are not enriched to protect privacy and conserve API quota.'
      };
    }

    const cached = await getCachedAgentResult('ip', normalizedType, normalizedIoc);
    if (cached) return cached;

    const result = await runIpAgent(normalizedIoc, options);
    if (result?.status === 'success') {
      await setCachedAgentResult('ip', normalizedType, normalizedIoc, result);
    }
    return result;
  }

  if (normalizedType === 'hash') {
    if (!isValidHash(normalizedIoc)) {
      return { status: 'error', errorCode: 'INVALID_IOC', errorMessage: 'Invalid hash value' };
    }

    const cached = await getCachedAgentResult('hash', 'hash', normalizedIoc);
    if (cached) return cached;

    const result = await runHashAgent(normalizedIoc, options);
    if (result?.status === 'success') {
      await setCachedAgentResult('hash', 'hash', normalizedIoc, result);
    }
    return result;
  }

  if (normalizedType === 'domain') {
    if (!isValidDomain(normalizedIoc)) {
      return { status: 'error', errorCode: 'INVALID_IOC', errorMessage: 'Invalid domain name' };
    }

    const cached = await getCachedAgentResult('domain', 'domain', normalizedIoc);
    if (cached) return cached;

    const result = await runDomainAgent(normalizedIoc, options);
    if (result?.status === 'success') {
      await setCachedAgentResult('domain', 'domain', normalizedIoc, result);
    }
    return result;
  }

  if (normalizedType === 'url') {
    if (!isValidUrl(normalizedIoc)) {
      return { status: 'error', errorCode: 'INVALID_IOC', errorMessage: 'Invalid URL (must start with http:// or https://)' };
    }

    const cached = await getCachedAgentResult('url', 'url', normalizedIoc);
    if (cached) return cached;

    const result = await runUrlAgent(normalizedIoc, options);
    if (result?.status === 'success') {
      await setCachedAgentResult('url', 'url', normalizedIoc, result);
    }
    return result;
  }

  return { status: 'error', errorMessage: `Unsupported agent type: ${iocType}` };
}

async function getEnabledProviders() {
  const stored = await new Promise((resolve) =>
    chrome.storage.local.get(['enrichmentProviders'], resolve)
  );
  return stored.enrichmentProviders || {};
}

async function runIpAgent(ip, options = {}) {
  const [keys, providerPrefs] = await Promise.all([
    new Promise((resolve) =>
      chrome.storage.local.get(['ipinfoApiKey', 'abuseipdbApiKey', 'greynoiseApiKey', 'virustotalApiKey'], resolve)
    ),
    getEnabledProviders()
  ]);

  const isEnabled = (pid) => providerPrefs[pid] !== false;

  const tasks = [
    isEnabled('ipinfo')    ? fetchIpInfo(ip, keys.ipinfoApiKey)              : Promise.resolve(null),
    isEnabled('abuseipdb') ? fetchAbuseIPDB(ip, keys.abuseipdbApiKey)        : Promise.resolve(null),
    isEnabled('greynoise') ? fetchGreyNoise(ip, keys.greynoiseApiKey)        : Promise.resolve(null),
    isEnabled('virustotal')? fetchVirusTotalIp(ip, keys.virustotalApiKey)    : Promise.resolve(null)
  ];

  const settledResults = await Promise.allSettled(tasks);
  const sources = settledResults
    .filter((r) => r.status === 'fulfilled' && r.value)
    .map((r) => r.value);
  const successful = sources.filter((s) => s.status === 'success');
  const nodes = dedupeById(
    sources.flatMap((s) => (Array.isArray(s.nodes) ? s.nodes : []))
  );
  const edges = dedupeById(
    sources.flatMap((s) => (Array.isArray(s.edges) ? s.edges : []))
  );

  const summary = buildIpSummary(sources);

  return {
    ioc: ip,
    iocType: 'ip',
    status: successful.length ? 'success' : 'error',
    sources,
    nodes,
    edges,
    summary,
    timestamp: Date.now(),
    metadata: {
      sourcesQueried: sources.length,
      sourcesSucceeded: successful.length
    }
  };
}

function buildIpSummary(sources) {
  const summary = { verdict: 'unknown', confidence: 0, tags: [], riskScore: 0 };
  const abuse = sources.find((s) => s.provider === 'abuseipdb' && s.status === 'success');
  const greynoise = sources.find((s) => s.provider === 'greynoise' && s.status === 'success');

  if (abuse?.data?.abuseConfidenceScore !== undefined) {
    summary.riskScore = abuse.data.abuseConfidenceScore;
    summary.confidence = Math.min(1, abuse.data.abuseConfidenceScore / 100);
    summary.verdict = abuse.data.abuseConfidenceScore >= 75 ? 'malicious' : abuse.data.abuseConfidenceScore >= 40 ? 'suspicious' : 'clean';
  }

  if (greynoise?.data?.classification) {
    summary.tags.push(greynoise.data.classification);
    if (greynoise.data.name) summary.tags.push(greynoise.data.name);
    if (summary.riskScore < 50 && greynoise.data.classification === 'malicious') {
      summary.riskScore = 75;
      summary.verdict = 'malicious';
    }
  }

  const vt = sources.find((s) => s.provider === 'virustotal' && s.status === 'success');
  if (vt?.data?.last_analysis_stats) {
    const stats = vt.data.last_analysis_stats;
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = malicious + suspicious + (stats.undetected || 0) + (stats.harmless || 0);
    if (malicious > 0 || suspicious > 0) {
      const vtScore = Math.round(((malicious + suspicious * 0.5) / Math.max(total, 1)) * 100);
      if (vtScore > summary.riskScore) {
        summary.riskScore = vtScore;
        summary.confidence = Math.max(summary.confidence, Math.min(1, vtScore / 100));
      }
      if (summary.verdict === 'unknown' || summary.verdict === 'clean') {
        summary.verdict = malicious >= 5 ? 'malicious' : 'suspicious';
      }
    }
    if (total > 0) {
      summary.tags.push(`VT:${malicious}/${total}`);
    }
  }

  return summary;
}

function buildHashSummary(sources) {
  const summary = {
    verdict: 'unknown',
    confidence: 0,
    tags: [],
    riskScore: 0,
    detections: { malicious: 0, suspicious: 0, total: 0 }
  };
  const vt = sources.find((s) => s.provider === 'virustotal' && s.status === 'success');
  const malwareBazaar = sources.find((s) => s.provider === 'malwarebazaar' && s.status === 'success');

  if (vt?.data?.last_analysis_stats) {
    const stats = vt.data.last_analysis_stats;
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((acc, value) => acc + (Number(value) || 0), 0);
    const score = Math.round(((malicious + suspicious * 0.5) / Math.max(total, 1)) * 100);
    summary.detections = { malicious, suspicious, total };
    summary.riskScore = score;
    summary.confidence = Math.min(1, score / 100);
    summary.verdict = malicious >= 5 ? 'malicious' : malicious >= 1 || suspicious >= 3 ? 'suspicious' : malicious === 0 && suspicious === 0 ? 'clean' : 'unknown';
    if (total > 0) {
      summary.tags.push(`VT:${malicious}/${total}`);
    }
  }

  if (malwareBazaar?.data?.signature) {
    summary.tags.push(malwareBazaar.data.signature);
  }

  return summary;
}

function buildDomainSummary(sources) {
  const summary = { verdict: 'unknown', confidence: 0, tags: [], riskScore: 0, resolvedIPs: 0, subdomains: 0 };
  const vt = sources.find((s) => s.provider === 'virustotal' && s.status === 'success');
  const crtsh = sources.find((s) => s.provider === 'crtsh' && s.status === 'success');

  summary.resolvedIPs = Array.isArray(vt?.data?.resolutions) ? vt.data.resolutions.length : 0;
  summary.subdomains = Array.isArray(crtsh?.data?.subdomains) ? crtsh.data.subdomains.length : 0;

  if (summary.resolvedIPs > 0) {
    summary.tags.push(`PDNS:${summary.resolvedIPs}`);
  }
  if (summary.subdomains > 0) {
    summary.tags.push(`SANs:${summary.subdomains}`);
  }

  if (vt?.data?.last_analysis_stats) {
    const stats = vt.data.last_analysis_stats;
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((acc, value) => acc + (Number(value) || 0), 0);
    const score = Math.round(((malicious + suspicious * 0.5) / Math.max(total, 1)) * 100);
    summary.riskScore = score;
    summary.confidence = Math.min(1, score / 100);
    summary.verdict = malicious >= 5 ? 'malicious' : malicious >= 1 || suspicious >= 3 ? 'suspicious' : malicious === 0 && suspicious === 0 ? 'clean' : 'unknown';
    if (total > 0) {
      summary.tags.push(`VT:${malicious}/${total}`);
    }
  }

  return summary;
}

async function fetchIpInfo(ip, apiKey) {
  try {
    if (!rateLimiter.canMakeRequest('ipinfo')) {
      return {
        provider: 'ipinfo',
        displayName: 'ipinfo.io',
        status: 'error',
        errorCode: 'RATE_LIMIT_EXCEEDED',
        errorMessage: `Try again in ${Math.ceil(rateLimiter.timeUntilAvailable('ipinfo') / 1000)}s`
      };
    }
    // Prefer header-based auth to avoid exposing tokens in URLs
    const url = `https://ipinfo.io/${encodeURIComponent(ip)}/json`;
    const headers = { Accept: 'application/json' };
    if (apiKey) {
      headers.Authorization = `Bearer ${apiKey}`;
    }
    const resp = await fetchWithBackoff(url, { headers });
    rateLimiter.recordRequest('ipinfo');
    if (!resp.ok) {
      return { provider: 'ipinfo', displayName: 'ipinfo.io', status: 'error', errorCode: 'NETWORK_ERROR', errorMessage: `HTTP ${resp.status}` };
    }
    const data = await resp.json();
    const nodes = [];
    const edges = [];
    const geoLabel = [data.city, data.region, data.country].filter(Boolean).join(', ');
    if (geoLabel || data.loc) {
      const geoId = `geo_${ip.replace(/[.:]/g, '_')}`;
      nodes.push({
        id: geoId,
        label: geoLabel || 'Geo',
        type: 'geo',
        properties: { city: data.city, region: data.region, country: data.country, loc: data.loc, timezone: data.timezone }
      });
      edges.push({ id: `edge_${ip}_geo`, from: ip, to: geoId, label: 'observed-at', properties: { source: 'ipinfo' } });
    }
    if (data.org) {
      const asMatch = data.org.match(/AS(\d+)\s*(.*)/);
      const asnNumber = asMatch ? `AS${asMatch[1]}` : null;
      const asnName = asMatch ? asMatch[2] : data.org;
      const asnId = `asn_${asnNumber ? asnNumber.replace(/^AS/, '') : `unknown_${ip.replace(/[.:]/g, '_')}`}`;
      nodes.push({
        id: asnId,
        label: asnNumber || asnName || 'ASN',
        type: 'asn',
        properties: { name: asnName, org: data.org }
      });
      edges.push({ id: `edge_${ip}_asn`, from: ip, to: asnId, label: 'belongs-to', properties: { source: 'ipinfo' } });
    }

    return {
      provider: 'ipinfo',
      displayName: 'ipinfo.io',
      status: 'success',
      cached: false,
      data: {
        city: data.city,
        region: data.region,
        country: data.country,
        loc: data.loc,
        org: data.org,
        postal: data.postal,
        timezone: data.timezone
      },
      nodes,
      edges,
      apiUrl: url,
      metadata: { ttlSeconds: 24 * 60 * 60, fetchedAt: Date.now() }
    };
  } catch (err) {
    return { provider: 'ipinfo', displayName: 'ipinfo.io', status: 'error', errorCode: 'NETWORK_ERROR', errorMessage: err.message };
  }
}

async function fetchAbuseIPDB(ip, apiKey) {
  if (!apiKey) {
    return { provider: 'abuseipdb', displayName: 'AbuseIPDB', status: 'error', errorCode: 'API_KEY_MISSING', errorMessage: 'AbuseIPDB API key not set' };
  }
  try {
    if (!rateLimiter.canMakeRequest('abuseipdb')) {
      return {
        provider: 'abuseipdb',
        displayName: 'AbuseIPDB',
        status: 'error',
        errorCode: 'RATE_LIMIT_EXCEEDED',
        errorMessage: `Try again in ${Math.ceil(rateLimiter.timeUntilAvailable('abuseipdb') / 1000)}s`
      };
    }
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
    const resp = await fetchWithBackoff(url, { headers: { Key: apiKey, Accept: 'application/json' } });
    rateLimiter.recordRequest('abuseipdb');
    if (!resp.ok) {
      return { provider: 'abuseipdb', displayName: 'AbuseIPDB', status: 'error', errorCode: 'NETWORK_ERROR', errorMessage: `HTTP ${resp.status}` };
    }
    const json = await resp.json();
    const data = json?.data || {};
    const nodes = [];
    const edges = [];
    const repId = `abuse_${ip.replace(/[.:]/g, '_')}`;
    nodes.push({
      id: repId,
      label: `AbuseIPDB ${data.abuseConfidenceScore ?? 'N/A'}/100`,
      type: 'reputation',
      properties: { score: data.abuseConfidenceScore, totalReports: data.totalReports, lastReported: data.lastReportedAt, isp: data.isp }
    });
    edges.push({ id: `edge_${ip}_abuse`, from: ip, to: repId, label: 'reported-by', properties: { source: 'abuseipdb' } });

    return {
      provider: 'abuseipdb',
      displayName: 'AbuseIPDB',
      status: 'success',
      cached: false,
      data: {
        abuseConfidenceScore: data.abuseConfidenceScore,
        totalReports: data.totalReports,
        lastReported: data.lastReportedAt,
        country: data.countryCode,
        usageType: data.usageType,
        isp: data.isp
      },
      nodes,
      edges,
      apiUrl: url,
      metadata: { ttlSeconds: 24 * 60 * 60, fetchedAt: Date.now() }
    };
  } catch (err) {
    return { provider: 'abuseipdb', displayName: 'AbuseIPDB', status: 'error', errorCode: 'NETWORK_ERROR', errorMessage: err.message };
  }
}

async function fetchGreyNoise(ip, apiKey) {
  if (!apiKey) {
    return { provider: 'greynoise', displayName: 'GreyNoise', status: 'error', errorCode: 'API_KEY_MISSING', errorMessage: 'GreyNoise API key not set' };
  }
  try {
    if (!rateLimiter.canMakeRequest('greynoise')) {
      return {
        provider: 'greynoise',
        displayName: 'GreyNoise',
        status: 'error',
        errorCode: 'RATE_LIMIT_EXCEEDED',
        errorMessage: `Try again in ${Math.ceil(rateLimiter.timeUntilAvailable('greynoise') / 1000)}s`
      };
    }
    const url = `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`;
    const resp = await fetchWithBackoff(url, { headers: { key: apiKey, Accept: 'application/json' } });
    rateLimiter.recordRequest('greynoise');
    if (!resp.ok) {
      return { provider: 'greynoise', displayName: 'GreyNoise', status: 'error', errorCode: 'NETWORK_ERROR', errorMessage: `HTTP ${resp.status}` };
    }
    const data = await resp.json();
    const nodes = [];
    const edges = [];
    const gnId = `gn_${ip.replace(/[.:]/g, '_')}`;
    nodes.push({
      id: gnId,
      label: data.classification ? `GreyNoise: ${data.classification}` : 'GreyNoise',
      type: 'classification',
      properties: { name: data.name, classification: data.classification, last_seen: data.last_seen, noise: data.noise }
    });
    edges.push({ id: `edge_${ip}_gn`, from: ip, to: gnId, label: 'classification', properties: { source: 'greynoise' } });
    return {
      provider: 'greynoise',
      displayName: 'GreyNoise',
      status: 'success',
      cached: false,
      data,
      nodes,
      edges,
      apiUrl: url,
      metadata: { ttlSeconds: 24 * 60 * 60, fetchedAt: Date.now() }
    };
  } catch (err) {
    return { provider: 'greynoise', displayName: 'GreyNoise', status: 'error', errorCode: 'NETWORK_ERROR', errorMessage: err.message };
  }
}

async function fetchVirusTotalIp(ip, apiKey) {
  if (!apiKey) {
    return { provider: 'virustotal', displayName: 'VirusTotal', status: 'error', errorCode: 'API_KEY_MISSING', errorMessage: 'VirusTotal API key not set' };
  }
  try {
    if (!rateLimiter.canMakeRequest('virustotal')) {
      return {
        provider: 'virustotal',
        displayName: 'VirusTotal',
        status: 'error',
        errorCode: 'RATE_LIMIT_EXCEEDED',
        errorMessage: `Try again in ${Math.ceil(rateLimiter.timeUntilAvailable('virustotal') / 1000)}s`
      };
    }
    const url = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`;
    const resp = await fetchWithBackoff(url, { headers: { 'x-apikey': apiKey, Accept: 'application/json' } });
    rateLimiter.recordRequest('virustotal');
    if (!resp.ok) {
      return { provider: 'virustotal', displayName: 'VirusTotal', status: 'error', errorCode: 'NETWORK_ERROR', errorMessage: `HTTP ${resp.status}` };
    }
    const json = await resp.json();
    const attrs = json?.data?.attributes || {};
  const nodes = [];
  const edges = [];
  if (attrs.asn || attrs.as_owner) {
    const asnNumber = attrs.asn || (attrs.network && attrs.network.asn);
    const asnId = asnNumber ? `asn_${asnNumber}` : `asn_unknown_${ip.replace(/[.:]/g, '_')}`;
    nodes.push({
      id: asnId,
      label: attrs.asn ? `AS${attrs.asn}` : (attrs.as_owner || 'ASN'),
      type: 'asn',
      properties: { owner: attrs.as_owner, network: attrs.network?.cidr, rir: attrs.network?.rir }
    });
    edges.push({ id: `edge_${ip}_vtasn`, from: ip, to: asnId, label: 'belongs-to', properties: { source: 'virustotal' } });
  }
    return {
      provider: 'virustotal',
      displayName: 'VirusTotal',
      status: 'success',
      cached: false,
      data: {
        asn: attrs.asn,
        as_owner: attrs.as_owner,
        country: attrs.country,
        network: attrs.network,
        last_analysis_stats: attrs.last_analysis_stats || null
      },
      nodes,
      edges,
      apiUrl: url,
      metadata: { ttlSeconds: 24 * 60 * 60, fetchedAt: Date.now() }
    };
  } catch (err) {
    return { provider: 'virustotal', displayName: 'VirusTotal', status: 'error', errorCode: 'NETWORK_ERROR', errorMessage: err.message };
  }
}

async function fetchVirusTotalFile(hash, apiKey) {
  if (!apiKey) {
    return { provider: 'virustotal', displayName: 'VirusTotal', status: 'error', errorCode: 'API_KEY_MISSING', errorMessage: 'VirusTotal API key not set' };
  }
  try {
    if (!rateLimiter.canMakeRequest('virustotal')) {
      return {
        provider: 'virustotal',
        displayName: 'VirusTotal',
        status: 'error',
        errorCode: 'RATE_LIMIT_EXCEEDED',
        errorMessage: `Try again in ${Math.ceil(rateLimiter.timeUntilAvailable('virustotal') / 1000)}s`
      };
    }
    const url = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(hash)}`;
    const resp = await fetchWithBackoff(url, { headers: { 'x-apikey': apiKey, Accept: 'application/json' } });
    rateLimiter.recordRequest('virustotal');
    if (!resp.ok) {
      return { provider: 'virustotal', displayName: 'VirusTotal', status: 'error', errorCode: 'NETWORK_ERROR', errorMessage: `HTTP ${resp.status}` };
    }
    const json = await resp.json();
    const attrs = json?.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((acc, value) => acc + (Number(value) || 0), 0);
    const nodeId = `hash_vt_${hash}`;
    const nodes = [{
      id: nodeId,
      label: attrs.meaningful_name || attrs.type_description || hash.slice(0, 12),
      type: 'malware',
      properties: {
        detections: malicious + suspicious,
        total,
        malware_name: attrs.meaningful_name || null,
        type_description: attrs.type_description,
        size: attrs.size
      }
    }];
    const edges = [{ id: `edge_${hash}_hashvt`, from: hash, to: nodeId, label: 'analyzed-by', properties: { source: 'virustotal' } }];
    return {
      provider: 'virustotal',
      displayName: 'VirusTotal',
      status: 'success',
      cached: false,
      data: {
        last_analysis_stats: attrs.last_analysis_stats || null,
        meaningful_name: attrs.meaningful_name,
        type_description: attrs.type_description,
        tags: attrs.tags || [],
        size: attrs.size,
        first_submission_date: attrs.first_submission_date,
        last_submission_date: attrs.last_submission_date,
        times_submitted: attrs.times_submitted
      },
      nodes,
      edges,
      apiUrl: url,
      metadata: { ttlSeconds: 7 * 24 * 60 * 60, fetchedAt: Date.now() }
    };
  } catch (err) {
    return { provider: 'virustotal', displayName: 'VirusTotal', status: 'error', errorCode: 'NETWORK_ERROR', errorMessage: err.message };
  }
}

async function fetchMalwareBazaar(hash) {
  try {
    const url = 'https://mb-api.abuse.ch/api/v1/';
    const resp = await fetchWithBackoff(url, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `query=get_info&hash=${encodeURIComponent(hash)}`
    });
    if (!resp.ok) {
      return { provider: 'malwarebazaar', displayName: 'MalwareBazaar', status: 'error', errorCode: 'NETWORK_ERROR', errorMessage: `HTTP ${resp.status}` };
    }
    const json = await resp.json();
    if (json?.query_status === 'file_is_unknown') {
      return {
        provider: 'malwarebazaar',
        displayName: 'MalwareBazaar',
        status: 'no_data',
        data: null,
        nodes: [],
        edges: [],
        apiUrl: url,
        metadata: { ttlSeconds: 7 * 24 * 60 * 60, fetchedAt: Date.now() }
      };
    }
    const data = Array.isArray(json?.data) ? json.data[0] : null;
    if (!data) {
      return {
        provider: 'malwarebazaar',
        displayName: 'MalwareBazaar',
        status: 'no_data',
        data: null,
        nodes: [],
        edges: [],
        apiUrl: url,
        metadata: { ttlSeconds: 7 * 24 * 60 * 60, fetchedAt: Date.now() }
      };
    }
    const nodeId = `mb_${hash}`;
    const nodes = [{
      id: nodeId,
      label: data.signature || data.file_name || hash.slice(0, 12),
      type: 'malware',
      properties: {
        signature: data.signature,
        file_type: data.file_type,
        file_name: data.file_name,
        delivery_method: data.delivery_method,
        tags: data.tags || []
      }
    }];
    const edges = [{ id: `edge_${hash}_mb`, from: hash, to: nodeId, label: 'classified-by', properties: { source: 'malwarebazaar' } }];
    return {
      provider: 'malwarebazaar',
      displayName: 'MalwareBazaar',
      status: 'success',
      cached: false,
      data: {
        signature: data.signature,
        file_type: data.file_type,
        file_name: data.file_name,
        delivery_method: data.delivery_method,
        tags: data.tags || [],
        first_seen: data.first_seen,
        last_seen: data.last_seen
      },
      nodes,
      edges,
      apiUrl: url,
      metadata: { ttlSeconds: 7 * 24 * 60 * 60, fetchedAt: Date.now() }
    };
  } catch (err) {
    return { provider: 'malwarebazaar', displayName: 'MalwareBazaar', status: 'error', errorCode: 'NETWORK_ERROR', errorMessage: err.message };
  }
}

async function fetchVirusTotalDomain(domain, apiKey) {
  if (!apiKey) {
    return { provider: 'virustotal', displayName: 'VirusTotal', status: 'error', errorCode: 'API_KEY_MISSING', errorMessage: 'VirusTotal API key not set' };
  }
  try {
    if (!rateLimiter.canMakeRequest('virustotal')) {
      return {
        provider: 'virustotal',
        displayName: 'VirusTotal',
        status: 'error',
        errorCode: 'RATE_LIMIT_EXCEEDED',
        errorMessage: `Try again in ${Math.ceil(rateLimiter.timeUntilAvailable('virustotal') / 1000)}s`
      };
    }
    const resolutionsUrl = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}/resolutions?limit=40`;
    const resolutionsResp = await fetchWithBackoff(resolutionsUrl, { headers: { 'x-apikey': apiKey, Accept: 'application/json' } });
    rateLimiter.recordRequest('virustotal');
    if (!resolutionsResp.ok) {
      return { provider: 'virustotal', displayName: 'VirusTotal', status: 'error', errorCode: 'NETWORK_ERROR', errorMessage: `HTTP ${resolutionsResp.status}` };
    }
    const resolutionsJson = await resolutionsResp.json();
    if (!rateLimiter.canMakeRequest('virustotal')) {
      return {
        provider: 'virustotal',
        displayName: 'VirusTotal',
        status: 'error',
        errorCode: 'RATE_LIMIT_EXCEEDED',
        errorMessage: `Try again in ${Math.ceil(rateLimiter.timeUntilAvailable('virustotal') / 1000)}s`
      };
    }
    const detailsUrl = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`;
    const detailsResp = await fetchWithBackoff(detailsUrl, { headers: { 'x-apikey': apiKey, Accept: 'application/json' } });
    rateLimiter.recordRequest('virustotal');
    if (!detailsResp.ok) {
      return { provider: 'virustotal', displayName: 'VirusTotal', status: 'error', errorCode: 'NETWORK_ERROR', errorMessage: `HTTP ${detailsResp.status}` };
    }
    const detailsJson = await detailsResp.json();
    const attrs = detailsJson?.data?.attributes || {};
    const resolutions = [];
    const nodes = [];
    const edges = [];
    if (Array.isArray(resolutionsJson?.data)) {
      for (const item of resolutionsJson.data) {
        const resolutionAttrs = item?.attributes || {};
        const resolvedIp = resolutionAttrs.ip_address;
        if (!resolvedIp) continue;
        resolutions.push({ ip_address: resolvedIp, last_seen: resolutionAttrs.last_seen || null });
        nodes.push({
          id: resolvedIp,
          label: resolvedIp,
          type: 'ip',
          properties: { last_seen: resolutionAttrs.last_seen || null }
        });
        edges.push({
          id: `edge_${domain}_${resolvedIp.replace(/[.:]/g, '_')}`,
          from: domain,
          to: resolvedIp,
          label: 'passive-dns',
          properties: { source: 'virustotal', last_seen: resolutionAttrs.last_seen || null }
        });
      }
    }
    return {
      provider: 'virustotal',
      displayName: 'VirusTotal',
      status: 'success',
      cached: false,
      data: {
        resolutions,
        last_analysis_stats: attrs.last_analysis_stats || null
      },
      nodes,
      edges,
      apiUrl: detailsUrl,
      metadata: { ttlSeconds: 7 * 24 * 60 * 60, fetchedAt: Date.now() }
    };
  } catch (err) {
    return { provider: 'virustotal', displayName: 'VirusTotal', status: 'error', errorCode: 'NETWORK_ERROR', errorMessage: err.message };
  }
}

async function fetchCRTsh(domain) {
  try {
    const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
    const resp = await fetchWithBackoff(url, { headers: { Accept: 'application/json' } });
    if (!resp.ok) {
      return { provider: 'crtsh', displayName: 'crt.sh', status: 'no_data', data: null, nodes: [], edges: [], apiUrl: url, metadata: { ttlSeconds: 7 * 24 * 60 * 60, fetchedAt: Date.now() } };
    }
    const json = await resp.json();
    if (!Array.isArray(json) || !json.length) {
      return { provider: 'crtsh', displayName: 'crt.sh', status: 'no_data', data: null, nodes: [], edges: [], apiUrl: url, metadata: { ttlSeconds: 7 * 24 * 60 * 60, fetchedAt: Date.now() } };
    }
    const subdomainSet = new Set();
    for (const entry of json) {
      const names = String(entry?.name_value || '').split('\n');
      for (const name of names) {
        const cleaned = name.replace(/^\*\./, '').trim().toLowerCase();
        if (!cleaned || cleaned === domain) continue;
        subdomainSet.add(cleaned);
        if (subdomainSet.size >= 50) break;
      }
      if (subdomainSet.size >= 50) break;
    }
    const subdomains = Array.from(subdomainSet);
    if (!subdomains.length) {
      return { provider: 'crtsh', displayName: 'crt.sh', status: 'no_data', data: null, nodes: [], edges: [], apiUrl: url, metadata: { ttlSeconds: 7 * 24 * 60 * 60, fetchedAt: Date.now() } };
    }
    const nodes = subdomains.map((subdomain) => ({
      id: subdomain,
      label: subdomain,
      type: 'domain',
      properties: { source: 'crtsh' }
    }));
    const edges = subdomains.map((subdomain) => ({
      id: `edge_${domain}_${subdomain.replace(/[^a-z0-9]/gi, '_')}`,
      from: domain,
      to: subdomain,
      label: 'certificate-san',
      properties: { source: 'crtsh' }
    }));
    return {
      provider: 'crtsh',
      displayName: 'crt.sh',
      status: 'success',
      cached: false,
      data: { subdomains },
      nodes,
      edges,
      apiUrl: url,
      metadata: { ttlSeconds: 7 * 24 * 60 * 60, fetchedAt: Date.now() }
    };
  } catch (err) {
    return { provider: 'crtsh', displayName: 'crt.sh', status: 'no_data', data: null, nodes: [], edges: [], apiUrl: `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, metadata: { ttlSeconds: 7 * 24 * 60 * 60, fetchedAt: Date.now() } };
  }
}

async function runHashAgent(hash, options = {}) {
  const [keys, providerPrefs] = await Promise.all([
    new Promise((resolve) => chrome.storage.local.get(['virustotalApiKey'], resolve)),
    getEnabledProviders()
  ]);

  const isEnabled = (pid) => providerPrefs[pid] !== false;

  const tasks = [
    isEnabled('virustotal')   ? fetchVirusTotalFile(hash, keys.virustotalApiKey) : Promise.resolve(null),
    isEnabled('malwarebazaar') ? fetchMalwareBazaar(hash)                         : Promise.resolve(null)
  ];

  const settledResults = await Promise.allSettled(tasks);
  const sources = settledResults
    .filter((r) => r.status === 'fulfilled' && r.value)
    .map((r) => r.value);
  const successful = sources.filter((s) => s.status === 'success');
  const nodes = dedupeById(
    sources.flatMap((s) => (Array.isArray(s.nodes) ? s.nodes : []))
  );
  const edges = dedupeById(
    sources.flatMap((s) => (Array.isArray(s.edges) ? s.edges : []))
  );

  const summary = buildHashSummary(sources);

  return {
    ioc: hash,
    iocType: 'hash',
    status: successful.length ? 'success' : 'error',
    sources,
    nodes,
    edges,
    summary,
    timestamp: Date.now(),
    metadata: {
      sourcesQueried: sources.length,
      sourcesSucceeded: successful.length
    }
  };
}

async function runDomainAgent(domain, options = {}) {
  const [keys, providerPrefs] = await Promise.all([
    new Promise((resolve) => chrome.storage.local.get(['virustotalApiKey'], resolve)),
    getEnabledProviders()
  ]);

  const isEnabled = (pid) => providerPrefs[pid] !== false;

  const tasks = [
    isEnabled('virustotal') ? fetchVirusTotalDomain(domain, keys.virustotalApiKey) : Promise.resolve(null),
    isEnabled('crtsh')      ? fetchCRTsh(domain)                                   : Promise.resolve(null)
  ];

  const settledResults = await Promise.allSettled(tasks);
  const sources = settledResults
    .filter((r) => r.status === 'fulfilled' && r.value)
    .map((r) => r.value);
  const successful = sources.filter((s) => s.status === 'success');
  const nodes = dedupeById(
    sources.flatMap((s) => (Array.isArray(s.nodes) ? s.nodes : []))
  );
  const edges = dedupeById(
    sources.flatMap((s) => (Array.isArray(s.edges) ? s.edges : []))
  );

  const summary = buildDomainSummary(sources);

  return {
    ioc: domain,
    iocType: 'domain',
    status: successful.length ? 'success' : 'error',
    sources,
    nodes,
    edges,
    summary,
    timestamp: Date.now(),
    metadata: {
      sourcesQueried: sources.length,
      sourcesSucceeded: successful.length
    }
  };
}

async function fetchURLscan(url, apiKey) {
  const provider = 'urlscan';
  const displayName = 'urlscan.io';
  const baseUrl = 'https://urlscan.io/api/v1';

  if (!apiKey) {
    return {
      provider, displayName, status: 'no_data',
      data: null, nodes: [], edges: [],
      errorMessage: 'No urlscan.io API key configured.',
      errorCode: 'API_KEY_MISSING',
      apiUrl: `${baseUrl}/scan/`,
      metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
    };
  }

  if (!rateLimiter.canMakeRequest(provider)) {
    return {
      provider, displayName, status: 'error',
      data: null, nodes: [], edges: [],
      errorMessage: 'Rate limit exceeded for urlscan.io.',
      errorCode: 'RATE_LIMIT_EXCEEDED',
      apiUrl: `${baseUrl}/scan/`,
      metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
    };
  }

  try {
    rateLimiter.recordRequest(provider);
    const submitRes = await fetch(`${baseUrl}/scan/`, {
      method: 'POST',
      headers: { 'API-Key': apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, visibility: 'unlisted' })
    });

    if (!submitRes.ok) {
      const errBody = await submitRes.text().catch(() => '');
      const errorCode = submitRes.status === 401 || submitRes.status === 403
        ? 'API_KEY_INVALID' : submitRes.status === 429
          ? 'RATE_LIMIT_EXCEEDED' : 'UNKNOWN_ERROR';
      return {
        provider, displayName, status: 'error', data: null, nodes: [], edges: [],
        errorMessage: `urlscan.io submission failed: HTTP ${submitRes.status}. ${errBody.slice(0, 120)}`,
        errorCode, apiUrl: `${baseUrl}/scan/`,
        metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
      };
    }

    const submitData = await submitRes.json();
    const uuid = submitData.uuid;
    if (!uuid) {
      return {
        provider, displayName, status: 'no_data', data: null, nodes: [], edges: [],
        errorMessage: 'urlscan.io did not return a scan UUID.',
        errorCode: 'NO_DATA', apiUrl: `${baseUrl}/scan/`,
        metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
      };
    }

    // Poll for result (max 10 attempts, 3s apart)
    const resultUrl = `${baseUrl}/result/${uuid}/`;
    let result = null;
    for (let attempt = 0; attempt < 10; attempt++) {
      await new Promise((r) => setTimeout(r, 3000));
      const pollRes = await fetch(resultUrl, { headers: { 'API-Key': apiKey } });
      if (pollRes.status === 404) continue; // Not ready yet
      if (!pollRes.ok) break;
      result = await pollRes.json();
      break;
    }

    if (!result) {
      return {
        provider, displayName, status: 'no_data', data: null, nodes: [], edges: [],
        errorMessage: 'urlscan.io scan result not available yet (timeout).',
        errorCode: 'TIMEOUT', apiUrl: resultUrl,
        metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
      };
    }

    const verdict = result.verdicts?.overall?.score ?? 0;
    const malicious = result.verdicts?.overall?.malicious ?? false;
    const categories = (result.verdicts?.overall?.categories || []).join(', ');
    const screenshotUrl = result.screenshot || null;
    const pageIp = result.page?.ip || null;
    const pageDomain = result.page?.domain || null;
    const pageServer = result.page?.server || null;
    const redirectCount = (result.data?.requests || []).filter((r) => r.response?.redirectURL).length;

    const nodes = [];
    const edges = [];

    if (pageDomain) {
      const domainId = `domain_${pageDomain.replace(/[^a-z0-9._-]/gi, '_')}`;
      nodes.push({ id: domainId, label: pageDomain, type: 'domain' });
      edges.push({ from: url, to: domainId, label: 'resolves-to' });
    }
    if (pageIp) {
      const ipId = `ip_${pageIp.replace(/[^0-9a-fA-F.:]/g, '_')}`;
      nodes.push({ id: ipId, label: pageIp, type: 'ip' });
      edges.push({ from: url, to: ipId, label: 'hosted-on' });
    }

    return {
      provider, displayName, status: 'success',
      data: {
        verdict: malicious ? 'malicious' : verdict > 50 ? 'suspicious' : 'clean',
        score: verdict,
        categories,
        screenshot: screenshotUrl,
        domain: pageDomain,
        ip: pageIp,
        server: pageServer,
        redirects: redirectCount,
        scanLink: `https://urlscan.io/result/${uuid}/`
      },
      nodes, edges,
      cached: false,
      apiUrl: resultUrl,
      metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
    };
  } catch (err) {
    return {
      provider, displayName, status: 'error', data: null, nodes: [], edges: [],
      errorMessage: `urlscan.io error: ${err.message}`,
      errorCode: 'NETWORK_ERROR', apiUrl: `${baseUrl}/scan/`,
      metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
    };
  }
}

async function fetchURLhaus(url) {
  const provider = 'urlhaus';
  const displayName = 'URLhaus';
  const apiUrl = 'https://urlhaus-api.abuse.ch/v1/url/';

  if (!rateLimiter.canMakeRequest(provider)) {
    return {
      provider, displayName, status: 'error', data: null, nodes: [], edges: [],
      errorMessage: 'Rate limit exceeded for URLhaus.', errorCode: 'RATE_LIMIT_EXCEEDED',
      apiUrl, metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
    };
  }

  try {
    rateLimiter.recordRequest(provider);
    const body = new URLSearchParams({ url });
    const res = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });

    if (!res.ok) {
      return {
        provider, displayName, status: 'error', data: null, nodes: [], edges: [],
        errorMessage: `URLhaus returned HTTP ${res.status}`, errorCode: 'UNKNOWN_ERROR',
        apiUrl, metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
      };
    }

    const data = await res.json();

    if (data.query_status === 'no_results') {
      return {
        provider, displayName, status: 'no_data',
        data: { queryStatus: 'not_found', threat: null, tags: [] },
        nodes: [], edges: [], cached: false,
        apiUrl, metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
      };
    }

    const threat = data.threat || null;
    const tags = Array.isArray(data.tags) ? data.tags : [];
    const urlStatus = data.url_status || null;
    const dateAdded = data.date_added || null;

    return {
      provider, displayName, status: 'success',
      data: { queryStatus: data.query_status, threat, tags: tags.join(', '), urlStatus, dateAdded },
      nodes: [], edges: [], cached: false,
      apiUrl, metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
    };
  } catch (err) {
    return {
      provider, displayName, status: 'error', data: null, nodes: [], edges: [],
      errorMessage: `URLhaus error: ${err.message}`, errorCode: 'NETWORK_ERROR',
      apiUrl, metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
    };
  }
}

async function fetchPhishTank(url) {
  const provider = 'phishtank';
  const displayName = 'PhishTank';
  const apiUrl = 'https://checkurl.phishtank.com/checkurl/';

  if (!rateLimiter.canMakeRequest(provider)) {
    return {
      provider, displayName, status: 'error', data: null, nodes: [], edges: [],
      errorMessage: 'Rate limit exceeded for PhishTank.', errorCode: 'RATE_LIMIT_EXCEEDED',
      apiUrl, metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
    };
  }

  try {
    rateLimiter.recordRequest(provider);
    const body = new URLSearchParams({ url, format: 'json' });
    const res = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });

    if (!res.ok) {
      return {
        provider, displayName, status: 'error', data: null, nodes: [], edges: [],
        errorMessage: `PhishTank returned HTTP ${res.status}`, errorCode: 'UNKNOWN_ERROR',
        apiUrl, metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
      };
    }

    const data = await res.json();
    const results = data.results || {};
    const inDatabase = results.in_database === true;
    const verified = results.verified === true;
    const phishId = results.phish_id || null;
    const verificationTime = results.verification_time || null;

    return {
      provider, displayName, status: 'success',
      data: { inDatabase, verified, phishId, verificationTime },
      nodes: [], edges: [], cached: false,
      apiUrl, metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
    };
  } catch (err) {
    return {
      provider, displayName, status: 'error', data: null, nodes: [], edges: [],
      errorMessage: `PhishTank error: ${err.message}`, errorCode: 'NETWORK_ERROR',
      apiUrl, metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
    };
  }
}

async function fetchVirusTotalUrl(url, apiKey) {
  const provider = 'virustotal';
  const displayName = 'VirusTotal';

  if (!apiKey) {
    return {
      provider, displayName, status: 'no_data', data: null, nodes: [], edges: [],
      errorMessage: 'No VirusTotal API key configured.', errorCode: 'API_KEY_MISSING',
      apiUrl: 'https://www.virustotal.com/api/v3/urls',
      metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
    };
  }

  if (!rateLimiter.canMakeRequest(provider)) {
    return {
      provider, displayName, status: 'error', data: null, nodes: [], edges: [],
      errorMessage: 'Rate limit exceeded for VirusTotal.', errorCode: 'RATE_LIMIT_EXCEEDED',
      apiUrl: 'https://www.virustotal.com/api/v3/urls',
      metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
    };
  }

  try {
    rateLimiter.recordRequest(provider);
    const urlId = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const apiUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;

    const res = await fetch(apiUrl, { headers: { 'x-apikey': apiKey } });

    if (!res.ok) {
      const errorCode = res.status === 401 || res.status === 403
        ? 'API_KEY_INVALID' : res.status === 429
          ? 'RATE_LIMIT_EXCEEDED' : res.status === 404
            ? 'NO_DATA' : 'UNKNOWN_ERROR';
      return {
        provider, displayName,
        status: res.status === 404 ? 'no_data' : 'error',
        data: null, nodes: [], edges: [],
        errorMessage: `VirusTotal returned HTTP ${res.status}`, errorCode,
        apiUrl, metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
      };
    }

    const json = await res.json();
    const attrs = json.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const total = malicious + suspicious + harmless + undetected;
    const categories = attrs.categories ? Object.values(attrs.categories).join(', ') : '';
    const finalUrl = attrs.last_final_url || url;
    const title = attrs.title || '';

    return {
      provider, displayName, status: 'success',
      data: {
        detectionRatio: `${malicious}/${total}`,
        malicious, suspicious, harmless, undetected,
        categories, finalUrl: finalUrl !== url ? finalUrl : undefined, title
      },
      nodes: [], edges: [], cached: false,
      apiUrl, metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
    };
  } catch (err) {
    return {
      provider, displayName: 'VirusTotal', status: 'error', data: null, nodes: [], edges: [],
      errorMessage: `VirusTotal error: ${err.message}`, errorCode: 'NETWORK_ERROR',
      apiUrl: 'https://www.virustotal.com/api/v3/urls',
      metadata: { ttlSeconds: CACHE_TTL.url / 1000, fetchedAt: Date.now() }
    };
  }
}

function buildUrlSummary(sources) {
  let riskScore = 0;
  let verdict = 'unknown';
  const tags = [];

  const urlscan = sources.find((s) => s.provider === 'urlscan' && s.status === 'success');
  const urlhaus = sources.find((s) => s.provider === 'urlhaus' && s.status === 'success');
  const phishtank = sources.find((s) => s.provider === 'phishtank' && s.status === 'success');
  const vt = sources.find((s) => s.provider === 'virustotal' && s.status === 'success');

  // PhishTank — verified phish = immediate high risk
  if (phishtank?.data?.verified) {
    riskScore = Math.max(riskScore, 90);
    tags.push('phishing');
    verdict = 'malicious';
  } else if (phishtank?.data?.inDatabase) {
    riskScore = Math.max(riskScore, 60);
    tags.push('phishing-suspected');
  }

  // URLhaus — known malware URL
  if (urlhaus?.data?.threat) {
    riskScore = Math.max(riskScore, 85);
    tags.push('malware');
    if (urlhaus.data.threat !== 'unknown') tags.push(urlhaus.data.threat.toLowerCase());
    verdict = 'malicious';
  }

  // urlscan.io verdict
  if (urlscan?.data) {
    const score = urlscan.data.score || 0;
    riskScore = Math.max(riskScore, Math.min(100, score));
    if (urlscan.data.verdict === 'malicious') verdict = 'malicious';
    else if (urlscan.data.verdict === 'suspicious' && verdict === 'unknown') verdict = 'suspicious';
    if (urlscan.data.categories) {
      urlscan.data.categories.split(',').map((c) => c.trim()).filter(Boolean).forEach((c) => tags.push(c));
    }
  }

  // VirusTotal detection ratio
  if (vt?.data) {
    const mal = vt.data.malicious || 0;
    const total = (vt.data.malicious || 0) + (vt.data.suspicious || 0) +
      (vt.data.harmless || 0) + (vt.data.undetected || 0);
    if (total > 0) {
      const vtRisk = Math.round((mal / total) * 100);
      riskScore = Math.max(riskScore, vtRisk);
      if (mal > 0) {
        tags.push(`vt:${mal}/${total}`);
        if (verdict === 'unknown') verdict = mal >= 3 ? 'malicious' : 'suspicious';
      }
    }
  }

  if (verdict === 'unknown' && riskScore === 0) verdict = 'clean';

  return {
    verdict,
    confidence: Math.min(1, riskScore / 100),
    tags: [...new Set(tags)],
    riskScore
  };
}

async function runUrlAgent(url, options = {}) {
  const [keys, providerPrefs] = await Promise.all([
    new Promise((resolve) =>
      chrome.storage.local.get(['urlscanApiKey', 'virustotalApiKey'], resolve)
    ),
    getEnabledProviders()
  ]);

  const isEnabled = (pid) => providerPrefs[pid] !== false;

  const tasks = [
    isEnabled('urlscan')    ? fetchURLscan(url, keys.urlscanApiKey)         : Promise.resolve(null),
    isEnabled('urlhaus')    ? fetchURLhaus(url)                              : Promise.resolve(null),
    isEnabled('phishtank')  ? fetchPhishTank(url)                           : Promise.resolve(null),
    isEnabled('virustotal') ? fetchVirusTotalUrl(url, keys.virustotalApiKey) : Promise.resolve(null)
  ];

  const settledResults = await Promise.allSettled(tasks);
  const sources = settledResults
    .filter((r) => r.status === 'fulfilled' && r.value)
    .map((r) => r.value);
  const successful = sources.filter((s) => s.status === 'success');
  const nodes = dedupeById(
    sources.flatMap((s) => (Array.isArray(s.nodes) ? s.nodes : []))
  );
  const edges = dedupeById(
    sources.flatMap((s) => (Array.isArray(s.edges) ? s.edges : []))
  );

  const summary = buildUrlSummary(sources);

  return {
    ioc: url,
    iocType: 'url',
    status: successful.length ? 'success' : 'error',
    sources,
    nodes,
    edges,
    summary,
    timestamp: Date.now(),
    metadata: {
      sourcesQueried: sources.length,
      sourcesSucceeded: successful.length
    }
  };
}

// Installation and setup handler
chrome.runtime.onInstalled.addListener(async (details) => {
  // On first install, set default settings
  if (details.reason === 'install') {
    chrome.storage.local.set({
      socSettings: {
        autoAnalyze: true,
        contextMenu: true,
        installedDate: new Date().toISOString()
      }
    });
  }

  // Restore floating window if it was open
  await loadFloatingWindowState();
  if (floatingWindowState.isOpen) {
    await restoreFloatingWindow();
  }

  // Always set up context menus on installation or update
  setupContextMenus();
});

// Startup handler - restore floating window if it was open
chrome.runtime.onStartup.addListener(async () => {
  await loadFloatingWindowState();
  if (floatingWindowState.isOpen) {
    await restoreFloatingWindow();
  }
});

// Function to set up all context menus
function setupContextMenus() {
  chrome.contextMenus.removeAll(() => {
    // Main analyze option
    chrome.contextMenus.create({
      id: 'analyze-selection',
      title: 'Analyze with SOC Toolkit',
      contexts: ['selection']
    });


  // Separator
  chrome.contextMenus.create({
    id: 'separator1',
    type: 'separator',
    contexts: ['selection']
  });

  // OSINT lookups (top-level for quick access)
  chrome.contextMenus.create({
    id: 'lookup-virustotal',
    title: 'Lookup in VirusTotal',
    contexts: ['selection']
  });

  chrome.contextMenus.create({
    id: 'lookup-alienvault',
    title: 'Lookup in OTX (AlienVault)',
    contexts: ['selection']
  });

  chrome.contextMenus.create({
    id: 'lookup-abuseipdb',
    title: 'Check in AbuseIPDB',
    contexts: ['selection']
  });

  chrome.contextMenus.create({
    id: 'lookup-ipinfo',
    title: 'Check in ipinfo.io',
    contexts: ['selection']
  });

  chrome.contextMenus.create({
    id: 'lookup-mitre',
    title: 'Lookup MITRE ATT&CK',
    contexts: ['selection']
  });

  chrome.contextMenus.create({
    id: 'lookup-blockchain',
    title: 'Check Crypto Address',
    contexts: ['selection']
  });

  chrome.contextMenus.create({
    id: 'separator-osint-end',
    type: 'separator',
    contexts: ['selection']
  });

  // Text Processing submenu
  chrome.contextMenus.create({
    id: 'text-processing',
    title: 'Text Processing',
    contexts: ['selection']
  });

  chrome.contextMenus.create({
    id: 'defang-iocs',
    parentId: 'text-processing',
    title: 'Defang IOCs (copy to clipboard)',
    contexts: ['selection']
  });

  chrome.contextMenus.create({
    id: 'extract-iocs',
    parentId: 'text-processing',
    title: 'Extract IOCs Only',
    contexts: ['selection']
  });

  chrome.contextMenus.create({
    id: 'url-decode',
    parentId: 'text-processing',
    title: 'URL Decode',
    contexts: ['selection']
  });

  chrome.contextMenus.create({
    id: 'generate-hash',
    parentId: 'text-processing',
    title: 'Generate Hash (SHA1/SHA256)',
    contexts: ['selection']
  });

  // CyberChef Recipes submenu
  chrome.contextMenus.create({
    id: 'cyberchef-recipes',
    title: 'Security Recipes (CyberChef)',
    contexts: ['selection']
  });
  // Create organized submenus to avoid a giant list
  chrome.contextMenus.create({
    id: 'cyberchef-malware',
    parentId: 'cyberchef-recipes',
    title: 'Malware Analysis',
    contexts: ['selection']
  });

  chrome.contextMenus.create({
    id: 'cyberchef-exif',
    parentId: 'cyberchef-recipes',
    title: 'Image / EXIF Tools',
    contexts: ['selection']
  });

  chrome.contextMenus.create({
    id: 'cyberchef-formatting',
    parentId: 'cyberchef-recipes',
    title: 'Data Formatting',
    contexts: ['selection']
  });

  // Basic encode/decode and general helpers (keep top-level for quick access)
  chrome.contextMenus.create({ id: 'decode-base64', parentId: 'cyberchef-recipes', title: 'Decode Base64', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'encode-base64', parentId: 'cyberchef-recipes', title: 'Encode Base64', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'decode-hex', parentId: 'cyberchef-recipes', title: 'Decode Hex', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'encode-hex', parentId: 'cyberchef-recipes', title: 'Encode Hex', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'decode-rot13', parentId: 'cyberchef-recipes', title: 'Decode ROT13', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'open-cyberchef', parentId: 'cyberchef-recipes', title: 'Open in CyberChef', contexts: ['selection'] });

  // --- Expand CyberChef Recipes, organized into submenus ---
  // OSINT / extraction helpers
  chrome.contextMenus.create({ id: 'cyberchef-extract-base64-inflate', parentId: 'cyberchef-recipes', title: 'Extract Base64, Inflate, Beautify', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'cyberchef-from-charcode', parentId: 'cyberchef-recipes', title: 'From CharCode', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'cyberchef-google-ei-timestamp', parentId: 'cyberchef-recipes', title: 'Google ei Timestamp Decode', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'cyberchef-extract-urls-ooxml', parentId: 'cyberchef-recipes', title: 'Extract URLs from OOXML', contexts: ['selection'] });

  // Malware Analysis submenu
  chrome.contextMenus.create({ id: 'cyberchef-gpp-password', parentId: 'cyberchef-malware', title: 'GPP Password Decrypt', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'cyberchef-extract-hex-hexdump', parentId: 'cyberchef-malware', title: 'Extract Hex / Hexdump', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'cyberchef-defeat-dosfuscation', parentId: 'cyberchef-malware', title: 'Defeat DOSfuscation', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'cyberchef-msfvenom-deob', parentId: 'cyberchef-malware', title: 'Deobfuscate MSF Venom PowerShell', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'cyberchef-cobaltstrike-config', parentId: 'cyberchef-malware', title: 'Parse Cobalt Strike Beacon Config', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'entropy-analysis', parentId: 'cyberchef-malware', title: 'Analyze Entropy', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'extract-strings', parentId: 'cyberchef-malware', title: 'Extract Readable Strings', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'cyberchef-reverse-substitute', parentId: 'cyberchef-malware', title: 'Reverse & Substitute', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'cyberchef-parse-sddl', parentId: 'cyberchef-malware', title: 'Parse SDDL', contexts: ['selection'] });

  // EXIF / image tools submenu
  chrome.contextMenus.create({ id: 'cyberchef-extract-exif', parentId: 'cyberchef-exif', title: 'Extract EXIF Data', contexts: ['selection'] });

  // Data formatting submenu
  chrome.contextMenus.create({ id: 'cyberchef-format-apache-log', parentId: 'cyberchef-formatting', title: 'Format Apache Access Log', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'cyberchef-decode-jwt', parentId: 'cyberchef-formatting', title: 'Decode JWT Token', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'cyberchef-decode-saml', parentId: 'cyberchef-formatting', title: 'Decode SAML Assertion', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'cyberchef-base45-decode', parentId: 'cyberchef-formatting', title: 'Base45 Decode', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'cyberchef-safelinks-decode', parentId: 'cyberchef-formatting', title: 'Decode Microsoft Safelinks', contexts: ['selection'] });
  chrome.contextMenus.create({ id: 'cyberchef-vtgrep', parentId: 'cyberchef-formatting', title: 'To VirusTotal Grep Query', contexts: ['selection'] });

  // Investigation Tools
  chrome.contextMenus.create({
    id: 'separator2',
    type: 'separator',
    contexts: ['selection']
  });

  chrome.contextMenus.create({
    id: 'add-to-notes',
    title: 'Add to Investigation Notes',
    contexts: ['selection']
  });
  });
}

// Context menu click handler
chrome.contextMenus.onClicked.addListener((info, tab) => {
  const selectedText = info.selectionText;
  
  switch (info.menuItemId) {
    case 'analyze-selection':
      // Store the selected text for analysis
      pendingAnalysis = selectedText;
      chrome.storage.local.set({ pendingAnalysis });
      updateBadge(true);
      chrome.action.openPopup();
      break;
      
    case 'lookup-virustotal':
      openVirusTotalLookup(selectedText);
      break;
      
    case 'lookup-alienvault':
      openAlienVaultLookup(selectedText);
      break;
      
    case 'lookup-abuseipdb':
      openAbuseIPDBLookup(selectedText);
      break;
      
    case 'lookup-ipinfo':
      openIpInfoLookup(selectedText);
      break;
      
    case 'lookup-mitre':
      openMitreLookup(selectedText);
      break;
      
    case 'lookup-blockchain':
      openBlockchainLookup(selectedText);
      break;
      
    case 'defang-iocs':
      defangAndCopy(selectedText);
      break;
      
    case 'extract-iocs':
      extractIOCsOnly(selectedText);
      break;
      
    case 'url-decode':
      urlDecodeText(selectedText);
      break;
      
    case 'generate-hash':
      generateHashOfText(selectedText);
      break;
      
    case 'decode-base64':
      decodeBase64Text(selectedText);
      break;
      
    case 'decode-hex':
      decodeHexText(selectedText);
      break;
      
    case 'encode-base64':
      encodeBase64Text(selectedText);
      break;
      
    case 'encode-hex':
      encodeHexText(selectedText);
      break;
      
    case 'decode-rot13':
      decodeROT13Text(selectedText);
      break;

    // --- CyberChef Recipes ---
    case 'cyberchef-extract-base64-inflate':
      openCyberChefRecipe(selectedText, 'extract-base64-inflate');
      break;
    case 'cyberchef-from-charcode':
      openCyberChefRecipe(selectedText, 'from-charcode');
      break;
    case 'cyberchef-gpp-password':
      openCyberChefRecipe(selectedText, 'gpp-password');
      break;
    case 'cyberchef-google-ei-timestamp':
      openCyberChefRecipe(selectedText, 'google-ei-timestamp');
      break;
    case 'cyberchef-extract-hex-hexdump':
      openCyberChefRecipe(selectedText, 'extract-hex-hexdump');
      break;
    case 'cyberchef-reverse-substitute':
      openCyberChefRecipe(selectedText, 'reverse-substitute');
      break;
    case 'cyberchef-extract-urls-ooxml':
      openCyberChefRecipe(selectedText, 'extract-urls-ooxml');
      break;
    case 'cyberchef-extract-exif':
      openCyberChefRecipe(selectedText, 'extract-exif-data');
      break;
    case 'cyberchef-defeat-dosfuscation':
      openCyberChefRecipe(selectedText, 'defeat-dosfuscation');
      break;
    case 'cyberchef-morse-code':
      openCyberChefRecipe(selectedText, 'morse-code');
      break;
    case 'cyberchef-parse-sddl':
      openCyberChefRecipe(selectedText, 'parse-sddl');
      break;
    case 'cyberchef-base45-decode':
      openCyberChefRecipe(selectedText, 'base45-decode');
      break;
    case 'cyberchef-safelinks-decode':
      openCyberChefRecipe(selectedText, 'safelinks-decode');
      break;
    case 'cyberchef-vtgrep':
      openCyberChefRecipe(selectedText, 'vtgrep');
      break;
    case 'cyberchef-decode-jwt':
      openCyberChefRecipe(selectedText, 'decode-jwt');
      break;
    case 'cyberchef-decode-saml':
      openCyberChefRecipe(selectedText, 'decode-saml');
      break;
    case 'cyberchef-format-apache-log':
      openCyberChefRecipe(selectedText, 'format-apache-log');
      break;
    case 'cyberchef-msfvenom-deob':
      openCyberChefRecipe(selectedText, 'msfvenom-deob');
      break;
    case 'cyberchef-cobaltstrike-config':
      openCyberChefRecipe(selectedText, 'cobaltstrike-config');
      break;
      
    case 'open-cyberchef':
      openInCyberChef(selectedText);
      break;
      
    case 'entropy-analysis':
      analyzeEntropy(selectedText);
      break;
      
    case 'extract-strings':
      extractStrings(selectedText);
      break;
      
    case 'add-to-notes':
      addToInvestigationNotes(selectedText);
      break;
  }
});

// Helper functions for context menu actions

// Map recipe keys to CyberChef recipe JSON (URL encoded)
const cyberchefRecipes = {
  'extract-base64-inflate': encodeURIComponent('[{"op":"Regular expression","args":["User defined","[a-zA-Z0-9+/=]{30,}",true,true,false,false,false,false,"List matches"]},{"op":"From Base64","args":["A-Za-z0-9+/=",true]},{"op":"Raw Inflate","args":[0,0,"Adaptive",false,false]},{"op":"Generic Code Beautify","args":[]}]'),
  'from-charcode': encodeURIComponent('[{"op":"Regular expression","args":["User defined","([0-9]{2,3}(,\\s|))+",true,true,false,false,false,false,"List matches"]},{"op":"From Charcode","args":["Comma",10]}]'),
  'gpp-password': encodeURIComponent('[{"op":"From Base64","args":["A-Za-z0-9+/=",true]},{"op":"To Hex","args":["None"]},{"op":"AES Decrypt","args":[{"option":"Hex","string":"4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"},{"option":"Hex","string":""},"CBC","Hex","Raw",{"option":"Hex","string":""}]},{"op":"Decode text","args":["UTF16LE (1200)"]}]'),
  'google-ei-timestamp': encodeURIComponent('[{"op":"From Base64","args":["A-Za-z0-9-_=",true]},{"op":"To Hex","args":["None"]},{"op":"Take bytes","args":[0,8,false]},{"op":"Swap endianness","args":["Hex",4,true]},{"op":"From Base","args":[16]},{"op":"From UNIX Timestamp","args":["Seconds (s)"]}]'),
  'extract-hex-hexdump': encodeURIComponent('[{"op":"Regular expression","args":["User defined","[a-fA-F0-9]{200,}",true,true,false,false,false,false,"List matches"]},{"op":"From Hex","args":["Auto"]},{"op":"To Hexdump","args":[16,false,false]}]'),
  'reverse-substitute': encodeURIComponent('[{"op":"Reverse","args":["Character"]},{"op":"Find / Replace","args":[{"option":"Regex","string":"%"},"A",true,false,true,false]},{"op":"Find / Replace","args":[{"option":"Regex","string":"×"},"T",true,false,false,false]},{"op":"Find / Replace","args":[{"option":"Simple string","string":"÷"},"V",true,false,false,false]},{"op":"From Base64","args":["A-Za-z0-9+/=",true]},{"op":"To Hexdump","args":[16,false,false]}]'),
  'extract-urls-ooxml': encodeURIComponent('[{"op":"Unzip","args":["",false]},{"op":"Extract URLs","args":[false]},{"op":"Filter","args":["Line feed","http://schemas.\\openxmlformats.\\org/",true]},{"op":"Filter","args":["Line feed","http://schemas.\\microsoft.\\com/",true]},{"op":"Filter","args":["Line feed","http://purl.\\org/",true]},{"op":"Filter","args":["Line feed","http://www.\\w.\\org/",true]},{"op":"Defang URL","args":[true,true,true,"Valid domains and full URLs"]}]'),
  'defeat-dosfuscation': encodeURIComponent('[{"op":"Comment","args":["Strip CMD caret (^) obfuscation: t^h^i^s -> this"]},{"op":"Find / Replace","args":[{"option":"Simple string","string":"^"},"",true,false,true,false]},{"op":"Comment","args":["Strip PowerShell backtick (`) obfuscation: po`wer -> power"]},{"op":"Find / Replace","args":[{"option":"Simple string","string":"`"},"",true,false,true,false]},{"op":"Comment","args":["Extract IOCs from deobfuscated output"]},{"op":"Extract URLs","args":[false]},{"op":"Extract domains","args":[true]}]'),
  'morse-code': encodeURIComponent('[{"op":"From Binary","args":["Space",8]},{"op":"From Morse Code","args":["Space","Forward slash"]},{"op":"Reverse","args":["Character"]},{"op":"ROT13","args":[true,true,false,13]}]'),
  'parse-sddl': encodeURIComponent('[{"op":"Comment","args":["subsection for the content before the ACE strings"]},{"op":"Subsection","args":["(.*?)\\(.*",false,true,false]},{"op":"Comment","args":["Each \"G:\" and \"D:\" on its own line"]},{"op":"Find / Replace","args":[{"option":"Regex","string":"([GD]):"},"\\n$1:",true,false,true,false]},{"op":"Comment","args":["add separator"]},{"op":"Find / Replace","args":[{"option":"Regex","string":"$"},"\\n######\\n",true,false,false,false]},{"op":"Merge","args":[]},{"op":"Comment","args":["subsection for the ACE strings"]},{"op":"Subsection","args":["######\\n(.*)",false,true,false]},{"op":"Find / Replace","args":[{"option":"Simple string","string":")("},"\\n",true,false,true,false]},{"op":"Find / Replace","args":[{"option":"Regex","string":"\\n"},"",true,false,true,false]}]'),
  'base45-decode': encodeURIComponent('[{"op":"From Base45","args":[]}]'),
  'safelinks-decode': encodeURIComponent('[{"op":"Split","args":["?","\\n"]},{"op":"Split","args":["&","\\n"]},{"op":"Split","args":["=","\\n"]},{"op":"Regular expression","args":["User defined","url\\s([^\\s]+)",true,true,false,false,false,false,"List capture groups"]},{"op":"URL Decode","args":[]}]'),
  'vtgrep': encodeURIComponent('[{"op":"To Hex","args":["Space",0]},{"op":"Find / Replace","args":[{"option":"Regex","string":"^"},"content:{",true,false,true,false]},{"op":"Find / Replace","args":[{"option":"Regex","string":"$"},"}",true,false,true,false]}]'),
  'decode-jwt': encodeURIComponent('[{"op":"URL Decode","args":[true]},{"op":"Fork","args":[".","\\n",false]},{"op":"From Base64","args":["A-Za-z0-9+\/=",true,false]},{"op":"Filter","args":["Line feed","^{.*}$",false]},{"op":"JSON Beautify","args":["  ",false,true]}]'),
  'decode-saml': encodeURIComponent('[{"op":"URL Decode","args":[true]},{"op":"From Base64","args":["A-Za-z0-9+\/=",true,false]},{"op":"Raw Inflate","args":[0,0,"Adaptive",false,true]},{"op":"XML Beautify","args":["\\t"]}]'),
  'format-apache-log': encodeURIComponent('[{"op":"Regular expression","args":["User defined","^(\\\S+) \\S+ \\S+ \\[([^\\]]+)\\] \\\"(\\\S+) (.*?) (\\\S+)\\\" (\\d+) (\\d+) \\\"([^\\\"]*)\\\" \\\"([^\\\"]*)\\\"",true,true,false,false,false,false,"List capture groups"]},{"op":"Find / Replace","args":[{"option":"Regex","string":"^(.*)$"},"Client: $R0\\nTime: $R1\\nMethod: $R2\\nPath: $R3\\nProto: $R4\\nStatus: $R5\\nBytes: $R6\\nReferrer: $R7\\nUser-Agent: $R8",false,false,true,false]}]'),
  'msfvenom-deob': encodeURIComponent('[{"op":"From Base64","args":["A-Za-z0-9+/=",true]},{"op":"To Hex","args":["None"]}]'),
  // Malware-analysis helpers
  'malware-extract-strings': encodeURIComponent('[{"op":"Regular expression","args":["User defined","[ -~]{4,}",true,true,false,false,false,false,"List matches"]}]'),
  'malware-pe-imports': encodeURIComponent('[{"op":"Regular expression","args":["User defined","MZ[\\s\\S]{1,1000}",true,true,false,false,false,false,"List matches"]},{"op":"To Hex","args":["None"]}]'),

  // EXIF / image extraction (simple matcher for EXIF markers)
  'extract-exif-data': encodeURIComponent('[{"op":"Regular expression","args":["User defined","Exif|GPS|Orientation",true,true,false,false,false,false,"List matches"]}]'),

  // Data formatting helpers
  'format-json-pretty': encodeURIComponent('[{"op":"URL Decode","args":[true]},{"op":"From Base64","args":["A-Za-z0-9+\\/=",true,false]},{"op":"JSON Beautify","args":["  ",false,true]}]'),
  'cobaltstrike-config': encodeURIComponent('[{"op":"To Hex","args":["None",0]},{"op":"Register","args":["([\\s\\S]*)",true,false,false]},{"op":"Regular expression","args":["User defined","(^(?:.*?)ffffff)",true,true,false,false,false,false,"List matches"]},{"op":"Find / Replace","args":[{"option":"Regex","string":"(..)"},"$1\\n",true,false,true,false]},{"op":"Add line numbers","args":[]},{"op":"Tail","args":["Line feed",1]},{"op":"Find / Replace","args":[{"option":"Regex","string":"(\\d+)"},"$1 4",true,false,true,false]},{"op":"Divide","args":["Space"]},{"op":"Find / Replace","args":[{"option":"Regex","string":"([0-9\\.]+)"},"$1 2",true,false,true,false]},{"op":"Sum","args":["Space"]},{"op":"Find / Replace","args":[{"option":"Regex","string":"(\\d+)"},"$1 4",true,false,true,false]}]'),
};

// Open CyberChef with a specific recipe and input
async function openCyberChefRecipe(text, recipeKey) {
  try {
    const result = await chrome.storage.local.get(['cyberchefUrl']);
    const cyberchefUrl = result.cyberchefUrl || 'https://gchq.github.io/CyberChef';
    const maxLength = 1500;
    const truncatedText = text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
    // CyberChef expects Base64 encoded input (UTF-8 -> Base64)
    const encodedInput = utf8ToBase64(truncatedText);
    const recipe = cyberchefRecipes[recipeKey];
    const url = `${cyberchefUrl}/#recipe=${recipe}&input=${encodedInput}`;
    chrome.tabs.create({ url });
    if (text.length > maxLength) {
      showNotification('Text Truncated', `Input truncated to ${maxLength} characters for URL compatibility`);
    }
  } catch (e) {
    showNotification('CyberChef Error', 'Failed to open CyberChef with recipe');
  }
}
function openVirusTotalLookup(text) {
  const cleanText = text.trim();
  const url = `https://www.virustotal.com/gui/search/${encodeURIComponent(cleanText)}`;
  chrome.tabs.create({ url });
}

function openAlienVaultLookup(text) {
  const cleanText = text.trim();
  // Detect IOC type for proper AlienVault endpoint
  let iocType = 'general';
  
  // Check if it's an IP address
  if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(cleanText)) {
    iocType = 'ip';
  }
  // Check if it's a hash (MD5, SHA1, SHA256)
  else if (/^[a-f0-9]{32}$/i.test(cleanText)) {
    iocType = 'file'; // MD5
  }
  else if (/^[a-f0-9]{40}$/i.test(cleanText)) {
    iocType = 'file'; // SHA1
  }
  else if (/^[a-f0-9]{64}$/i.test(cleanText)) {
    iocType = 'file'; // SHA256
  }
  // Check if it looks like a domain
  else if (/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(cleanText)) {
    iocType = 'domain';
  }
  // Check if it's a URL
  else if (/^https?:\/\//i.test(cleanText)) {
    iocType = 'url';
  }
  
  let url;
  switch (iocType) {
    case 'ip':
      url = `https://otx.alienvault.com/indicator/ip/${encodeURIComponent(cleanText)}`;
      break;
    case 'domain':
      url = `https://otx.alienvault.com/indicator/domain/${encodeURIComponent(cleanText)}`;
      break;
    case 'file':
      url = `https://otx.alienvault.com/indicator/file/${encodeURIComponent(cleanText)}`;
      break;
    case 'url':
      url = `https://otx.alienvault.com/indicator/url/${encodeURIComponent(cleanText)}`;
      break;
    default:
      // Use general search for unknown types
      url = `https://otx.alienvault.com/browse/global/pulses?q=${encodeURIComponent(cleanText)}`;
  }
  
  chrome.tabs.create({ url });
}

function openAbuseIPDBLookup(text) {
  const cleanText = text.trim();
  const url = `https://www.abuseipdb.com/check/${encodeURIComponent(cleanText)}`;
  chrome.tabs.create({ url });
}

function openIpInfoLookup(text) {
  const cleanText = text.trim();
  const url = `https://ipinfo.io/${encodeURIComponent(cleanText)}`;
  chrome.tabs.create({ url });
}

function openMitreLookup(text) {
  const cleanText = text.trim().toUpperCase();
  // Extract MITRE technique ID if present (format: T1234 or T1234.567)
  const mitreMatch = cleanText.match(/T\d{4}(?:\.\d{3})?/);
  if (mitreMatch) {
    // Sub-techniques use a path separator: T1055.001 -> T1055/001
    const url = `https://attack.mitre.org/techniques/${mitreMatch[0].replace('.', '/')}/`;
    chrome.tabs.create({ url });
  } else {
    showNotification('Invalid MITRE Technique', 'Format should be T1234 or T1234.567');
  }
}

function openBlockchainLookup(text) {
  const cleanText = text.trim();
  let url;
  
  // Check if it's a Bitcoin address (starts with 1, 3, or bc1)
  if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(cleanText) || /^bc1[a-z0-9]{39,59}$/i.test(cleanText)) {
    url = `https://www.blockchain.com/explorer/addresses/btc/${encodeURIComponent(cleanText)}`;
  }
  // Check if it's an Ethereum address (0x followed by 40 hex chars)
  else if (/^0x[a-fA-F0-9]{40}$/.test(cleanText)) {
    url = `https://etherscan.io/address/${encodeURIComponent(cleanText)}`;
  }
  // Otherwise, try generic blockchain explorers
  else {
    url = `https://www.blockchain.com/explorer/search?search=${encodeURIComponent(cleanText)}`;
  }
  
  chrome.tabs.create({ url });
}

function defangAndCopy(text) {
  // Mirror popup.js SOCToolkit#defangText so the output round-trips through the
  // popup's refang, which expects [.] and [at] and protocol-anchored hxxp/fxp.
  // The old chain used bare /ftp/g (mangling words like "software") and [@]
  // (which the popup's refang does not reverse).
  const defanged = text
    .replace(/https:\/\//gi, 'hxxps://')
    .replace(/http:\/\//gi, 'hxxp://')
    .replace(/ftp:\/\//gi, 'fxp://')
    .replace(/\./g, '[.]')
    .replace(/@/g, '[at]');

  // Copy to clipboard and show notification
  copyToClipboard(defanged);
  showNotification('IOCs Defanged', `Defanged IOCs copied to clipboard`);
}

function extractIOCsOnly(text) {
  // Use the same IOC extraction logic from popup.js
  chrome.storage.local.set({ 
    pendingAction: 'extract-iocs',
    pendingText: text 
  });
  chrome.action.openPopup();
}

function urlDecodeText(text) {
  try {
    const decoded = decodeURIComponent(text);
    copyToClipboard(decoded);
    showNotification('URL Decoded', 'Decoded text copied to clipboard');
  } catch (e) {
    showNotification('URL Decode Error', 'Invalid URL encoding');
  }
}

async function generateHashOfText(text) {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    
    // Generate SHA1 and SHA256 in parallel
    const [sha1Buffer, sha256Buffer] = await Promise.all([
      crypto.subtle.digest('SHA-1', data),
      crypto.subtle.digest('SHA-256', data)
    ]);
    
    // Convert buffers to hex strings more efficiently
    const sha1 = bufferToHex(sha1Buffer);
    const sha256 = bufferToHex(sha256Buffer);
    
    const result = `SHA1: ${sha1}\nSHA256: ${sha256}`;
    copyToClipboard(result);
    showNotification('Hashes Generated', 'SHA1 and SHA256 copied to clipboard');
  } catch (e) {
    showNotification('Hash Error', 'Failed to generate hashes');
  }
}

// Helper function to convert buffer to hex string efficiently
function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  const hexParts = [];
  for (let i = 0; i < bytes.length; i++) {
    hexParts.push(bytes[i].toString(16).padStart(2, '0'));
  }
  return hexParts.join('');
}

function decodeBase64Text(text) {
  try {
    const decoded = atob(text.trim());
    copyToClipboard(decoded);
    showNotification('Base64 Decoded', 'Decoded text copied to clipboard');
  } catch (e) {
    showNotification('Base64 Error', 'Invalid Base64 encoding');
  }
}

function encodeBase64Text(text) {
  try {
    const encoded = btoa(text);
    copyToClipboard(encoded);
    showNotification('Base64 Encoded', 'Encoded text copied to clipboard');
  } catch (e) {
    showNotification('Base64 Error', 'Failed to encode text');
  }
}

function decodeHexText(text) {
  try {
    const hex = text.replace(/\s/g, '').replace(/0x/gi, '');
    const decoded = hex.match(/.{1,2}/g)
      .map(byte => String.fromCharCode(parseInt(byte, 16)))
      .join('');
    copyToClipboard(decoded);
    showNotification('Hex Decoded', 'Decoded text copied to clipboard');
  } catch (e) {
    showNotification('Hex Error', 'Invalid hex encoding');
  }
}

function encodeHexText(text) {
  try {
    const encoded = Array.from(text)
      .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
      .join('');
    copyToClipboard(encoded);
    showNotification('Hex Encoded', 'Encoded text copied to clipboard');
  } catch (e) {
    showNotification('Hex Error', 'Failed to encode text');
  }
}

function decodeROT13Text(text) {
  try {
    const decoded = text.replace(/[a-zA-Z]/g, char => {
      const base = char <= 'Z' ? 65 : 97;
      return String.fromCharCode(((char.charCodeAt(0) - base + 13) % 26) + base);
    });
    copyToClipboard(decoded);
    showNotification('ROT13 Decoded', 'Decoded text copied to clipboard');
  } catch (e) {
    showNotification('ROT13 Error', 'Failed to decode text');
  }
}

async function openInCyberChef(text) {
  try {
    // Load custom CyberChef URL from settings
    const result = await chrome.storage.local.get(['cyberchefUrl']);
    const cyberchefUrl = result.cyberchefUrl || 'https://gchq.github.io/CyberChef';
    
    // Limit text length to prevent URL length issues (browsers typically support ~2000 chars)
    const maxLength = 1500; // Leave room for URL structure
    const truncatedText = text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
    
    // CyberChef expects Base64 encoded input (UTF-8 -> Base64)
    const encodedInput = utf8ToBase64(truncatedText);
    const url = `${cyberchefUrl}/#input=${encodedInput}`;
    
    chrome.tabs.create({ url });
    
    // Notify user if text was truncated
    if (text.length > maxLength) {
      showNotification('Text Truncated', `Input truncated to ${maxLength} characters for URL compatibility`);
    }
  } catch (e) {
    showNotification('CyberChef Error', 'Failed to open CyberChef');
  }
}

function analyzeEntropy(text) {
  const entropy = calculateEntropy(text);
  const result = `Text: ${text.substring(0, 50)}${text.length > 50 ? '...' : ''}\nEntropy: ${entropy.toFixed(4)}\nAnalysis: ${entropy > 4.5 ? 'High (possibly encrypted/encoded)' : entropy > 3.5 ? 'Medium' : 'Low (readable text)'}`;
  copyToClipboard(result);
  showNotification('Entropy Analysis', 'Results copied to clipboard');
}

function calculateEntropy(str) {
  const freq = {};
  for (let char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  
  let entropy = 0;
  const len = str.length;
  for (let char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function extractStrings(text) {
  // Extract readable ASCII strings (4+ characters)
  const strings = text.match(/[ -~]{4,}/g) || [];
  const result = strings.join('\n');
  copyToClipboard(result);
  showNotification('Strings Extracted', `${strings.length} strings copied to clipboard`);
}

function addToInvestigationNotes(text) {
  const timestamp = new Date().toISOString();
  const note = `[${timestamp}] ${text}`;
  
  chrome.storage.local.get(['investigationNotes'], (result) => {
    const notes = result.investigationNotes || [];
    notes.push(note);
    chrome.storage.local.set({ investigationNotes: notes });
    showNotification('Note Added', 'Added to investigation notes');
  });
}

async function copyToClipboard(text) {
  // Content script copies from the message payload below; the previous
  // storage.local write of `clipboardText` was never read and only left copied
  // text (which may include IOCs / page selection) sitting on disk.

  // Try to copy via content script in active tab (inject on demand)
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    if (!tabs || !tabs[0]) return;
    const tabId = tabs[0].id;
    try {
      if (tabs[0].url && /^chrome:|^about:|^edge:/.test(tabs[0].url)) return;
      await ensureContentScript(tabId);
      chrome.tabs.sendMessage(tabId, { action: 'copyToClipboard', text });
    } catch (err) {
      console.warn('copyToClipboard tab message failed:', err && err.message ? err.message : err);
    }
  });
}

function showNotification(title, message) {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon48.png',
    title,
    message
  });
}

// Message handling
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getPendingAnalysis') {
    (async () => {
      // Fall back to the storage copy: the MV3 service worker can be killed
      // between the context-menu click and the popup opening, which would wipe
      // the in-memory global. Always clear the storage copy so selected page
      // text is not left on disk.
      let text = pendingAnalysis;
      if (!text) {
        const stored = await new Promise((r) => chrome.storage.local.get(['pendingAnalysis'], r));
        text = stored.pendingAnalysis || null;
      }
      pendingAnalysis = null;
      await new Promise((r) => chrome.storage.local.remove(['pendingAnalysis'], r));
      updateBadge(false);
      sendResponse({ text: text || null });
    })();
    return true;
  }

  if (request.action === 'agentEnrich' && request.ioc) {
    (async () => {
      try {
        const res = await runAgent(request.iocType || 'ip', request.ioc, request.options || {});
        sendResponse(res);
      } catch (err) {
        sendResponse({ status: 'error', errorMessage: err.message });
      }
    })();
    return true;
  }
  
  if (request.action === 'toggleFloat') {
    handleFloatingWindow(sendResponse);
    return true; // Keep the message channel open for async response
  }

  if (request.action === 'getRateLimitStatus') {
    const status = {};
    for (const [provider, limit] of Object.entries(RATE_LIMITS)) {
      const log = rateLimiter.requestLog.get(provider) || [];
      const now = Date.now();
      const recent = log.filter(ts => now - ts < limit.window);
      status[provider] = {
        used: recent.length,
        limit: limit.requests,
        window: limit.window,
        resetInMs: recent.length > 0 ? Math.max(0, Math.min(...recent) + limit.window - now) : 0
      };
    }
    sendResponse({ status });
    return true;
  }
  
  // ... other message handlers
  // Passive DNS enrichment handler (VirusTotal fallback to web UI)
  if (request.action === 'passiveDnsEnrich' && request.domain) {
    (async () => {
      try {
        const domain = request.domain.trim();
        const cachedKey = `pdns_cache_${domain}`;
        const cache = await new Promise(resolve => chrome.storage.local.get([cachedKey], resolve));
        const cached = cache[cachedKey];
        const now = Date.now();
        // Use cache if fresh (24h)
        if (cached && cached.timestamp && (now - cached.timestamp) < 24 * 60 * 60 * 1000) {
          sendResponse({ provider: cached.provider, records: cached.records, cached: true });
          return;
        }

        const st = await new Promise(resolve => chrome.storage.local.get(['virustotalApiKey'], resolve));
        const apiKey = st.virustotalApiKey;

        if (!apiKey) {
          // No API key -> open VirusTotal web UI for manual lookup
          openVirusTotalLookup(domain);
          sendResponse({ fallback: 'web', opened: true });
          return;
        }

        // Call VirusTotal Domain resolutions endpoint
        const url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}/resolutions`;
        const resp = await fetch(url, { headers: { 'x-apikey': apiKey } });
        if (!resp.ok) {
          // If rate-limited or error, fallback to web UI
          openVirusTotalLookup(domain);
          sendResponse({ fallback: 'web', opened: true, status: resp.status });
          return;
        }

        const j = await resp.json();
        const records = [];
        if (j && j.data && Array.isArray(j.data)) {
          for (const item of j.data) {
            const attrs = item.attributes || {};
            // VT returns { ip_address, last_seen } in attributes for resolutions
            records.push({ ip: attrs.ip_address || attrs.value || null, lastSeen: attrs.last_seen || null });
          }
        }

        // Cache normalized result
        const cacheObj = { provider: 'virustotal', records, timestamp: Date.now() };
        chrome.storage.local.set({ [cachedKey]: cacheObj });

        sendResponse({ provider: 'virustotal', records });
      } catch (err) {
        console.error('Passive DNS enrichment error:', err);
        // On error, open web UI
        if (request.domain) openVirusTotalLookup(request.domain);
        sendResponse({ error: err.message });
      }
    })();
    return true; // Keep message channel open for async response
  }

  // ASN enrichment for IPs (uses ipinfo.io as a no-key option)
  if (request.action === 'asnEnrich' && request.ip) {
    (async () => {
      try {
        const ip = request.ip.trim();
        const cachedKey = `asn_cache_${ip}`;
        const cache = await new Promise(resolve => chrome.storage.local.get([cachedKey], resolve));
        const cached = cache[cachedKey];
        const now = Date.now();
        if (cached && cached.timestamp && (now - cached.timestamp) < 24 * 60 * 60 * 1000) {
          sendResponse({ cached: true, asn: cached.asn });
          return;
        }
        // Prefer VirusTotal if API key present for richer ASN/prefix/registry info
        const cfg = await new Promise(resolve => chrome.storage.local.get(['virustotalApiKey'], resolve));
        const vtKey = cfg.virustotalApiKey;
        let asn = null;
        if (vtKey) {
          try {
            const vtUrl = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`;
            const vtResp = await fetch(vtUrl, { headers: { 'x-apikey': vtKey } });
            if (vtResp.ok) {
              const vj = await vtResp.json();
              const attrs = (vj && vj.data && vj.data.attributes) || {};
              // Attempt to extract ASN details
              if (attrs.asn || attrs.as_owner || (attrs.network && attrs.network.asn)) {
                const asnNumber = attrs.asn || (attrs.network && attrs.network.asn) || null;
                const asnName = attrs.as_owner || (attrs.network && attrs.network.name) || null;
                const prefix = (attrs.network && attrs.network.cidr) || null;
                const registry = (attrs.network && attrs.network.rir) || null;
                asn = { number: asnNumber ? `AS${asnNumber}` : null, name: asnName, prefix, registry };
              }
            }
          } catch (e) {
            console.warn('VirusTotal ASN lookup failed, falling back to ipinfo', e);
          }
        }

        // Fallback to ipinfo if VT didn't return ASN info
        if (!asn) {
          const url = `https://ipinfo.io/${encodeURIComponent(ip)}/json`;
          const resp = await fetch(url);
          if (!resp.ok) {
            openIpInfoLookup(ip);
            sendResponse({ fallback: 'web', opened: true, status: resp.status });
            return;
          }
          const j = await resp.json();
          if (j && j.org) {
            const m = j.org.match(/AS(\d+)\s*(.*)/);
            if (m) {
              asn = { number: `AS${m[1]}`, name: (m[2] || '').trim(), prefix: j.ip || null, registry: j.country || null };
            } else {
              asn = { number: null, name: j.org, prefix: j.ip || null, registry: j.country || null };
            }
          }
        }

        const cacheObj = { asn, timestamp: Date.now() };
        chrome.storage.local.set({ [cachedKey]: cacheObj });
        sendResponse({ asn });
      } catch (err) {
        console.error('ASN enrichment error:', err);
        if (request.ip) openIpInfoLookup(request.ip);
        sendResponse({ error: err.message });
      }
    })();
    return true;
  }

  // No handler matched: return false so the message channel closes immediately
  // instead of being held open (which hangs any sender awaiting sendResponse).
  return false;
});

// Inject content.js into a tab on demand (used by snippet overlay + selected-text features)
async function ensureContentScript(tabId) {
  if (!tabId) return false;
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content.js']
    });
    return true;
  } catch (err) {
    console.warn('SOC Toolkit: content script injection failed:', err && err.message ? err.message : err);
    return false;
  }
}

// Command handler
chrome.commands.onCommand.addListener((command) => {
  if (command === '_execute_action') {
    // Handle keyboard shortcut
    chrome.action.openPopup();
  } else if (command === 'toggle-snippets') {
    // Toggle snippet expansion in active tab (inject content.js first; do not auto-inject on every page)
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (!tabs || !tabs[0]) return;
      const tabId = tabs[0].id;
      try {
        if (tabs[0].url && /^chrome:|^about:|^edge:/.test(tabs[0].url)) return; // can't inject into chrome:// pages
        await ensureContentScript(tabId);
        chrome.tabs.sendMessage(tabId, { action: 'toggleSnippets' }, (response) => {
          if (chrome.runtime.lastError) {
            console.error('Snippet toggle failed:', chrome.runtime.lastError.message);
          }
        });
      } catch (err) {
        console.error('toggle-snippets failed:', err);
      }
    });
  }
});

// Floating window state management
async function saveFloatingWindowState() {
  try {
    await chrome.storage.local.set({ floatingWindowState });
  } catch (error) {
    console.error('Error saving floating window state:', error);
  }
}

async function loadFloatingWindowState() {
  try {
    const result = await chrome.storage.local.get(['floatingWindowState']);
    if (result.floatingWindowState) {
      floatingWindowState = { ...floatingWindowState, ...result.floatingWindowState };
    }
  } catch (error) {
    console.error('Error loading floating window state:', error);
  }
}

async function restoreFloatingWindow() {
  try {
    // Check if the window still exists
    if (floatingWindow) {
      try {
        await chrome.windows.get(floatingWindow.id);
        return; // Window still exists, no need to restore
      } catch {
        floatingWindow = null; // Window doesn't exist anymore
      }
    }

    // Create new floating window with saved state
    const window = await chrome.windows.create({
      url: chrome.runtime.getURL('popup.html'),
      type: 'popup',
      width: floatingWindowState.width,
      height: floatingWindowState.height,
      left: floatingWindowState.left,
      top: floatingWindowState.top,
      focused: false
    });

    floatingWindow = window;
    floatingWindowState.isOpen = true;
    await saveFloatingWindowState();
  } catch (error) {
    console.error('Error restoring floating window:', error);
    floatingWindowState.isOpen = false;
    await saveFloatingWindowState();
  }
}

// Floating window management
async function handleFloatingWindow(sendResponse) {
  try {
    // Close existing floating window if it exists
    if (floatingWindow) {
      await chrome.windows.remove(floatingWindow.id);
      floatingWindow = null;
      floatingWindowState.isOpen = false;
      await saveFloatingWindowState();
      sendResponse({ success: true, action: 'closed' });
      return;
    }

    // Create new floating window
    const window = await chrome.windows.create({
      url: chrome.runtime.getURL('popup.html'),
      type: 'popup',
      width: floatingWindowState.width,
      height: floatingWindowState.height,
      left: floatingWindowState.left,
      top: floatingWindowState.top,
      focused: true
    });

    floatingWindow = window;
    floatingWindowState.isOpen = true;
    await saveFloatingWindowState();

    // Listen for window position/size changes. Guard on floatingWindow: once the
    // window closes this listener must not dereference a null floatingWindow.id.
    const onBoundsChangedListener = (win) => {
      if (!floatingWindow || win.id !== floatingWindow.id) return;
      floatingWindowState.width = win.width;
      floatingWindowState.height = win.height;
      floatingWindowState.left = win.left;
      floatingWindowState.top = win.top;
      saveFloatingWindowState();
    };

    // Listen for window close events, and tear down BOTH listeners on close so
    // onBoundsChanged doesn't keep firing (and throwing) for every other window.
    const onRemovedListener = (windowId) => {
      if (!floatingWindow || windowId !== floatingWindow.id) return;
      floatingWindow = null;
      floatingWindowState.isOpen = false;
      saveFloatingWindowState();
      chrome.windows.onRemoved.removeListener(onRemovedListener);
      chrome.windows.onBoundsChanged.removeListener(onBoundsChangedListener);
    };

    chrome.windows.onRemoved.addListener(onRemovedListener);
    chrome.windows.onBoundsChanged.addListener(onBoundsChangedListener);

    sendResponse({ success: true, windowId: window.id, action: 'opened' });
  } catch (error) {
    console.error('Error creating floating window:', error);
    sendResponse({ success: false, error: error.message });
  }
}

// Window closed handler
chrome.windows.onRemoved.addListener((windowId) => {
  if (floatingWindow && floatingWindow.id === windowId) {
    floatingWindow = null;
  }
});

// Badge setup
chrome.action.setBadgeBackgroundColor({ color: '#3b82f6' });

function updateBadge(hasPending) {
  chrome.action.setBadgeText({ text: hasPending ? '!' : '' });
}
