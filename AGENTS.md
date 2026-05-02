# SOC Analyst Toolkit — Agents & Enrichment Roadmap

This document defines agent-like enrichment components ("agents") for the SOC Analyst Toolkit extension. It provides prioritized tasks, integration notes, security considerations, and implementation guidance so maintainers can implement or extend enrichment functionality consistently.

## Table of Contents

- [Purpose & High-Level Goals](#purpose--high-level-goals)
- [Agent Overview by IOC Type](#agent-overview-by-ioc-type)
- [Agent Architecture](#agent-architecture)
- [API Key Management](#api-key-management)
- [Normalized Result Format](#normalized-result-format)
- [Caching & TTL Strategy](#caching--ttl-strategy)
- [Rate-Limiting & Backoff](#rate-limiting--backoff)
- [Privacy & User Consent](#privacy--user-consent)
- [UX Patterns](#ux-patterns)
- [Resiliency & Error Handling](#resiliency--error-handling)
- [Developer & Testing Notes](#developer--testing-notes)
- [Security Scanning & CI](#security-scanning--ci)
- [Priority Implementation Roadmap](#priority-implementation-roadmap)
- [Implementation Checklist](#implementation-checklist)
- [Per-Agent Detailed Specifications](#per-agent-detailed-specifications)
  - [IP Agent](#ip-agent)
  - [Domain Agent](#domain-agent)
  - [URL Agent](#url-agent)
  - [Hash Agent](#hash-agent)
  - [Email Agent](#email-agent)
  - [Certificate Agent](#certificate-agent)
- [References & Useful Endpoints](#references--useful-endpoints)
- [Long-term Enhancements](#long-term-enhancements)

---

## Purpose & High-Level Goals

### Purpose
Define safe, auditable, user-initiated enrichment of IOCs (IPs, domains, URLs, hashes, emails, certificates, ASN/CIDR) using third-party services and internal feeds.

### High-Level Goals
1. **User-Initiated Only**: All network lookups initiated only by explicit user actions (privacy requirement)
2. **Pluggable Architecture**: Enable new connectors to be added with minimal changes
3. **Normalized Results**: Consistent result format with clear provenance and TTLs
4. **Safe & Auditable**: All integrations traceable, testable, and security-scanned
5. **Performance**: Efficient caching and rate-limiting to minimize redundant API calls

### Non-Goals
- Automated background scanning without user action
- Storing sensitive IOC data in cloud services
- Real-time alerting or monitoring

---

## Agent Overview by IOC Type

### IP Agent
**Tasks**: Geolocation, ASN, abuse score, Shodan/Censys data, GreyNoise, open ports, historical observed ports, passive DNS mapping.

**Primary Sources**: VirusTotal (when API key present), AbuseIPDB, GreyNoise, Shodan, Censys, ipinfo.io (no-key fallback).

**Output**: ASN node, geo node, abuse score node, optional Shodan device node(s), edges: `observed-at`, `belongs-to`, `reported-by`.

### Domain Agent
**Tasks**: Passive DNS, WHOIS, registration history, subdomain enumeration, crt.sh certificate history, screenshot, reputation score.

**Primary Sources**: VirusTotal, PassiveTotal/DNSDB (if available), crt.sh, WHOIS (WhoisXML or native whois via service), urlscan.io (for live pages/screenshots).

**Output**: IP nodes from passive DNS, WHOIS node, subdomain nodes, certificate nodes.

### URL Agent
**Tasks**: urlscan.io scan, redirect chain extraction, page content hash, screenshot, reputation/phishing lists, sandboxed behavior (if downloadable payloads exist).

**Primary Sources**: urlscan.io, VirusTotal URL endpoint, PhishTank, urlscan screenshots API.

**Output**: URL node with metadata, links to scans and screenshots, extracted IOCs (domains/hashes) added to graph.

### Hash/File Agent
**Tasks**: VirusTotal file report, sandbox (HybridAnalysis), YARA/peinfo extraction, pehash/SSDEEP similarity, embedded URL extraction.

**Primary Sources**: VirusTotal file API, HybridAnalysis, MISP/internal feed.

**Output**: File node with file metadata and edges to observed domains/IPs/samples.

### Email Agent
**Tasks**: MX/SPF/DKIM verification, sender domain WHOIS, breach/paste checks (HaveIBeenPwned, Pastebin), associated IPs extraction.

**Primary Sources**: DNS lookups, WHOIS, HaveIBeenPwned (requires API), internal mail logs.

**Output**: Email node with validation status, MX records, breach data, edges to domain nodes.

### Certificate Agent
**Tasks**: SANs, issuer, CT logs via crt.sh, mapping certs → domains → IPs.

**Primary Sources**: crt.sh, Censys, certstream APIs.

**Output**: Certificate node with issuer/subject/SANs, edges to domain nodes discovered in SANs.

---

## Agent Architecture

### Design Principles

1. **User-Initiated Only**: All enrichment requests triggered by explicit user action (button click, context menu selection, node double-click)
2. **Background Processing**: Use `background.js` / service-worker as the central orchestrator for all API calls
3. **Separation of Concerns**: 
   - Background/service-worker: network calls, caching, rate limits, API key management
   - Popup/UI: renders progressive results, displays provenance, allows user to accept/merge results into graph
4. **Agent Isolation**: Each agent is a self-contained module with consistent interface

### Agent Registry

Keep a single background/service-worker module `agentsRegistry` that registers available agents with metadata:

```javascript
// background.js - Agent Registry
const agentsRegistry = {
  'ip-geo': {
    id: 'ip-geo',
    name: 'IP Geolocation',
    supportedTypes: ['ip', 'ipv4', 'ipv6'],
    requiredApiKeys: ['ipinfo'],
    optionalApiKeys: ['maxmind'],
    rateLimitBudget: { requests: 50000, window: 86400000 }, // 50k/day
    uiLabel: 'Enrich with Geolocation',
    run: async (ioc, options) => { /* implementation */ }
  },
  'ip-reputation': {
    id: 'ip-reputation',
    name: 'IP Reputation',
    supportedTypes: ['ip', 'ipv4', 'ipv6'],
    requiredApiKeys: ['abuseipdb'],
    optionalApiKeys: ['greynoise'],
    rateLimitBudget: { requests: 1000, window: 86400000 }, // 1k/day
    uiLabel: 'Enrich with Reputation Data',
    run: async (ioc, options) => { /* implementation */ }
  },
  // ... more agents
};
```

### Standard Agent Interface

All agents expose a standard interface:

```javascript
async run({ type, value, options }) {
  return {
    status: 'success' | 'error' | 'no_data',
    data: { /* normalized data */ },
    source: 'provider-name',
    cached: true | false,
    nodes: [ /* graph nodes to add */ ],
    edges: [ /* graph edges to add */ ],
    metadata: {
      fetchedAt: timestamp,
      ttlSeconds: number,
      apiUrl: 'https://...',
      rateLimit: { remaining: number, resetAt: timestamp }
    }
  };
}
```

### Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         popup.js                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  User triggers enrichment (click "Enrich IP")        │   │
│  └──────────────────────────────────────────────────────┘   │
│                            │                                 │
│                            ▼                                 │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  chrome.runtime.sendMessage({                        │   │
│  │    action: 'enrichIP',                               │   │
│  │    ip: '1.2.3.4'                                     │   │
│  │  })                                                  │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      background.js                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  chrome.runtime.onMessage listener                   │   │
│  │  ├─ Check cache for existing results                 │   │
│  │  ├─ Check rate limits                                │   │
│  │  ├─ Validate API keys                                │   │
│  │  └─ Dispatch to appropriate agent                    │   │
│  └──────────────────────────────────────────────────────┘   │
│                            │                                 │
│                            ▼                                 │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Agent Modules                           │   │
│  │  ┌────────────────────────────────────────────────┐  │   │
│  │  │  IPAgent.enrich(ip)                            │  │   │
│  │  │  ├─ fetchGeoLocation()                         │  │   │
│  │  │  ├─ fetchASN()                                 │  │   │
│  │  │  ├─ fetchAbuseIPDB()                           │  │   │
│  │  │  └─ aggregateResults()                         │  │   │
│  │  └────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────┘   │
│                            │                                 │
│                            ▼                                 │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Cache results (chrome.storage.local)               │   │
│  │  Return normalized result to popup                  │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                         popup.js                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Receive enrichment results                          │   │
│  │  Render in collapsible "Enrichment" section         │   │
│  │  Display error states gracefully                     │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### File Structure

```
background.js
  ├─ agentsRegistry (Map: id -> agent metadata & run function)
  ├─ enrichmentCache (Map: ioc -> cached result)
  ├─ rateLimiter (per-source token bucket with persisted counters)
  └─ agents/
      ├─ IPAgent (geo, ASN, reputation)
      ├─ DomainAgent (WHOIS, passive DNS, crt.sh)
      ├─ HashAgent (VirusTotal, malware analysis)
      ├─ URLAgent (urlscan.io, PhishTank)
      ├─ EmailAgent (HIBP, domain validation)
      └─ CertificateAgent (CT logs, SANs)

popup.js
  └─ enrichmentUI/
      ├─ renderEnrichmentSection() - collapsible results display
      ├─ renderStreamingResults() - progressive loading panel
      ├─ renderMergeConfirmation() - accept/discard UI
      ├─ showEnrichmentLoading() - spinner states
      └─ handleEnrichmentError() - structured error display
```

### Notes for Maintainers

- **Single Point for Network Calls**: Keep the background/service-worker file as the single place where outbound network calls are made to avoid CORS and expose keys only to the worker.
- **Graceful Fallbacks**: When possible, prefer publicly accessible web UI fallbacks when API keys are missing to keep the experience graceful.
- **Mock Server**: Consider creating a small mock agent server to enable offline testing of UI functionality without burning third-party quotas.

---

## API Key Management

### Storage
- Store keys in `chrome.storage.local` per-service
- For now, store raw but minimize exposure (masked UIs, copy-protection)
- Future: encrypt with platform APIs if available

### Settings UI
Provide a `Settings` area for:
- API key inputs per service
- Test connection buttons to validate keys
- Rate-limit counters per-service showing remaining quota
- Enable/disable toggles for each source

### Key Validation
- Validate and surface API response codes:
  - `401/403` → invalid key; show error and link to signup page
  - `429` → rate-limited; show clear message and fallback behavior
  - `200` → valid; show success confirmation

### Security
- Mask API keys in UI (show only first/last 4 characters)
- Never log full API keys to console
- Clear keys immediately when user removes them
- Use HTTPS for all API calls

---

## Normalized Result Format

All agents return results in a consistent, structured format to simplify rendering and caching.

### Standard Format

```javascript
{
  "source": "virustotal",              // Provider identifier (lowercase, no spaces)
  "type": "ip",                        // ip, domain, url, hash, email, certificate, asn
  "ioc": "1.2.3.4",                    // The IOC being enriched
  "timestamp": 1702841234567,          // Unix timestamp (ms)
  "status": "success",                 // success, error, no_data
  "cached": false,                     // Whether result came from cache
  "data": {                            // Provider-specific enrichment data
    // Flexible structure per source
  },
  "nodes": [                           // Graph nodes to add/update
    {
      "id": "asn-4837",
      "label": "AS4837 CHINA UNICOM",
      "type": "asn",
      "properties": { "country": "CN", "org": "CHINA UNICOM" }
    },
    {
      "id": "geo-beijing",
      "label": "Beijing, CN",
      "type": "geo",
      "properties": { "city": "Beijing", "country": "CN", "lat": 39.9042, "lon": 116.4074 }
    }
  ],
  "edges": [                           // Graph edges to add
    {
      "from": "1.2.3.4",
      "to": "asn-4837",
      "label": "belongs-to",
      "properties": { "source": "virustotal" }
    },
    {
      "from": "1.2.3.4",
      "to": "geo-beijing",
      "label": "observed-at",
      "properties": { "source": "ipinfo" }
    }
  ],
  "metadata": {
    "fetchedAt": 1702841234567,
    "ttlSeconds": 86400,               // 24 hours
    "apiUrl": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
    "enrichmentTime": 342,             // Time taken (ms)
    "rateLimit": {
      "remaining": 450,
      "resetAt": 1702844834567
    }
  },
  "errorMessage": null                 // Error details if status == "error"
}
```

### Aggregated Results

For multi-source enrichment, wrap individual results:

```javascript
{
  "ioc": "1.2.3.4",
  "iocType": "ip",
  "timestamp": 1702841234567,
  "sources": [                         // Array of source results
    {
      "provider": "abuseipdb",         // Source identifier (lowercase, no spaces)
      "displayName": "AbuseIPDB",      // Human-readable name
      "status": "success",             // success, error, no_data
      "cached": false,                 // Whether result came from cache
      "data": {                        // Provider-specific enrichment data
        "abuseConfidenceScore": 85,
        "country": "CN",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example Hosting Ltd",
        "totalReports": 42,
        "lastReported": "2024-01-15T10:30:00Z"
      },
      "errorMessage": null,            // Error details if status == "error"
      "apiUrl": "https://api.abuseipdb.com/...",  // API endpoint used (for debugging)
      "rateLimit": {                   // Rate limit info (optional)
        "remaining": 450,
        "resetAt": 1702844834567
      }
    },
    {
      "provider": "ipinfo",
      "displayName": "ipinfo.io",
      "status": "success",
      "cached": true,
      "data": {
        "city": "Beijing",
        "region": "Beijing",
        "country": "CN",
        "loc": "39.9042,116.4074",
        "org": "AS4837 CHINA UNICOM China169 Backbone",
        "postal": "100000",
        "timezone": "Asia/Shanghai"
      },
      "errorMessage": null,
      "apiUrl": "https://ipinfo.io/1.2.3.4/json"
    }
  ],
  "summary": {                         // High-level summary for quick display
    "verdict": "malicious",            // clean, suspicious, malicious, unknown
    "confidence": 0.85,                // 0.0 to 1.0
    "tags": ["scanner", "datacenter", "china"],
    "riskScore": 85                    // 0-100 aggregate risk score
  },
  "metadata": {
    "enrichmentTime": 342,             // Time taken to enrich (ms)
    "sourcesQueried": 2,
    "sourcesSucceeded": 2,
    "sourcesFailed": 0
  }
}
```

### Error Format

When an individual source fails:

```javascript
{
  "provider": "greynoise",
  "displayName": "GreyNoise",
  "status": "error",
  "cached": false,
  "data": null,
  "errorMessage": "API rate limit exceeded. Try again in 15 minutes.",
  "errorCode": "RATE_LIMIT_EXCEEDED",  // Standardized error codes
  "apiUrl": "https://api.greynoise.io/v3/community/1.2.3.4"
}
```

**Standardized Error Codes:**
- `API_KEY_MISSING`: No API key configured
- `API_KEY_INVALID`: API key rejected by provider
- `RATE_LIMIT_EXCEEDED`: Rate limit hit
- `NETWORK_ERROR`: Network connectivity issue
- `TIMEOUT`: Request timed out
- `INVALID_IOC`: IOC format rejected by provider
- `NO_DATA`: Provider returned no results (not an error)
- `UNKNOWN_ERROR`: Unexpected error

---

## Caching & TTL Strategy

Effective caching reduces API costs, improves performance, and respects rate limits.

### Cache Storage

- **Location**: `chrome.storage.local`
- **Key Format**: `agent_<source>_<type>_<value>`
  - Examples: `agent_virustotal_ip_1.2.3.4`, `agent_abuseipdb_ip_1.2.3.4`
  - For sensitive IOCs (URLs, emails), consider hashing: `agent_virustotal_url_<sha256_hash>`
- **Value**: Normalized result object with cache metadata
- **On `run`**: If cached and not expired, return cached result and mark `cached: true` in response
- **Privacy**: Hash or encode IOC values in keys for sensitive data (URLs with credentials, file paths)

### TTL (Time-To-Live) by IOC Type

Different IOC types have different data volatility:

| IOC Type | Default TTL | Rationale | Configurable |
|----------|-------------|-----------|--------------|
| **IP** | 24 hours | IP reputation changes daily; geo rarely changes | Per-agent override |
| **Domain** | 7 days | WHOIS stable; passive DNS accumulates over time | Per-agent override |
| **Hash** | 7 days | File analysis results; AV verdicts stabilize quickly | Per-agent override |
| **URL** | 6 hours | URLs can be taken down or redirected quickly | Per-agent override |
| **Email** | 7 days | Email domain reputation relatively stable | Per-agent override |
| **Certificate** | 30 days | Certificates valid for months/years | Per-agent override |
| **ASN/CIDR** | 7 days | ASN assignments change infrequently | Per-agent override |

### Cache Invalidation

- **Manual**: User can clear cache via Settings tab ("Clear Enrichment Cache" button)
- **Automatic**: Cache entries expire based on TTL
- **On Error**: Failed requests are NOT cached to allow immediate retry
- **On Update**: When re-enriching, old cache entry is replaced

### Cache Size Limits

- **Max entries**: 1000 cached results per source
- **Eviction policy**: LRU (Least Recently Used)
- **Storage quota**: Chrome extension limit (~10MB for local storage)
- **UI**: Provide cache viewer and purge options (already present in the popup); add per-source TTL overrides later

### Implementation Example

```javascript
// background.js
const CACHE_TTL = {
  ip: 24 * 60 * 60 * 1000,       // 24 hours
  domain: 7 * 24 * 60 * 60 * 1000,  // 7 days
  hash: 30 * 24 * 60 * 60 * 1000,   // 30 days
  url: 6 * 60 * 60 * 1000,       // 6 hours
  email: 7 * 24 * 60 * 60 * 1000,   // 7 days
  certificate: 30 * 24 * 60 * 60 * 1000  // 30 days
};

async function getCachedEnrichment(source, iocType, ioc) {
  const cacheKey = `agent_${source}_${iocType}_${ioc}`;
  const result = await chrome.storage.local.get([cacheKey]);
  
  if (result[cacheKey]) {
    const cached = result[cacheKey];
    const age = Date.now() - cached.timestamp;
    const ttl = cached.metadata?.ttlSeconds * 1000 || CACHE_TTL[iocType];
    
    if (age < ttl) {
      // Create a copy and mark as cached (avoid mutating stored object)
      const cachedCopy = JSON.parse(JSON.stringify(cached));
      cachedCopy.cached = true;
      return cachedCopy;
    } else {
      // Expired - remove from cache
      await chrome.storage.local.remove([cacheKey]);
    }
  }
  
  return null;
}

async function setCachedEnrichment(source, iocType, ioc, result) {
  const cacheKey = `agent_${source}_${iocType}_${ioc}`;
  
  // Add timestamp if not present
  if (!result.timestamp) {
    result.timestamp = Date.now();
  }
  
  await chrome.storage.local.set({ [cacheKey]: result });
  
  // Enforce max cache size (LRU eviction)
  // Get all agent cache keys
  const allData = await chrome.storage.local.get(null);
  const cacheEntries = Object.entries(allData)
    .filter(([key]) => key.startsWith('agent_'))
    .map(([key, val]) => ({ key, timestamp: val.timestamp || 0 }));
  
  if (cacheEntries.length > 1000) {
    // Sort by timestamp, keep newest 1000
    cacheEntries.sort((a, b) => b.timestamp - a.timestamp);
    const toRemove = cacheEntries.slice(1000).map(e => e.key);
    await chrome.storage.local.remove(toRemove);
  }
}
```

---

## Rate-Limiting & Backoff

Respect API provider rate limits to avoid account suspension and ensure reliable service.

### Per-Source Token Bucket

Implement a per-source token bucket with persisted counters in `chrome.storage.local`:

```javascript
// background.js - Rate Limiter
const RATE_LIMITS = {
  abuseipdb: {
    requests: 1000,      // Max requests
    window: 86400000,    // Per day (ms)
    backoff: 300000      // 5 min backoff on limit
  },
  ipinfo: {
    requests: 50000,
    window: 86400000,
    backoff: 60000       // 1 min backoff
  },
  virustotal: {
    requests: 4,         // Free tier: 4 req/min
    window: 60000,       // Per minute
    backoff: 900000      // 15 min backoff
  },
  greynoise: {
    requests: 100,
    window: 86400000,
    backoff: 300000
  },
  shodan: {
    requests: 100,
    window: 86400000,
    backoff: 300000
  },
  urlscanio: {
    requests: 50,
    window: 86400000,
    backoff: 300000
  }
};

class RateLimiter {
  constructor() {
    this.requestLog = new Map();  // provider -> [timestamp, timestamp, ...]
  }
  
  canMakeRequest(provider) {
    const limit = RATE_LIMITS[provider];
    if (!limit) return true;  // No limit defined
    
    const now = Date.now();
    const requests = this.requestLog.get(provider) || [];
    
    // Remove requests outside the window
    const recentRequests = requests.filter(ts => now - ts < limit.window);
    this.requestLog.set(provider, recentRequests);
    
    return recentRequests.length < limit.requests;
  }
  
  recordRequest(provider) {
    const requests = this.requestLog.get(provider) || [];
    requests.push(Date.now());
    this.requestLog.set(provider, requests);
  }
  
  getTimeUntilAvailable(provider) {
    const limit = RATE_LIMITS[provider];
    if (!limit) return 0;
    
    const requests = this.requestLog.get(provider) || [];
    if (requests.length === 0) return 0;
    
    const oldestRequest = Math.min(...requests);
    const windowEnd = oldestRequest + limit.window;
    const waitTime = Math.max(0, windowEnd - Date.now());
    
    return waitTime;
  }
}

const rateLimiter = new RateLimiter();
```

### Exponential Backoff

For transient errors (network issues, timeouts):

```javascript
async function fetchWithBackoff(url, options, maxRetries = 3) {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const response = await fetch(url, options);
      
      if (response.ok) {
        return response;
      } else if (response.status === 429) {
        // Rate limited - use exponential backoff
        const retryAfter = response.headers.get('Retry-After');
        const delay = retryAfter 
          ? parseInt(retryAfter) * 1000 
          : Math.min(1000 * Math.pow(2, attempt), 30000);
        
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      } else {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
    } catch (error) {
      if (attempt === maxRetries - 1) throw error;
      
      // Exponential backoff: 1s, 2s, 4s
      const delay = 1000 * Math.pow(2, attempt);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}
```

### Handling 429 Errors

On 429 errors, implement exponential backoff per-request and surface fallback:

```javascript
// On 429 error:
// 1. Parse Retry-After header if present
// 2. Calculate exponential backoff: Math.min(1000 * Math.pow(2, attempt), 30000)
// 3. Display user message: "Rate limit exceeded. Retrying in Xs..."
// 4. Offer fallback: "Open web UI" or "Queue offline retry" (if user opts-in)
```

### User Feedback

When rate limits are hit:
- Display clear error message in enrichment section
- Show time remaining until rate limit resets
- Offer option to use cached data (even if expired)
- Provide link to upgrade to paid API tier (if applicable)
- Allow user to queue request for later (opt-in)

---

## Privacy & User Consent

Enrichment involves sending IOCs to third-party services. Privacy must be a top priority.

### Core Principles

1. **User-Initiated Only**: All lookups triggered by explicit user action (button click, context menu, node double-click); never auto-run on load
2. **API Key Storage**: API keys stored locally in `chrome.storage.local` (never in cloud)
3. **No Automatic Enrichment**: No background scanning without user consent
4. **Data Minimization**: Only send necessary IOC data (not full context/notes)
5. **Transparency**: Clearly state in UI where API keys are stored and that lookups send data to third parties

### Global Toggle

Provide a global toggle to disable specific third-party integrations:

```
Settings → Privacy
  ☐ Disable all third-party enrichment
  ☐ Disable IP enrichment
  ☐ Disable URL scanning
  ☐ Disable file hash lookups
```

### Data Retention

- **Cache**: User can clear cache at any time via Settings
- **API Keys**: Deleted immediately when user removes them
- **Request Logs**: Rate limiter logs cleared on browser restart
- **No Telemetry**: No usage data sent to extension developers

---

## UX Patterns

Enrichment should enhance the analyst workflow without adding friction.

### Enrich Submenu (Right-Click Node)

Lists available agents for that IOC type and optionally the provider:

```
Right-click on IP node → Enrich
  → Enrich with Geolocation (ipinfo.io)
  → Enrich with Reputation (AbuseIPDB)
  → Enrich with Classification (GreyNoise)
  → Enrich with All IP Sources
```

### Streaming Results Panel

Show provider rows with a loading spinner; append parsed nodes/edges as they arrive:

```
┌────────────────────────────────────────────────┐
│ Enriching 1.2.3.4...                           │
├────────────────────────────────────────────────┤
│ ✓ ipinfo.io          Completed (342ms)        │
│   Found: Beijing, CN | AS4837                  │
│                                                │
│ ⏳ AbuseIPDB          Fetching...              │
│                                                │
│ ⏳ GreyNoise          Fetching...              │
└────────────────────────────────────────────────┘
```

### Merge Confirmation

Let the user accept or discard agent results before they are merged into the graph:

```
┌────────────────────────────────────────────────┐
│ Enrichment Results for 1.2.3.4                 │
├────────────────────────────────────────────────┤
│ ☑ Add ASN node: AS4837 (ipinfo.io)            │
│ ☑ Add Geo node: Beijing, CN (ipinfo.io)       │
│ ☑ Add Reputation: 85/100 High Risk (AbuseIPDB)│
│ ☐ Add Classification: Malicious (GreyNoise)   │
│                                                │
│ [Accept Selected] [Accept All] [Discard All]  │
└────────────────────────────────────────────────┘
```

### Investigation Pane

Provide:
- Raw JSON viewer for debugging
- Link to source URL (e.g., "View on VirusTotal")
- Quick actions: "Open in VT", "Open in urlscan", "Export JSON"

```
┌────────────────────────────────────────────────┐
│ Source: VirusTotal                             │
│ API URL: https://www.virustotal.com/api/...   │
│ Fetched: 2 minutes ago (cached)                │
│                                                │
│ [View Raw JSON] [Open in VirusTotal] [Export] │
└────────────────────────────────────────────────┘
```

### Placement in IOC Display

Add "Enrichment" section below OSINT links:

```
┌────────────────────────────────────────────────┐
│ 🌐 1.2.3.4 (IPv4)                              │
│                                                │
│ OSINT Links:                                   │
│ [VirusTotal] [AbuseIPDB] [ipinfo.io] ...      │
│                                                │
│ ▼ Enrichment                      [Refresh ↻]  │
│ ┌────────────────────────────────────────────┐ │
│ │ 📍 Geolocation                             │ │
│ │   City: Beijing, China                     │ │
│ │   Coordinates: 39.9042, 116.4074           │ │
│ │   ASN: AS4837 (CHINA UNICOM)               │ │
│ │   Source: ipinfo.io (cached)               │ │
│ │                                            │ │
│ │ ⚠ Reputation                               │ │
│ │   Risk Score: 85/100 (High)                │ │
│ │   Total Reports: 42                        │ │
│ │   Last Reported: 2 hours ago               │ │
│ │   Categories: Scanner, Brute Force         │ │
│ │   Source: AbuseIPDB                        │ │
│ │                                            │ │
│ │ 🔍 Classification                          │ │
│ │   Verdict: Malicious                       │ │
│ │   Category: Activity                       │ │
│ │   Tags: Scanner, Web Scanner               │ │
│ │   Source: GreyNoise                        │ │
│ └────────────────────────────────────────────┘ │
└────────────────────────────────────────────────┘
```

### Collapsible Sections

Allow collapsing enrichment results to reduce clutter:

```
▶ Enrichment (3 sources, last updated 2h ago)   [Refresh ↻]
```

### Loading States

Show clear, progressive loading indicators:

```
▼ Enrichment                      [Refresh ↻]
┌────────────────────────────────────────────┐
│ ⏳ Enriching IP address...                 │
│ • Querying ipinfo.io...         ✓ Done    │
│ • Querying AbuseIPDB...          ⏳         │
│ • Querying GreyNoise...          ⏳         │
└────────────────────────────────────────────┘
```

### Error Handling

Handle errors gracefully:

```
▼ Enrichment                      [Refresh ↻]
┌────────────────────────────────────────────┐
│ ⚠ AbuseIPDB                                │
│   Rate limit exceeded. Try again in 14m.   │
│   [View cached result (2 days old)]        │
│                                            │
│ ❌ GreyNoise                               │
│   API key invalid. Check settings.         │
│   [Configure API key]                      │
└────────────────────────────────────────────┘
```

### Batch Enrichment

For multiple IOCs, offer batch enrichment:

```
IOCs: 15 IPs, 8 Domains, 3 Hashes

[Enrich All IPs (15)] [Enrich All Domains (8)] [Enrich All Hashes (3)]

⚠ Batch enrichment will use ~26 API credits across 3 services.
```

### Keyboard Shortcuts

- `E`: Enrich current IOC (when node is selected)
- `Shift+E`: Enrich all IOCs in view
- `Ctrl+E`: Clear enrichment cache
- `Alt+E`: Toggle enrichment panel

### Export Integration

Include enrichment data in all export formats:

**CSV:**
```csv
IOC,Type,Geo,ASN,Risk Score,Reputation
1.2.3.4,IP,Beijing/CN,AS4837,85,Malicious
```

**JSON:**
```json
{
  "ioc": "1.2.3.4",
  "type": "ip",
  "enrichment": {
    "geo": {"city": "Beijing", "country": "CN"},
    "asn": "AS4837",
    "riskScore": 85,
    "reputation": "Malicious"
  }
}
```

---

## Resiliency & Error Handling

### Structured Error Returns

If a fetch returns non-OK, log details in background console and return structured error to popup:

```javascript
{
  "status": "error",
  "error": "API rate limit exceeded",
  "errorCode": "RATE_LIMIT_EXCEEDED",
  "errorStatus": 429,
  "source": "greynoise",
  "fallback": {
    "action": "open_web_ui",
    "url": "https://viz.greynoise.io/ip/1.2.3.4"
  }
}
```

### Fallback Flows

Use fallback flows when possible:
- **No API key** → Open web UI for manual lookup
- **VT fails** → ipinfo fallback for ASN/geo
- **urlscan.io rate limit** → PhishTank check only
- **Network error** → Show cached result with warning

### Error Display

```
┌────────────────────────────────────────────────┐
│ ⚠ GreyNoise                                    │
│   Rate limit exceeded. Try again in 14m.       │
│   [View cached result (2 days old)]            │
│   [Open GreyNoise Web UI]                      │
└────────────────────────────────────────────────┘
```

---

## Developer & Testing Notes

### Unit Testable Pieces

Components that should have unit tests:
- Result normalization utilities (standardize different API response formats)
- Caching and TTL logic (get/set/evict)
- Rate limiter behavior (token bucket, backoff)
- IOC validation (IPv4/IPv6, domain format, hash format)

### Manual Testing

Provide scripted Playwright tests that simulate popup flow and call mock agent endpoints:

```javascript
// Example: test-ip-enrichment.spec.js
test('IP enrichment with mock API', async ({ page, context }) => {
  // Intercept API calls and return mock responses
  await page.route('https://api.abuseipdb.com/**', route => {
    route.fulfill({
      status: 200,
      body: JSON.stringify({ data: { abuseConfidenceScore: 85 } })
    });
  });
  
  // Open popup and trigger enrichment
  await page.goto('popup.html');
  await page.fill('#iocInput', '1.2.3.4');
  await page.click('#analyzeBtn');
  await page.click('[data-enrich="ip"]');
  
  // Verify results rendered
  await expect(page.locator('.enrichment-result')).toContainText('85/100');
});
```

### Integration Tests with Mock Responses

Run integration tests with recorded mock responses to avoid burning API quotas:

```javascript
// mock-responses/abuseipdb-1.2.3.4.json
{
  "data": {
    "ipAddress": "1.2.3.4",
    "abuseConfidenceScore": 85,
    "countryCode": "CN",
    "usageType": "Data Center/Web Hosting/Transit",
    "isp": "China Unicom",
    "totalReports": 42,
    "lastReportedAt": "2024-01-15T10:30:00+00:00"
  }
}
```

### Mock Agent Server

Consider creating a small mock agent server for offline testing:

```javascript
// mock-server.js (Express or similar)
app.get('/mock/abuseipdb/:ip', (req, res) => {
  const mockResponse = require(`./mock-responses/abuseipdb-${req.params.ip}.json`);
  res.json(mockResponse);
});
```

---

## Security Scanning & CI

### After Adding Dependencies

After adding any dependencies or running installs, run the Codacy `trivy` scan as described in repository instructions:

```bash
# Install trivy if not present
# Run scan on the project
trivy fs --security-checks vuln .
```

### API Keys in CI

For any API keys in CI:
- Load from GitHub Secrets (never commit keys)
- Use test/sandbox API keys only
- Rotate keys regularly
- Limit CI key permissions to minimum required

### Security Checklist

- [ ] All API calls use HTTPS only
- [ ] API keys never logged to console
- [ ] Input validation on all IOCs before sending to APIs
- [ ] Content Security Policy in manifest.json
- [ ] No `eval()` or unsafe dynamic code execution
- [ ] Dependencies scanned with `trivy`
- [ ] API responses sanitized before rendering in UI

---

## Priority Implementation Roadmap

### Short-Term Priorities

1. **IP Agent (Geo, ASN, AbuseIPDB)** — ⭐ **HIGH PRIORITY**
   - Implement background handlers for ipinfo.io, AbuseIPDB, GreyNoise
   - Build graph merge UI
   - Add Settings section for API keys
   - **Rationale**: Most common IOC type, immediate value

2. **Hash/File Agent (VirusTotal + HybridAnalysis)** — **HIGH PRIORITY**
   - Show file metadata and AV detection ratio
   - Extract embedded IOCs and add to graph
   - Link to sandbox reports

3. **URL Agent (urlscan.io + PhishTank)** — **MEDIUM PRIORITY**
   - Integrate urlscan.io for screenshots and classification
   - Extract linked IOCs (domains, IPs) from scan results
   - Add to graph with edges

4. **Domain Agent (Passive DNS + WHOIS + crt.sh)** — **MEDIUM PRIORITY**
   - Implement passive DNS via VirusTotal
   - Add WHOIS data enrichment
   - Certificate transparency via crt.sh

5. **Optional Advanced Connectors (Shodan, Censys, PassiveTotal)** — **LOW PRIORITY**
   - Behind feature flags
   - Require API key configuration in Settings
   - Premium/paid tier features

### Long-Term Enhancements

- **Threat Correlation Engine**: Dedupe across sources, track first-seen vs last-seen, show timeline
- **Automated Enrichment Workflows**: User-defined sequence of agents to run for each IOC type (with consent and throttling)
- **Export/Ingest Connectors**: MISP, SIEM (CEF), internal ticketing systems
- **Collaborative Intelligence**: Share enrichment results across team (opt-in, on-premises only)
- **Custom Agent SDK**: Allow users to write their own enrichment agents with templates

---

## Implementation Checklist

Use this checklist when integrating a single agent:

### Per-Agent Implementation Tasks

- [ ] **UI Integration**
  - [ ] Add UI menu item for agent under right-click submenu (popup/UI)
  - [ ] Add "Enrich" button to IOC display
  - [ ] Create loading state UI component
  - [ ] Create results display component
  - [ ] Create merge confirmation UI with checkboxes

- [ ] **Background/Service Worker**
  - [ ] Register agent metadata in `agentsRegistry` (id, name, supported types, required keys)
  - [ ] Implement network call with proper headers (`x-apikey`, `User-Agent`)
  - [ ] Add error handling (401, 403, 429, timeout, network error)
  - [ ] Implement exponential backoff for retries
  - [ ] Add rate limiting check before making request

- [ ] **Data Processing**
  - [ ] Normalize result into standard format
  - [ ] Extract nodes and edges for graph
  - [ ] Cache result under `agent_<src>_<type>_<value>` key
  - [ ] Set appropriate TTL in metadata
  - [ ] Send normalized response back to popup

- [ ] **Settings UI**
  - [ ] Add API key input field in Settings tab
  - [ ] Add enable/disable toggle
  - [ ] Add "Test Connection" button
  - [ ] Add rate limit status display
  - [ ] Add link to provider signup page

- [ ] **Testing**
  - [ ] Write unit tests for normalization logic
  - [ ] Write unit tests for caching logic
  - [ ] Create mock API responses for integration tests
  - [ ] Write Playwright test for end-to-end flow
  - [ ] Test with various IOC formats
  - [ ] Test error scenarios (invalid key, rate limit, timeout)

- [ ] **Documentation**
  - [ ] Add documentation entry in `AGENTS.md` with:
    - Provider API docs link
    - Rate limits and costs
    - Required/optional API keys
    - Example request/response
    - Known limitations
  - [ ] Update README.md with new enrichment capability
  - [ ] Add setup instructions to user guide

- [ ] **Security**
  - [ ] Run `trivy` scan if dependencies added
  - [ ] Validate IOC format before sending to API
  - [ ] Sanitize API responses before rendering
  - [ ] Test CSP compliance
  - [ ] Review error messages for information leakage

---

## Per-Agent Detailed Specifications

Each agent follows a consistent implementation pattern. Use these specifications as reference.

---

### IP Agent

**Priority**: ⭐ **TOP PRIORITY**

**Scope**: Enrich IPv4 and IPv6 addresses with geolocation, ASN, abuse score, open ports, and classification.

#### Data Sources

| Source | Data Provided | API Key | Rate Limit | Cost | Priority |
|--------|---------------|---------|------------|------|----------|
| **ipinfo.io** | Geo, ASN, ISP, org | Optional (free tier) | 50k/month | Free | Primary |
| **AbuseIPDB** | Abuse reports, confidence score | Yes | 1k/day | Free | High |
| **GreyNoise** | Noise classification, tags | Yes (community) | 100/day | Free | High |
| **VirusTotal** | Passive DNS, ASN, prefix, registry | Yes | 4/min | Free | Medium |
| **Shodan** | Open ports, banners, services | Yes | 100/month | $49/mo | Optional |
| **Censys** | Certificate data, services | Yes | 250/day | Free | Optional |

#### Implementation Tasks

- [ ] **1. Agent Structure**
  - [ ] Create `IPAgent` class in `background.js`
  - [ ] Implement `IPAgent.enrich(ip)` method
  - [ ] Add IP validation (IPv4 + IPv6)

- [ ] **2. API Integration**
  - [ ] Implement `fetchIPInfo()` for ipinfo.io
    - Endpoint: `https://ipinfo.io/{ip}/json` (token optional: `?token={key}`)
    - Parse: city, region, country, loc, org, postal, timezone
    - Fallback: No API key required for basic info
  - [ ] Implement `fetchAbuseIPDB()` for AbuseIPDB
    - Endpoint: `https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90`
    - Header: `Key: {apiKey}`, `Accept: application/json`
    - Parse: abuseConfidenceScore, usageType, totalReports, lastReportedAt
    - Note: Requires API key
  - [ ] Implement `fetchGreyNoise()` for GreyNoise Community
    - Endpoint: `https://api.greynoise.io/v3/community/{ip}`
    - Header: `key: {apiKey}`
    - Parse: classification, name, link, riot (benign internet scanner), noise
    - Note: Free community tier available
  - [ ] Implement `fetchVirusTotalIP()` for passive DNS and ASN
    - Endpoint: `https://www.virustotal.com/api/v3/ip_addresses/{ip}`
    - Header: `x-apikey: {apiKey}`
    - Parse: asn, as_owner, country, network, resolutions (passive DNS)
    - Note: Prefer VT when API key present for richer ASN/prefix/registry info
  - [ ] (Optional) Implement `fetchShodan()` for open ports
    - Endpoint: `https://api.shodan.io/shodan/host/{ip}?key={apiKey}`
    - Parse: ports, services, banners, vulns
    - Note: Paid API ($49/mo)

- [ ] **3. Result Aggregation**
  - [ ] Combine results into normalized format
  - [ ] Calculate aggregate risk score (0-100)
    - Weight: AbuseIPDB confidence (50%), GreyNoise classification (30%), ISP type (20%)
  - [ ] Determine verdict: `clean`, `suspicious`, `malicious`, `unknown`
  - [ ] Generate tags: e.g., `["scanner", "datacenter", "china"]`

- [ ] **4. Caching**
  - [ ] Set TTL to 24 hours
  - [ ] Cache key: `agent_<source>_ip_<ipAddress>` (e.g., `agent_ipinfo_ip_1.2.3.4`)
  - [ ] Handle cache hits/misses

- [ ] **5. Rate Limiting**
  - [ ] Configure rate limits for each source
  - [ ] Implement request tracking
  - [ ] Add exponential backoff for 429 errors

- [ ] **6. UI Integration**
  - [ ] Add "Enrich" button to IP IOC display
  - [ ] Create enrichment result renderer
  - [ ] Show loading state during enrichment
  - [ ] Display error states with retry options
  - [ ] Add "Refresh" button for cache invalidation

- [ ] **7. Settings UI**
  - [ ] Add "IP Enrichment" section to Settings tab
  - [ ] API key inputs for ipinfo.io, AbuseIPDB, GreyNoise, VirusTotal
  - [ ] Enable/disable toggles for each source
  - [ ] Rate limit status display
  - [ ] "Test Connection" button for each source

- [ ] **8. Testing**
  - [ ] Test with various IP formats (IPv4, IPv6)
  - [ ] Test with known malicious IPs (e.g., from AbuseIPDB blacklist)
  - [ ] Test with known clean IPs (e.g., Google DNS: 8.8.8.8)
  - [ ] Test rate limit handling
  - [ ] Test cache expiration
  - [ ] Test error handling (invalid key, network error)

- [ ] **9. Documentation**
  - [ ] Update README.md with IP enrichment feature
  - [ ] Add API key setup instructions
  - [ ] Document rate limits and costs

- [ ] **10. Security**
  - [ ] Run Codacy `trivy` scan for any added dependencies
  - [ ] Validate IP input to prevent injection
  - [ ] Use HTTPS for all API calls
  - [ ] Sanitize API responses before rendering

---

### Domain Agent

**Priority**: **MEDIUM**

**Scope**: Enrich domain names with WHOIS, passive DNS, registration history, subdomain enumeration, certificate history, and reputation.

#### Data Sources

| Source | Data Provided | API Key | Rate Limit | Cost | Priority |
|--------|---------------|---------|------------|------|----------|
| **VirusTotal** | Passive DNS, related IPs, resolutions | Yes | 4/min | Free | Primary |
| **crt.sh** | Certificate transparency, SANs, subdomains | No | None | Free | High |
| **WHOIS** | Registrar, creation date, expiry, nameservers | Optional | Varies | Varies | High |
| **URLhaus** | Malware hosting status | No | None | Free | Medium |
| **urlscan.io** | Screenshot, live page analysis | Yes | 50/day | Free | Optional |
| **PassiveTotal** | Historical DNS, WHOIS timeline | Yes | Varies | Paid | Optional |

#### Implementation Tasks

- [ ] **1. Agent Structure**
  - [ ] Create `DomainAgent` class in `background.js`
  - [ ] Implement `DomainAgent.enrich(domain)` method
  - [ ] Add domain validation (TLD check, format validation)

- [ ] **2. API Integration**
  - [ ] Implement `fetchVirusTotalDomain()` for passive DNS
    - Endpoint: `https://www.virustotal.com/api/v3/domains/{domain}/resolutions`
    - Header: `x-apikey: {apiKey}`
    - Parse: resolutions (IP addresses), last_https_certificate, categories
  - [ ] Implement `fetchCRTsh()` for certificate transparency
    - Endpoint: `https://crt.sh/?q=%25.{domain}&output=json`
    - No API key required
    - Parse: SANs, issuers, validity periods → extract subdomains
  - [ ] Implement `fetchWHOIS()` for registration data
    - Options: WhoisXML API, native whois command via proxy service
    - Parse: registrar, creation_date, expiry_date, nameservers, registrant (if not privacy-protected)
  - [ ] Implement `fetchURLhaus()` for malware hosting
    - Endpoint: `https://urlhaus-api.abuse.ch/v1/host/`
    - POST: `host={domain}`
    - Parse: malware URL count, threat status, tags
  - [ ] (Optional) Implement `fetchURLscan()` for live page screenshot
    - Endpoint: `https://urlscan.io/api/v1/scan/`
    - POST: `{"url": "https://{domain}"}`
    - Parse: scan UUID → fetch screenshot and verdict

- [ ] **3. Result Aggregation**
  - [ ] Calculate domain age
  - [ ] Determine reputation score
  - [ ] Identify suspicious patterns (recent registration, privacy protection)

- [ ] **4. Caching**
  - [ ] Set TTL to 7 days
  - [ ] Cache key: `agent_<source>_domain_<domainName>` (e.g., `agent_virustotal_domain_example.com`)

- [ ] **5. UI Integration**
  - [ ] Add "Enrich" button to domain IOC display
  - [ ] Render WHOIS data, passive DNS records, reputation

- [ ] **6. Testing**
  - [ ] Test with legitimate domains (google.com)
  - [ ] Test with known malicious domains
  - [ ] Test with newly registered domains

---

### URL Agent

**Priority**: **MEDIUM**

**Scope**: Enrich URLs with safety status, redirect chain, screenshots, phishing classification, and extracted IOCs.

#### Data Sources

| Source | Data Provided | API Key | Rate Limit | Cost | Priority |
|--------|---------------|---------|------------|------|----------|
| **urlscan.io** | Screenshot, redirect chain, classification, extracted IOCs | Yes | 50/day (free) | Free | Primary |
| **VirusTotal** | URL analysis, detection ratio, categories | Yes | 4/min | Free | High |
| **URLhaus** | Malware URL status, tags | No | None | Free | High |
| **PhishTank** | Phishing status | No | None | Free | Medium |

#### Implementation Tasks

- [ ] **1. Agent Structure**
  - [ ] Create `URLAgent` class in `background.js`
  - [ ] Implement `URLAgent.enrich(url)` method
  - [ ] Add URL validation and normalization

- [ ] **2. API Integration**
  - [ ] Implement `fetchURLscan()` for comprehensive analysis
    - Endpoint: Submit `https://urlscan.io/api/v1/scan/` POST `{"url": "{url}"}`
    - Poll result: `https://urlscan.io/api/v1/result/{uuid}/`
    - Parse: screenshot, page title, server, IPs, domains, hashes, redirect chain
    - Extract IOCs: domains, IPs, hashes from page resources
  - [ ] Implement `fetchVirusTotalURL()` for detection ratio
    - Endpoint: `https://www.virustotal.com/api/v3/urls/{base64_url_id}`
    - Header: `x-apikey: {apiKey}`
    - Parse: last_analysis_stats (malicious/suspicious/clean), categories, redirects
  - [ ] Implement `fetchURLhaus()` for malware status
    - Endpoint: `https://urlhaus-api.abuse.ch/v1/url/`
    - POST: `url={url}`
    - Parse: threat status, tags, payload availability
  - [ ] Implement `fetchPhishTank()` for phishing status
    - Endpoint: `http://checkurl.phishtank.com/checkurl/` POST `{"url": "{url}"}`
    - Parse: in_database, verified, verification_time

- [ ] **3. Result Aggregation**
  - [ ] Display screenshot (if available)
  - [ ] Show detection ratio (X/Y engines flagged as malicious)
  - [ ] Highlight key indicators (redirects, TLS certificate)

- [ ] **4. Caching**
  - [ ] Set TTL to 6 hours (URLs can change quickly)
  - [ ] Cache key: `agent_<source>_url_<urlHash>` (hash to avoid storing full URL with potential credentials)

- [ ] **5. UI Integration**
  - [ ] Add "Enrich" button to URL IOC display
  - [ ] Render screenshot inline (optional, behind toggle)
  - [ ] Show detection results

---

### Hash Agent

**Priority**: **HIGH**

**Scope**: Enrich file hashes (MD5, SHA1, SHA256) with multi-AV scan results, malware family classification, sandbox analysis, and extracted IOCs.

#### Data Sources

| Source | Data Provided | API Key | Rate Limit | Cost | Priority |
|--------|---------------|---------|------------|------|----------|
| **VirusTotal** | Multi-AV scan results (70+ engines), file metadata | Yes | 4/min | Free | Primary |
| **MalwareBazaar** | Malware family, tags, signature | No | None | Free | High |
| **Hybrid Analysis** | Sandbox detonation, behavioral analysis | Yes | 200/month | Free | High |

#### Implementation Tasks

- [ ] **1. Agent Structure**
  - [ ] Create `HashAgent` class in `background.js`
  - [ ] Implement `HashAgent.enrich(hash)` method
  - [ ] Support MD5, SHA1, SHA256

- [ ] **2. API Integration**
  - [ ] Implement `fetchVirusTotalHash()` for AV results
    - Endpoint: `https://www.virustotal.com/api/v3/files/{sha256}`
    - Header: `x-apikey: {apiKey}`
    - Parse: last_analysis_stats (malicious/suspicious/clean), names (malware names), type_description, contacted_domains, contacted_ips
    - Extract embedded IOCs: domains, IPs from file behavior
  - [ ] Implement `fetchMalwareBazaar()` for malware family
    - Endpoint: `https://mb-api.abuse.ch/api/v1/` POST `{"query": "get_info", "hash": "{sha256}"}`
    - Parse: signature (malware family), tags, file_type, delivery_method
  - [ ] Implement `fetchHybridAnalysis()` for sandbox report
    - Endpoint: `https://www.hybrid-analysis.com/api/v2/search/hash`
    - POST: `hash={sha256}`
    - Header: `api-key: {apiKey}`
    - Parse: verdict, threat_score, sandbox reports, extracted IOCs

- [ ] **3. Result Aggregation**
  - [ ] Show detection ratio (e.g., 45/70 AV engines detected)
  - [ ] Display top malware family names
  - [ ] Link to sandbox report (if available)

- [ ] **4. Caching**
  - [ ] Set TTL to 7 days (hash results stabilize quickly)
  - [ ] Cache key: `agent_<source>_hash_<hashValue>` (e.g., `agent_virustotal_hash_<sha256>`)

- [ ] **5. UI Integration**
  - [ ] Add "Enrich" button to hash IOC display
  - [ ] Render AV detection table
  - [ ] Highlight malware family

---

### Email Agent

**Priority**: **MEDIUM**

**Scope**: Enrich email addresses with MX/SPF/DKIM verification, breach detection, sender domain analysis, and paste monitoring.

#### Data Sources

| Source | Data Provided | API Key | Rate Limit | Cost | Priority |
|--------|---------------|---------|------------|------|----------|
| **HaveIBeenPwned** | Breach detection, paste monitoring | Yes (free) | 1,500/day | Free | Primary |
| **DNS Lookups** | MX, SPF, DKIM records | No | None | Free | High |
| **WHOIS** | Domain registration (reuse Domain Agent) | Optional | Varies | Varies | Medium |

#### Implementation Tasks

- [ ] **1. Agent Structure**
  - [ ] Create `EmailAgent` class in `background.js`
  - [ ] Implement `EmailAgent.enrich(email)` method
  - [ ] Split email into local part and domain

- [ ] **2. API Integration**
  - [ ] Implement `fetchHIBP()` for breach detection
    - Endpoint: `https://haveibeenpwned.com/api/v3/breachedaccount/{email}`
    - Header: `hibp-api-key: {apiKey}`, `User-Agent: SOC-Analyst-Toolkit/{version}`
    - Parse: breach names, breach dates, data classes (passwords, emails, etc.)
    - Privacy note: Warn user that querying reveals email to HIBP
  - [ ] Implement `fetchDNSRecords()` for email validation
    - MX records: DNS lookup for domain MX records
    - SPF: DNS TXT record lookup for SPF policy
    - DKIM: Check for DKIM selector (requires domain knowledge)
    - Parse: MX servers, SPF policy (pass/fail/softfail), validation status
  - [ ] Implement domain reputation (reuse DomainAgent for email domain)

- [ ] **3. Result Aggregation**
  - [ ] Show number of breaches
  - [ ] List breach names and dates
  - [ ] Domain reputation score

- [ ] **4. Caching**
  - [ ] Set TTL to 7 days
  - [ ] Cache key: `agent_<source>_email_<emailHash>` (hash for privacy, e.g., SHA256 of email)

- [ ] **5. Privacy Warning**
  - [ ] Display warning that querying HIBP reveals email to service
  - [ ] Require explicit user confirmation before query

---

### Certificate Agent

**Priority**: **LOW**

**Scope**: Enrich SSL/TLS certificates with transparency logs, SANs extraction, issuer validation, and certificate chain analysis.

#### Data Sources

| Source | Data Provided | API Key | Rate Limit | Cost | Priority |
|--------|---------------|---------|------------|------|----------|
| **crt.sh** | Certificate transparency logs, SANs, domains | No | None | Free | Primary |
| **Censys** | Certificate details, chain, validation | Yes | 250/day | Free | High |
| **certstream APIs** | Real-time CT log monitoring | No | Varies | Free | Optional |

#### Implementation Tasks

- [ ] **1. Agent Structure**
  - [ ] Create `CertificateAgent` class in `background.js`
  - [ ] Implement `CertificateAgent.enrich(certHash)` method

- [ ] **2. API Integration**
  - [ ] Implement `fetchCRTsh()` for CT logs
    - Endpoint: `https://crt.sh/?q={domain}&output=json`
    - No API key required
    - Parse: issuer, subject, SANs, not_before, not_after
    - Extract domains from SANs → create domain nodes and edges
  - [ ] Implement `fetchCensys()` for certificate details
    - Endpoint: `https://search.censys.io/api/v2/certificates/{fingerprint}`
    - Header: `Authorization: Basic {base64(api_id:api_secret)}`
    - Parse: parsed.subject, parsed.issuer, parsed.extensions, validation_level
    - Map certs → domains → IPs

- [ ] **3. Result Aggregation**
  - [ ] Show issuer, subject, validity period
  - [ ] List SANs (Subject Alternative Names)
  - [ ] Highlight expired or self-signed certificates

- [ ] **4. Caching**
  - [ ] Set TTL to 30 days
  - [ ] Cache key: `agent_<source>_certificate_<certHash>` (e.g., `agent_crtsh_certificate_<sha256>`)

- [ ] **5. UI Integration**
  - [ ] Add "Enrich" button to certificate IOC display
  - [ ] Render certificate details in table format

---

## Next Steps

1. **Immediate**: Implement **IP Agent** (top priority)
   - Start with ipinfo.io and AbuseIPDB (most accessible APIs)
   - Add GreyNoise and VirusTotal after core functionality works
   
2. **After IP Agent**: Implement **Hash Agent** (high value, simpler than Domain Agent)
   
3. **Incremental Rollout**: Release each agent as a minor version update
   - v0.5.0: IP Agent
   - v0.6.0: Hash Agent
   - v0.7.0: Domain Agent
   - v0.8.0: URL Agent
   - v0.9.0: Email Agent
   - v1.0.0: Certificate Agent + full enrichment suite

4. **Post-Implementation**:
   - Run Codacy `trivy` scan for security vulnerabilities
   - Update README.md with enrichment documentation
   - Create video tutorial/GIF demos for each agent
   - Collect user feedback and iterate

---

## References & Useful Endpoints

### IP Enrichment
- **VirusTotal**: https://developers.virustotal.com/reference/ip-info
- **AbuseIPDB**: https://www.abuseipdb.com/api
- **GreyNoise**: https://docs.greynoise.io/reference/get_v3-community-ip
- **ipinfo.io**: https://ipinfo.io/developers
- **Shodan**: https://developer.shodan.io/api
- **Censys**: https://search.censys.io/api

### Domain Enrichment
- **VirusTotal Domains**: https://developers.virustotal.com/reference/domain-info
- **crt.sh (Certificate Transparency)**: https://crt.sh/
- **URLhaus Host API**: https://urlhaus-api.abuse.ch/
- **urlscan.io API**: https://urlscan.io/about-api/

### URL Enrichment
- **urlscan.io**: https://urlscan.io/docs/api/
- **VirusTotal URL**: https://developers.virustotal.com/reference/url-info
- **PhishTank**: https://www.phishtank.com/api_info.php
- **URLhaus URL API**: https://urlhaus-api.abuse.ch/

### File/Hash Enrichment
- **VirusTotal Files**: https://developers.virustotal.com/reference/file-info
- **MalwareBazaar**: https://bazaar.abuse.ch/api/
- **Hybrid Analysis**: https://www.hybrid-analysis.com/docs/api/v2

### Email Enrichment
- **HaveIBeenPwned**: https://haveibeenpwned.com/API/v3

### Certificate Enrichment
- **crt.sh**: https://crt.sh/ (JSON output: add `&output=json`)
- **Censys Certificates**: https://search.censys.io/api

### General Resources
- **MISP API**: https://www.misp-project.org/openapi/ (for future integrations)
- **AlienVault OTX**: https://otx.alienvault.com/api
- **abuse.ch APIs**: https://abuse.ch/ (URLhaus, ThreatFox, MalwareBazaar)

---

## Long-term Enhancements

### Threat Correlation Engine
- Dedupe IOCs across sources
- Track first-seen vs. last-seen timestamps
- Build timeline visualizations
- Correlate related IOCs (e.g., IPs in same ASN, domains with same registrar)

### Automated Enrichment Workflows
- User-defined sequence of agents to run for each IOC type
- Configurable trigger conditions (e.g., "Always enrich high-risk IPs")
- Workflow templates: "Quick Triage", "Deep Dive", "Compliance Check"
- Throttling and batching for bulk enrichment
- Requires explicit user consent per workflow

### Export/Ingest Connectors
- **MISP Integration**: Export enrichment results to MISP events
- **SIEM Integration**: CEF/LEEF format for Splunk, QRadar, etc.
- **Ticketing Systems**: Jira, ServiceNow, GitHub Issues
- **Threat Intel Platforms**: STIX/TAXII feeds

### Collaborative Intelligence
- Share enrichment results across team (opt-in, on-premises only)
- Deduplication of API calls across team members
- Shared cache for common IOCs
- Privacy-preserving: only share IOC metadata, not investigation context

### Custom Agent SDK
- Template for writing custom enrichment agents
- Documentation and examples
- Validation and testing utilities
- Community agent repository

---

## Contact & Contribution

Open issues or feature requests in the repository for specific agent integrations so we can track work and API keys required.

For questions or suggestions, please open a GitHub issue with the label `enhancement` or `agent-integration`.

---

**Document Version**: 1.0  
**Last Updated**: December 17, 2025  
**Author**: SOC Analyst Toolkit Development Team  
**License**: Same as project (see LICENSE file)
