# Enrichment Architecture

How IOC enrichment works in SOC Analyst Toolkit: providers per IOC type, the
normalized result format, caching, rate limiting, error handling, consent,
and the checklist for adding a new provider. All enrichment runs in the MV3
service worker (`background.js`); the popup only renders results.

## Current providers

| IOC type | Providers (in fetch order) | API key |
|---|---|---|
| IP | ipinfo.io, AbuseIPDB, IPAddress.to, Scamalytics, VirusTotal | ipinfo (optional), AbuseIPDB, Scamalytics (username + key + node); IPAddress.to and VirusTotal-fallback paths keyless |
| Hash | VirusTotal, MalwareBazaar, Hybrid Analysis | VirusTotal, Hybrid Analysis; MalwareBazaar keyless |
| URL | urlscan.io, VirusTotal, URLhaus, PhishTank | urlscan (optional), VirusTotal; URLhaus and PhishTank keyless |
| Domain | VirusTotal (passive DNS via `passiveDnsEnrich`), crt.sh (ASN/prefix via `asnEnrich`) | VirusTotal; crt.sh keyless |

Keyless providers work with zero configuration. When a keyed provider has no
key, its fetch is skipped or falls back to opening the provider's web UI.

## Flow

```
popup.js                     background.js                       provider
  │  agentEnrich {ioc, type}    │                                  │
  │ ──────────────────────────► │ consent already gated in popup   │
  │                             │ ├─ cache hit? → return cached    │
  │                             │ ├─ rate limiter allows?          │
  │                             │ ├─ fetchWithBackoff ────────────►│
  │                             │ ├─ normalize to source format    │
  │                             │ ├─ cache under agent_* key       │
  │ ◄──── aggregated result ────┘                                  │
  │ render verdict chip, risk bar, source cards, graph nodes        │
```

Message-router actions (see `background.js` `onMessage`):

- `agentEnrich` , full per-type enrichment (`runAgent` dispatches to
  `runIpAgent` / `runHashAgent` / `runDomainAgent` / `runUrlAgent`)
- `passiveDnsEnrich` , domain → resolving IPs (VirusTotal), cached under `pdns_cache_*`
- `asnEnrich` , IP → network CIDR, prefix, registry, sibling registry (VirusTotal + ipinfo), cached under `asn_cache_*`

## Normalized result format

Each provider returns one source result; the agent aggregates them.

```javascript
// Per source (what a fetchXxx() returns):
{
  provider: 'abuseipdb',          // lowercase identifier
  displayName: 'AbuseIPDB',
  status: 'success',              // success | error | no_data
  cached: false,
  data: { abuseConfidenceScore: 85, countryCode: 'CN', /* provider-specific */ },
  nodes: [ /* graph nodes: geo_*, asn_* */ ],
  edges: [ /* graph edges: edge_<ip>_geo, edge_<ip>_asn */ ],
  errorMessage: null,
  errorCode: null,                // see error taxonomy
  apiUrl: 'https://api.abuseipdb.com/...',
}

// Aggregated (what the popup receives):
{
  ioc: '1.2.3.4',
  iocType: 'ip',
  sources: [ /* the per-source results above */ ],
  summary: {
    verdict: 'malicious',         // clean | suspicious | malicious | unknown
    confidence: 0.85,             // 0..1
    tags: ['vpn', 'datacenter'],  // lowercase flag tags
    riskScore: 85,                // 0..100
  },
  metadata: { enrichmentTime: 342, sourcesQueried: 2, sourcesSucceeded: 2 },
}
```

### Risk-score chain (IP)

First contributor wins; later sources only fill gaps:

1. **AbuseIPDB** `abuseConfidenceScore` (≥75 malicious, ≥40 suspicious, else clean)
2. **VirusTotal** detection ratio raises the score if higher; sets verdict only from unknown/clean
3. **IPAddress.to** `fraud_score` , only when AbuseIPDB contributed nothing
4. **Scamalytics** score, only when neither AbuseIPDB nor IPAddress.to contributed

Flag sources (`is_vpn`, `is_proxy`, `is_tor`, `is_hosting`, `is_datacenter`,
`blacklisted`) always merge into `summary.tags` regardless of who won the score.

Node/edge ids are stable across providers (`geo_<ip>`, `asn_<num>`,
`edge_<ip>_geo`) so `dedupeById` merges sources into one graph instead of
duplicating nodes.

## Caching

- **Location**: `chrome.storage.local`
- **Keys**: `agent_<source>_<iocType>_<ioc>` (plus `pdns_cache_<domain>`, `asn_cache_<ip>`)
- **TTL** (`CACHE_TTL` in background.js): ip 24h, domain 7d, hash 7d, url 6h, email 7d, certificate 30d
- **Cap**: 1000 entries; writing past the cap evicts the oldest (`agentCacheKeysToPrune`)
- **Errors are never cached** so a transient failure retries immediately
- Cache hits return with `cached: true`; the UI shows the fetched age
- Users can clear stored data from Settings

## Rate limiting

`RATE_LIMITS` in background.js, one bucket per provider, persisted across
service-worker restarts where possible:

| Provider | Budget | Backoff on limit |
|---|---|---|
| abuseipdb | 1,000 / day | 5 min |
| ipinfo | 50,000 / day | 1 min |
| virustotal | 4 / min | 15 min |
| urlscan | 100 / day | 1 min |
| urlhaus | 500 / day | 1 min |
| phishtank | 500 / day | 1 min |
| ipaddressto | 500 / day | 1 min |
| scamalytics | 5,000 / 30 days | 1 min |

Transport-level resilience is `fetchWithBackoff` (background.js): retries on
429/5xx with `Retry-After` respected, exponential backoff capped at 30s.
When a provider is exhausted, the agent falls back (next provider, cached
result, or web UI) instead of failing the whole enrichment.

## Error taxonomy

`httpErrorCode` maps HTTP status; throws map to `NETWORK_ERROR`/`TIMEOUT`.

| Code | Meaning |
|---|---|
| `API_KEY_MISSING` | No key configured for a keyed provider |
| `API_KEY_INVALID` | Provider rejected the key (401/403) |
| `RATE_LIMIT_EXCEEDED` | Budget exhausted (429, or provider-side credit exhaustion) |
| `NETWORK_ERROR` | Fetch failed / DNS / offline |
| `TIMEOUT` | Request timed out |
| `INVALID_IOC` | IOC failed pre-flight validation, never sent to the provider |
| `PRIVATE_IP` | Private/reserved IP ranges are not enriched |
| `NO_DATA` | Provider answered but had nothing (not an error) |
| `UNKNOWN_ERROR` | Anything else |

## Consent & privacy

- Enrichment is user-initiated; every entry point goes through
  `_ensureConsent('enrichment')` in the popup (first-run consent modal)
- **Auto-enrich is off by default.** When enabled, it enriches only the first
  5 IOCs per type after an analysis; the rest wait behind "Enrich remaining (N)"
  in the Actions menu
- API keys live only in `chrome.storage.local`; never logged, masked in the UI
- Only the IOC value is sent to providers, no page context, no notes
- The consent state can be reviewed and reset in Settings

## Adding a provider

1. **Fetch + normalize**, `fetchXxx()` in background.js returning the source
   result shape above (status/data/errorCode; add graph nodes/edges only if
   they belong on the shared graph)
2. **Wire into the agent**, call it from the matching `run<Type>Agent`, and
   if it produces a score, extend `build<Type>Summary` (respect the existing
   fallback chain)
3. **Rate limit**, add a `RATE_LIMITS` entry
4. **Settings**, key inputs under the provider id (`<provider>ApiKey`),
   enable/disable toggle in the provider toggle list (`providerToggle_<id>`)
5. **OSINT link**, add the web-UI lookup in `generateOSINTLinks` (popup.js)
   so every IOC row links out even without a key
6. **Tests**, fetch/normalize tests in `tests/verify_background.js` (fetch is
   stubbed by the harness); summary-chain tests in `tests/verify_features.js`
   against the real `buildIpSummary`. Mock shapes belong in the test, not in
   a parallel copy of production code
7. **Docs**, provider table above, FEATURES.md, CHANGELOG

## Not implemented (roadmap candidates)

- Email agent: MX/SPF validation, HaveIBeenPwned breach checks (needs key +
  explicit privacy warning, querying reveals the address)
- Certificate agent: crt.sh CT-log expansion into domain nodes
- Shodan / Censys port and service data (paid/keys)
- WHOIS registration data (no reliable keyless API)
- Export connectors: MISP, STIX/TAXII, SIEM formats
- Per-provider TTL overrides in Settings
