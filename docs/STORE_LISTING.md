# SOC Analyst Toolkit — Chrome Web Store Listing

Copy each section below into the matching field in the Chrome Web Store developer dashboard.

## Title

SOC Analyst Toolkit

## Short description (≤ 132 chars)

Extract IOCs from selected text, run OSINT lookups across 20+ threat-intel platforms, manage snippets, and triage with AI. 100% local.

## Detailed description

100% free, no in-app purchases, no subscriptions, no ads, no premium tier. MIT-licensed open source.

### IOC Detection & Analysis
- IPv4 / IPv6, domains, URLs, email addresses, file hashes (MD5 / SHA1 / SHA256 / SHA512), CVEs, MITRE ATT&CK technique IDs, cryptocurrency addresses (Bitcoin / Ethereum), MAC addresses
- Defang / refang, batch dedupe, per-type statistics

### OSINT Integration
- 20+ platforms: VirusTotal, AbuseIPDB, urlscan.io, Shodan, Censys, GreyNoise, Hybrid Analysis, MAEC, MISP, ThreatConnect, IBM X-Force Exchange, Pulsedive, AlienVault OTX, ThreatBook, urlscan, PhishTank, VIPR,PolySwarm, urlquery, InQuest, IPinfo, Spur Context, Hydroflux

### Productivity
- Personal searchable snippet library with prefix triggers
- Timestamped investigation notes
- Text processing: Base64, hex, ROT13, URL decode, entropy, hash generation
- CyberChef integration (including custom / self-hosted instances)
- Export IOCs as CSV / JSON / Markdown / Obsidian-compatible
- 7 themes (Arc / Coffee / Monokai / Oceanic / Solarized / Earth / Midnight)

### Ask AI
- Bring-your-own-key triage assistant: Paste any provider-compatible endpoint URL and key in Settings, select a model, and right-click selected text or an IOC to triage with AI. Prompts are configurable. No data is sent until you invoke AI, and the extension never sees your key.

### Privacy
- All data stored locally in your browser
- No analytics, no telemetry, no fingerprinting
- Network requests only when you initiate an OSINT lookup or invoke Ask AI
- Open source: review the code on GitHub

## Category

Productivity

## Language

English

## Single-purpose justification

The extension's single purpose is to help security analysts extract indicators of compromise (IOCs) from any web page and pivot to OSINT lookups and triage tools in a single click. Every feature — IOC detection, OSINT lookups, snippets, notes, text processing, CyberChef integration, and AI triage — exists to reduce manual copy/paste during incident response and threat research. No feature exists to monetize user behavior, collect usage data, or change the browser's core functionality.

## Permission justifications

- **`storage`** — Stores user settings (theme, snippets, custom OSINT sources, Ask AI config, enrichment cache) in `chrome.storage.local`. No sync, no remote.
- **`clipboardWrite`** — Copies IOCs and AI triage prompts to the clipboard at user request.
- **`contextMenus`** — Adds the right-click "Analyze with SOC Toolkit" item and the OSINT-lookup submenu.
- **`notifications`** — Surfaces background-task results (e.g. enrichment agent completion).
- **`activeTab`** — Lets the context-menu actions read the current tab's selected text.

## Privacy policy URL

`https://raw.githubusercontent.com/<your-org>/<your-repo>/main/docs/PRIVACY.md`

(Replace `<your-org>` and `<your-repo>` with the actual GitHub repo path.)

## Single-purpose disclosure

The extension contains no analytics SDK, no remote code load, no auto-update mechanism, no fingerprinting. All code is the files in this repository.
