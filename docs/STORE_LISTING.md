# SOC Analyst Toolkit — Chrome Web Store Listing

Copy each section below into the matching field in the Chrome Web Store developer dashboard.

## Title

SOC Analyst Toolkit

## Short description (≤ 132 chars)

Extract IOCs from selected text, run OSINT lookups across 20+ threat-intel platforms, manage snippets, and triage with AI.

## Detailed description

SOC Analyst Toolkit is a free, open-source browser extension for SOC analysts and cybersecurity professionals. It extracts indicators of compromise (IOCs) from selected text, generates deep links to 20+ threat-intel platforms for one-click lookup, manages a personal snippet library, and offers an optional Ask AI panel that builds a triage prompt for the user's chosen AI chat.

100% free, no in-app purchases, no subscriptions, no ads, no premium tier. MIT-licensed open source.

### IOC Detection & Analysis
- IPv4 / IPv6, domains, URLs, email addresses, file hashes (MD5 / SHA1 / SHA256 / SHA512), CVEs, MITRE ATT&CK technique IDs, cryptocurrency addresses (Bitcoin / Ethereum), MAC addresses
- Defang / refang, batch dedupe, per-type statistics

### OSINT Integration
Quick lookup against 20+ providers including VirusTotal, AlienVault OTX, AbuseIPDB, ipinfo.io, GreyNoise, Shodan, URLhaus, urlscan.io, MalwareBazaar, Hybrid Analysis, MITRE ATT&CK, D3FEND, blockchain explorers, MAC vendor databases. Configurable IP enrichment with caching and rate limits. Custom OSINT sources supported.

### Productivity
- Personal searchable snippet library with prefix triggers
- Timestamped investigation notes
- Text processing: Base64, hex, ROT13, URL decode, entropy, hash generation
- CyberChef integration (including custom / self-hosted instances)
- Export IOCs as CSV / JSON / Markdown / Obsidian-compatible
- 7 themes (Arc / Coffee / Monokai / Oceanic / Solarized / Earth / Midnight)

### Ask AI
Replaces the older "Ask Claude" clipboard shortcut with a configurable helper. Pick a target AI chat from a preset dropdown (Claude / ChatGPT / Gemini / Copilot / Perplexity / Mistral / Custom…) and customize the prompt template via Settings. All processing is local; the extension never makes network calls without a user action.

### Privacy
- All data stored locally in your browser
- No analytics, no telemetry, no fingerprinting
- Network requests only when you initiate an OSINT lookup
- Open source: review the code on GitHub

## Category

Productivity

## Language

English

## Single-purpose justification

Triage security indicators of compromise. The extension extracts IOCs from selected text, generates deep links to 20+ OSINT providers for one-click lookup, manages analyst snippets, and offers an optional Ask AI panel that builds a triage prompt for the user's chosen AI chat. All processing is local; the only outbound network calls are user-initiated.

## Permission justifications

- **`storage`** — Stores user settings (theme, snippets, custom OSINT sources, Ask AI config, enrichment cache) in `chrome.storage.local`. No sync, no remote.
- **`clipboardWrite`** — Copies IOCs and AI triage prompts to the clipboard at user request.
- **`contextMenus`** — Adds the right-click "Analyze with SOC Toolkit" item and the OSINT-lookup submenu.
- **`notifications`** — Surfaces background-task results (e.g. enrichment agent completion).
- **`activeTab`** — Lets the context-menu actions read the current tab's selected text.
- **`scripting`** — Lets the extension inject the IOC-extraction helper into the active tab when the user picks "Analyze with SOC Toolkit" from the right-click menu. Used only on explicit user action, only against the active tab, and only to read selected text — no automatic global content script.
- **`host_permissions` (21 explicit third-party domains)** — The manifest declares a narrow allowlist of the OSINT and enrichment providers the extension talks to: `virustotal.com`, `abuseipdb.com`, `ipinfo.io`, `greynoise.io`, `urlscan.io`, `urlhaus.abuse.ch`, `bazaar.abuse.ch`, `otx.alienvault.com`, `macvendors.com`, `blockchain.com`, `etherscan.io`, `attack.mitre.org`, `crt.sh`, `phishtank.com`, plus GCHQ CyberChef. This is a principle-of-least-privilege allowlist: the extension cannot reach any domain that is not on the list. Only the user-configured domains on this allowlist are contacted, only when the user clicks.

  Custom OSINT sources you add in Settings (domain-based deep links) are opened by your browser as a normal new tab; they do not require any additional `host_permissions` because the browser, not the extension, navigates to them. Ask AI is clipboard-only — the extension does not contact any AI provider itself.

## Privacy policy URL

`https://raw.githubusercontent.com/<your-org>/<your-repo>/main/docs/PRIVACY.md`

(Replace `<your-org>` and `<your-repo>` with the actual GitHub repo path.)

## Single-purpose disclosure

The extension contains no analytics SDK, no remote code load, no auto-update mechanism, no fingerprinting. All code is the files in this repository.
