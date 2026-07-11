# Chrome Web Store Listing — SOC Analyst Toolkit

## Store Metadata

**Title:** SOC Analyst Toolkit

**Short description** (≤ 132 chars):
Extract, defang, and pivot on IOCs in seconds. Built for SOC analysts.

**Category:** Productivity

---

## Detailed Description

SOC Analyst Toolkit is a free, privacy-first browser extension for security operations center (SOC) analysts and cybersecurity professionals. It streamlines the investigation of security alerts by extracting, transforming, and enriching indicators of compromise (IOCs) directly in your browser — no data leaves your machine until you choose to look it up.

### Key Features

**IOC Extraction**
- Automatically detects 9 IOC types from any selected text: IPv4, IPv6, domains, URLs, email addresses, file hashes (MD5, SHA1, SHA256, SHA512), CVE identifiers, MITRE ATT&CK technique IDs, and cryptocurrency addresses.
- Real-time statistics dashboard with per-type counts.
- Deduplication and sorting with one click.

**OSINT Integration**
- One-click lookup links to 20+ threat intelligence platforms: VirusTotal, AlienVault OTX, AbuseIPDB, ipinfo.io, GreyNoise, Shodan, URLhaus, urlscan.io, NVD, MITRE ATT&CK, and more.
- Group IOCs by type and open all lookups in a single tab group.
- Custom OSINT entries in Settings — add your internal threat intel sources.

**Defanging & Refanging**
- Defang IOCs for safe sharing (hxxp://, [.] , [@] , etc.).
- Refang with a single click for use in tools.
- Copy individual or all IOCs as defanged text.

**AI-Assisted Triage**
- Build structured triage prompts for any AI chat tool.
- Choose from presets (Claude, ChatGPT, Gemini) or use a custom URL.
- Copy prompt to clipboard and paste into your AI of choice.
- No data sent to AI providers — you control where the prompt goes.

**Text Utilities**
- Hash text with MD5, SHA1, SHA256, or SHA-512.
- Base64 encode/decode, URL encode/decode.
- CyberChef integration for 100+ operations.
- Sort and deduplicate lines.

**Privacy-First**
- All data stored locally in your browser (`chrome.storage.local`).
- No telemetry, analytics, or third-party SDKs.
- No data sent without a deliberate user action.
- Consent modal and reset option included.

---

## Single-Purpose Justification

This extension performs one purpose: it extracts, transforms, and links IOCs for security analysis. All features serve this purpose. No unrelated functionality is bundled.

---

## Permission Justifications

| Permission | Justification |
|---|---|
| `activeTab` | Required to read selected text from the current tab when you click the extension. No other tab access. |
| `storage` | Stores your settings, saved notes, IOC history, and enrichment-agent results locally in the browser. Never transmitted anywhere. |
| `clipboardRead` | Used only when you click the Paste button to populate IOC input from your clipboard. Not read in the background. |
| `clipboardWrite` | Used only when you click Copy to place defanged IOCs or triage prompts on your clipboard. |
| `notifications` | Shows a brief success confirmation after copying to clipboard. No push notifications. |
| Host permissions for OSINT domains | Opens OSINT lookup links in new tabs when you click them. Each domain is listed explicitly (e.g., `*://*.virustotal.com/*`). No `<all_urls>` permission. Custom user-added URLs open as normal browser tabs. |

---

## Privacy Policy

Privacy policy URL: [https://github.com/jergensturdley/analyst-toolkit-main/blob/main/docs/PRIVACY.md](https://github.com/jergensturdley/analyst-toolkit-main/blob/main/docs/PRIVACY.md)

Key points covered:
- Extension is 100% free, no in-app purchases or subscriptions.
- All data stored locally in `chrome.storage.local`.
- No analytics, telemetry, or third-party data sharing.
- Network requests only on explicit user action (clicking a lookup link or running an enrichment agent).
- Extension author has no access to user data.

---

## Screenshots

Recommended dimensions: 1280×800 PNG. Extension popup renders at ~400px wide.

**Suggested screenshots:**
1. Main IOC extraction view — text selected, IOCs extracted and categorized
2. OSINT lookup panel — one-click links to VirusTotal, AbuseIPDB, GreyNoise
3. Defang/copy panel — defanged IOCs ready to share
4. AI triage prompt builder — prompt composed and copied
5. Settings — custom OSINT entries and preferences

---

## Assets to Upload

| Asset | Dimensions | Format |
|---|---|---|
| Small promo tile | 440×280 | PNG |
| Marquee | 1400×560 | PNG or SVG |
| Screenshots | 1280×800 | PNG (×5) |
| Icon | 128×128 | PNG |

---

---

## Privacy Tab — Ready-to-Paste Justifications

Copy each field below into the corresponding box on the **Privacy practices** tab of the Developer Dashboard.

---

### Single Purpose Description (required)

This extension performs one purpose: it extracts, transforms, and links indicators of compromise (IOCs) for security analysis. All features — IOC parsing, OSINT lookup links, defanging, AI triage prompt building, and text utilities — serve this single purpose. No unrelated functionality is bundled.

---

### Permission Justifications

**activeTab**
Required to read the text you have selected in the current browser tab when you click the extension icon. The extension reads no other tab content and makes no requests without a deliberate user action.

**clipboardRead (Paste button)**
Used only when you click the optional Paste button in the IOC input area, to place your clipboard contents into the extension for processing. The extension does not read the clipboard in the background or at any other time.

**clipboardWrite (Copy operations)**
Used only when you click Copy to place defanged IOCs, triage prompts, or exported data onto your clipboard for use in other tools. No data is written to the clipboard without a deliberate user action.

**contextMenus**
Adds right-click context menu entries ("Lookup in VirusTotal", "Lookup in AbuseIPDB", etc.) for fast OSINT pivoting. The menu items appear only when you right-click while the extension is active.

**Host Permission (OSINT lookups)**
Opens OSINT lookup links in new tabs when you click them. Each domain is listed explicitly: `https://www.virustotal.com/*`, `https://www.abuseipdb.com/*`, `https://ipinfo.io/*`, `https://api.greynoise.io/*`, `https://urlscan.io/*`, `https://urlhaus.abuse.ch/*`, `https://otx.alienvault.com/*`, `https://attack.mitre.org/*`, `https://nvd.nist.gov/*`, `https://cve.mitre.org/*`, `https://cyberchef.org/*`, and similar. No `<all_urls>` permission is used. Custom user-added URLs open as normal browser tabs with no special permission.

**notifications**
Displays a brief in-browser success confirmation when IOC data is copied to your clipboard. No push notifications, no background alerts.

**scripting**
Injects a minimal content script into the active tab to capture selected text when you invoke the extension, enabling IOC extraction from any webpage you are analyzing.

**storage**
Stores your settings, saved notes, IOC history, and enrichment-agent results locally in the browser using `chrome.storage.local`. This data never leaves your device and is never transmitted to the extension author or any third party.

---

### Remote Code

This extension does not load or execute any remote code. All logic runs locally from the installed extension files. No CDNs, no external scripts, no eval.

---

## Version History

| Version | Date | Notes |
|---|---|---|
| 0.5.0 | 2026-07-10 | IOC table refactor, shared prompt module, privacy docs, consent UI |
| 0.4.x | [prior] | Prior stable release |
