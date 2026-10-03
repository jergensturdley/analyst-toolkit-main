# Chrome Web Store Listing — SOC Analyst Toolkit

Store copy reflecting v0.5.8. Host lists and permission names match
`manifest.json` exactly; update both together on any permission change.

## Store Metadata

**Title:** SOC Analyst Toolkit

**Short description** (≤ 132 chars):
Extract, defang, and pivot on IOCs in seconds. Built for SOC analysts.

**Category:** Productivity

---

## Detailed Description

SOC Analyst Toolkit is a free, privacy-first browser extension for security operations center (SOC) analysts and cybersecurity professionals. It streamlines the investigation of security alerts by extracting, transforming, and enriching indicators of compromise (IOCs) directly in your browser — nothing leaves your machine until you look something up.

### Key Features

**IOC Extraction**
- Automatically detects 9 IOC types from any selected text: IPv4, IPv6, domains, URLs, email addresses, file hashes (MD5, SHA1, SHA256, SHA512), CVE identifiers, MITRE ATT&CK technique IDs, and cryptocurrency addresses.
- Real-time statistics dashboard with per-type counts.
- Deduplication and sorting with one click.

**Auto-Enrichment**
- One click per indicator enriches it against VirusTotal, AbuseIPDB, ipinfo.io, and IPAddress.to — with keyless coverage from crt.sh, MalwareBazaar, and urlscan.
- Optional auto-enrich toggle (off by default): after an analysis, the first 5 indicators per type enrich automatically; "Enrich remaining" covers the rest.
- Each result row shows a verdict chip and risk score. Click it for per-provider facts, each with its own copy button.
- First use asks consent once; enrichment honors your per-provider toggles and API keys, and caches results so re-checks cost no quota.

**OSINT Integration**
- One-click lookup links to 20+ threat intelligence platforms: VirusTotal, AlienVault OTX, AbuseIPDB, ipinfo.io, IPAddress.to, Shodan, URLhaus, urlscan.io, NVD, MITRE ATT&CK, and more.
- Links sit behind a per-row toggle; "Expand all links" opens them in one click.
- Copy any link plain or as Markdown.
- Custom OSINT entries in Settings — add your internal threat intel sources.

**IOC Relation Graph**
- See how extracted indicators relate in an interactive graph.
- Right-click a node to enrich it, pull passive DNS, resolve ASNs, or open it in VirusTotal or CyberChef.
- Collapsible out of the way when you only need the list; the choice is remembered.

**Workspace**
- Pop the toolkit into a floating window that stays open while you work; drag the corner grip to resize it, press Esc to close it.
- OSINT links open in background tabs so your analysis stays on screen; middle-click or Ctrl/Cmd-click keeps normal browser behavior.
- Choose tabs across the top or a sidebar rail on the left in Settings → Window & Layout.

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
- Hash text with SHA-1 or SHA-256.
- Base64 encode/decode, URL encode/decode.
- CyberChef integration for 100+ operations.
- Sort and deduplicate lines.

**Privacy-First**
- All data stored locally in your browser (`chrome.storage.local`).
- No telemetry, analytics, or third-party SDKs.
- Lookups happen only when you click. Enrichment requires one-time consent; the automatic pass is opt-in and off by default.
- Consent modal and reset option included.

---

## Single-Purpose Justification

This extension performs one purpose: it extracts, transforms, and links IOCs for security analysis. All features serve this purpose. No unrelated functionality is bundled.

---

## Permission Justifications

| Permission | Justification |
|---|---|
| `activeTab` | Required to read selected text from the current tab when you click the extension. No other tab access. |
| `storage` | Stores your settings, saved notes, IOC history, and enrichment results locally in the browser. Never transmitted anywhere. |
| `clipboardRead` | Used only when you click the Paste button to populate IOC input from your clipboard. Not read in the background. |
| `clipboardWrite` | Used only when you click Copy to place defanged IOCs, triage prompts, or exported data on your clipboard. |
| `notifications` | Shows brief progress and success messages during enrichment and copy actions. No push notifications. |
| `contextMenus` | Adds right-click entries ("Lookup in VirusTotal", "Analyze with SOC Toolkit") for fast pivoting. |
| `scripting` | Injects a minimal content script into the active tab to capture selected text when you invoke the extension. |
| `sidePanel` | Lets the toolkit open in the browser's side panel when you click "Open in sidebar" or turn on the toolbar-click option. Chrome-only; grants no page access. |
| Host permissions for OSINT domains | Opens OSINT lookup links and enrichment requests to the exact hosts listed below. No `<all_urls>` permission. Custom user-added URLs open as normal browser tabs. |

---

## Privacy Policy

Privacy policy URL: [https://github.com/jergensturdley/analyst-toolkit-main/blob/main/docs/PRIVACY.md](https://github.com/jergensturdley/analyst-toolkit-main/blob/main/docs/PRIVACY.md)

Key points covered:
- Extension is 100% free, no in-app purchases or subscriptions.
- All data stored locally in `chrome.storage.local`.
- No analytics, telemetry, or third-party data sharing.
- Network requests happen only through lookups you click and enrichment you trigger or opt into.
- Extension author has no access to user data.

---

## Screenshots

Store format: 1280×800 JPEG. `screenshots/store/screenshot-1..6.jpg` are the upload-ready files, regenerated by `scripts/make-store-jpegs.sh` after each `screenshots/take.js` run (capture at 2×, pad onto the popup's own background).

1. `screenshot-1.jpg` — clean input state
2. `screenshot-2.jpg` — sample text analyzed, IOCs categorized with Enrich pills and Links toggles
3. `screenshot-3.jpg` — verdict chip, inline provider summary, and the enrichment detail panel
4. `screenshot-4.jpg` — IOC relation graph
5. `screenshot-5.jpg` / `screenshot-6.jpg` — Settings, enrichment providers and API keys
6. `screenshot-7.jpg` — sidebar navigation layout (`scripts/capture-feature-shots.js`)
7. `screenshot-8.jpg` — floating window with the resize grip (`scripts/capture-feature-shots.js`)
8. `screenshot-9.jpg` — side panel triaging the sample alert beside the page (`scripts/capture-feature-shots.js`)

The store accepts up to five screenshots per listing: pick five of the nine
above per release (7-9 showcase the current features).

---

## Assets to Upload

| Asset | Dimensions | Format |
|---|---|---|
| Small promo tile | 440×280 | PNG |
| Marquee | 1400×560 | PNG or SVG |
| Screenshots | 1280×800 | PNG (×5) |
| Icon | 128×128 | PNG |

---

## Privacy Tab — Ready-to-Paste Justifications

Copy each field below into the corresponding box on the **Privacy practices** tab of the Developer Dashboard.

---

### Single Purpose Description (required)

This extension performs one purpose: it extracts, transforms, and links indicators of compromise (IOCs) for security analysis. All features — IOC parsing, enrichment, OSINT lookup links, defanging, AI triage prompt building, and text utilities — serve this single purpose. No unrelated functionality is bundled.

---

### Permission Justifications

**activeTab**
Required to read the text you have selected in the current browser tab when you click the extension icon. The extension reads no other tab content.

**clipboardRead (Paste button)**
Used only when you click the optional Paste button in the IOC input area, to place your clipboard contents into the extension for processing. The extension does not read the clipboard in the background or at any other time.

**clipboardWrite (Copy operations)**
Used only when you click Copy to place defanged IOCs, triage prompts, or exported data onto your clipboard for use in other tools.

**contextMenus**
Adds right-click context menu entries ("Lookup in VirusTotal", "Lookup in AbuseIPDB", etc.) for fast OSINT pivoting.

**notifications**
Displays brief in-browser progress and success messages during enrichment and copy actions. No push notifications, no background alerts.

**scripting**
Injects a minimal content script into the active tab to capture selected text when you invoke the extension, enabling IOC extraction from any webpage you are analyzing.

**storage**
Stores your settings, saved notes, IOC history, and enrichment results locally in the browser using `chrome.storage.local`. This data never leaves your device and is never transmitted to the extension author or any third party.

**Host permissions (enrichment and OSINT lookups)**
Used to open OSINT lookup links in new tabs and to send enrichment requests when you enrich an indicator (manually, or via the opt-in auto-enrich toggle after one-time consent). The exact hosts granted are:

- `https://www.virustotal.com/*`
- `https://www.abuseipdb.com/*`
- `https://api.abuseipdb.com/*`
- `https://ipaddress.to/*`
- `https://ipinfo.io/*`
- `https://urlscan.io/*`
- `https://urlhaus-api.abuse.ch/*`
- `https://urlhaus.abuse.ch/*`
- `https://mb-api.abuse.ch/*`
- `https://bazaar.abuse.ch/*`
- `https://otx.alienvault.com/*`
- `https://gchq.github.io/*`
- `https://cyberchef.org/*`
- `https://macvendors.com/*`
- `https://www.macvendorlookup.com/*`
- `https://www.blockchain.com/*`
- `https://etherscan.io/*`
- `https://attack.mitre.org/*`
- `https://crt.sh/*`
- `https://checkurl.phishtank.com/*`

No `<all_urls>` permission is used. Custom user-added OSINT URLs open as normal browser tabs with no special permission.

---

### Remote Code

This extension does not load or execute any remote code. All logic runs locally from the installed extension files. No CDNs, no external scripts, no eval. The graph and icon libraries are bundled locally.

---

## Version History

| Version | Date | Notes |
|---|---|---|
| 0.5.8 | 2026-10-02 | Tools tab: transform workbench, live regex tester, URL unfurl, relocated file hashing on collapsible and resizable cards; Notes tab removed |
| 0.5.7 | 2026-10-02 | Chrome side panel (dock from the popup header or Settings, optional toolbar-click docking) with a responsive narrow layout shared with small floating windows; version-drift CI guard; screenshot pipeline fixes |
| 0.5.6 | 2026-10-02 | Sidebar navigation and a resizable floating window with Esc-to-close; OSINT links open in background tabs so the popup stays open; 28 fixes across IOC parsing, popup state and enrichment agents |
| 0.5.5 | 2026-09-30 | Live IOC results search box; expand/collapse-all-links choice remembered; toggle-state, version-label and packaging fixes |
| 0.5.4 | 2026-09-21 | Opt-in auto-enrichment (first 5 per type), verdict chips with inline enrichment summaries, single grouped Actions menu, enrichment panel close, collapsible IOC relation graph |
| 0.5.3 | 2026-09-09 | IPAddress.to enrichment source and OSINT link; GreyNoise removed (service discontinued); per-field copy buttons on enrichment cards |
| 0.5.2 | 2026-08-14 | Firefox (AMO) support; floating-window and snippet fixes; settings merge fix |
| 0.5.1 | 2026-07-11 | VirusTotal URL report route, CSP-safe buttons, CSV export hardening, clipboardRead for Paste |
| 0.5.0 | 2026-07-08 | IOC table refactor, shared prompt module, privacy docs, consent UI |
