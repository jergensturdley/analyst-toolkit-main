# Changelog

All notable changes to the SOC Analyst Toolkit will be documented in this file.

## [0.5.8] - 2026-10-03

### Added

- Tools tab (Alt+3): transform workbench, live regex tester, URL unfurler, and file hash analysis, all local, on collapsible and resizable cards that remember their state

### Removed

- Notes tab; stored investigation notes are dropped once on the next popup open

## [0.5.7] - 2026-10-02

### Added

- Chrome side panel: open the toolkit in the browser's sidebar from the header button or Settings → Window & Layout; a segmented pill nav and a narrow, non-overflowing layout fill the panel, and an option makes the toolbar button open the sidebar instead of the popup (Chrome only — Firefox has no side panel API, and its build strips the manifest key)
- Small floating windows share the panel's responsive narrow layout below ~430px
- CI now fails when any version surface (package.json, popup fallback label, CHANGELOG section, store listing header) drifts from the manifest
- Store screenshots for the sidebar, floating window and side panel, regenerable via `scripts/capture-feature-shots.js`

### Fixed

- `screenshots/take.js` hardcoded a Playwright browser-cache path that no longer exists and crashed with a raw stack trace without the npm package; it now resolves any cached build and prints the install command when the prerequisite is missing

## [0.5.6] - 2026-10-02

### Fixed

**IOC parsing**
- Duplicate IOCs no longer reach the results list, statistics, graph, exports or the Ask-AI prompt; the dedupe button's "removed" count no longer counts blank lines
- Compressed and IPv4-mapped IPv6 addresses extract whole (`2001:db8::1` was truncated to `2001:db8::`, `::ffff:192.168.1.1` mangled to `::ffff:192`)
- The context-menu "Extract IOCs" action now refangs defanged text before extraction, matching the popup path

**Popup**
- Restored settings now show their saved state on the Auto-Analyze, Auto-Enrich and Graph toggles
- Row Enrich and Details use the refanged value after a row is defanged, so providers are no longer queried with `192[.]168[.]1[.]1`
- Ask AI no longer ships the previous case's IOCs after Clear, and "Enrich remaining" no longer re-sends IOCs from an earlier analysis
- "Export Selected" exports only the selected rows, and exporting an empty list no longer downloads a blank row
- Snippet Edit no longer overwrites the wrong snippet when the list is filtered, and importing snippets refreshes the list immediately
- The "System" theme persists as a choice and keeps following the OS preference; "Copy Crypto" works; downward drags in the custom OSINT list land on the drop target; Select All resets on re-analysis

**Enrichment (background)**
- urlscan.io edges appear in the IOC graph again instead of being dropped for lack of ids
- HTTP 401/403 and 429 report as invalid key and rate limit instead of a generic network error across all providers
- VirusTotal ASN nodes carry the announced prefix and registry; URLs with non-latin1 characters no longer fail VirusTotal lookups
- A URLhaus outage reports as an error instead of a clean lookup; the ipinfo ASN fallback stops mislabeling the IP and country as prefix and registry
- A transient ASN miss is no longer cached for 24 hours, the enrichment cache prunes to 1000 entries, and the passive-DNS/ASN context-menu lookups share the VirusTotal rate budget

**Other**
- Page IOC highlighting applies to every match instead of stopping after the first
- The store-package verifier no longer demands files the build intentionally omits
- Version labels aligned at 0.5.5 across manifest, package.json, popup fallback and store listing

### Added
- Offline behavior tests now run the real `popup.js` and `background.js` in Node VM sandboxes (`tests/verify_popup.js`, `tests/verify_background.js`) instead of testing only a parser mock
- OSINT links open in a background tab so the toolkit window stays open for the rest of the triage; a new "Window & Layout" setting controls this, and middle/Ctrl/Cmd/Shift/Alt-clicks keep normal browser behavior (the bulk "Open in VirusTotal" action follows the same setting)
- The floating window sizes fluidly (the UI fills whatever size you drag the window to), gains a drag-to-resize grip in its bottom-right corner, and closes with Esc (Esc still clears the analysis in the toolbar popup; an open dialog takes precedence)
- Optional sidebar navigation: "Window & Layout" in Settings offers tabs across the top (default) or a vertical rail on the left

## [0.5.5] - 2026-09-30

### Added
- Search box above the IOC list that filters results live as you type, combining with the category filter
- The expand/collapse-all-links choice is remembered, so rows open the same way next popup session

### Fixed
- Expand-all-links toggle saved its state inverted, so the persisted choice never matched the toggle
- Popup version label read from the manifest instead of a hardcoded "v0.4"
- `vis-network.min.js` replaced with an unminified build (Chrome Web Store rejected the minified bundle for readability review)

## [0.5.4] - 2026-09-21

### Added
- Auto-enrichment toggle (off by default): after an analysis, the first 5 IOCs per type (IPs, domains, hashes, URLs) enrich automatically, and "Enrich remaining (N)" in the Actions menu covers the rest
- Verdict chips and risk scores on each result row; clicking a chip expands per-provider facts with per-value copy buttons, and "Details" opens the full enrichment panel
- Per-row Enrich and Links buttons; OSINT links are collapsed by default
- Collapsible IOC relation graph; the collapsed or expanded choice is remembered
- "Expand all links" control above the results list

### Changed
- Results header reduced to a single Actions menu holding copy, enrich, export, filter, and graph controls
- Enrichment panel gained a close button

## [0.5.3] - 2026-09-09

### Removed
- GreyNoise enrichment source and OSINT link (service discontinued / site unresolvable)

### Added
- IPAddress.to as a keyless IP enrichment source (geolocation, ASN, VPN/proxy/Tor flags, fraud score with AbuseIPDB as primary)
- IPAddress.to OSINT link + right-click "Check in IPAddress.to" lookup
- Per-field copy buttons on enrichment source cards

## [0.5.2] - 2026-08-14

### Added
- **Firefox support.** `scripts/build-store-package.sh firefox` builds an AMO package from the same source, rewriting the background service worker to an event page (Firefox MV3 has no service workers) and adding the `browser_specific_settings.gecko` block. Requires Firefox 128 or later.
- **Guards for two Chrome-only APIs** so the extension runs under Firefox: `windows.onBoundsChanged` (on Firefox the floating window reopens at default geometry instead of remembering size and position) and `storage.local.getBytesInUse` (the storage usage indicator is hidden rather than throwing).

### Fixed
- **Floating window no longer auto-opens on browser launch.** A persisted "open" flag was never cleared on browser quit, so the popout re-created itself at every startup. It now opens only from the toolbar button; window size/position are still remembered.
- **Page snippet overlay**: clicking a snippet threw a `ReferenceError` (undefined helper) and never copied — now copies the snippet content.
- **Settings**: changing theme / auto-analyze / graph toggles no longer resets the page-snippet-system toggle and bulk link preference (settings are merged instead of overwritten).

### Changed
- Triage prompt builder consolidated into `triage_prompt.js` (single implementation shared by popup and tests); removed duplicated and dead code across popup, background, and content scripts.

## [0.5.1] - 2026-07-11

### Fixed
- **VirusTotal URL lookups**: URL indicators now open the `/gui/url/<id>` report route; the previous `/gui/search/<encoded-url>` 404'd on the encoded slashes.
- **MV3 CSP**: Custom OSINT source and note-delete buttons used inline `onclick` (blocked on extension pages) and are now wired via event delegation.
- **File hashes**: Removed the bogus "MD5" row (it printed a 32-bit non-cryptographic value); SHA-1 / SHA-256 only.
- **IOC results**: Hash type filter now matches; defang/refang no longer corrupts copied/exported values; non-Latin1 IOCs no longer abort rendering.
- **Ask AI**: Prompt is copied to the clipboard before the AI tab opens.
- **CSV export**: Quotes are escaped and spreadsheet formula injection is neutralized.
- **Service worker**: `getPendingAnalysis` survives worker restarts and clears stored selection; floating-window bounds listener no longer leaks; unmatched messages close the channel.
- **Data cleanup**: "Clear old data" now also prunes enrichment / passive-DNS / ASN caches.

### Added
- `clipboardRead` permission for the Paste button.

### Changed
- MITRE sub-technique links use the `T####/###` path form; background defang matches the popup so output round-trips through refang.

## [0.5.0] - 2026-07-08

### Added
- **Ask AI**: Replaces "Ask Claude" with a configurable clipboard-copy triage helper. Choose target AI chat from a preset dropdown (Claude / ChatGPT / Gemini / Copilot / Perplexity / Mistral / Custom…) and customize the prompt template via Settings. All processing local; no API keys; no streaming.

### Fixed
- **CyberChef Integration**: Fixed URL encoding issue where highlighted text showed unexpected characters (e.g., %20, %21). CyberChef now correctly receives Base64 encoded input instead of URL encoded text.

### Changed
- **OSINT Sources**: Removed ANY.RUN from hash analysis integrations. Hash IOCs now link to VirusTotal, threat.rip, MalwareBazaar, and Hybrid Analysis.

### Verified
- **Pulsedive Integration**: Confirmed correct Base64 encoding for IOC parameters.

## [0.4.0] - 2024-01-15

### Added - Enhanced IOC Detection
- **Bitcoin Address Detection**: Supports P2PKH (1...), P2SH (3...), and Bech32 (bc1...) formats
- **Ethereum Address Detection**: Recognizes Ethereum wallet addresses (0x + 40 hex chars)
- **MITRE ATT&CK Technique IDs**: Extracts technique identifiers (e.g., T1566, T1059.001)
- **MAC Address Detection**: Supports colon and hyphen-separated formats
- **Color-coded IOC Types**: All new IOC types have unique color schemes across all themes

### Added - Enhanced OSINT Integration
- **MITRE ATT&CK Integration**: Direct links to attack.mitre.org and D3FEND
- **Cryptocurrency Analysis**:
  - Blockchain.com and BlockCypher for Bitcoin addresses
  - Etherscan and Ethplorer for Ethereum addresses
- **MAC Vendor Lookup**: macvendors.com and macvendorlookup.com integration
- **Additional Threat Intelligence Sources**:
  - URLhaus for URL/malware analysis
  - ThreatFox for IOC threat intelligence
  - MalwareBazaar for malware hash lookups
  - Hybrid Analysis for sandbox analysis
  - GreyNoise for IP noise/threat classification
  - Shodan for IP reconnaissance
- **Context Menu Integration**: Quick lookups for MITRE techniques and crypto addresses

### Added - Batch Operations
- **Deduplicate IOCs**: Remove duplicate IOCs with one click (case-insensitive)
- **Sort IOCs**: Alphabetically sort all IOCs in the input field
- **IOC Statistics Dashboard**: Real-time visual statistics showing:
  - Count by IOC type (IPs, Domains, URLs, Emails, Hashes, CVEs, MITRE, Crypto, MACs)
  - Total IOC count
  - Grid layout with color-coded stat cards

### Added - User Interface Improvements
- **Keyboard Shortcuts Reference**: Built-in reference panel in Settings tab showing:
  - Extension hotkeys (Ctrl+Shift+S, Ctrl+Shift+T)
  - Page-level shortcuts (Ctrl+Alt+L, Ctrl+Alt+S)
  - Input shortcuts (Ctrl+Enter)
- **Quick Copy Buttons**: Individual copy buttons for:
  - All MITRE ATT&CK techniques
  - All cryptocurrency addresses
  - All MAC addresses
  - (In addition to existing: IPs, Domains, URLs, Hashes, CVEs)

### Changed
- Updated README.md with comprehensive feature documentation
- Bumped version to 0.4 in manifest.json
- Enhanced description in manifest to highlight OSINT integration

### Technical Details
- All new regex patterns are optimized for performance
- Maintains privacy-first approach - all processing remains local
- No new external dependencies added
- Fully compatible with existing export formats (CSV, JSON, Markdown, Obsidian)

## [0.3.0] - Previous Release
- Base IOC extraction (IPv4, IPv6, domains, URLs, emails, hashes, CVEs)
- OSINT integration (VirusTotal, AlienVault, AbuseIPDB, ipinfo.io)
- Snippet management system
- Investigation notes
- Multiple theme support
- Export functionality
