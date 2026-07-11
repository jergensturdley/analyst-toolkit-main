# Changelog

All notable changes to the SOC Analyst Toolkit will be documented in this file.

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
