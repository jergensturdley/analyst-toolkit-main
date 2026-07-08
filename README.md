
# SOC Analyst Toolkit

A browser extension for security operations center (SOC) analysts and cybersecurity professionals to streamline the analysis of indicators of compromise (IOCs).

## Overview

This extension provides a suite of tools to accelerate the investigation of security alerts. It extracts IOCs (IPs, domains, URLs, hashes, etc.) from selected text, provides quick links to popular OSINT services, and includes text manipulation utilities for common analyst tasks. All processing is done locally in the browser for privacy and security.

## Features

### IOC Detection & Analysis
- **Comprehensive IOC Extraction**: Automatically detects and extracts multiple IOC types:
  - IP addresses (IPv4 and IPv6)
  - Domains and URLs
  - Email addresses
  - File hashes (MD5, SHA1, SHA256)
  - CVE identifiers
  - MITRE ATT&CK technique IDs (T1234, T1234.567)
  - Cryptocurrency addresses (Bitcoin, Ethereum)
  - MAC addresses
- **IOC Statistics**: Real-time statistics dashboard showing counts by IOC type
- **Batch Operations**: Deduplicate and sort IOCs with one click
- **Defanging/Refanging**: Convert IOCs to safe formats for sharing

### OSINT Integration
- **Comprehensive Threat Intelligence**: Quick lookup in 20+ OSINT platforms including:
  - VirusTotal, AlienVault OTX, AbuseIPDB, ipinfo.io
  - GreyNoise, Shodan (for IPs)
  - URLhaus, urlscan.io (for URLs/domains)
  - MalwareBazaar, Hybrid Analysis (for hashes)
  - MITRE ATT&CK, D3FEND (for techniques)
  - Blockchain explorers (for crypto addresses)
  - MAC vendor lookups
- **Agent Enrichment**: Configurable IP enrichment (ipinfo.io, AbuseIPDB, GreyNoise, VirusTotal) with caching and rate limits, triggered from the IOC graph right-click menu.
- **Custom OSINT Sources**: Add your own internal tools and platforms
- **Context Menu Integration**: Right-click any selected text for instant OSINT lookups

### Productivity Features
- **Snippet Library**: Personal, searchable library for frequently used notes, commands, and templates
- **Investigation Notes**: Track your analysis with timestamped notes
- **Text Processing Tools**: 
  - Base64 encoding/decoding
  - Hex encoding/decoding
  - ROT13 decoding
  - URL decoding
  - Entropy analysis
  - String extraction
  - Hash generation (SHA1, SHA256)
- **CyberChef Integration**: Open selected text in CyberChef for advanced processing and analysis
  - Support for custom/self-hosted CyberChef instances
  - Configurable URL in settings
- **Export Options**: Export IOCs in multiple formats (CSV, JSON, Markdown, Obsidian-compatible)
- **Ask AI**: Copies a triage prompt — formatted from your current IOCs and the original raw input — to your clipboard and opens your chosen AI chat in a new tab. Configure the target URL and prompt template from the Ask AI section of Settings (preset dropdown covers Claude, ChatGPT, Gemini, Copilot, Perplexity, and Mistral; pick "Custom…" for any other URL). Custom templates support `{{iocs}}` and `{{rawInput}}` placeholders.
- **Keyboard Shortcuts**: Efficient workflow with customizable hotkeys
- **Modern Themes**: 7 Bearded-inspired themes optimized for extended use:
  - Arc (Default - GitHub-inspired)
  - Coffee (Warm brown)
  - Monokai (Classic vibrant)
  - Oceanic (Cool and calming)
  - Solarized (Precise and refined)
  - Earth (Natural and grounded)
  - Midnight (Deep and mysterious)

### Privacy & Security
- **Privacy-Focused**: All data processing and storage happens locally in your browser
- **No Tracking**: No external data transmission, analytics, or telemetry
- **Open Source**: Fully transparent codebase for security review

## Installation

1. Open your browser and navigate to `chrome://extensions/`.
2. Enable "Developer mode".
3. Click "Load unpacked" and select the directory containing this project's files.
4. Pin the extension to your toolbar for easy access.

## Usage

- **IOC Analysis**: Select text on any webpage and right-click to "Analyze with SOC Toolkit". The popup will open with the extracted IOCs.
- **OSINT Lookups**: Select an IOC and right-click to open it directly in an OSINT tool.
- **Text Processing**: Right-click selected text and navigate to "Text Processing" or "Security Recipes (CyberChef)" submenu for encoding/decoding and analysis operations.
- **CyberChef Integration**: Select text and right-click → "Security Recipes (CyberChef)" → "Open in CyberChef" to process in your configured CyberChef instance.
- **Snippet Access**: Click the extension icon in your toolbar to open the popup and access the snippet library.
- **Theme Customization**: Open the extension popup → Settings tab → Theme Selection to choose your preferred theme.

## Technical Details

- **Manifest Version**: 3
- **Permissions**: `storage`, `clipboardWrite`, `contextMenus`, `notifications`, `activeTab`.
- **Storage**: Uses local browser storage for all user data.

## Contributing

Contributions are welcome. Please feel free to submit bug reports, feature requests, or pull requests.

### Developer Documentation

- **[AGENTS.md](AGENTS.md)**: Comprehensive guide for implementing enrichment agents for third-party threat intelligence integrations. Includes architecture, API specifications, caching strategy, and implementation checklists.
- **[FEATURES.md](FEATURES.md)**: Detailed feature documentation for all IOC types and OSINT integrations.
- **[UPGRADE_GUIDE.md](UPGRADE_GUIDE.md)**: Guide for upgrading between major versions.

## License

See the LICENSE file for details.
