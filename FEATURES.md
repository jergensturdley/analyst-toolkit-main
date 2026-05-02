# SOC Analyst Toolkit - Feature Guide

## 🔍 IOC Detection & Extraction

### Supported IOC Types

#### Network Indicators
- **IPv4 Addresses**: Standard IPv4 format (e.g., 192.168.1.1)
- **IPv6 Addresses**: Full, compressed, and mixed formats
- **Domains**: Validates against 1000+ TLDs
- **URLs**: HTTP/HTTPS protocols with full path support
- **Email Addresses**: Standard email format with domain validation

#### File Indicators
- **MD5 Hashes**: 32-character hexadecimal
- **SHA1 Hashes**: 40-character hexadecimal
- **SHA256 Hashes**: 64-character hexadecimal

#### Threat Intelligence
- **CVE Identifiers**: CVE-YYYY-NNNNN format
- **MITRE ATT&CK Techniques**: T1234 and T1234.567 formats

#### Cryptocurrency (NEW in v0.4)
- **Bitcoin Addresses**:
  - Legacy P2PKH (starts with 1)
  - P2SH (starts with 3)
  - Bech32/SegWit (starts with bc1)
- **Ethereum Addresses**: 0x followed by 40 hex characters

#### Hardware Identifiers (NEW in v0.4)
- **MAC Addresses**: Supports both colon and hyphen separators

## 🌐 OSINT Integration

### Threat Intelligence Platforms
- **VirusTotal**: Multi-engine malware scanner
- **AlienVault OTX**: Open Threat Exchange
- **ThreatFox**: Abuse.ch threat intelligence (NEW)
- **Pulsedive**: Threat intelligence and IOC analysis

### IP Address Analysis
- **AbuseIPDB**: IP abuse reporting and checking
- **ipinfo.io**: IP geolocation and ASN information
- **GreyNoise**: IP noise classification (NEW)
- **Shodan**: Internet device search engine (NEW)

### URL & Domain Analysis
- **urlscan.io**: URL and website scanner
- **URLhaus**: Malware URL sharing platform (NEW)

### Hash & Malware Analysis
- **MalwareBazaar**: Malware sample sharing (NEW)
- **Hybrid Analysis**: Automated malware analysis (NEW)
- **threat.rip**: Threat intelligence aggregation

### Vulnerability Research
- **NVD**: National Vulnerability Database
- **MITRE CVE**: CVE details and references
- **CVE Details**: Vulnerability statistics
- **Exploit-DB**: Exploit database

### MITRE ATT&CK (NEW in v0.4)
- **MITRE ATT&CK**: Official technique documentation
- **D3FEND**: Defensive countermeasures

### Cryptocurrency (NEW in v0.4)
- **Blockchain.com**: Bitcoin blockchain explorer
- **BlockCypher**: Multi-blockchain API
- **Etherscan**: Ethereum blockchain explorer
- **Ethplorer**: Ethereum analytics

### Hardware (NEW in v0.4)
- **macvendors.com**: MAC address vendor lookup
- **macvendorlookup.com**: MAC address information

### Custom Sources
- Add your own internal tools and platforms
- Use {{IOC}} placeholder for dynamic URLs
- Filter by IOC type or apply to all types

## 🛠️ Batch Operations

### Deduplicate
- Removes duplicate IOCs from input
- Case-insensitive matching
- Preserves original case of first occurrence

### Sort
- Alphabetically sorts all IOCs
- Case-insensitive sorting
- Maintains line-by-line format

### Statistics Dashboard
- Real-time IOC counts by type
- Visual grid layout
- Color-coded stat cards
- Total count display

## 📋 Quick Copy Features

### Copy All IOCs
Copies all extracted IOCs to clipboard

### Copy by Type
Individual buttons for:
- All IPs (IPv4 and IPv6)
- All Domains
- All URLs
- All Hashes (MD5, SHA1, SHA256)
- All CVEs
- All MITRE ATT&CK Techniques (NEW)
- All Cryptocurrency Addresses (NEW)
- All MAC Addresses (NEW)

## 📤 Export Options

### Formats
- **CSV**: Comma-separated values with headers
- **JSON**: Structured JSON with type metadata
- **Markdown**: Human-readable markdown format
- **Obsidian**: Graph-enabled markdown for Obsidian

### Graph Export
- PNG image export
- SVG vector export

## ⌨️ Keyboard Shortcuts

### Extension Control
- **Ctrl+Shift+S** (Cmd+Shift+S on Mac): Open SOC Toolkit
- **Ctrl+Shift+T** (Cmd+Shift+T on Mac): Toggle snippet expansion

### Page-Level Actions
- **Ctrl+Alt+L**: Show snippets for copying
- **Ctrl+Alt+S**: Toggle snippet system on/off

### Input Actions
- **Ctrl+Enter**: Analyze IOCs (when in input field)

## 🎨 Themes

### Available Themes
- **Matrix (Green)**: Classic terminal green on black
- **Cyber Blue**: Modern cybersecurity blue
- **Alert Red**: High-contrast security red
- **Royal Purple**: Professional purple theme
- **Security Orange**: Warm security orange
- **Neon Cyan**: Bright cyan theme
- **Auto (System)**: Follows system theme preference

### Theme Features
- Consistent color schemes across all IOC types
- Proper contrast for readability
- Color-coded IOC badges
- Themed OSINT links

## 🔒 Privacy & Security

### Local Processing
- All IOC extraction happens locally in your browser
- No data sent to external servers for processing
- Chrome local storage only for user preferences

### User-Initiated Actions
- OSINT lookups only when you click links
- Clipboard operations require user action
- No automatic external connections

### Data Storage
- Snippets stored locally
- Investigation notes stored locally
- Settings stored locally
- No cloud sync or external storage

## 📝 Snippet Management

### Features
- Create reusable text snippets
- Tag-based organization
- Search and filter
- Template variables (date, time, etc.)
- Export/import as JSON

### Usage
- Quick access via popup
- On-page snippet insertion
- Keyboard shortcuts for efficiency

## 🗒️ Investigation Notes

### Features
- Timestamped notes
- Rich text support
- Tag organization
- Export to multiple formats
- Context menu integration

### Use Cases
- Incident timelines
- Analysis notes
- Evidence collection
- Report drafting

## 🔧 Text Processing Tools

### Defanging
Convert IOCs to safe formats:
- `.` → `[.]`
- `http` → `hxxp`
- `@` → `[at]`

### Refanging
Restore defanged IOCs to original format

### Decoding
- URL decode
- Base64 decode
- Hex decode

### Analysis
- Entropy calculation
- String extraction
- Hash generation (SHA1, SHA256)

## 🎯 Context Menu Integration

### Right-Click Actions
- Analyze with SOC Toolkit
- Quick OSINT lookups
- Text processing (defang, decode)
- Add to investigation notes
- Generate hashes

### Smart Detection
Context menu adapts based on selected text:
- Detects IOC type automatically
- Suggests relevant OSINT sources
- Provides appropriate processing options
