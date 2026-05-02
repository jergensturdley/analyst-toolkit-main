# Upgrade Guide: v0.3 → v0.4

## What's New in v0.4

This major update brings powerful new capabilities to enhance your security analysis workflow.

## New IOC Types

### 🪙 Cryptocurrency Addresses
**Bitcoin**
- Legacy (P2PKH): `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`
- Script (P2SH): `3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy`
- SegWit (Bech32): `bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq`

**Ethereum**
- Standard format: `0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0`

**OSINT Integration:**
- Blockchain.com - Transaction history
- BlockCypher - Multi-chain explorer
- Etherscan - Ethereum blockchain
- Ethplorer - Token analytics

### 🎯 MITRE ATT&CK Techniques
- Technique IDs: `T1566`, `T1059.001`
- Automatic detection in incident reports
- Direct links to MITRE ATT&CK framework
- D3FEND defensive countermeasures

**Use Cases:**
- Threat intelligence enrichment
- Incident categorization
- Defensive strategy planning

### 🔧 MAC Addresses
- Colon format: `00:1B:44:11:3A:B7`
- Hyphen format: `00-1B-44-11-3A-B8`
- Vendor lookup integration
- Hardware identification

**OSINT Integration:**
- macvendors.com - Manufacturer lookup
- macvendorlookup.com - Detailed info

## Enhanced OSINT Coverage

### New Threat Intelligence Sources
1. **URLhaus** - Malware URL database (abuse.ch)
2. **ThreatFox** - IOC sharing platform (abuse.ch)
3. **MalwareBazaar** - Malware sample repository
4. **Hybrid Analysis** - Sandbox analysis platform
5. **GreyNoise** - Internet noise classification
6. **Shodan** - Internet-connected device search

### What This Means
- **Faster Analysis**: More sources = better context
- **Better Coverage**: Specialized tools for each IOC type
- **Reduced False Positives**: Cross-reference multiple sources

## New Workflow Features

### Batch Operations
**Deduplicate**
```
Before:
192.168.1.1
malicious.com
192.168.1.1
MALICIOUS.COM

After (Dedupe):
192.168.1.1
malicious.com
```
- Case-insensitive matching
- Preserves first occurrence
- One-click operation

**Sort**
```
Before:
zebra-virus.com
alpha-malware.com
beta-trojan.net

After (Sort):
alpha-malware.com
beta-trojan.net
zebra-virus.com
```
- Alphabetical ordering
- Clean output for reports

### Statistics Dashboard
Real-time visualization showing:
- Count by IOC type (IPs, Domains, URLs, etc.)
- Total IOC count
- Color-coded stat cards
- Grid layout for easy scanning

**Benefits:**
- Quick overview of analysis scope
- Identify patterns in IOC distribution
- Report generation support

### Keyboard Shortcuts
| Shortcut | Action |
|----------|--------|
| `Ctrl+Shift+S` | Open toolkit |
| `Ctrl+Shift+T` | Toggle snippets |
| `Ctrl+Alt+L` | Show snippet list |
| `Ctrl+Enter` | Analyze IOCs |

**Productivity Boost:**
- Faster navigation
- Hands-on-keyboard workflow
- Reduced mouse dependency

## Migration Notes

### No Breaking Changes
All existing features work exactly as before:
- Existing IOC types unchanged
- Export formats compatible
- Snippets preserved
- Settings retained

### What Updates Automatically
- IOC detection (new types auto-detected)
- OSINT links (new sources appear automatically)
- UI enhancements (visible immediately)

### What You Can Configure
- Quick copy buttons (use as needed)
- Statistics display (always visible with results)
- Keyboard shortcuts (refer to Settings tab)

## Usage Examples

### Example 1: Ransomware Analysis
**Input:**
```
Ransomware incident detected
Payment demanded to: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
Attack used technique: T1486
Hash: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
```

**v0.4 Detects:**
- ✓ Bitcoin address → Blockchain explorer links
- ✓ MITRE technique → ATT&CK framework link
- ✓ SHA256 hash → Malware analysis links

**Workflow:**
1. Select and analyze text
2. View statistics: 1 Crypto, 1 MITRE, 1 Hash
3. Click "All Crypto" to copy Bitcoin address
4. Open blockchain explorer for payment tracking

### Example 2: Phishing Investigation
**Input:**
```
Phishing email from: attacker@evil.com
Sent from IP: 203.0.113.42
MAC: 00:1B:44:11:3A:B7
Used T1566 (Phishing)
```

**v0.4 Analysis:**
- Statistics: 1 Email, 1 IP, 1 MAC, 1 MITRE
- Dedupe (if duplicates found)
- Sort (for clean reporting)
- Quick copy by type for sharing

### Example 3: Threat Intel Report
**Paste 50+ IOCs from report:**
1. Click "Dedupe" → Remove 15 duplicates
2. Click "Sort" → Alphabetical order
3. View statistics → Overview of IOC types
4. Export as CSV → Share with team

**Time Saved:** 5-10 minutes per analysis

## Performance

### Regex Optimizations
All new patterns optimized for:
- Fast matching (< 100ms for typical text)
- Low false positives
- Memory efficiency

### No Performance Impact
- Local processing only
- No additional API calls
- Same memory footprint

## Privacy & Security

### Privacy Maintained
- ✅ All new IOC detection is local
- ✅ No data sent to external servers
- ✅ OSINT links only open when clicked
- ✅ No tracking or analytics

### Security Validated
- ✅ CodeQL scanning: 0 vulnerabilities
- ✅ No new dependencies added
- ✅ Following secure coding practices
- ✅ Input validation on all new patterns

## Tips & Best Practices

### Cryptocurrency IOCs
- Always verify wallet addresses in multiple explorers
- Check transaction history for patterns
- Note: Address format can indicate blockchain type

### MITRE ATT&CK
- Use technique IDs to categorize incidents
- Build playbooks around common techniques
- Link to defensive countermeasures in D3FEND

### Batch Operations
- Dedupe before analysis (cleaner results)
- Sort before export (easier sharing)
- Use statistics to validate extraction

### Quick Copy
- Copy by type for targeted sharing
- Use "All" buttons for comprehensive lists
- Combine with export for documentation

## Troubleshooting

### IOC Not Detected?
1. Check format matches examples
2. Ensure no extra characters
3. Try pasting directly (avoid copy/paste artifacts)

### OSINT Link Not Working?
1. Verify IOC format is correct
2. Check internet connection
3. Some sources may require sign-up

### Performance Issues?
1. Analyze in smaller batches (< 1000 IOCs)
2. Clear old data in Settings
3. Disable graph visualization for large datasets

## Feedback & Support

Found a bug or have a feature request?
- Open an issue on GitHub
- Include sample IOCs (sanitized)
- Specify browser version

Want to contribute?
- Check the codebase (it's open source!)
- Submit pull requests
- Share your workflows

## What's Next?

Planned for future releases:
- YARA rule detection
- Registry key/mutex patterns
- Risk scoring algorithms
- Timeline visualization
- Additional OSINT sources
- Enhanced export formats

Stay tuned for v0.5!
