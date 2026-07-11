# SOC Analyst Toolkit — Privacy Policy

SOC Analyst Toolkit is free, with no in-app purchases, subscriptions, ads, upsells, or premium tiers. It does not collect, transmit, or sell user data.

## Pricing

The extension is 100% free. There are no in-app purchases, no subscriptions, no ads, no premium features, and no paid tier. The source is open (MIT license) on GitHub.

## Data storage

Settings, snippets, IOC history, and enrichment-agent results are stored locally in your browser via `chrome.storage.local`. They never leave your machine except when you explicitly initiate an OSINT lookup.

The optional Paste button uses clipboard-read access only after you click it, to place clipboard text into the IOC input. Clipboard contents are not read in the background, stored automatically, or sent to the extension author.

## Network usage

Outbound HTTP requests only occur when you click an OSINT lookup link or run an enrichment agent. Requests go to the providers configured in Settings (default: VirusTotal, ipinfo.io, AbuseIPDB, GreyNoise). Ask AI is a clipboard-copy helper: it builds a triage prompt and copies it to your clipboard so you can paste it into the AI chat of your choice; the extension itself does not contact any AI provider. The extension never makes network requests without a user action.

## Third-party access

The extension author has no access to user data. No analytics SDK, telemetry, fingerprinting, or remote code loading is included.

## Updates

This policy may change with new versions; the change log is in `CHANGELOG.md` in the project repository.

## Contact

Open an issue on the project GitHub repository.
