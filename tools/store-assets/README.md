# Store assets

SVG-only assets for the Chrome Web Store listing.

## Files

- `marquee.svg` — 1400×560 marquee tile.
- `small-promo.svg` — 440×280 small promo tile.
- `sample-iocs.txt` — sample alert text used in the screenshot recipe.

## Rendering to PNG (optional)

SVG works in some Chrome Web Store slots. If you need PNG:

1. Open the SVG in Chrome.
2. File → Save As → choose PNG.
3. Resize / crop to the target dimensions if needed.

No `rsvg-convert` or other tool dependency — the SVGs are the canonical artifact.

## Screenshot recipe

Five screenshots, 1280×800 PNG, captured manually in the default Arc theme.

1. Load the extension unpacked (`chrome://extensions` → Load unpacked → select this repo).
2. Open the toolbar popup.
3. Paste the contents of `sample-iocs.txt` into the IOC input.
4. Click "Analyze".
5. Use Chrome DevTools → toggle device toolbar → 1280×800.
6. Capture each of the five views below; save into `screenshots/`:

   - `01-ioc-extraction.png` — IOC list with type badges and counts.
   - `02-osint-links.png` — per-IOC OSINT link list expanded.
   - `03-graph-view.png` — vis-network graph view.
   - `04-snippets.png` — snippets tab with a few sample snippets.
   - `05-ask-ai.png` — settings tab showing the Ask AI section (preset dropdown + URL + template textarea + Reset button).

The screenshots are committed to `screenshots/` separately (Task 8 / manual step) and are NOT included in the package zip — they're uploaded directly to the Chrome Web Store dashboard.
