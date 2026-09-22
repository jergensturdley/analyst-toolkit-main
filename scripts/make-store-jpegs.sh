#!/usr/bin/env bash
# Convert screenshots/take.js captures into Chrome Web Store JPEGs
# (1280x800): scale to 800 high, pad onto the popup's background color.
set -euo pipefail
cd "$(dirname "$0")/.."
i=1
for f in \
  screenshots/01-initial-empty.png \
  screenshots/02-ioc-parsing.png \
  screenshots/03-enrichment.png \
  screenshots/04-graph.png \
  screenshots/05-settings-top.png \
  screenshots/06-settings-mid.png; do
  ffmpeg -y -v error -i "$f" \
    -vf "scale=-2:800:flags=lanczos,pad=1280:800:(ow-iw)/2:(oh-ih)/2:color=#0d1117" \
    -q:v 2 "screenshots/store/screenshot-$i.jpg"
  i=$((i+1))
done
echo "wrote screenshots/store/screenshot-1..6.jpg"
