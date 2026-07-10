#!/usr/bin/env python3
"""Capture Chrome Web Store screenshots for SOC Analyst Toolkit.

Loads the unpacked extension in Chromium via Playwright, interacts with
the popup, and saves five 1280×800 PNGs to tools/store-assets/screenshots/.

Usage:
    python3 scripts/capture-store-screenshots.py
"""

import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCREENSHOT_DIR = REPO_ROOT / "tools" / "store-assets" / "screenshots"
SAMPLE_IOCS = (REPO_ROOT / "tools" / "store-assets" / "sample-iocs.txt").read_text().strip()

SHOTS = [
    "01-ioc-extraction.png",
    "02-osint-links.png",
    "03-graph-view.png",
    "04-snippets.png",
    "05-ask-ai.png",
]


def composite_to_1280x800(src_path: Path, dst_path: Path):
    """Center the captured popup on a 1280×800 dark canvas."""
    bg = "#0d1117"
    subprocess.run([
        "magick",
        "-size", "1280x800", f"xc:{bg}",
        str(src_path),
        "-gravity", "center",
        "-composite",
        str(dst_path),
    ], check=True, capture_output=True)


def main():
    from playwright.sync_api import sync_playwright

    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    tmp_dir = SCREENSHOT_DIR / "_tmp"
    tmp_dir.mkdir(exist_ok=True)

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir="/tmp/soc-toolkit-pw-profile5",
            headless=False,
            args=[
                f"--disable-extensions-except={REPO_ROOT}",
                f"--load-extension={REPO_ROOT}",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-background-networking",
            ],
            viewport={"width": 800, "height": 900},
            locale="en-US",
        )

        # Find extension ID
        sw_urls = []
        context.on("serviceworker", lambda sw: sw_urls.append(sw.url))
        for sw in context.service_workers:
            sw_urls.append(sw.url)

        ext_id = None
        deadline = time.time() + 15
        while time.time() < deadline:
            for url in sw_urls:
                if url.startswith("chrome-extension://"):
                    ext_id = url.split("/")[2]
                    break
            if ext_id:
                break
            for sw in context.service_workers:
                if sw.url.startswith("chrome-extension://"):
                    ext_id = sw.url.split("/")[2]
                    break
            if ext_id:
                break
            time.sleep(0.5)

        if not ext_id:
            print("ERROR: Could not find extension ID", file=sys.stderr)
            context.close()
            sys.exit(1)

        popup_url = f"chrome-extension://{ext_id}/popup.html"
        print(f"Extension ID: {ext_id}")

        page = context.new_page()
        page.goto(popup_url, wait_until="networkidle")
        page.wait_for_timeout(2000)

        dismiss_consent(page)

        def take(name):
            """Capture body element, composite onto 1280×800 canvas."""
            tmp = tmp_dir / name
            final = SCREENSHOT_DIR / name
            body = page.locator("body")
            body.screenshot(path=str(tmp))
            composite_to_1280x800(tmp, final)
            print(f"  ✓ {name}")

        # ── Screenshot 1: IOC Extraction ──
        print("📸 01-ioc-extraction.png")
        page.locator("#iocInput").fill(SAMPLE_IOCS)
        page.click("#analyzeBtn")
        page.wait_for_timeout(2000)
        page.click('.tab-btn[data-tab="ioc"]')
        page.wait_for_timeout(500)
        page.evaluate("window.scrollTo(0, 0)")
        page.wait_for_timeout(300)
        take("01-ioc-extraction.png")

        # ── Screenshot 2: OSINT Links ──
        print("📸 02-osint-links.png")
        ioc_item = page.locator(".ioc-item").first
        if ioc_item.count() > 0:
            ioc_item.click()
            page.wait_for_timeout(600)
        page.evaluate("window.scrollTo(0, 0)")
        page.wait_for_timeout(300)
        take("02-osint-links.png")

        # ── Screenshot 3: Graph View ──
        print("📸 03-graph-view.png")
        graph = page.locator("#iocGraph")
        if graph.count() > 0:
            graph.scroll_into_view_if_needed()
            page.wait_for_timeout(2500)
        take("03-graph-view.png")

        # ── Screenshot 4: Snippets ──
        print("📸 04-snippets.png")
        # Clear existing snippets
        page.evaluate("""() => {
            if (typeof chrome !== 'undefined' && chrome.storage) {
                chrome.storage.local.set({ snippets: [] });
            }
        }""")
        page.wait_for_timeout(300)
        page.reload(wait_until="networkidle")
        page.wait_for_timeout(1500)
        dismiss_consent(page)
        page.click('.tab-btn[data-tab="snippets"]')
        page.wait_for_timeout(500)
        create_sample_snippets(page)
        page.wait_for_timeout(2000)
        page.evaluate("() => { document.querySelectorAll('.notification').forEach(el => el.remove()); }")
        page.wait_for_timeout(300)
        page.evaluate("window.scrollTo(0, 0)")
        page.wait_for_timeout(300)
        take("04-snippets.png")

        # ── Screenshot 5: Ask AI Settings ──
        print("📸 05-ask-ai.png")
        page.click('.tab-btn[data-tab="settings"]')
        page.wait_for_timeout(800)
        ask_ai = page.locator("#askAiSettingsSection")
        if ask_ai.count() > 0:
            ask_ai.scroll_into_view_if_needed()
            page.wait_for_timeout(500)
        take("05-ask-ai.png")

        context.close()

    # Clean up temp files
    for f in tmp_dir.iterdir():
        f.unlink()
    tmp_dir.rmdir()

    print(f"\n✅ All screenshots saved to {SCREENSHOT_DIR}/")
    for shot in SHOTS:
        path = SCREENSHOT_DIR / shot
        if path.exists():
            print(f"  {shot} ({path.stat().st_size // 1024} KB)")
        else:
            print(f"  {shot} MISSING")


def dismiss_consent(page):
    for sel in [
        "#consentModal button.btn-primary",
        "button:has-text('Accept')",
        "button:has-text('I Understand')",
        "button:has-text('Confirm')",
        "#consentAcceptBtn",
    ]:
        el = page.locator(sel).first
        try:
            if el.count() > 0 and el.is_visible():
                el.click()
                page.wait_for_timeout(500)
                print("  dismissed consent")
                return
        except Exception:
            continue


def create_sample_snippets(page):
    snippets = [
        ("triage-template", "## Triage Notes\n- IOC: {{ioc}}\n- Source: {{source}}\n- Severity: \n- Action: "),
        ("vt-search", "https://www.virustotal.com/gui/search/{{ioc}}"),
        ("incident-header", "# Incident Report\nDate: {{date}}\nAnalyst: __\nSeverity: High"),
    ]

    for name, content in snippets:
        add_btn = page.locator("#addSnippetBtn")
        if add_btn.count() == 0 or not add_btn.is_visible():
            continue
        add_btn.click()
        page.wait_for_timeout(400)

        name_in = page.locator("#snippetNameInput")
        content_in = page.locator("#snippetContentInput")
        if name_in.count() > 0:
            name_in.fill(name)
        if content_in.count() > 0:
            content_in.fill(content)
        page.wait_for_timeout(200)

        save_btn = page.locator("#snippetSaveBtn")
        if save_btn.count() > 0:
            save_btn.click()
            page.wait_for_timeout(400)

    page.wait_for_timeout(300)


if __name__ == "__main__":
    main()
