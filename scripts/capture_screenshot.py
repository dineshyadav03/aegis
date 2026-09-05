"""One-off script to capture a screenshot of the Gradio UI for the README.

Not part of the app itself — run manually, drives the already-running
Gradio server via the system's installed Edge browser (no extra browser
download needed).
"""

from pathlib import Path

from playwright.sync_api import sync_playwright

CSV_CONTENT = """timestamp,event_type,user,source_ip,status,country,bytes,message
2026-09-01T11:09:00,login,rpatel,10.0.0.101,success,US,,
2026-09-01T17:27:00,login,jsmith,198.51.100.23,fail,RU,,
2026-09-01T17:26:00,login,jsmith,198.51.100.23,fail,RU,,
2026-09-01T17:20:00,login,jsmith,198.51.100.23,fail,RU,,
2026-09-01T17:23:00,login,jsmith,198.51.100.23,fail,RU,,
2026-09-01T17:24:00,login,jsmith,198.51.100.23,fail,RU,,
2026-09-01T17:25:00,login,jsmith,198.51.100.23,fail,RU,,
2026-09-01T20:40:00,login,mchen,203.0.113.50,success,CN,,
2026-09-01T17:31:00,sudo,adoyle,10.0.0.12,success,US,,routine maintenance
2026-09-02T03:15:00,data_download,jsmith,198.51.100.23,success,RU,5000000,
"""

tmp_csv = Path(__file__).resolve().parent.parent / "data" / "_screenshot_sample.csv"
tmp_csv.write_text(CSV_CONTENT)

out_path = Path(__file__).resolve().parent.parent / "docs" / "ui_screenshot.png"
out_path.parent.mkdir(exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(channel="msedge", headless=True)
    page = browser.new_page(viewport={"width": 1440, "height": 900}, color_scheme="dark")
    page.goto("http://localhost:7860", wait_until="networkidle")

    page.set_input_files('input[type="file"]', str(tmp_csv))
    page.wait_for_timeout(1000)

    checkboxes = page.locator('input[type="checkbox"]')
    checkboxes.nth(1).check(force=True)  # Fast mode
    page.wait_for_timeout(300)

    page.get_by_role("button", name="Analyze Security Logs").click()
    # GraphRAG hits Neo4j + rate-limited Voyage AI embeddings per finding, so
    # this can take 30-60s for a handful of findings — poll for the actual
    # stat cards rather than a fixed sleep.
    page.wait_for_selector("text=Events Processed", timeout=90000)
    page.wait_for_timeout(1000)

    page.screenshot(path=str(out_path))
    browser.close()

tmp_csv.unlink(missing_ok=True)
print(f"Saved screenshot to {out_path}")
