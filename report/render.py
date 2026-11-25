"""Рендер иллюстраций отчёта в PNG через Playwright (Edge):
  * term <txt> <png> [title] — вывод консоли в виде окна терминала;
  * html <html> <png>         — произвольная HTML-схема;
  * url <url> <png> [w h full] — снимок веб-страницы.
"""
import html
import sys

from playwright.sync_api import sync_playwright

TERM = """<!doctype html><meta charset="utf-8"><style>
body{margin:0;background:#fff;font-family:Consolas,'Cascadia Mono',monospace}
.win{display:inline-block;min-width:900px;max-width:1500px;border-radius:8px;overflow:hidden;
     box-shadow:0 2px 10px rgba(0,0,0,.35);margin:10px}
.bar{background:#3c3c3c;color:#ddd;font:13px Segoe UI,sans-serif;padding:7px 12px}
.bar i{display:inline-block;width:11px;height:11px;border-radius:50%;margin-right:6px;vertical-align:-1px}
pre{margin:0;background:#1e1e1e;color:#d4d4d4;padding:12px 16px;font-size:14px;line-height:1.35;white-space:pre-wrap}
.r{color:#f48771}.g{color:#89d185}.y{color:#e5c07b}.c{color:#61afef}
</style><div class="win"><div class="bar"><i style="background:#ff5f56"></i><i style="background:#ffbd2e"></i>
<i style="background:#27c93f"></i>&nbsp; TITLE</div><pre>BODY</pre></div>"""


def colorize(line: str) -> str:
    e = html.escape(line)
    low = line.lower()
    if any(k in line for k in ("FAIL", "FAILED", "CRITICAL", "HIGH ", "│ HIGH", "Error", "ERROR")) or "leaks found" in low:
        return f'<span class="r">{e}</span>'
    if any(k in line for k in ("PASS", "passed", "No known vulnerabilities", "no leaks found", " OK", "(OK)")):
        return f'<span class="g">{e}</span>'
    if line.startswith(("$", "#", "===", "root@")):
        return f'<span class="c">{e}</span>'
    if "MEDIUM" in line or "WARN" in line or "Medium" in line:
        return f'<span class="y">{e}</span>'
    return e


def shoot(page_html=None, url=None, out=None, w=1200, h=600, full=True):
    with sync_playwright() as p:
        b = p.chromium.launch(channel="msedge")
        pg = b.new_page(viewport={"width": w, "height": h}, device_scale_factor=2)
        if url:
            pg.goto(url, wait_until="load", timeout=60000)
            pg.wait_for_timeout(3000)
            pg.wait_for_timeout(1000)
            pg.screenshot(path=out, full_page=full)
        else:
            pg.set_content(page_html)
            pg.wait_for_timeout(300)
            el = pg.query_selector(".win") or pg.query_selector("body > *")
            el.screenshot(path=out)
        b.close()


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "term":
        src, out = sys.argv[2], sys.argv[3]
        title = sys.argv[4] if len(sys.argv) > 4 else "bash"
        text = open(src, encoding="utf-8", errors="replace").read().rstrip("\n")
        body = "\n".join(colorize(l) for l in text.split("\n"))
        shoot(TERM.replace("TITLE", html.escape(title)).replace("BODY", body), out=out, w=1600)
    elif mode == "html":
        shoot(open(sys.argv[2], encoding="utf-8").read(), out=sys.argv[3], w=1600)
    elif mode == "url":
        w = int(sys.argv[4]) if len(sys.argv) > 4 else 1400
        h = int(sys.argv[5]) if len(sys.argv) > 5 else 900
        full = len(sys.argv) > 6 and sys.argv[6] == "full"
        shoot(url=sys.argv[2], out=sys.argv[3], w=w, h=h, full=full)
