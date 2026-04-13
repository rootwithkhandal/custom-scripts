#!/usr/bin/env python3
"""
web_scraper.py — v2.0
Recursive web scraper with link/image/email extraction,
robots.txt support, rate limiting, and rich TUI output.
"""

import argparse
import json
import re
import sys
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup

# ── optional rich TUI ────────────────────────────────────────
try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

# ── defaults ─────────────────────────────────────────────────
DEFAULT_DELAY   = 0.5   # seconds between requests
DEFAULT_TIMEOUT = 10
DEFAULT_UA      = "Mozilla/5.0 (compatible; web_scraper/2.0)"

# ── regex patterns ────────────────────────────────────────────
RE_EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
RE_PHONE = re.compile(r"(?:\+?\d[\d\s\-().]{7,}\d)")


# ── helpers ──────────────────────────────────────────────────
def _print(msg, style=""):
    if RICH:
        console.print(f"[{style}]{msg}[/]" if style else msg)
    else:
        print(msg)

def _ok(msg):   _print(f"  ✔  {msg}", "bold green")
def _err(msg):  _print(f"  ✘  {msg}", "bold red")
def _warn(msg): _print(f"  ⚠  {msg}", "yellow")
def _info(msg): _print(f"  →  {msg}", "cyan")


def print_header():
    if RICH:
        console.print(Panel.fit(
            "[bold green]  WEB SCRAPER  v2.0[/]\n"
            "[dim]Crawl · Links · Images · Emails · robots.txt[/]",
            border_style="green"
        ))
    else:
        print("\n" + "=" * 50)
        print("   WEB SCRAPER  v2.0")
        print("   Crawl · Links · Images · Emails · robots.txt")
        print("=" * 50 + "\n")


def _same_domain(base: str, url: str) -> bool:
    return urlparse(url).netloc == urlparse(base).netloc


def _normalise(base: str, href: str) -> str | None:
    """Resolve relative URL and strip fragments."""
    if not href or href.startswith(("mailto:", "tel:", "javascript:")):
        return None
    url = urljoin(base, href).split("#")[0].rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return None
    return url


def _load_robots(base_url: str, session: requests.Session) -> RobotFileParser:
    rp = RobotFileParser()
    robots_url = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}/robots.txt"
    try:
        r = session.get(robots_url, timeout=5)
        rp.parse(r.text.splitlines())
    except Exception:
        pass
    return rp


def _fetch(url: str, session: requests.Session, timeout: int) -> BeautifulSoup | None:
    try:
        r = session.get(url, timeout=timeout)
        r.raise_for_status()
        ct = r.headers.get("Content-Type", "")
        if "html" not in ct:
            return None
        return BeautifulSoup(r.text, "html.parser")
    except requests.RequestException as e:
        _warn(f"Failed: {url}  ({e})")
        return None


# ── page data extraction ──────────────────────────────────────
def _extract(soup: BeautifulSoup, page_url: str) -> dict:
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    meta_desc = ""
    meta_tag = soup.find("meta", attrs={"name": re.compile("description", re.I)})
    if meta_tag and meta_tag.get("content"):
        meta_desc = meta_tag["content"].strip()

    text = soup.get_text(separator=" ")

    links  = []
    for a in soup.find_all("a", href=True):
        norm = _normalise(page_url, a["href"])
        if norm:
            links.append({"url": norm, "text": a.get_text(strip=True)[:80]})

    images = []
    for img in soup.find_all("img", src=True):
        src = _normalise(page_url, img["src"])
        if src:
            images.append({"src": src, "alt": img.get("alt", "")[:80]})

    emails = list(set(RE_EMAIL.findall(text)))
    phones = list(set(RE_PHONE.findall(text)))

    return {
        "url":         page_url,
        "title":       title,
        "description": meta_desc,
        "links":       links,
        "images":      images,
        "emails":      emails,
        "phones":      phones,
    }


# ── crawler ───────────────────────────────────────────────────
def crawl(start_url: str, depth: int, delay: float, timeout: int,
          stay_on_domain: bool, respect_robots: bool,
          extract_images: bool, extract_emails: bool) -> list[dict]:

    session = requests.Session()
    session.headers["User-Agent"] = DEFAULT_UA

    robots = _load_robots(start_url, session) if respect_robots else None

    visited: set[str]   = set()
    queue:   deque      = deque([(start_url, 0)])
    results: list[dict] = []

    # Live table rows for rich display
    live_rows: list[tuple] = []

    def _make_table() -> Table:
        t = Table(box=box.SIMPLE_HEAD, border_style="green",
                  header_style="bold green", show_edge=False, expand=True)
        t.add_column("Depth", width=6,  style="dim")
        t.add_column("Status", width=7)
        t.add_column("Title",  width=28, no_wrap=True)
        t.add_column("URL",    no_wrap=True, style="dim")
        for row in live_rows[-25:]:
            t.add_row(*row)
        return t

    def _process():
        while queue:
            url, cur_depth = queue.popleft()
            if url in visited or cur_depth > depth:
                continue
            visited.add(url)

            # robots.txt check
            if robots and not robots.can_fetch(DEFAULT_UA, url):
                live_rows.append((str(cur_depth), "[yellow]skip[/]", "robots.txt", url))
                continue

            soup = _fetch(url, session, timeout)
            if soup is None:
                live_rows.append((str(cur_depth), "[red]fail[/]", "-", url))
                continue

            data = _extract(soup, url)
            if not extract_images:
                data["images"] = []
            if not extract_emails:
                data["emails"] = []
                data["phones"] = []

            results.append(data)
            title = data["title"][:28] or urlparse(url).path[:28] or "/"
            live_rows.append((str(cur_depth), "[green]ok[/]", title, url))

            # Enqueue child links
            if cur_depth < depth:
                for link in data["links"]:
                    child = link["url"]
                    if child not in visited:
                        if stay_on_domain and not _same_domain(start_url, child):
                            continue
                        queue.append((child, cur_depth + 1))

            time.sleep(delay)

    if RICH:
        with Live(console=console, refresh_per_second=4) as live:
            import threading
            t = threading.Thread(target=_process, daemon=True)
            t.start()
            while t.is_alive():
                live.update(Panel(
                    _make_table(),
                    title=f"[dim]Visited: {len(visited)}  Queued: {len(queue)}[/]",
                    border_style="green",
                ))
                time.sleep(0.25)
            live.update(Panel(_make_table(), border_style="green"))
    else:
        _process()

    return results


# ── output ────────────────────────────────────────────────────
def _save(results: list[dict], output: Path):
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.suffix == ".json":
        output.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        lines = []
        for p in results:
            lines.append(f"\n{'='*60}")
            lines.append(f"URL   : {p['url']}")
            lines.append(f"Title : {p['title']}")
            if p["description"]:
                lines.append(f"Desc  : {p['description']}")
            if p["emails"]:
                lines.append(f"Emails: {', '.join(p['emails'])}")
            if p["phones"]:
                lines.append(f"Phones: {', '.join(p['phones'])}")
            lines.append(f"Links : {len(p['links'])}")
            for lnk in p["links"]:
                lines.append(f"  {lnk['url']}")
            if p["images"]:
                lines.append(f"Images: {len(p['images'])}")
                for img in p["images"]:
                    lines.append(f"  {img['src']}")
        output.write_text("\n".join(lines), encoding="utf-8")
    _ok(f"Saved {len(results)} pages → {output}")


def _show_summary(results: list[dict], output: Path | None):
    all_links  = sum(len(p["links"])  for p in results)
    all_images = sum(len(p["images"]) for p in results)
    all_emails = set(e for p in results for e in p["emails"])
    all_phones = set(ph for p in results for ph in p["phones"])

    if RICH:
        t = Table(title="Scrape Summary", box=box.ROUNDED,
                  border_style="green", show_header=False)
        t.add_column(style="cyan", width=14)
        t.add_column(style="white")
        t.add_row("Pages",   str(len(results)))
        t.add_row("Links",   str(all_links))
        t.add_row("Images",  str(all_images))
        t.add_row("Emails",  str(len(all_emails)))
        t.add_row("Phones",  str(len(all_phones)))
        if all_emails:
            t.add_row("",    "\n".join(all_emails))
        if output:
            t.add_row("Output", str(output))
        console.print(t)
    else:
        print(f"\n  Pages  : {len(results)}")
        print(f"  Links  : {all_links}")
        print(f"  Images : {all_images}")
        print(f"  Emails : {len(all_emails)}")
        if all_emails:
            for e in all_emails:
                print(f"    {e}")
        if output:
            print(f"  Output : {output}")


# ── main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Web Scraper v2.0 — recursive crawl with link/email/image extraction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 web_scraper.py https://example.com\n"
            "  python3 web_scraper.py https://example.com --depth 2 -o results.json\n"
            "  python3 web_scraper.py https://example.com --no-robots --delay 1\n"
            "  python3 web_scraper.py https://example.com --external --no-images\n"
        )
    )
    parser.add_argument("url",                        help="Start URL to scrape")
    parser.add_argument("--depth",      type=int, default=1,
                        help="Crawl depth (default: 1)")
    parser.add_argument("--delay",      type=float, default=DEFAULT_DELAY,
                        help=f"Delay between requests in seconds (default: {DEFAULT_DELAY})")
    parser.add_argument("--timeout",    type=int, default=DEFAULT_TIMEOUT,
                        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-o", "--output", default="",
                        help="Save results to file (.json or .txt)")
    parser.add_argument("--external",   action="store_true",
                        help="Follow links to external domains (default: stay on domain)")
    parser.add_argument("--no-robots",  action="store_true",
                        help="Ignore robots.txt")
    parser.add_argument("--no-images",  action="store_true",
                        help="Skip image extraction")
    parser.add_argument("--no-emails",  action="store_true",
                        help="Skip email/phone extraction")
    args = parser.parse_args()

    # Basic URL validation
    parsed = urlparse(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        _err("Invalid URL. Must start with http:// or https://")
        sys.exit(1)

    print_header()

    if RICH:
        cfg = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        cfg.add_column(style="cyan")
        cfg.add_column(style="white")
        cfg.add_row("URL",        args.url)
        cfg.add_row("Depth",      str(args.depth))
        cfg.add_row("Delay",      f"{args.delay}s")
        cfg.add_row("Domain",     "stay on domain" if not args.external else "follow external")
        cfg.add_row("robots.txt", "ignored" if args.no_robots else "respected")
        cfg.add_row("Output",     args.output or "none")
        console.print(cfg)
    else:
        print(f"  URL     : {args.url}")
        print(f"  Depth   : {args.depth}")
        print(f"  Delay   : {args.delay}s")
        print(f"  Domain  : {'external ok' if args.external else 'same domain only'}")
        print(f"  Robots  : {'ignored' if args.no_robots else 'respected'}\n")

    results = crawl(
        start_url=args.url,
        depth=args.depth,
        delay=args.delay,
        timeout=args.timeout,
        stay_on_domain=not args.external,
        respect_robots=not args.no_robots,
        extract_images=not args.no_images,
        extract_emails=not args.no_emails,
    )

    output = Path(args.output).expanduser().resolve() if args.output else None
    if output and results:
        _save(results, output)

    _show_summary(results, output)


if __name__ == "__main__":
    main()
