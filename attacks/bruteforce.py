#!/usr/bin/env python3
"""
bruteforce.py — v2.0
Multiprocessing brute-force / dictionary password cracker.
Supports plaintext comparison and hash cracking (md5/sha1/sha256/sha512).
"""

import argparse
import hashlib
import itertools
import logging
import os
import sys
import time
from multiprocessing import Pool, cpu_count, Manager
from pathlib import Path

# ── optional rich TUI ────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich.text import Text
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

# ── logging ──────────────────────────────────────────────────
LOG_FILE = Path.home() / "bruteforce.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── charsets ─────────────────────────────────────────────────
CHARSETS = {
    "lower":   "abcdefghijklmnopqrstuvwxyz",
    "upper":   "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "digits":  "0123456789",
    "special": "!@#$%^&*()-_=+[]{}|;:',.<>?/`~",
    "alpha":   "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alnum":   "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "all":     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~",
}

# ── helpers ──────────────────────────────────────────────────
def _print(msg, style=""):
    if RICH:
        console.print(f"[{style}]{msg}[/]" if style else msg)
    else:
        print(msg)

def _ok(msg):   _print(f"  ✔  {msg}", "bold green");  log.info(msg)
def _err(msg):  _print(f"  ✘  {msg}", "bold red");    log.error(msg)
def _info(msg): _print(f"  →  {msg}", "cyan");         log.info(msg)

def print_header():
    if RICH:
        console.print(Panel.fit(
            "[bold green]  BRUTEFORCE  v2.0[/]\n"
            "[dim]Brute-force · Dictionary · Hash cracking[/]",
            border_style="green"
        ))
    else:
        print("\n" + "=" * 48)
        print("   BRUTEFORCE  v2.0")
        print("   Brute-force · Dictionary · Hash cracking")
        print("=" * 48 + "\n")


def _hash(text: str, algo: str) -> str:
    return hashlib.new(algo, text.encode()).hexdigest()


def _fmt_num(n: int) -> str:
    """Format large numbers with K/M/B suffix."""
    if n >= 1_000_000_000:
        return f"{n/1_000_000_000:.1f}B"
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}K"
    return str(n)


# ── worker (module-level for multiprocessing pickling) ───────
# These globals are set in each worker process via initializer
_TARGET   = None
_ALGO     = None   # None = plaintext compare

def _init_worker(target, algo):
    global _TARGET, _ALGO
    _TARGET = target
    _ALGO   = algo

def _check(attempt_tuple):
    """Return the attempt string if it matches, else None."""
    attempt = "".join(attempt_tuple) if isinstance(attempt_tuple, tuple) else attempt_tuple
    candidate = _hash(attempt, _ALGO) if _ALGO else attempt
    return attempt if candidate == _TARGET else None


# ── brute-force attack ───────────────────────────────────────
def brute_force(target: str, algo: str | None, charset: str,
                min_len: int, max_len: int, workers: int) -> str | None:
    """Iterate all combinations from min_len to max_len."""
    total = sum(len(charset) ** l for l in range(min_len, max_len + 1))
    _info(f"Charset size : {len(charset)}")
    _info(f"Length range : {min_len}–{max_len}")
    _info(f"Total combos : {_fmt_num(total)}")
    _info(f"Workers      : {workers}")

    start    = time.time()
    checked  = 0
    found    = None
    chunk    = 5000

    def _gen():
        for length in range(min_len, max_len + 1):
            yield from itertools.product(charset, repeat=length)

    with Pool(workers, initializer=_init_worker, initargs=(target, algo)) as pool:
        try:
            if RICH:
                with Live(console=console, refresh_per_second=8) as live:
                    for result in pool.imap_unordered(_check, _gen(), chunksize=chunk):
                        checked += 1
                        if result:
                            found = result
                            pool.terminate()
                            break
                        if checked % (chunk * workers) == 0:
                            elapsed = time.time() - start
                            speed   = checked / elapsed if elapsed else 0
                            pct     = checked * 100 / total if total else 0
                            bar_len = 28
                            filled  = int(bar_len * pct / 100)
                            bar     = "█" * filled + "░" * (bar_len - filled)
                            live.update(
                                Text.from_markup(
                                    f"  [green][{bar}][/] [cyan]{pct:.1f}%[/]  "
                                    f"[white]{_fmt_num(checked)}/{_fmt_num(total)}[/]  "
                                    f"[yellow]{_fmt_num(int(speed))}/s[/]  "
                                    f"[dim]{elapsed:.0f}s[/]"
                                )
                            )
            else:
                for result in pool.imap_unordered(_check, _gen(), chunksize=chunk):
                    checked += 1
                    if result:
                        found = result
                        pool.terminate()
                        break
                    if checked % (chunk * workers) == 0:
                        elapsed = time.time() - start
                        speed   = checked / elapsed if elapsed else 0
                        pct     = checked * 100 / total if total else 0
                        bar_len = 28
                        filled  = int(bar_len * pct / 100)
                        bar     = "█" * filled + "░" * (bar_len - filled)
                        print(f"\r  [{bar}] {pct:.1f}%  "
                              f"{_fmt_num(checked)}/{_fmt_num(total)}  "
                              f"{_fmt_num(int(speed))}/s  {elapsed:.0f}s",
                              end="", flush=True)
        except KeyboardInterrupt:
            pool.terminate()
            _err("Interrupted by user.")
            return None

    if not RICH:
        print()

    elapsed = time.time() - start
    _info(f"Checked {_fmt_num(checked)} in {elapsed:.1f}s  "
          f"({_fmt_num(int(checked/elapsed if elapsed else 0))}/s avg)")
    return found


# ── dictionary attack ────────────────────────────────────────
def dictionary_attack(target: str, algo: str | None,
                      wordlist: Path, workers: int) -> str | None:
    """Try every word in a wordlist file."""
    if not wordlist.exists():
        _err(f"Wordlist not found: {wordlist}")
        return None

    words = wordlist.read_text(errors="ignore").splitlines()
    total = len(words)
    _info(f"Wordlist : {wordlist}  ({_fmt_num(total)} words)")
    _info(f"Workers  : {workers}")

    start   = time.time()
    checked = 0
    found   = None
    chunk   = 1000

    with Pool(workers, initializer=_init_worker, initargs=(target, algo)) as pool:
        try:
            if RICH:
                with Live(console=console, refresh_per_second=8) as live:
                    for result in pool.imap_unordered(_check, words, chunksize=chunk):
                        checked += 1
                        if result:
                            found = result
                            pool.terminate()
                            break
                        if checked % (chunk * 2) == 0:
                            elapsed = time.time() - start
                            speed   = checked / elapsed if elapsed else 0
                            pct     = checked * 100 / total
                            bar_len = 28
                            filled  = int(bar_len * pct / 100)
                            bar     = "█" * filled + "░" * (bar_len - filled)
                            live.update(
                                Text.from_markup(
                                    f"  [green][{bar}][/] [cyan]{pct:.1f}%[/]  "
                                    f"[white]{_fmt_num(checked)}/{_fmt_num(total)}[/]  "
                                    f"[yellow]{_fmt_num(int(speed))}/s[/]  "
                                    f"[dim]{elapsed:.0f}s[/]"
                                )
                            )
            else:
                for result in pool.imap_unordered(_check, words, chunksize=chunk):
                    checked += 1
                    if result:
                        found = result
                        pool.terminate()
                        break
                    if checked % (chunk * 2) == 0:
                        elapsed = time.time() - start
                        speed   = checked / elapsed if elapsed else 0
                        pct     = checked * 100 / total
                        bar_len = 28
                        filled  = int(bar_len * pct / 100)
                        bar     = "█" * filled + "░" * (bar_len - filled)
                        print(f"\r  [{bar}] {pct:.1f}%  "
                              f"{_fmt_num(checked)}/{_fmt_num(total)}  "
                              f"{_fmt_num(int(speed))}/s  {elapsed:.0f}s",
                              end="", flush=True)
        except KeyboardInterrupt:
            pool.terminate()
            _err("Interrupted by user.")
            return None

    if not RICH:
        print()

    elapsed = time.time() - start
    _info(f"Checked {_fmt_num(checked)} in {elapsed:.1f}s")
    return found


# ── result display ───────────────────────────────────────────
def show_result(found: str | None, target: str, algo: str | None, elapsed: float):
    if found:
        log.info(f"FOUND: '{found}' for target '{target}'")
        if RICH:
            console.print(Panel(
                f"[bold green]PASSWORD FOUND[/]\n\n"
                f"[cyan]Password :[/] [bold white]{found}[/]\n"
                f"[cyan]Target   :[/] {target}\n"
                f"[cyan]Algorithm:[/] {algo or 'plaintext'}\n"
                f"[cyan]Time     :[/] {elapsed:.1f}s",
                border_style="green", expand=False
            ))
        else:
            print("\n" + "=" * 40)
            print(f"  PASSWORD FOUND: {found}")
            print(f"  Target  : {target}")
            print(f"  Algo    : {algo or 'plaintext'}")
            print(f"  Time    : {elapsed:.1f}s")
            print("=" * 40)
    else:
        log.info(f"NOT FOUND for target '{target}'")
        if RICH:
            console.print(Panel(
                "[bold red]PASSWORD NOT FOUND[/]\n"
                f"[dim]Target: {target}[/]",
                border_style="red", expand=False
            ))
        else:
            print("\n  ✘  Password not found.")


# ── main ─────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Bruteforce v2.0 — brute-force and dictionary password cracker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # brute-force plaintext\n"
            "  python3 bruteforce.py -t abc1 --charset digits --max-len 4\n\n"
            "  # crack an MD5 hash\n"
            "  python3 bruteforce.py -t 5d41402abc4b2a76b9719d911017c592 --algo md5 --charset lower --max-len 5\n\n"
            "  # dictionary attack on SHA256 hash\n"
            "  python3 bruteforce.py -t <hash> --algo sha256 --wordlist /usr/share/wordlists/rockyou.txt\n\n"
            "  # custom charset\n"
            "  python3 bruteforce.py -t secret --custom-charset 'abcdefghijklmnopqrstuvwxyz0123456789' --max-len 6\n"
        )
    )

    parser.add_argument("-t", "--target",   required=True,
                        help="Target password (plaintext) or hash to crack")
    parser.add_argument("--algo",           default=None,
                        choices=["md5", "sha1", "sha256", "sha512"],
                        help="Hash algorithm (omit for plaintext comparison)")
    parser.add_argument("--wordlist",       help="Path to wordlist file (dictionary attack)")
    parser.add_argument("--charset",        default="alnum",
                        choices=list(CHARSETS.keys()),
                        help="Built-in charset for brute-force (default: alnum)")
    parser.add_argument("--custom-charset", help="Custom charset string (overrides --charset)")
    parser.add_argument("--min-len",        type=int, default=1,
                        help="Minimum password length (default: 1)")
    parser.add_argument("--max-len",        type=int, default=4,
                        help="Maximum password length (default: 4)")
    parser.add_argument("--workers",        type=int, default=cpu_count(),
                        help=f"Worker processes (default: {cpu_count()})")

    args = parser.parse_args()

    # Sanitize file path args immediately to break taint chain
    if args.wordlist:
        args.wordlist = os.path.realpath(args.wordlist)

    print_header()

    target  = args.target
    algo    = args.algo
    workers = max(1, args.workers)

    # Show config summary
    if RICH:
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        t.add_column(style="cyan")
        t.add_column(style="white")
        t.add_row("Target",    target)
        t.add_row("Algorithm", algo or "plaintext")
        t.add_row("Mode",      "dictionary" if args.wordlist else "brute-force")
        t.add_row("Workers",   str(workers))
        console.print(t)
    else:
        print(f"  Target    : {target}")
        print(f"  Algorithm : {algo or 'plaintext'}")
        print(f"  Mode      : {'dictionary' if args.wordlist else 'brute-force'}")
        print(f"  Workers   : {workers}\n")

    start = time.time()

    if args.wordlist:
        wordlist_path = Path(args.wordlist).expanduser().resolve()
        if not wordlist_path.is_file():
            _err(f"Wordlist not found: {wordlist_path}")
            sys.exit(1)
        found = dictionary_attack(target, algo, wordlist_path, workers)
    else:
        charset = args.custom_charset or CHARSETS[args.charset]
        if not charset:
            _err("Charset is empty.")
            sys.exit(1)
        if args.min_len < 1 or args.max_len < args.min_len:
            _err("Invalid length range.")
            sys.exit(1)
        found = brute_force(target, algo, charset, args.min_len, args.max_len, workers)

    elapsed = time.time() - start
    show_result(found, target, algo, elapsed)
    _info(f"Log: {LOG_FILE}")


if __name__ == "__main__":
    main()
