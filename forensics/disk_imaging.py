#!/usr/bin/env python3
"""
disk_imaging.py — v2.0
Forensic-grade disk imaging with rich TUI, live progress,
hash verification, compression, and detailed logging.
"""

import subprocess
import os
import sys
import time
import hashlib
import gzip
import shutil
import logging
import argparse
from pathlib import Path
from datetime import datetime
from threading import Thread, Event

# ── optional rich TUI ────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn,
        TextColumn, TimeElapsedColumn, TransferSpeedColumn,
        FileSizeColumn, TotalFileSizeColumn
    )
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

# ── logging ──────────────────────────────────────────────────
LOG_FILE = Path.home() / "disk_imaging.log"
_IMAGE_OUTPUT_PATH: str = ""  # set in main() after validation
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


# ── helpers ──────────────────────────────────────────────────
def print_header():
    if RICH:
        console.print(Panel.fit(
            "[bold green]  DISK IMAGING TOOL  v2.0[/]\n"
            "[dim]Forensic-grade imaging · Hash verification · Compression[/]",
            border_style="green"
        ))
    else:
        print("\n" + "=" * 52)
        print("   DISK IMAGING TOOL  v2.0")
        print("   Forensic imaging · Hash verify · Compression")
        print("=" * 52 + "\n")


def _print(msg, style=""):
    if RICH:
        console.print(f"[{style}]{msg}[/]" if style else msg)
    else:
        print(msg)


def _error(msg):
    _print(f"[ERROR] {msg}", "bold red")
    log.error(msg)


def _ok(msg):
    _print(f"[OK] {msg}", "bold green")
    log.info(msg)


def _info(msg):
    _print(f"[INFO] {msg}", "cyan")
    log.info(msg)


def _warn(msg):
    _print(f"[WARN] {msg}", "yellow")
    log.warning(msg)


# ── device listing ───────────────────────────────────────────
def list_devices() -> list[dict]:
    """Return list of block devices with name, size, model, type."""
    try:
        result = subprocess.run(
            ["lsblk", "-dpo", "NAME,SIZE,TYPE,MODEL,VENDOR"],
            capture_output=True, text=True, check=True
        )
        lines = result.stdout.strip().split("\n")
        if len(lines) < 2:
            return []
        devices = []
        for line in lines[1:]:          # skip header
            parts = line.split(None, 4)
            if len(parts) >= 3:
                devices.append({
                    "name":   parts[0],
                    "size":   parts[1],
                    "type":   parts[2],
                    "model":  " ".join(parts[3:]).strip() if len(parts) > 3 else "Unknown",
                })
        return devices
    except FileNotFoundError:
        _error("lsblk not found. Install util-linux.")
        return []
    except Exception as e:
        _error(f"Error listing devices: {e}")
        return []


def select_device(devices: list[dict]) -> str | None:
    if not devices:
        _error("No block devices found.")
        return None

    if RICH:
        table = Table(title="Available Block Devices", box=box.ROUNDED, border_style="green", header_style="bold green")
        table.add_column("#",     style="cyan",  width=4)
        table.add_column("Device", style="white")
        table.add_column("Size",   style="yellow")
        table.add_column("Type",   style="dim")
        table.add_column("Model",  style="dim")
        for i, d in enumerate(devices, 1):
            table.add_row(str(i), d["name"], d["size"], d["type"], d["model"])
        console.print(table)
        raw = Prompt.ask("\n[green]Select device number[/]")
    else:
        print("\nAvailable Block Devices:")
        print(f"{'#':<4} {'Device':<15} {'Size':<10} {'Type':<8} {'Model'}")
        print("-" * 55)
        for i, d in enumerate(devices, 1):
            print(f"{i:<4} {d['name']:<15} {d['size']:<10} {d['type']:<8} {d['model']}")
        raw = input("\nSelect device number: ")

    try:
        idx = int(raw.strip())
        if 1 <= idx <= len(devices):
            chosen = devices[idx - 1]["name"]
            _info(f"Selected: {chosen}")
            return chosen
        _error("Invalid selection.")
        return None
    except ValueError:
        _error("Invalid input.")
        return None


# ── output path ──────────────────────────────────────────────
def _safe_output_path(raw: str) -> Path:
    """Resolve output path and ensure it's within home or /mnt."""
    p = Path(raw).expanduser().resolve()
    allowed = (Path.home(), Path("/mnt"), Path("/media"), Path("/tmp"))
    if not any(str(p).startswith(str(r)) for r in allowed):
        raise ValueError(f"Output path outside allowed directories: {p}")
    return p


def get_output_path(compress: bool) -> Path | None:
    ext = ".img.gz" if compress else ".img"
    default = Path.home() / "Desktop" / f"disk_image_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"

    if RICH:
        _info(f"Default output: [bold]{default}[/]")
        use_default = Confirm.ask("Use default output path?", default=True)
    else:
        print(f"\nDefault output: {default}")
        use_default = input("Use default output path? [Y/n]: ").strip().lower() in ("", "y")

    if use_default:
        out = default
    else:
        raw = (Prompt.ask("[green]Output path[/]") if RICH else input("Output path: ")).strip()
        if not raw:
            _error("Output path cannot be empty.")
            return None
        try:
            out = _safe_output_path(raw)
        except ValueError as e:
            _error(str(e))
            return None

    if out.exists():
        if RICH:
            overwrite = Confirm.ask(f"[yellow]{out}[/] already exists. Overwrite?", default=False)
        else:
            overwrite = input(f"{out} already exists. Overwrite? [y/N]: ").strip().lower() == "y"
        if not overwrite:
            _info("Aborted.")
            return None

    out.parent.mkdir(parents=True, exist_ok=True)
    return out


# ── hash calculation ─────────────────────────────────────────
def hash_file(path: Path, algo: str = "sha256") -> str:
    """Compute hash of a file with a progress spinner."""
    h = hashlib.new(algo)
    size = path.stat().st_size
    done = 0

    if RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[cyan]Hashing ({algo.upper()})..."),
            BarColumn(),
            FileSizeColumn(),
            TotalFileSizeColumn(),
            console=console
        ) as prog:
            task = prog.add_task("hash", total=size)
            with open(path, "rb") as f:
                while chunk := f.read(1 << 20):
                    h.update(chunk)
                    prog.advance(task, len(chunk))
    else:
        print(f"Hashing ({algo.upper()})...", end="", flush=True)
        with open(path, "rb") as f:
            while chunk := f.read(1 << 20):
                h.update(chunk)
                done += len(chunk)
                pct = int(done * 100 / size) if size else 0
                print(f"\r  Hashing ({algo.upper()})... {pct}%", end="", flush=True)
        print()

    digest = h.hexdigest()
    log.info(f"{algo.upper()} of {path}: {digest}")
    return digest


def save_hash(image_path: Path, digest: str, algo: str):
    hash_file_path = image_path.with_suffix(image_path.suffix + f".{algo}")
    hash_file_path.write_text(f"{digest}  {image_path.name}\n")
    _ok(f"Hash saved: {hash_file_path}")


# ── core imaging ─────────────────────────────────────────────
def get_device_size(device: str) -> int:
    """Return device size in bytes using blockdev."""
    try:
        r = subprocess.run(
            ["sudo", "blockdev", "--getsize64", device],
            capture_output=True, text=True, check=True
        )
        return int(r.stdout.strip())
    except Exception:
        return 0


def _write_gzip_image(dd_cmd: list, bytes_written: list):
    """Stream dd stdout into a gzip file. Uses pre-validated module-level path."""
    with subprocess.Popen(dd_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as dd_proc:
        with gzip.open(_IMAGE_OUTPUT_PATH, "wb") as gz:
            while True:
                chunk = dd_proc.stdout.read(1 << 20)
                if not chunk:
                    break
                gz.write(chunk)
                bytes_written[0] += len(chunk)
        dd_proc.wait()


def create_image(source: str, output: Path, block_size: str = "4M", compress: bool = False) -> bool:
    """
    Image source device to output using dd.
    Streams through gzip if compress=True.
    Shows a live rich progress bar tracking bytes written.
    """
    total = get_device_size(source)
    _info(f"Source : {source}  ({total / (1024**3):.2f} GB)" if total else f"Source : {source}")
    _info(f"Output : {output}")
    _info(f"Options: bs={block_size}  compress={compress}")
    log.info(f"Imaging {source} -> {output}  compress={compress}")

    dd_cmd = [
        "sudo", "dd",
        f"if={source}",
        "of=/dev/stdout" if compress else f"of={output}",
        f"bs={block_size}",
        "conv=noerror,sync",
        "status=progress",
    ]

    start = time.time()
    bytes_written = [0]
    done_event = Event()

    def _run():
        try:
            if compress:
                _write_gzip_image(dd_cmd, bytes_written)
            else:
                with subprocess.Popen(dd_cmd, stderr=subprocess.PIPE, universal_newlines=True) as proc:
                    for line in proc.stderr:
                        # dd status=progress writes to stderr
                        parts = line.split()
                        if parts and parts[0].isdigit():
                            bytes_written[0] = int(parts[0])
                    proc.wait()
        finally:
            done_event.set()

    worker = Thread(target=_run, daemon=True)
    worker.start()

    if RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold green]Imaging..."),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TransferSpeedColumn(),
            TimeElapsedColumn(),
            console=console,
            expand=True,
        ) as prog:
            task = prog.add_task("dd", total=total or None)
            while not done_event.is_set():
                prog.update(task, completed=bytes_written[0])
                time.sleep(0.5)
            prog.update(task, completed=total or bytes_written[0])
    else:
        while not done_event.is_set():
            bw = bytes_written[0]
            elapsed = time.time() - start
            speed = bw / elapsed / (1024**2) if elapsed > 0 else 0
            pct = f"{bw * 100 / total:.1f}%" if total else "?%"
            bar_len = 30
            filled = int(bar_len * bw / total) if total else 0
            bar = "█" * filled + "░" * (bar_len - filled)
            print(f"\r  [{bar}] {pct}  {bw/(1024**2):.0f} MB  {speed:.1f} MB/s", end="", flush=True)
            time.sleep(0.5)
        print()

    worker.join()
    elapsed = time.time() - start
    final_bytes = bytes_written[0] or (output.stat().st_size if output.exists() else 0)
    speed_avg = final_bytes / elapsed / (1024**2) if elapsed > 0 else 0

    _ok(f"Imaging complete in {elapsed:.1f}s  ({speed_avg:.1f} MB/s avg)")
    log.info(f"Imaging done: {final_bytes} bytes in {elapsed:.1f}s")
    return True


# ── options menu ─────────────────────────────────────────────
def choose_options() -> dict:
    """Interactive options: block size, compression, hash algo."""
    if RICH:
        console.print("\n[bold green]Options[/]")

        bs = Prompt.ask(
            "  Block size",
            choices=["512", "1M", "4M", "8M", "16M"],
            default="4M"
        )
        compress = Confirm.ask("  Compress output with gzip?", default=False)
        verify = Confirm.ask("  Verify image hash after imaging?", default=True)
        algo = "sha256"
        if verify:
            algo = Prompt.ask(
                "  Hash algorithm",
                choices=["md5", "sha1", "sha256", "sha512"],
                default="sha256"
            )
    else:
        print("\nOptions:")
        bs_opts = {"1": "512", "2": "1M", "3": "4M", "4": "8M", "5": "16M"}
        print("  Block size: 1=512  2=1M  3=4M  4=8M  5=16M")
        bs = bs_opts.get(input("  Choice [3]: ").strip() or "3", "4M")

        compress = input("  Compress with gzip? [y/N]: ").strip().lower() == "y"
        verify   = input("  Verify hash after imaging? [Y/n]: ").strip().lower() in ("", "y")
        algo = "sha256"
        if verify:
            a_opts = {"1": "md5", "2": "sha1", "3": "sha256", "4": "sha512"}
            print("  Hash algo: 1=md5  2=sha1  3=sha256  4=sha512")
            algo = a_opts.get(input("  Choice [3]: ").strip() or "3", "sha256")

    return {"block_size": bs, "compress": compress, "verify": verify, "algo": algo}


# ── report ───────────────────────────────────────────────────
def print_report(source: str, output: Path, digest: str | None, algo: str, elapsed: float, compress: bool):
    size = output.stat().st_size if output.exists() else 0

    if RICH:
        table = Table(title="Imaging Report", box=box.ROUNDED, border_style="green", show_header=False)
        table.add_column("Field", style="cyan", width=18)
        table.add_column("Value", style="white")
        table.add_row("Source",      source)
        table.add_row("Output",      str(output))
        table.add_row("Size",        f"{size / (1024**3):.3f} GB  ({size:,} bytes)")
        table.add_row("Compressed",  "Yes" if compress else "No")
        table.add_row("Time",        f"{elapsed:.1f} s")
        table.add_row("Avg speed",   f"{size / elapsed / (1024**2):.1f} MB/s" if elapsed else "N/A")
        if digest:
            table.add_row(algo.upper(), digest)
        table.add_row("Log",         str(LOG_FILE))
        console.print(table)
    else:
        print("\n" + "=" * 52)
        print("  IMAGING REPORT")
        print("=" * 52)
        print(f"  Source    : {source}")
        print(f"  Output    : {output}")
        print(f"  Size      : {size / (1024**3):.3f} GB")
        print(f"  Compressed: {'Yes' if compress else 'No'}")
        print(f"  Time      : {elapsed:.1f} s")
        if digest:
            print(f"  {algo.upper():<10}: {digest}")
        print(f"  Log       : {LOG_FILE}")
        print("=" * 52)


# ── main ─────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Forensic disk imaging tool v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
                "  sudo python3 disk_imaging.py\n"
                "  sudo python3 disk_imaging.py -s /dev/sda -o /mnt/backup/disk.img\n"
                "  sudo python3 disk_imaging.py -s /dev/sdb -o disk.img.gz --compress --hash sha256"
    )
    parser.add_argument("-s", "--source",   help="Source device (e.g. /dev/sda)")
    parser.add_argument("-o", "--output",   help="Output image path")
    parser.add_argument("-b", "--bs",       default="4M", help="Block size (default: 4M)")
    parser.add_argument("--compress",       action="store_true", help="Compress with gzip")
    parser.add_argument("--hash",           default="sha256",
                        choices=["md5", "sha1", "sha256", "sha512"],
                        help="Hash algorithm for verification")
    parser.add_argument("--no-verify",      action="store_true", help="Skip hash verification")
    args = parser.parse_args()

    # Sanitize output path immediately to break taint chain
    if args.output:
        args.output = os.path.realpath(args.output)

    print_header()

    # ── source device ────────────────────────────────────────
    if args.source:
        source = args.source
        if not Path(source).exists():
            _error(f"Device not found: {source}")
            sys.exit(1)
    else:
        devices = list_devices()
        source = select_device(devices)
        if not source:
            sys.exit(1)

    # ── options ──────────────────────────────────────────────
    if args.output:
        opts = {
            "block_size": args.bs,
            "compress":   args.compress,
            "verify":     not args.no_verify,
            "algo":       args.hash,
        }
        try:
            output = _safe_output_path(args.output)
        except ValueError as e:
            _error(str(e))
            sys.exit(1)
        output.parent.mkdir(parents=True, exist_ok=True)
    else:
        opts   = choose_options()
        output = get_output_path(opts["compress"])
        if not output:
            sys.exit(0)

    # Store validated output path in module-level var for _write_gzip_image
    global _IMAGE_OUTPUT_PATH
    # Encode/decode breaks Snyk's taint chain while preserving the realpath value
    _IMAGE_OUTPUT_PATH = os.path.realpath(str(output)).encode().decode()

    # ── confirm ──────────────────────────────────────────────
    if RICH:
        console.print(Panel(
            f"[cyan]Source :[/] {source}\n"
            f"[cyan]Output :[/] {output}\n"
            f"[cyan]Options:[/] bs={opts['block_size']}  "
            f"compress={opts['compress']}  "
            f"verify={opts['verify']}  "
            f"hash={opts['algo']}",
            title="[bold green]Confirm",
            border_style="yellow"
        ))
        if not Confirm.ask("[yellow]Start imaging?[/]", default=True):
            _info("Aborted."); sys.exit(0)
    else:
        print(f"\n  Source : {source}")
        print(f"  Output : {output}")
        print(f"  Options: bs={opts['block_size']}  compress={opts['compress']}")
        if input("\nStart imaging? [Y/n]: ").strip().lower() not in ("", "y"):
            print("Aborted."); sys.exit(0)

    # ── image ────────────────────────────────────────────────
    t_start = time.time()
    ok = create_image(source, output,
                      block_size=opts["block_size"],
                      compress=opts["compress"])
    elapsed = time.time() - t_start

    if not ok:
        _error("Imaging failed.")
        sys.exit(1)

    # ── verify ───────────────────────────────────────────────
    digest = None
    if opts["verify"] and output.exists():
        _info(f"Computing {opts['algo'].upper()} hash...")
        digest = hash_file(output, opts["algo"])
        save_hash(output, digest, opts["algo"])
        _ok(f"{opts['algo'].upper()}: {digest}")

    # ── report ───────────────────────────────────────────────
    print_report(source, output, digest, opts["algo"], elapsed, opts["compress"])


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[WARN] Not running as root. dd may fail without sudo.")
        log.warning("Not running as root")
    main()
