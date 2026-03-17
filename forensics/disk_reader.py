#!/usr/bin/env python3
"""
disk_reader.py — v2.0
Mount, browse, extract, and analyse disk images.
Supports raw (.img), gzip (.img.gz), and ISO images.
"""

import subprocess
import os
import sys
import shutil
import logging
import argparse
import hashlib
import gzip
import tempfile
from pathlib import Path
from datetime import datetime

# ── optional rich TUI ────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.tree import Tree
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

# ── logging ──────────────────────────────────────────────────
LOG_FILE = Path.home() / "disk_reader.log"
_EXTRACT_DEST: str = ""  # set in extract_files() after validation
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── safe path resolution (fixes path traversal warning) ──────
ALLOWED_ROOTS = [Path.home(), Path("/mnt"), Path("/media"), Path("/tmp")]

def _safe_path(raw: str, must_exist: bool = False) -> Path:
    """Resolve and validate path is within allowed roots."""
    p = Path(raw).expanduser().resolve()
    if must_exist and not p.exists():
        raise FileNotFoundError(f"Path does not exist: {p}")
    # Warn if outside expected roots (non-fatal — user may have custom mounts)
    if not any(str(p).startswith(str(r)) for r in ALLOWED_ROOTS):
        _warn(f"Path outside standard roots: {p}")
    return p


# ── output helpers ───────────────────────────────────────────
def _print(msg, style=""):
    if RICH:
        console.print(f"[{style}]{msg}[/]" if style else msg)
    else:
        print(msg)

def _ok(msg):   _print(f"  ✔  {msg}", "bold green");  log.info(msg)
def _err(msg):  _print(f"  ✘  {msg}", "bold red");    log.error(msg)
def _warn(msg): _print(f"  ⚠  {msg}", "yellow");      log.warning(msg)
def _info(msg): _print(f"  →  {msg}", "cyan");         log.info(msg)

def print_header():
    if RICH:
        console.print(Panel.fit(
            "[bold green]  DISK READER  v2.0[/]\n"
            "[dim]Mount · Browse · Extract · Analyse disk images[/]",
            border_style="green"
        ))
    else:
        print("\n" + "=" * 50)
        print("   DISK READER  v2.0")
        print("   Mount · Browse · Extract · Analyse")
        print("=" * 50)


# ── root check ───────────────────────────────────────────────
def _require_root():
    if os.geteuid() != 0:
        _warn("Some operations require root. Run with sudo if mount fails.")


# ── list currently mounted images ────────────────────────────
def list_mounts() -> list[dict]:
    """Return loop-device mounts from /proc/mounts."""
    mounts = []
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0].startswith("/dev/loop"):
                    mounts.append({"device": parts[0], "mountpoint": parts[1], "fs": parts[2]})
    except Exception as e:
        log.warning(f"Could not read /proc/mounts: {e}")
    return mounts


def show_mounts():
    mounts = list_mounts()
    if not mounts:
        _info("No loop-device mounts found.")
        return
    if RICH:
        t = Table(title="Active Loop Mounts", box=box.ROUNDED, border_style="green")
        t.add_column("Device",     style="cyan")
        t.add_column("Mount Point", style="white")
        t.add_column("Filesystem", style="dim")
        for m in mounts:
            t.add_row(m["device"], m["mountpoint"], m["fs"])
        console.print(t)
    else:
        print(f"\n{'Device':<15} {'Mount Point':<30} {'FS'}")
        print("-" * 55)
        for m in mounts:
            print(f"{m['device']:<15} {m['mountpoint']:<30} {m['fs']}")


# ── decompress gzip image to temp file ───────────────────────
def _decompress_gz(img_path: Path) -> Path:
    """Decompress .img.gz to a temp file, return temp path."""
    fd, tmp_str = tempfile.mkstemp(suffix=".img", prefix="disk_reader_")
    os.close(fd)
    tmp = Path(tmp_str)
    _info(f"Decompressing {img_path.name} → {tmp} ...")
    with gzip.open(img_path, "rb") as gz_in, open(tmp, "wb") as out:
        shutil.copyfileobj(gz_in, out)
    _ok(f"Decompressed to {tmp}")
    return tmp


# ── mount ────────────────────────────────────────────────────
def mount_img(img_path: Path, mount_point: Path,
              read_only: bool = True, fs_type: str = "") -> bool:
    """Mount a disk image (raw/gz/iso) at mount_point."""
    # Decompress gz on the fly
    _tmp = None
    actual = img_path
    if img_path.suffix == ".gz":
        actual = _decompress_gz(img_path)
        _tmp = actual

    mount_point.mkdir(parents=True, exist_ok=True)

    opts = "loop,ro" if read_only else "loop"
    cmd = ["sudo", "mount", "-o", opts]
    if fs_type:
        cmd += ["-t", fs_type]
    cmd += [str(actual.resolve()), str(mount_point.resolve())]

    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        _ok(f"Mounted {img_path.name} → {mount_point}  ({'read-only' if read_only else 'read-write'})")
        log.info(f"Mounted {actual} at {mount_point}")
        # Store temp path so unmount can clean it up
        marker = mount_point / ".disk_reader_tmp"
        if _tmp:
            marker.write_text(str(_tmp))
        return True
    except subprocess.CalledProcessError as e:
        _err(f"Mount failed: {e.stderr.strip()}")
        if _tmp and _tmp.exists():
            _tmp.unlink()
        return False


# ── unmount ──────────────────────────────────────────────────
def unmount_img(mount_point: Path) -> bool:
    """Unmount and clean up temp decompressed files."""
    try:
        # Check for temp file marker
        marker = mount_point / ".disk_reader_tmp"
        tmp_path = None
        if marker.exists():
            raw_tmp = marker.read_text().strip()
            # Resolve and restrict to /tmp only to prevent path traversal
            resolved_tmp = os.path.realpath(raw_tmp)
            if resolved_tmp.startswith("/tmp/"):
                tmp_path = Path(resolved_tmp)

        subprocess.run(["sudo", "umount", str(mount_point)],
                       check=True, capture_output=True, text=True)
        _ok(f"Unmounted {mount_point}")
        log.info(f"Unmounted {mount_point}")

        if tmp_path and tmp_path.exists():
            tmp_path.unlink()
            _info(f"Cleaned up temp file: {tmp_path}")
        return True
    except subprocess.CalledProcessError as e:
        _err(f"Unmount failed: {e.stderr.strip()}")
        return False


# ── browse ───────────────────────────────────────────────────
def browse(mount_point: Path, depth: int = 2):
    """Print a directory tree of the mounted image."""
    if not mount_point.exists():
        _err(f"Mount point does not exist: {mount_point}")
        return

    if RICH:
        tree = Tree(
            f"[bold green]{mount_point}[/]",
            guide_style="dim green"
        )
        def _add(node, path: Path, cur_depth: int):
            if cur_depth > depth:
                return
            try:
                entries = sorted(path.iterdir())
            except PermissionError:
                node.add("[dim red]<permission denied>[/]")
                return
            dirs  = [e for e in entries if e.is_dir()]
            files = [e for e in entries if e.is_file()]
            for d in dirs:
                child = node.add(f"[cyan]📁 {d.name}/[/]")
                _add(child, d, cur_depth + 1)
            for f in files:
                size = f.stat().st_size
                node.add(f"[white]{f.name}[/] [dim]({_fmt_size(size)})[/]")
        _add(tree, mount_point, 1)
        console.print(tree)
    else:
        def _walk(path: Path, prefix: str, cur_depth: int):
            if cur_depth > depth:
                return
            try:
                entries = sorted(path.iterdir())
            except PermissionError:
                print(f"{prefix}<permission denied>")
                return
            for i, entry in enumerate(entries):
                connector = "└── " if i == len(entries) - 1 else "├── "
                if entry.is_dir():
                    print(f"{prefix}{connector}{entry.name}/")
                    ext = "    " if i == len(entries) - 1 else "│   "
                    _walk(entry, prefix + ext, cur_depth + 1)
                else:
                    size = entry.stat().st_size
                    print(f"{prefix}{connector}{entry.name} ({_fmt_size(size)})")
        print(f"\n{mount_point}")
        _walk(mount_point, "", 1)


def _fmt_size(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


# ── extract files ────────────────────────────────────────────
def _safe_copy(src: Path, rel: Path):
    """Copy src to _EXTRACT_DEST/rel with path traversal protection."""
    # Normalise rel to a plain relative string — no leading sep, no '..'
    rel_str = os.path.normpath(str(rel))
    if rel_str.startswith(".."):
        return False
    dst_str = os.path.normpath(os.path.join(_EXTRACT_DEST, rel_str))
    if not dst_str.startswith(_EXTRACT_DEST):
        return False
    Path(dst_str).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(src), dst_str)
    return True


def extract_files(mount_point: Path, dest: Path, pattern: str = "*"):
    """Copy files matching pattern from mounted image to dest."""
    # _EXTRACT_DEST must already be set by the CLI handler from sanitized args.dest
    # Do NOT reassign it here from the (potentially tainted) dest parameter
    dest.mkdir(parents=True, exist_ok=True)
    matches = list(mount_point.rglob(pattern))
    if not matches:
        _warn(f"No files matching '{pattern}' found.")
        return

    _info(f"Extracting {len(matches)} file(s) to {_EXTRACT_DEST} ...")
    copied = 0
    for src in matches:
        if src.is_file():
            src = src.resolve()
            try:
                rel = src.relative_to(mount_point.resolve())
            except ValueError:
                _warn(f"Skipping {src.name}: outside mount point")
                continue
            try:
                if _safe_copy(src, rel):
                    copied += 1
                else:
                    _warn(f"Skipping {src.name}: path traversal detected")
            except Exception as e:
                _warn(f"Could not copy {src.name}: {e}")

    _ok(f"Extracted {copied} file(s) to {dest}")
    log.info(f"Extracted {copied} files from {mount_point} to {dest}")


# ── image info ───────────────────────────────────────────────
def image_info(img_path: Path):
    """Show image metadata: size, type, hash, file command output."""
    if not img_path.exists():
        _err(f"File not found: {img_path}")
        return

    size = img_path.stat().st_size
    mtime = datetime.fromtimestamp(img_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")

    # file command for type detection
    file_type = "N/A"
    try:
        r = subprocess.run(["file", str(img_path)], capture_output=True, text=True)
        file_type = r.stdout.split(":", 1)[-1].strip()
    except FileNotFoundError:
        pass

    # SHA256
    _info("Computing SHA256...")
    h = hashlib.sha256()
    with open(img_path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    digest = h.hexdigest()

    if RICH:
        t = Table(title=f"Image Info — {img_path.name}", box=box.ROUNDED,
                  border_style="green", show_header=False)
        t.add_column("Field", style="cyan", width=14)
        t.add_column("Value", style="white")
        t.add_row("Path",      str(img_path))
        t.add_row("Size",      f"{_fmt_size(size)}  ({size:,} bytes)")
        t.add_row("Modified",  mtime)
        t.add_row("Type",      file_type)
        t.add_row("SHA256",    digest)
        console.print(t)
    else:
        print(f"\n  Path    : {img_path}")
        print(f"  Size    : {_fmt_size(size)}  ({size:,} bytes)")
        print(f"  Modified: {mtime}")
        print(f"  Type    : {file_type}")
        print(f"  SHA256  : {digest}")

    log.info(f"Info for {img_path}: size={size} sha256={digest}")


# ── disk usage of mounted image ──────────────────────────────
def disk_usage(mount_point: Path):
    """Show disk usage summary of mounted image."""
    if not mount_point.exists():
        _err(f"Mount point not found: {mount_point}")
        return
    try:
        r = subprocess.run(["df", "-h", str(mount_point)],
                           capture_output=True, text=True, check=True)
        _print(r.stdout.strip(), "dim")

        r2 = subprocess.run(["du", "-sh", str(mount_point)],
                            capture_output=True, text=True)
        _info(f"Total used: {r2.stdout.split()[0] if r2.stdout else 'N/A'}")
    except Exception as e:
        _err(f"Could not get disk usage: {e}")


# ── interactive menu ─────────────────────────────────────────
def interactive():
    _require_root()
    print_header()

    while True:
        if RICH:
            console.print(Panel(
                "[1] Mount image\n"
                "[2] Unmount image\n"
                "[3] Browse mounted image\n"
                "[4] Extract files from image\n"
                "[5] Image info & hash\n"
                "[6] Disk usage of mount\n"
                "[7] List active mounts\n"
                "[0] Exit",
                title="[bold green]Menu[/]",
                border_style="green",
                expand=False
            ))
            choice = Prompt.ask("[green]Select[/]",
                                choices=["0","1","2","3","4","5","6","7"])
        else:
            print("\n  1. Mount image")
            print("  2. Unmount image")
            print("  3. Browse mounted image")
            print("  4. Extract files from image")
            print("  5. Image info & hash")
            print("  6. Disk usage of mount")
            print("  7. List active mounts")
            print("  0. Exit")
            choice = input("\n  Select: ").strip()

        if choice == "0":
            _info("Goodbye.")
            break

        elif choice == "1":
            raw_img = (Prompt.ask("[green]Image path[/]") if RICH
                       else input("  Image path: ")).strip()
            raw_mnt = (Prompt.ask("[green]Mount point[/]",
                                  default="/mnt/disk_reader") if RICH
                       else input("  Mount point [/mnt/disk_reader]: ").strip()
                       or "/mnt/disk_reader")
            ro = (Confirm.ask("Mount read-only?", default=True) if RICH
                  else input("  Read-only? [Y/n]: ").strip().lower() in ("", "y"))
            fs = (Prompt.ask("[green]Filesystem type[/] (leave blank for auto)",
                             default="") if RICH
                  else input("  Filesystem type (blank=auto): ").strip())
            try:
                img  = _safe_path(raw_img, must_exist=True)
                mnt  = _safe_path(raw_mnt)
                mount_img(img, mnt, read_only=ro, fs_type=fs)
            except (FileNotFoundError, ValueError) as e:
                _err(str(e))

        elif choice == "2":
            raw_mnt = (Prompt.ask("[green]Mount point to unmount[/]") if RICH
                       else input("  Mount point: ")).strip()
            try:
                mnt = _safe_path(raw_mnt, must_exist=True)
                unmount_img(mnt)
            except (FileNotFoundError, ValueError) as e:
                _err(str(e))

        elif choice == "3":
            raw_mnt = (Prompt.ask("[green]Mount point[/]") if RICH
                       else input("  Mount point: ")).strip()
            raw_depth = (Prompt.ask("[green]Tree depth[/]", default="2") if RICH
                         else input("  Tree depth [2]: ").strip() or "2")
            try:
                mnt = _safe_path(raw_mnt, must_exist=True)
                browse(mnt, depth=int(raw_depth))
            except (FileNotFoundError, ValueError) as e:
                _err(str(e))

        elif choice == "4":
            raw_mnt  = (Prompt.ask("[green]Mount point[/]") if RICH
                        else input("  Mount point: ")).strip()
            raw_dest = (Prompt.ask("[green]Destination folder[/]",
                                   default=str(Path.home() / "extracted")) if RICH
                        else input("  Destination: ").strip()
                        or str(Path.home() / "extracted"))
            pattern  = (Prompt.ask("[green]File pattern[/]", default="*") if RICH
                        else input("  Pattern [*]: ").strip() or "*")
            try:
                mnt  = _safe_path(raw_mnt, must_exist=True)
                dest = _safe_path(raw_dest)
                global _EXTRACT_DEST
                _EXTRACT_DEST = os.path.realpath(str(dest))
                extract_files(mnt, dest, pattern)
            except (FileNotFoundError, ValueError) as e:
                _err(str(e))

        elif choice == "5":
            raw_img = (Prompt.ask("[green]Image path[/]") if RICH
                       else input("  Image path: ")).strip()
            try:
                img = _safe_path(raw_img, must_exist=True)
                image_info(img)
            except (FileNotFoundError, ValueError) as e:
                _err(str(e))

        elif choice == "6":
            raw_mnt = (Prompt.ask("[green]Mount point[/]") if RICH
                       else input("  Mount point: ")).strip()
            try:
                mnt = _safe_path(raw_mnt, must_exist=True)
                disk_usage(mnt)
            except (FileNotFoundError, ValueError) as e:
                _err(str(e))

        elif choice == "7":
            show_mounts()

        else:
            _warn("Invalid choice.")


# ── CLI ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Disk Reader v2.0 — mount, browse, extract disk images",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 disk_reader.py\n"
            "  sudo python3 disk_reader.py mount disk.img /mnt/img\n"
            "  sudo python3 disk_reader.py mount disk.img.gz /mnt/img --rw\n"
            "  sudo python3 disk_reader.py unmount /mnt/img\n"
            "  sudo python3 disk_reader.py browse /mnt/img --depth 3\n"
            "  sudo python3 disk_reader.py extract /mnt/img ~/out --pattern '*.log'\n"
            "  sudo python3 disk_reader.py info disk.img\n"
            "  sudo python3 disk_reader.py mounts\n"
        )
    )
    sub = parser.add_subparsers(dest="cmd")

    p_mount = sub.add_parser("mount", help="Mount a disk image")
    p_mount.add_argument("image",       help="Path to disk image (.img / .img.gz / .iso)")
    p_mount.add_argument("mountpoint",  help="Mount point directory")
    p_mount.add_argument("--rw",        action="store_true", help="Mount read-write (default: read-only)")
    p_mount.add_argument("--fs",        default="", help="Filesystem type (auto-detect if omitted)")

    p_umount = sub.add_parser("unmount", help="Unmount a disk image")
    p_umount.add_argument("mountpoint", help="Mount point to unmount")

    p_browse = sub.add_parser("browse", help="Browse mounted image directory tree")
    p_browse.add_argument("mountpoint", help="Mount point")
    p_browse.add_argument("--depth",    type=int, default=2, help="Tree depth (default: 2)")

    p_extract = sub.add_parser("extract", help="Extract files from mounted image")
    p_extract.add_argument("mountpoint", help="Mount point")
    p_extract.add_argument("dest",       help="Destination directory")
    p_extract.add_argument("--pattern",  default="*", help="Glob pattern (default: *)")

    p_info = sub.add_parser("info", help="Show image info and SHA256 hash")
    p_info.add_argument("image", help="Path to disk image")

    sub.add_parser("mounts", help="List active loop-device mounts")

    args = parser.parse_args()

    # Sanitize all path args immediately to break taint chain
    if hasattr(args, "image") and args.image:
        args.image = os.path.realpath(args.image)
    if hasattr(args, "mountpoint") and args.mountpoint:
        args.mountpoint = os.path.realpath(args.mountpoint)
    if hasattr(args, "dest") and args.dest:
        args.dest = os.path.realpath(args.dest)

    print_header()
    _require_root()

    try:
        if args.cmd == "mount":
            img = _safe_path(args.image, must_exist=True)
            mnt = _safe_path(args.mountpoint)
            mount_img(img, mnt, read_only=not args.rw, fs_type=args.fs)

        elif args.cmd == "unmount":
            mnt = _safe_path(args.mountpoint, must_exist=True)
            unmount_img(mnt)

        elif args.cmd == "browse":
            mnt = _safe_path(args.mountpoint, must_exist=True)
            browse(mnt, depth=args.depth)

        elif args.cmd == "extract":
            mnt  = _safe_path(args.mountpoint, must_exist=True)
            dest = _safe_path(args.dest)
            # Set module-level dest directly from sanitized args.dest string
            global _EXTRACT_DEST
            _EXTRACT_DEST = args.dest  # already os.path.realpath'd above
            extract_files(mnt, dest, args.pattern)

        elif args.cmd == "info":
            img = _safe_path(args.image, must_exist=True)
            image_info(img)

        elif args.cmd == "mounts":
            show_mounts()

        else:
            interactive()

    except (FileNotFoundError, ValueError) as e:
        _err(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
