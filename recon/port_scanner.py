#!/usr/bin/env python3
"""
port_scanner.py — v2.0
Multi-threaded TCP/UDP port scanner with service detection,
banner grabbing, rich TUI, and JSON/text output.
"""

import argparse
import json
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# ── optional rich TUI ────────────────────────────────────────
try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn, TimeElapsedColumn
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

# ── well-known ports ─────────────────────────────────────────
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 8888, 9200, 27017,
]

SERVICE_NAMES = {
    21: "FTP",    22: "SSH",     23: "Telnet",  25: "SMTP",
    53: "DNS",    80: "HTTP",   110: "POP3",   111: "RPC",
   135: "MSRPC", 139: "NetBIOS",143: "IMAP",  443: "HTTPS",
   445: "SMB",   465: "SMTPS",  587: "SMTP",  993: "IMAPS",
   995: "POP3S",1433: "MSSQL", 1521: "Oracle",2049: "NFS",
  3306: "MySQL", 3389: "RDP",  5432: "PgSQL", 5900: "VNC",
  6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
  8888: "Jupyter", 9200: "Elasticsearch", 27017: "MongoDB",
}


# ── helpers ──────────────────────────────────────────────────
def _print(msg, style=""):
    if RICH:
        console.print(f"[{style}]{msg}[/]" if style else msg)
    else:
        print(msg)

def _ok(msg):   _print(f"  ✔  {msg}", "bold green")
def _err(msg):  _print(f"  ✘  {msg}", "bold red")
def _info(msg): _print(f"  →  {msg}", "cyan")
def _warn(msg): _print(f"  ⚠  {msg}", "yellow")


def print_header():
    if RICH:
        console.print(Panel.fit(
            "[bold green]  PORT SCANNER  v2.0[/]\n"
            "[dim]TCP · UDP · Banner grab · Service detection[/]",
            border_style="green"
        ))
    else:
        print("\n" + "=" * 50)
        print("   PORT SCANNER  v2.0")
        print("   TCP · UDP · Banner grab · Service detection")
        print("=" * 50 + "\n")


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def _service(port: int) -> str:
    if port in SERVICE_NAMES:
        return SERVICE_NAMES[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return ""


def _ttl_os_hint(ip: str) -> str:
    """Ping once and guess OS from TTL."""
    try:
        import subprocess
        r = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, text=True, timeout=3
        )
        for line in r.stdout.splitlines():
            if "ttl=" in line.lower():
                ttl = int(line.lower().split("ttl=")[1].split()[0])
                if ttl <= 64:
                    return f"Linux/Unix (TTL {ttl})"
                elif ttl <= 128:
                    return f"Windows (TTL {ttl})"
                else:
                    return f"Network device (TTL {ttl})"
    except Exception:
        pass
    return "Unknown"


# ── banner grabbing ───────────────────────────────────────────
def _grab_banner(ip: str, port: int, timeout: float) -> str:
    """Try to grab a service banner."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # Send HTTP request for web ports
            if port in (80, 8080, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner on connect
            banner = s.recv(1024).decode(errors="ignore").strip()
            # Return first non-empty line
            for line in banner.splitlines():
                line = line.strip()
                if line:
                    return line[:80]
    except Exception:
        pass
    return ""


# ── TCP scan ──────────────────────────────────────────────────
def _scan_tcp(ip: str, port: int, timeout: float, grab: bool) -> dict | None:
    """Return result dict if port is open, else None."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            banner = _grab_banner(ip, port, timeout) if grab else ""
            return {
                "port":    port,
                "proto":   "TCP",
                "state":   "open",
                "service": _service(port),
                "banner":  banner,
            }
    except (ConnectionRefusedError, socket.timeout, OSError):
        return None


# ── UDP scan ──────────────────────────────────────────────────
def _scan_udp(ip: str, port: int, timeout: float) -> dict | None:
    """Best-effort UDP scan (open|filtered)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00", (ip, port))
            s.recvfrom(1024)
            return {
                "port":    port,
                "proto":   "UDP",
                "state":   "open",
                "service": _service(port),
                "banner":  "",
            }
    except socket.timeout:
        # No ICMP unreachable = possibly open|filtered
        return {
            "port":    port,
            "proto":   "UDP",
            "state":   "open|filtered",
            "service": _service(port),
            "banner":  "",
        }
    except OSError:
        return None


# ── scanner ───────────────────────────────────────────────────
def scan(ip: str, ports: list[int], threads: int, timeout: float,
         udp: bool, grab: bool) -> list[dict]:

    open_ports: list[dict] = []
    total = len(ports)
    start = time.time()

    # Cap threads sensibly — no point in more threads than ports
    workers = min(threads, total)

    def _worker(port: int) -> dict | None:
        result = _scan_tcp(ip, port, timeout, grab)
        if udp and result is None:
            result = _scan_udp(ip, port, timeout)
        return result

    if RICH:
        open_table = Table(
            box=box.SIMPLE_HEAD, border_style="green",
            header_style="bold green", show_edge=False, expand=True
        )
        open_table.add_column("Port",    width=7,  style="cyan")
        open_table.add_column("Proto",   width=6)
        open_table.add_column("State",   width=14)
        open_table.add_column("Service", width=14, style="yellow")
        open_table.add_column("Banner",  style="dim")

        with Progress(
            TextColumn("[cyan]Scanning..."),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            TextColumn("[yellow]{task.fields[speed]}/s[/]"),
            TimeElapsedColumn(),
            console=console,
            expand=True,
        ) as prog:
            task = prog.add_task("scan", total=total, speed="0")
            done = 0
            # Submit in chunks to avoid allocating 65k futures at once
            chunk_size = min(5000, total)
            port_iter = iter(ports)

            with ThreadPoolExecutor(max_workers=workers) as ex:
                # Seed initial chunk
                pending = {ex.submit(_worker, p): p
                           for p in list(_take(port_iter, chunk_size))}
                while pending:
                    for fut in as_completed(list(pending)):
                        pending.pop(fut)
                        done += 1
                        elapsed = time.time() - start
                        speed = int(done / elapsed) if elapsed else 0
                        prog.update(task, advance=1, speed=f"{speed:,}")
                        result = fut.result()
                        if result:
                            open_ports.append(result)
                            state_color = "green" if result["state"] == "open" else "yellow"
                            open_table.add_row(
                                str(result["port"]),
                                result["proto"],
                                f"[{state_color}]{result['state']}[/]",
                                result["service"],
                                result["banner"],
                            )
                        # Refill from remaining ports
                        nxt = list(_take(port_iter, 1))
                        if nxt:
                            p = nxt[0]
                            pending[ex.submit(_worker, p)] = p
                        break  # re-enter as_completed with updated pending

        console.print(Panel(open_table, title="[bold green]Open Ports[/]",
                            border_style="green"))
    else:
        print(f"\n  Scanning {total} ports on {ip}...\n")
        print(f"  {'Port':<8} {'Proto':<6} {'State':<16} {'Service':<14} Banner")
        print("  " + "-" * 70)
        done = 0
        chunk_size = min(5000, total)
        port_iter = iter(ports)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            pending = {ex.submit(_worker, p): p
                       for p in list(_take(port_iter, chunk_size))}
            while pending:
                for fut in as_completed(list(pending)):
                    pending.pop(fut)
                    done += 1
                    elapsed = time.time() - start
                    speed = int(done / elapsed) if elapsed else 0
                    print(f"\r  Progress: {done}/{total}  {speed:,}/s   ", end="", flush=True)
                    result = fut.result()
                    if result:
                        open_ports.append(result)
                        print(f"\r  {result['port']:<8} {result['proto']:<6} "
                              f"{result['state']:<16} {result['service']:<14} "
                              f"{result['banner']}")
                    nxt = list(_take(port_iter, 1))
                    if nxt:
                        p = nxt[0]
                        pending[ex.submit(_worker, p)] = p
                    break
        print()

    elapsed = time.time() - start
    open_ports.sort(key=lambda x: x["port"])
    rate = int(total / elapsed) if elapsed else 0
    _info(f"Scanned {total:,} ports in {elapsed:.1f}s  ({rate:,}/s)  —  {len(open_ports)} open")
    return open_ports


def _take(it, n: int):
    """Yield up to n items from iterator."""
    for _ in range(n):
        try:
            yield next(it)
        except StopIteration:
            break


# ── output ────────────────────────────────────────────────────
def _save(results: list[dict], target: str, ip: str, output: Path):
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.suffix == ".json":
        data = {
            "target":    target,
            "ip":        ip,
            "timestamp": datetime.now().isoformat(),
            "ports":     results,
        }
        output.write_text(json.dumps(data, indent=2))
    else:
        lines = [f"Scan: {target} ({ip})  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                 "-" * 60]
        for r in results:
            lines.append(f"{r['port']:<8} {r['proto']:<6} {r['state']:<16} "
                         f"{r['service']:<14} {r['banner']}")
        output.write_text("\n".join(lines))
    _ok(f"Saved → {output}")


# ── main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Port Scanner v2.1 — TCP/UDP scanner with banner grabbing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 port_scanner.py 192.168.1.1\n"
            "  python3 port_scanner.py 192.168.1.1 --common\n"
            "  python3 port_scanner.py 192.168.1.1 -p 1-1024\n"
            "  python3 port_scanner.py 192.168.1.1 -p all\n"
            "  python3 port_scanner.py 192.168.1.1 -p 22,80,443,8080\n"
            "  python3 port_scanner.py 192.168.1.1 -p all --threads 2000 --timeout 0.1\n"
            "  python3 port_scanner.py 192.168.1.1 --banner -o scan.json\n"
        )
    )
    parser.add_argument("target",               help="Target IP or hostname")
    parser.add_argument("-p", "--ports",        default="1-1024",
                        help="Port range (1-1024), list (22,80,443), or 'all' (1-65535)")
    parser.add_argument("--common",             action="store_true",
                        help="Scan common ports only (overrides -p)")
    parser.add_argument("--threads",            type=int, default=1000,
                        help="Thread count (default: 1000)")
    parser.add_argument("--timeout",            type=float, default=0.2,
                        help="Connection timeout in seconds (default: 0.2)")
    parser.add_argument("--udp",                action="store_true",
                        help="Also run UDP scan on same ports")
    parser.add_argument("--banner",             action="store_true",
                        help="Grab service banners from open ports")
    parser.add_argument("-o", "--output",       default="",
                        help="Save results to file (.json or .txt)")
    args = parser.parse_args()

    print_header()

    # Resolve host
    ip = _resolve(args.target)
    if not ip:
        _err(f"Could not resolve: {args.target}")
        sys.exit(1)
    if ip != args.target:
        _info(f"Resolved {args.target} → {ip}")

    # OS hint
    os_hint = _ttl_os_hint(ip)

    # Build port list
    if args.common:
        ports = COMMON_PORTS
    elif args.ports == "all":
        ports = list(range(1, 65536))
    elif "-" in args.ports:
        start_p, end_p = args.ports.split("-", 1)
        ports = list(range(int(start_p), int(end_p) + 1))
    else:
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]

    if not ports:
        _err("No valid ports specified.")
        sys.exit(1)

    if RICH:
        from rich.table import Table as T
        cfg = T(box=box.SIMPLE, show_header=False, padding=(0, 1))
        cfg.add_column(style="cyan")
        cfg.add_column(style="white")
        cfg.add_row("Target",  f"{args.target} ({ip})")
        cfg.add_row("OS hint", os_hint)
        cfg.add_row("Ports",   f"{len(ports)} ports")
        cfg.add_row("Threads", str(args.threads))
        cfg.add_row("Timeout", f"{args.timeout}s")
        cfg.add_row("UDP",     "yes" if args.udp else "no")
        cfg.add_row("Banner",  "yes" if args.banner else "no")
        console.print(cfg)
    else:
        print(f"  Target  : {args.target} ({ip})")
        print(f"  OS hint : {os_hint}")
        print(f"  Ports   : {len(ports)}")
        print(f"  Threads : {args.threads}")
        print(f"  Timeout : {args.timeout}s\n")

    results = scan(ip, ports, args.threads, args.timeout, args.udp, args.banner)

    if args.output:
        output = Path(args.output).expanduser().resolve()
        _save(results, args.target, ip, output)

    if not results:
        _warn("No open ports found.")


if __name__ == "__main__":
    main()
