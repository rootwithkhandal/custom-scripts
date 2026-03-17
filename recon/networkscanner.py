#!/usr/bin/env python3
"""
networkscanner.py — v2.0
Network scanner using python-nmap with host discovery,
service/OS detection, rich TUI, and JSON/text output.
"""

import argparse
import json
import os
import socket
import struct
import sys
from datetime import datetime
from pathlib import Path

try:
    import nmap
except ImportError:
    print("  ✘  python-nmap not installed. Run: pip install python-nmap")
    sys.exit(1)

# ── optional rich TUI ────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

# ── scan profiles ─────────────────────────────────────────────
PROFILES = {
    "quick":      "-sn",                          # ping sweep only
    "basic":      "-sS -T4 --open",               # SYN scan, open ports
    "service":    "-sS -sV -T4 --open",           # + service versions
    "aggressive": "-A -T4",                        # OS + version + scripts + traceroute
    "udp":        "-sU -T4 --open",               # UDP scan
    "full":       "-sS -sV -O -T4 --open",        # SYN + version + OS
    "stealth":    "-sS -T2 -f --open",            # slow + fragmented
    "vuln":       "-sV --script=vuln -T4",        # vulnerability scripts
}

OUTPUT_DIR = Path("scan_results")


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
            "[bold green]  NETWORK SCANNER  v2.0[/]\n"
            "[dim]Host discovery · Services · OS · Rich TUI · JSON output[/]",
            border_style="green"
        ))
    else:
        print("\n" + "=" * 54)
        print("   NETWORK SCANNER  v2.0")
        print("   Host discovery · Services · OS · JSON output")
        print("=" * 54 + "\n")


def _local_subnet() -> str:
    """Best-effort detection of local /24 subnet."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        parts = ip.rsplit(".", 1)
        return f"{parts[0]}.0/24"
    except Exception:
        return "192.168.1.0/24"


def _fmt_ports(host_data: dict) -> str:
    """Return compact open-ports string: 22/tcp 80/tcp ..."""
    parts = []
    for proto in host_data.get("protocols", {}):
        for port, info in host_data["protocols"][proto].items():
            if info.get("state") == "open":
                parts.append(f"{port}/{proto}")
    return " ".join(sorted(parts, key=lambda x: int(x.split("/")[0]))) or "-"


# ── parse nmap result for one host ───────────────────────────
def _parse_host(nm: "nmap.PortScanner", host: str) -> dict:
    h = nm[host]
    hostname = h.hostname() or ""

    # Collect protocols / ports
    protocols: dict = {}
    for proto in h.all_protocols():
        protocols[proto] = {}
        for port in sorted(h[proto].keys()):
            info = h[proto][port]
            protocols[proto][port] = {
                "state":   info.get("state", ""),
                "name":    info.get("name", ""),
                "product": info.get("product", ""),
                "version": info.get("version", ""),
                "extrainfo": info.get("extrainfo", ""),
            }

    # OS detection
    os_name = ""
    os_accuracy = ""
    try:
        osmatch = h.get("osmatch", [])
        if osmatch:
            os_name     = osmatch[0].get("name", "")
            os_accuracy = osmatch[0].get("accuracy", "")
    except Exception:
        pass

    # MAC + vendor
    mac = vendor = ""
    try:
        addresses = h.get("addresses", {})
        mac    = addresses.get("mac", "")
        vendor = h.get("vendor", {}).get(mac, "") if mac else ""
    except Exception:
        pass

    return {
        "ip":          host,
        "hostname":    hostname,
        "state":       h.state(),
        "mac":         mac,
        "vendor":      vendor,
        "os":          os_name,
        "os_accuracy": os_accuracy,
        "protocols":   protocols,
    }


# ── build rich results table ──────────────────────────────────
def _build_table(hosts: list[dict]) -> "Table":
    t = Table(
        box=box.ROUNDED, border_style="green",
        header_style="bold green", expand=True
    )
    t.add_column("IP",       style="cyan",   width=16, no_wrap=True)
    t.add_column("Hostname", style="white",  width=22, no_wrap=True)
    t.add_column("State",    width=8,        no_wrap=True)
    t.add_column("MAC",      style="dim",    width=18, no_wrap=True)
    t.add_column("Vendor",   style="yellow", width=16, no_wrap=True)
    t.add_column("OS",       style="dim",    width=22, no_wrap=True)
    t.add_column("Open Ports", style="green", no_wrap=True)

    for h in hosts:
        state_fmt = (
            "[green]up[/]" if h["state"] == "up" else "[red]down[/]"
        ) if RICH else h["state"]
        os_str = h["os"]
        if h["os_accuracy"]:
            os_str += f" ({h['os_accuracy']}%)"
        t.add_row(
            h["ip"],
            h["hostname"] or "-",
            state_fmt,
            h["mac"] or "-",
            h["vendor"] or "-",
            os_str or "-",
            _fmt_ports(h),
        )
    return t


# ── detailed host panel ───────────────────────────────────────
def _print_host_detail(h: dict):
    if not h["protocols"]:
        return
    if RICH:
        pt = Table(box=box.SIMPLE_HEAD, border_style="dim green",
                   header_style="bold green", show_edge=False)
        pt.add_column("Port",    style="cyan",   width=8)
        pt.add_column("Proto",   width=6)
        pt.add_column("State",   width=10)
        pt.add_column("Service", style="yellow", width=14)
        pt.add_column("Version", style="dim")
        for proto, ports in h["protocols"].items():
            for port, info in ports.items():
                ver = " ".join(filter(None, [
                    info["product"], info["version"], info["extrainfo"]
                ]))
                state_col = "[green]open[/]" if info["state"] == "open" else f"[dim]{info['state']}[/]"
                pt.add_row(str(port), proto, state_col, info["name"], ver)
        console.print(Panel(
            pt,
            title=f"[cyan]{h['ip']}[/]  [dim]{h['hostname']}[/]",
            border_style="green",
        ))
    else:
        print(f"\n  {h['ip']}  {h['hostname']}")
        print(f"  {'Port':<8} {'Proto':<6} {'State':<10} {'Service':<14} Version")
        print("  " + "-" * 60)
        for proto, ports in h["protocols"].items():
            for port, info in ports.items():
                ver = " ".join(filter(None, [info["product"], info["version"]]))
                print(f"  {port:<8} {proto:<6} {info['state']:<10} {info['name']:<14} {ver}")


# ── save output ───────────────────────────────────────────────
def _save(hosts: list[dict], target: str, profile: str, output: Path):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)

    if output.suffix == ".json":
        data = {
            "target":    target,
            "profile":   profile,
            "timestamp": datetime.now().isoformat(),
            "hosts":     hosts,
        }
        output.write_text(json.dumps(data, indent=2))
    else:
        lines = [
            f"Network Scan — {target}  [{profile}]",
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 60,
        ]
        for h in hosts:
            lines.append(f"\n{h['ip']}  {h['hostname']}  [{h['state']}]")
            if h["mac"]:
                lines.append(f"  MAC   : {h['mac']}  {h['vendor']}")
            if h["os"]:
                lines.append(f"  OS    : {h['os']} ({h['os_accuracy']}%)")
            for proto, ports in h["protocols"].items():
                for port, info in ports.items():
                    ver = " ".join(filter(None, [info["product"], info["version"]]))
                    lines.append(f"  {port}/{proto:<6} {info['state']:<10} {info['name']:<14} {ver}")
        output.write_text("\n".join(lines))

    _ok(f"Saved {len(hosts)} hosts → {output}")


# ── main scan ─────────────────────────────────────────────────
def run_scan(target: str, ports: str, profile: str, output: Path | None) -> list[dict]:
    nm_args = PROFILES[profile]
    if ports:
        nm_args += f" -p {ports}"

    _info(f"Target  : {target}")
    _info(f"Profile : {profile}  ({nm_args})")
    if ports:
        _info(f"Ports   : {ports}")
    print()

    nm = nmap.PortScanner()

    if RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Scanning..."),
            TimeElapsedColumn(),
            console=console,
        ) as prog:
            prog.add_task("scan")
            try:
                nm.scan(hosts=target, arguments=nm_args)
            except nmap.PortScannerError as e:
                _err(f"Scan error: {e}")
                sys.exit(1)
    else:
        _info("Scanning... (this may take a while)")
        try:
            nm.scan(hosts=target, arguments=nm_args)
        except nmap.PortScannerError as e:
            _err(f"Scan error: {e}")
            sys.exit(1)

    hosts = [_parse_host(nm, h) for h in nm.all_hosts()]
    up    = [h for h in hosts if h["state"] == "up"]

    _ok(f"Scan complete — {len(hosts)} hosts found, {len(up)} up")
    print()

    if not hosts:
        _warn("No hosts found.")
        return hosts

    # Summary table
    if RICH:
        console.print(_build_table(hosts))
    else:
        print(f"\n  {'IP':<16} {'Hostname':<22} {'State':<8} {'OS':<24} Open Ports")
        print("  " + "-" * 90)
        for h in hosts:
            print(f"  {h['ip']:<16} {(h['hostname'] or '-'):<22} {h['state']:<8} "
                  f"{(h['os'] or '-'):<24} {_fmt_ports(h)}")

    # Per-host port detail
    print()
    for h in up:
        if h["protocols"]:
            _print_host_detail(h)

    return hosts


# ── main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Network Scanner v2.0 — host discovery, services, OS detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Profiles:\n"
            "  quick      Ping sweep only (-sn)\n"
            "  basic      SYN scan, open ports (-sS -T4)\n"
            "  service    + service version detection (-sV)\n"
            "  aggressive OS + version + scripts (-A)\n"
            "  udp        UDP scan (-sU)\n"
            "  full       SYN + version + OS (-sS -sV -O)\n"
            "  stealth    Slow + fragmented (-sS -T2 -f)\n"
            "  vuln       Vulnerability scripts (--script=vuln)\n\n"
            "Examples:\n"
            "  sudo python3 networkscanner.py\n"
            "  sudo python3 networkscanner.py -t 192.168.1.0/24\n"
            "  sudo python3 networkscanner.py -t 192.168.1.1 --profile aggressive\n"
            "  sudo python3 networkscanner.py -t 192.168.1.0/24 --profile service -p 22,80,443\n"
            "  sudo python3 networkscanner.py -t 192.168.1.0/24 -o results.json\n"
        )
    )
    parser.add_argument("-t", "--target",  default="",
                        help="Target IP, hostname, or CIDR (default: local /24 subnet)")
    parser.add_argument("--profile",       default="basic",
                        choices=list(PROFILES.keys()),
                        help="Scan profile (default: basic)")
    parser.add_argument("-p", "--ports",   default="",
                        help="Port range override, e.g. 1-1024 or 22,80,443")
    parser.add_argument("-o", "--output",  default="",
                        help="Save results to file (.json or .txt)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        _warn("Some scan types require root. Run with sudo for best results.")

    print_header()

    target = args.target or _local_subnet()
    if not args.target:
        _info(f"No target specified — using local subnet: {target}")

    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    output = (
        Path(args.output).expanduser().resolve()
        if args.output
        else OUTPUT_DIR / f"scan_{ts}.txt"
    )

    hosts = run_scan(target, args.ports, args.profile, output)

    if hosts:
        _save(hosts, target, args.profile, output)


if __name__ == "__main__":
    main()
