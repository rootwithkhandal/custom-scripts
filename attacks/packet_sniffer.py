#!/usr/bin/env python3
"""
packet_sniffer.py — v2.0
Raw socket packet sniffer with IP/TCP/UDP/ICMP parsing,
protocol filtering, live rich TUI, and JSON/text logging.
Requires root / sudo.
"""

import argparse
import json
import os
import signal
import socket
import struct
import sys
import time
from datetime import datetime
from pathlib import Path

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

# ── protocol map ─────────────────────────────────────────────
PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}
PROTO_COLORS = {"TCP": "cyan", "UDP": "green", "ICMP": "yellow", "OTHER": "dim"}

# ── stats ─────────────────────────────────────────────────────
_stats: dict = {"total": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
_stop = False
_packets: list[dict] = []   # for JSON output


# ── header parsers ────────────────────────────────────────────
def parse_ip(data: bytes) -> dict | None:
    """Parse IPv4 header (20 bytes minimum)."""
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4          # header length in bytes
    proto_num = data[9]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    total_len = struct.unpack("!H", data[2:4])[0]
    ttl = data[8]
    proto = PROTO_MAP.get(proto_num, f"OTHER({proto_num})")
    return {
        "proto_num": proto_num,
        "proto":     proto,
        "src":       src,
        "dst":       dst,
        "ttl":       ttl,
        "length":    total_len,
        "ihl":       ihl,
        "payload":   data[ihl:],
    }


def parse_tcp(data: bytes) -> dict:
    """Parse TCP header."""
    if len(data) < 20:
        return {}
    src_port, dst_port, seq, ack = struct.unpack("!HHII", data[:12])
    offset = ((data[12] >> 4) * 4)
    flags_byte = data[13]
    flags = {
        "FIN": bool(flags_byte & 0x01),
        "SYN": bool(flags_byte & 0x02),
        "RST": bool(flags_byte & 0x04),
        "PSH": bool(flags_byte & 0x08),
        "ACK": bool(flags_byte & 0x10),
        "URG": bool(flags_byte & 0x20),
    }
    flag_str = " ".join(k for k, v in flags.items() if v) or "-"
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq":      seq,
        "ack":      ack,
        "flags":    flag_str,
        "payload":  data[offset:],
    }


def parse_udp(data: bytes) -> dict:
    """Parse UDP header."""
    if len(data) < 8:
        return {}
    src_port, dst_port, length = struct.unpack("!HHH", data[:6])
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length":   length,
        "payload":  data[8:],
    }


def parse_icmp(data: bytes) -> dict:
    """Parse ICMP header."""
    if len(data) < 4:
        return {}
    icmp_type, code = data[0], data[1]
    type_map = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request",
                11: "Time Exceeded", 5: "Redirect"}
    return {
        "type":      icmp_type,
        "code":      code,
        "type_name": type_map.get(icmp_type, f"Type {icmp_type}"),
    }


def _safe_payload_preview(payload: bytes, n: int = 48) -> str:
    """Return printable ASCII preview of payload."""
    return "".join(chr(b) if 32 <= b < 127 else "." for b in payload[:n])


# ── display ───────────────────────────────────────────────────
def _make_table(rows: list[dict], limit: int = 30) -> Table:
    t = Table(
        box=box.SIMPLE_HEAD,
        border_style="green",
        header_style="bold green",
        show_edge=False,
        expand=True,
    )
    t.add_column("Time",     style="dim",    width=10, no_wrap=True)
    t.add_column("Proto",    width=6,        no_wrap=True)
    t.add_column("Src",      style="white",  width=21, no_wrap=True)
    t.add_column("Dst",      style="white",  width=21, no_wrap=True)
    t.add_column("Len",      style="dim",    width=6,  no_wrap=True)
    t.add_column("Info",     style="dim",    no_wrap=True)

    for row in rows[-limit:]:
        proto = row.get("proto", "?")
        color = PROTO_COLORS.get(proto if proto in PROTO_COLORS else "OTHER", "dim")
        src = f"{row['src']}:{row.get('src_port','')}" if row.get("src_port") else row["src"]
        dst = f"{row['dst']}:{row.get('dst_port','')}" if row.get("dst_port") else row["dst"]
        t.add_row(
            row["time"],
            f"[{color}]{proto}[/]",
            src,
            dst,
            str(row.get("length", "")),
            row.get("info", ""),
        )
    return t


def _stats_line() -> str:
    s = _stats
    return (
        f"[dim]Packets:[/] [white]{s['total']}[/]  "
        f"[cyan]TCP {s['TCP']}[/]  "
        f"[green]UDP {s['UDP']}[/]  "
        f"[yellow]ICMP {s['ICMP']}[/]  "
        f"[dim]Other {s['OTHER']}[/]"
    )


def print_header():
    if RICH:
        console.print(Panel.fit(
            "[bold green]  PACKET SNIFFER  v2.0[/]\n"
            "[dim]IP · TCP · UDP · ICMP · Filter · JSON logging[/]",
            border_style="green"
        ))
    else:
        print("\n" + "=" * 52)
        print("   PACKET SNIFFER  v2.0")
        print("   IP · TCP · UDP · ICMP · Filter · JSON logging")
        print("=" * 52 + "\n")


def _show_summary(output: Path | None):
    s = _stats
    if RICH:
        t = Table(title="Capture Summary", box=box.ROUNDED,
                  border_style="green", show_header=False)
        t.add_column(style="cyan", width=10)
        t.add_column(style="white")
        t.add_row("Total",  str(s["total"]))
        t.add_row("TCP",    str(s["TCP"]))
        t.add_row("UDP",    str(s["UDP"]))
        t.add_row("ICMP",   str(s["ICMP"]))
        t.add_row("Other",  str(s["OTHER"]))
        if output:
            t.add_row("Saved",  str(output))
        console.print(t)
    else:
        print("\n  Capture Summary")
        print(f"  Total : {s['total']}")
        print(f"  TCP   : {s['TCP']}")
        print(f"  UDP   : {s['UDP']}")
        print(f"  ICMP  : {s['ICMP']}")
        print(f"  Other : {s['OTHER']}")
        if output:
            print(f"  Saved : {output}")


# ── sniffer core ──────────────────────────────────────────────
def sniff(iface: str, filter_proto: str, filter_ip: str,
          filter_port: int, count: int, output: Path | None,
          show_payload: bool):
    global _stop

    # Bind to interface
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        if iface:
            sock.bind((iface, 0))
    except PermissionError:
        print("  ✘  Permission denied — run with sudo.")
        sys.exit(1)
    except OSError as e:
        print(f"  ✘  Socket error: {e}")
        sys.exit(1)

    rows: list[dict] = []

    def _handle_signal(sig, frame):
        global _stop
        _stop = True

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    def _capture():
        global _stop
        while not _stop:
            if count and _stats["total"] >= count:
                _stop = True
                break
            try:
                sock.settimeout(1.0)
                raw, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                break

            # AF_PACKET gives Ethernet frame — skip 14-byte Ethernet header
            ip = parse_ip(raw[14:])
            if not ip:
                continue

            proto     = ip["proto"]
            proto_key = proto if proto in ("TCP", "UDP", "ICMP") else "OTHER"

            # Protocol filter
            if filter_proto and filter_proto.upper() not in (proto, proto_key):
                continue

            # IP filter
            if filter_ip and filter_ip not in (ip["src"], ip["dst"]):
                continue

            # Parse transport layer
            info = ""
            src_port = dst_port = None
            if proto == "TCP":
                tcp = parse_tcp(ip["payload"])
                src_port = tcp.get("src_port")
                dst_port = tcp.get("dst_port")
                info = f"Flags: {tcp.get('flags','-')}"
                if show_payload and tcp.get("payload"):
                    info += f"  {_safe_payload_preview(tcp['payload'])}"
            elif proto == "UDP":
                udp = parse_udp(ip["payload"])
                src_port = udp.get("src_port")
                dst_port = udp.get("dst_port")
                if show_payload and udp.get("payload"):
                    info = _safe_payload_preview(udp["payload"])
            elif proto == "ICMP":
                icmp = parse_icmp(ip["payload"])
                info = icmp.get("type_name", "")

            # Port filter
            if filter_port and filter_port not in (src_port, dst_port):
                continue

            _stats["total"] += 1
            _stats[proto_key] += 1

            ts = datetime.now().strftime("%H:%M:%S")
            row = {
                "time":     ts,
                "proto":    proto_key,
                "src":      ip["src"],
                "dst":      ip["dst"],
                "src_port": src_port,
                "dst_port": dst_port,
                "length":   ip["length"],
                "ttl":      ip["ttl"],
                "info":     info,
            }
            rows.append(row)
            _packets.append(row)

    if RICH:
        with Live(console=console, refresh_per_second=4, screen=False) as live:
            import threading
            t = threading.Thread(target=_capture, daemon=True)
            t.start()
            while not _stop:
                live.update(
                    Panel(
                        _make_table(rows),
                        title=_stats_line(),
                        border_style="green",
                        expand=True,
                    )
                )
                time.sleep(0.25)
            t.join(timeout=2)
    else:
        print(f"  {'Time':<10} {'Proto':<6} {'Src':<22} {'Dst':<22} {'Len':<6} Info")
        print("  " + "-" * 80)
        import threading
        t = threading.Thread(target=_capture, daemon=True)
        t.start()
        while not _stop:
            if rows:
                r = rows[-1]
                src = f"{r['src']}:{r.get('src_port','')}" if r.get("src_port") else r["src"]
                dst = f"{r['dst']}:{r.get('dst_port','')}" if r.get("dst_port") else r["dst"]
                print(f"  {r['time']:<10} {r['proto']:<6} {src:<22} {dst:<22} {r['length']:<6} {r['info']}")
                rows.clear()
            time.sleep(0.1)
        t.join(timeout=2)

    sock.close()

    # Save output
    if output and _packets:
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.suffix == ".json":
            output.write_text(json.dumps(_packets, indent=2))
        else:
            lines = []
            for p in _packets:
                src = f"{p['src']}:{p['src_port']}" if p.get("src_port") else p["src"]
                dst = f"{p['dst']}:{p['dst_port']}" if p.get("dst_port") else p["dst"]
                lines.append(f"{p['time']}  {p['proto']:<6}  {src:<22}  {dst:<22}  {p['length']}  {p['info']}")
            output.write_text("\n".join(lines))
        if RICH:
            console.print(f"  [green]✔[/]  Saved {len(_packets)} packets → {output}")
        else:
            print(f"  ✔  Saved {len(_packets)} packets → {output}")


# ── main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Packet Sniffer v2.0 — IP/TCP/UDP/ICMP capture with filtering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 packet_sniffer.py\n"
            "  sudo python3 packet_sniffer.py -i eth0\n"
            "  sudo python3 packet_sniffer.py --proto TCP --port 80\n"
            "  sudo python3 packet_sniffer.py --ip 192.168.1.1 -n 100\n"
            "  sudo python3 packet_sniffer.py -o capture.json\n"
            "  sudo python3 packet_sniffer.py --proto UDP --payload\n"
        )
    )
    parser.add_argument("-i", "--iface",   default="",
                        help="Network interface (default: all)")
    parser.add_argument("--proto",         default="",
                        choices=["TCP", "UDP", "ICMP", ""],
                        help="Filter by protocol")
    parser.add_argument("--ip",            default="",
                        help="Filter by IP address (src or dst)")
    parser.add_argument("--port",          type=int, default=0,
                        help="Filter by port number (TCP/UDP)")
    parser.add_argument("-n", "--count",   type=int, default=0,
                        help="Stop after N packets (0 = unlimited)")
    parser.add_argument("-o", "--output",  default="",
                        help="Save capture to file (.txt or .json)")
    parser.add_argument("--payload",       action="store_true",
                        help="Show ASCII payload preview")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("  ✘  Run with sudo.")
        sys.exit(1)

    print_header()

    if RICH:
        from rich.table import Table as T
        cfg = T(box=box.SIMPLE, show_header=False, padding=(0, 1))
        cfg.add_column(style="cyan")
        cfg.add_column(style="white")
        cfg.add_row("Interface", args.iface or "all")
        cfg.add_row("Protocol",  args.proto or "all")
        cfg.add_row("IP filter", args.ip    or "none")
        cfg.add_row("Port",      str(args.port) if args.port else "none")
        cfg.add_row("Count",     str(args.count) if args.count else "unlimited")
        cfg.add_row("Output",    args.output or "none")
        console.print(cfg)
    else:
        print(f"  Interface : {args.iface or 'all'}")
        print(f"  Protocol  : {args.proto or 'all'}")
        print(f"  IP filter : {args.ip or 'none'}")
        print(f"  Port      : {args.port or 'none'}")
        print(f"  Count     : {args.count or 'unlimited'}")
        print(f"  Output    : {args.output or 'none'}\n")

    output = Path(args.output).expanduser().resolve() if args.output else None

    sniff(
        iface=args.iface,
        filter_proto=args.proto,
        filter_ip=args.ip,
        filter_port=args.port,
        count=args.count,
        output=output,
        show_payload=args.payload,
    )

    _show_summary(output)


if __name__ == "__main__":
    main()
