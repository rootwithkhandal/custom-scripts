#!/usr/bin/env python3
"""
server_status.py — v2.0
Send a Discord webhook embed for server status events.
Config loaded from .env file.

Usage:
  python3 server_status.py                  # default: offline alert
  python3 server_status.py --status online
  python3 server_status.py --status warning --message "High CPU usage"
  python3 server_status.py --status offline --message "Unexpected shutdown"
"""

import argparse
import os
import socket
import sys
import uuid
from datetime import datetime
from pathlib import Path

# ── load .env ────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    # Manual fallback parser if python-dotenv not installed
    env_file = Path(__file__).parent / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

from discord_webhook import DiscordWebhook, DiscordEmbed

# ── config from env ───────────────────────────────────────────
WEBHOOK_URL  = os.getenv("DISCORD_WEBHOOK_URL", "")
SERVER_NAME  = os.getenv("SERVER_NAME", "Admin Server")
SERVER_ENV   = os.getenv("SERVER_ENV", "Production")
SERVER_ICON  = os.getenv("SERVER_ICON_URL", "")

# ── status config ─────────────────────────────────────────────
STATUS_CONFIG = {
    "online": {
        "color":  "03b182",
        "title":  f"✅  {SERVER_NAME} — Online",
        "footer": "Server is up and running",
    },
    "offline": {
        "color":  "ed4245",
        "title":  f"🔴  {SERVER_NAME} — Offline",
        "footer": "Confirm the situation immediately",
    },
    "warning": {
        "color":  "fee75c",
        "title":  f"⚠️  {SERVER_NAME} — Warning",
        "footer": "Investigate as soon as possible",
    },
}


# ── system info ───────────────────────────────────────────────
def _get_ip() -> str:
    override = os.getenv("SERVER_IP", "").strip()
    if override:
        return override
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "Unknown"


def _get_mac() -> str:
    override = os.getenv("SERVER_MAC", "").strip()
    if override:
        return override
    try:
        mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
        return ":".join(mac[i:i+2] for i in range(0, 12, 2)).upper()
    except Exception:
        return "Unknown"


def _get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "Unknown"


# ── send webhook ──────────────────────────────────────────────
def send_status(status: str, message: str = "") -> bool:
    if not WEBHOOK_URL:
        print("  ✘  DISCORD_WEBHOOK_URL not set in .env")
        sys.exit(1)

    cfg      = STATUS_CONFIG.get(status, STATUS_CONFIG["offline"])
    hostname = _get_hostname()
    ip       = _get_ip()
    mac      = _get_mac()
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    webhook = DiscordWebhook(url=WEBHOOK_URL, rate_limit_retry=True)

    embed = DiscordEmbed(
        title=cfg["title"],
        description=message or cfg["footer"],
        color=cfg["color"],
    )

    if SERVER_ICON:
        embed.set_author(name=SERVER_NAME, icon_url=SERVER_ICON)
    else:
        embed.set_author(name=SERVER_NAME)

    embed.set_footer(text=cfg["footer"])
    embed.set_timestamp()

    embed.add_embed_field(name="Hostname",    value=hostname,   inline=True)
    embed.add_embed_field(name="IP Address",  value=ip,         inline=True)
    embed.add_embed_field(name="MAC Address", value=mac,        inline=True)
    embed.add_embed_field(name="Environment", value=SERVER_ENV, inline=True)
    embed.add_embed_field(name="Status",      value=status.capitalize(), inline=True)
    embed.add_embed_field(name="Timestamp",   value=ts,         inline=True)

    webhook.add_embed(embed)
    response = webhook.execute()

    if response.status_code in (200, 204):
        print(f"  ✔  Status '{status}' sent to Discord")
        return True
    else:
        print(f"  ✘  Webhook failed: HTTP {response.status_code}")
        return False


# ── main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="server_status.py v2.0 — send server status to Discord",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 server_status.py\n"
            "  python3 server_status.py --status online\n"
            "  python3 server_status.py --status warning --message 'High CPU usage'\n"
            "  python3 server_status.py --status offline --message 'Unexpected shutdown'\n"
        )
    )
    parser.add_argument(
        "--status", default="offline",
        choices=["online", "offline", "warning"],
        help="Status to report (default: offline)"
    )
    parser.add_argument(
        "--message", default="",
        help="Optional custom message for the embed description"
    )
    args = parser.parse_args()
    send_status(args.status, args.message)


if __name__ == "__main__":
    main()
