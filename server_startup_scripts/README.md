# server_startup_scripts/

Discord webhook notifier for server status events, with environment-based config.

## Files

| File | Description |
|------|-------------|
| `server_status.py` | Sends online/offline/warning embeds to a Discord webhook |
| `.env.example` | Template for environment variables |
| `setup.sh` | Creates a venv and installs dependencies |

---

## Requirements

```bash
pip install discord-webhook python-dotenv
```

Or use the setup script:

```bash
bash setup.sh
```

---

## Setup

```bash
cp .env.example .env
```

Edit `.env` and fill in your values:

```env
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
SERVER_NAME=My Server
SERVER_ENV=Production
SERVER_ICON_URL=          # optional
SERVER_IP=                # optional, auto-detected if blank
SERVER_MAC=               # optional, auto-detected if blank
```

---

## server_status.py

Sends a color-coded Discord embed with hostname, IP, MAC, environment, and timestamp.

| Status | Color | Use case |
|--------|-------|----------|
| `online` | green | Server started successfully |
| `offline` | red | Server shut down or unreachable |
| `warning` | yellow | High load, disk space, etc. |

```bash
# send offline alert (default)
python3 server_status.py

# send online notification
python3 server_status.py --status online

# send warning with custom message
python3 server_status.py --status warning --message "High CPU usage"

# send offline with custom message
python3 server_status.py --status offline --message "Unexpected shutdown"
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--status` | `offline` | `online` `offline` `warning` |
| `--message` | — | Custom embed description |

---

## Automate on boot

Add to crontab or a systemd service to fire on startup:

```bash
@reboot cd /path/to/server_startup_scripts && python3 server_status.py --status online
```
