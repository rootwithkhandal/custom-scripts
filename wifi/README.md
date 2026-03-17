# wifi/

WiFi device discovery tools.

## Scripts

| Script | Description |
|--------|-------------|
| `connected-devices-scanner.sh` | Scans local network for connected devices using ARP scan or netdiscover |

---

## Requirements

```bash
apt install arp-scan netdiscover nmap    # Debian/Ubuntu
pkg install arp-scan nmap               # Termux
```

The script will attempt to install missing tools automatically via `apt-get`.

---

## connected-devices-scanner.sh

Scans the local network for connected devices. Two modes available.

```bash
bash connected-devices-scanner.sh
```

**Options:**

| Option | Method | Description |
|--------|--------|-------------|
| `1` | `arp-scan --localnet` on `wlan0` | Fast ARP scan of local network |
| `2` | `netdiscover -r <ip>/24` | Scan a custom subnet |

For option 2, enter your WiFi IP address when prompted (e.g. `192.168.1.5`). The script will scan the `/24` subnet.

If neither option matches, falls back to `nmap localhost`.
