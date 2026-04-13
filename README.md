# custom-scripts

A collection of Python and Bash scripts for networking, recon, attacks, forensics, and server automation.

---

## Structure

```
.
├── attacks/
│   ├── bruteforce.py
│   ├── keylogger.py
│   └── packet_sniffer.py
├── forensics/
│   ├── disk_imaging.py
│   └── disk_reader.py
├── recon/
│   ├── ip_scanner.sh
│   ├── ip-finder.sh
│   ├── networkscanner.py
│   ├── port_scanner.py
│   ├── simple_ip_scanner.sh
│   └── web_scraper.py
├── scan_results/
├── server_startup_scripts/
│   ├── .env.example
│   ├── server_status.py
│   └── setup.sh
├── settingups/
│   ├── python_modules.sh
│   └── ubuntu-setup.sh
└── wifi/
    └── connected-devices-scanner.sh
```

Each folder has its own `README.md` with detailed usage.

---

## attacks/

| Script | Description |
|--------|-------------|
| `bruteforce.py` | Brute-force and dictionary cracker — md5/sha1/sha256/sha512, configurable charsets, live progress, rich TUI |
| `keylogger.py` | Keystroke logger — timestamps, window tracking, session buffering, log rotation |
| `packet_sniffer.py` | Raw socket sniffer — IP/TCP/UDP/ICMP parsing, protocol/IP/port filters, live table, JSON output |

```bash
# crack MD5 hash
python3 attacks/bruteforce.py -t <hash> --algo md5 --charset lower --max-len 5

# dictionary attack
python3 attacks/bruteforce.py -t <hash> --algo sha256 --wordlist rockyou.txt

# keylogger with timestamps and window tracking
python3 attacks/keylogger.py --timestamps --window-tracking

# sniff TCP on port 80
sudo python3 attacks/packet_sniffer.py --proto TCP --port 80 -o capture.json
```

---

## forensics/

| Script | Description |
|--------|-------------|
| `disk_imaging.py` | Forensic disk imaging — live progress, gzip compression, SHA256/MD5/SHA1/SHA512 verification |
| `disk_reader.py` | Disk image tool — mount/unmount/browse/extract for `.img`, `.img.gz`, `.iso` |

```bash
# image a disk
sudo python3 forensics/disk_imaging.py -s /dev/sda -o backup.img --hash sha256

# mount and browse
sudo python3 forensics/disk_reader.py mount disk.img /mnt/img
sudo python3 forensics/disk_reader.py browse /mnt/img --depth 3
sudo python3 forensics/disk_reader.py extract /mnt/img ~/out --pattern '*.log'
sudo python3 forensics/disk_reader.py unmount /mnt/img
```

---

## recon/

| Script | Description |
|--------|-------------|
| `ip_scanner.sh` | Interactive nmap scanner — 27 scan modes, saves to `scan_results/` |
| `simple_ip_scanner.sh` | Same 27 modes, saves to `~/nmap_scans/` |
| `ip-finder.sh` | WiFi device discovery — ARP scan + nmap ping sweep |
| `networkscanner.py` | Python nmap wrapper — 8 profiles, host/service/OS detection, rich table |
| `port_scanner.py` | Multi-threaded TCP/UDP scanner — banner grabbing, 65k+ ports, rich progress |
| `web_scraper.py` | Recursive web crawler — links/images/emails, robots.txt, JSON output |

```bash
# interactive nmap scanner
bash recon/ip_scanner.sh

# network scan with service detection
sudo python3 recon/networkscanner.py -t 192.168.1.0/24 --profile service

# scan all ports
python3 recon/port_scanner.py 192.168.1.1 -p all --threads 2000

# web scrape with depth
python3 recon/web_scraper.py https://example.com --depth 2 -o results.json
```

**networkscanner.py profiles:** `quick` `basic` `service` `aggressive` `udp` `full` `stealth` `vuln`

---

## server_startup_scripts/

| File | Description |
|------|-------------|
| `server_status.py` | Discord webhook notifier — online/offline/warning embeds with hostname, IP, MAC |
| `.env.example` | Template for webhook URL and server config |
| `setup.sh` | Creates venv and installs dependencies |

```bash
cd server_startup_scripts
cp .env.example .env        # fill in DISCORD_WEBHOOK_URL
bash setup.sh

python3 server_status.py --status online
python3 server_status.py --status warning --message "High CPU usage"
python3 server_status.py --status offline
```

---

## settingups/

| Script | Description |
|--------|-------------|
| `python_modules.sh` | Installs Python security/ML/networking modules via pip3 |
| `ubuntu-setup.sh` | Full Ubuntu dev setup — SSH/GPG keys, Docker, ZSH, NVM, dotfiles |
| `wazuh-install.sh` | Automated Wazuh SIEM single-node installer — Indexer + Manager + Dashboard |

```bash
bash settingups/python_modules.sh
bash settingups/ubuntu-setup.sh

# Wazuh SIEM
sudo bash settingups/wazuh-install.sh              # full install
sudo bash settingups/wazuh-install.sh --status     # check services
sudo bash settingups/wazuh-install.sh --uninstall  # remove
```

---

## wifi/

| Script | Description |
|--------|-------------|
| `connected-devices-scanner.sh` | Scans local network — ARP scan on wlan0 or netdiscover on custom subnet |

```bash
bash wifi/connected-devices-scanner.sh
```

---

## Requirements

```bash
# Python deps
pip install rich requests beautifulsoup4 pynput python-nmap python-dotenv discord-webhook

# System tools (Termux)
pkg install nmap arp-scan netdiscover xdotool

# System tools (Debian/Ubuntu)
sudo apt install nmap arp-scan netdiscover xdotool

# Full Python stack
bash settingups/python_modules.sh
```

---

## scan_results/

Scan output from `ip_scanner.sh` and `networkscanner.py` is saved here automatically as timestamped `.txt` and `.gnmap` files.
