# recon/

Reconnaissance tools for network scanning, port scanning, and web scraping.

## Scripts

| Script | Description |
|--------|-------------|
| `ip_scanner.sh` | Interactive nmap scanner — 27 scan modes, colored TUI, saves to `scan_results/` |
| `simple_ip_scanner.sh` | Same 27 nmap modes, saves to `~/nmap_scans/` |
| `ip-finder.sh` | WiFi device discovery — ARP scan + nmap ping sweep |
| `networkscanner.py` | Python nmap wrapper — 8 scan profiles, host/service/OS detection, rich table |
| `port_scanner.py` | Multi-threaded TCP/UDP port scanner — banner grabbing, 65k+ ports, rich progress |
| `web_scraper.py` | Recursive web scraper — links/images/emails, robots.txt, live table, JSON output |

---

## Requirements

```bash
pip install rich python-nmap requests beautifulsoup4

pkg install nmap arp-scan    # Termux
apt install nmap arp-scan    # Debian/Ubuntu
```

---

## ip_scanner.sh

Interactive nmap scanner with 27 scan modes. Saves results to `scan_results/` in the current directory.

```bash
bash ip_scanner.sh
```

Enter a target (IP, hostname, or CIDR), then pick a scan mode from the menu.

**Scan modes include:** normal, stealth (-sS), aggressive (-A), IPv6, ping sweep, TCP SYN/ACK ping, UDP, SCTP, ICMP, ARP, traceroute, idle/zombie, spoof MAC, service version, RPC, OS detection, bad checksum, decoy, reverse DNS, IP protocol ping, custom source port, custom DNS, OS guess, custom MTU, and custom nmap flags.

Results saved as `.txt` and `.gnmap` in `scan_results/`.

---

## simple_ip_scanner.sh

Same 27 scan modes as `ip_scanner.sh` but saves to `~/nmap_scans/`.

```bash
bash simple_ip_scanner.sh
```

---

## ip-finder.sh

Discovers devices on the local WiFi network. Auto-detects interface.

```bash
bash ip-finder.sh
```

Choose scan method:
- `1` — ARP scan (fast, layer 2, uses `arp-scan`)
- `2` — Nmap ping sweep (more detail)
- `3` — Both

Results saved to `~/wifi_scans/`.

---

## networkscanner.py

Python-based network scanner using `python-nmap`. Auto-detects local subnet if no target given.

```bash
# auto-detect local subnet
sudo python3 networkscanner.py

# specific target
sudo python3 networkscanner.py -t 192.168.1.0/24

# scan profile
sudo python3 networkscanner.py -t 192.168.1.0/24 --profile service

# custom ports
sudo python3 networkscanner.py -t 192.168.1.0/24 --profile service -p 22,80,443

# save output
sudo python3 networkscanner.py -t 192.168.1.0/24 -o results.json
sudo python3 networkscanner.py -t 192.168.1.0/24 -o results.txt
```

**Profiles:**

| Profile | Flags | Description |
|---------|-------|-------------|
| `quick` | `-sn` | Ping sweep only |
| `basic` | `-sS -T4 --open` | SYN scan (default) |
| `service` | `-sS -sV -T4 --open` | + service version detection |
| `aggressive` | `-A -T4` | OS + version + scripts + traceroute |
| `udp` | `-sU -T4 --open` | UDP scan |
| `full` | `-sS -sV -O -T4 --open` | SYN + version + OS |
| `stealth` | `-sS -T2 -f --open` | Slow + fragmented |
| `vuln` | `-sV --script=vuln -T4` | Vulnerability scripts |

Results saved to `scan_results/` by default.

---

## port_scanner.py

Multi-threaded TCP/UDP port scanner with service detection and banner grabbing.

```bash
# default: ports 1-1024
python3 port_scanner.py 192.168.1.1

# well-known ports only
python3 port_scanner.py 192.168.1.1 --common

# port range
python3 port_scanner.py 192.168.1.1 -p 1-1024

# all 65535 ports
python3 port_scanner.py 192.168.1.1 -p all

# specific ports
python3 port_scanner.py 192.168.1.1 -p 22,80,443,8080

# all ports, high performance
python3 port_scanner.py 192.168.1.1 -p all --threads 2000 --timeout 0.1

# with banner grabbing
python3 port_scanner.py 192.168.1.1 --banner

# UDP scan
python3 port_scanner.py 192.168.1.1 --udp

# save output
python3 port_scanner.py 192.168.1.1 -p all -o scan.json
python3 port_scanner.py 192.168.1.1 -p all -o scan.txt
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-p` | `1-1024` | Port range, list, or `all` |
| `--common` | off | Scan ~30 well-known ports |
| `--threads` | `1000` | Thread count |
| `--timeout` | `0.2s` | Connection timeout |
| `--udp` | off | Also run UDP scan |
| `--banner` | off | Grab service banners |
| `-o` | none | Output file (`.json` or `.txt`) |

---

## web_scraper.py

Recursive BFS web crawler. Extracts links, images, emails, and phone numbers.

```bash
# basic crawl (depth 1)
python3 web_scraper.py https://example.com

# deeper crawl
python3 web_scraper.py https://example.com --depth 3

# save results
python3 web_scraper.py https://example.com -o results.json
python3 web_scraper.py https://example.com -o results.txt

# ignore robots.txt
python3 web_scraper.py https://example.com --no-robots

# follow external links
python3 web_scraper.py https://example.com --external

# skip images
python3 web_scraper.py https://example.com --no-images

# custom delay between requests
python3 web_scraper.py https://example.com --delay 1.5
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--depth` | `1` | Crawl depth |
| `--delay` | `0.5s` | Delay between requests |
| `--timeout` | `10s` | Request timeout |
| `-o` | none | Output file (`.json` or `.txt`) |
| `--external` | off | Follow links to other domains |
| `--no-robots` | off | Ignore robots.txt |
| `--no-images` | off | Skip image extraction |
| `--no-emails` | off | Skip email/phone extraction |
