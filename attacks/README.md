# attacks/

Offensive security tools for password cracking, keystroke capture, and packet analysis.

## Scripts

| Script | Description |
|--------|-------------|
| `bruteforce.py` | Brute-force and dictionary password cracker — hash cracking, configurable charsets, live progress, rich TUI |
| `keylogger.py` | Keystroke logger — timestamps, window tracking, session buffering, log rotation, rich TUI |
| `packet_sniffer.py` | Raw socket packet sniffer — IP/TCP/UDP/ICMP parsing, filters, live table, JSON output |

---

## Requirements

```bash
pip install rich pynput
```

For window tracking in keylogger:

```bash
pkg install xdotool        # Termux
apt install xdotool        # Debian/Ubuntu
```

---

## bruteforce.py

Multiprocessing brute-force and dictionary cracker. Supports plaintext comparison and hash cracking.

**Charsets:** `lower` `upper` `digits` `alpha` `alnum` `special` `all`

```bash
# brute-force plaintext
python3 bruteforce.py -t abc1 --charset alnum --max-len 4

# crack MD5 hash
python3 bruteforce.py -t 5d41402abc4b2a76b9719d911017c592 --algo md5 --charset lower --max-len 5

# dictionary attack
python3 bruteforce.py -t <hash> --algo sha256 --wordlist /path/to/rockyou.txt

# custom charset
python3 bruteforce.py -t <hash> --algo sha1 --custom-charset 'abc123!@#' --min-len 4 --max-len 8

# control workers
python3 bruteforce.py -t <hash> --algo md5 --charset alnum --max-len 6 --workers 4
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-t` | required | Target plaintext or hash |
| `--algo` | none (plaintext) | `md5` `sha1` `sha256` `sha512` |
| `--wordlist` | — | Path to wordlist file |
| `--charset` | `alnum` | Built-in charset |
| `--custom-charset` | — | Custom charset string |
| `--min-len` | `1` | Minimum password length |
| `--max-len` | `4` | Maximum password length |
| `--workers` | CPU count | Worker processes |

Log saved to `~/bruteforce.log`.

---

## keylogger.py

Captures keystrokes to a log file. Requires `pynput`.

```bash
# basic — logs to ~/keylog.txt
python3 keylogger.py

# custom output file
python3 keylogger.py -o ~/logs/keys.txt

# with timestamps on special keys
python3 keylogger.py --timestamps

# with active window tracking
python3 keylogger.py --window-tracking

# auto-stop after 60 seconds
python3 keylogger.py --timeout 60

# all options
python3 keylogger.py -o keys.txt --timestamps --window-tracking --max-size 10
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-o` | `~/keylog.txt` | Output log file |
| `--timestamps` | off | Prefix special keys with HH:MM:SS |
| `--window-tracking` | off | Log active window title on change |
| `--timeout` | 0 (unlimited) | Auto-stop after N seconds |
| `--max-size` | `5` | Max log size in MB before rotation |

Stop with `Ctrl+C`. Log rotated to `.txt.1` when size limit is reached.

---

## packet_sniffer.py

Raw socket sniffer. Requires root/sudo.

```bash
# capture all traffic
sudo python3 packet_sniffer.py

# specific interface
sudo python3 packet_sniffer.py -i eth0

# filter by protocol
sudo python3 packet_sniffer.py --proto TCP
sudo python3 packet_sniffer.py --proto UDP
sudo python3 packet_sniffer.py --proto ICMP

# filter by port
sudo python3 packet_sniffer.py --port 80

# filter by IP
sudo python3 packet_sniffer.py --ip 192.168.1.1

# capture 100 packets then stop
sudo python3 packet_sniffer.py -n 100

# show payload preview
sudo python3 packet_sniffer.py --payload

# save to file
sudo python3 packet_sniffer.py -o capture.json
sudo python3 packet_sniffer.py -o capture.txt

# combined
sudo python3 packet_sniffer.py -i eth0 --proto TCP --port 443 -n 200 -o tls.json
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-i` | all | Network interface |
| `--proto` | all | `TCP` `UDP` `ICMP` |
| `--ip` | none | Filter by src or dst IP |
| `--port` | none | Filter by port (TCP/UDP) |
| `-n` | 0 (unlimited) | Stop after N packets |
| `-o` | none | Output file (`.json` or `.txt`) |
| `--payload` | off | Show ASCII payload preview |

Stop with `Ctrl+C`.
