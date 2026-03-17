#!/usr/bin/env bash
# full-network-scanner.sh — v2.0
# Interactive nmap scanner with 27 scan modes, colored TUI,
# output saving, and auto-install of nmap.

set -euo pipefail

# ── colors ────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;92m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
DIM='\033[2m'
RESET='\033[0m'

# ── output dir ────────────────────────────────────────────────
OUTPUT_DIR="$(pwd)/scan_results"
mkdir -p "$OUTPUT_DIR"

# ── helpers ───────────────────────────────────────────────────
_ok()   { echo -e "${GREEN}  ✔  ${WHITE}$*${RESET}"; }
_err()  { echo -e "${RED}  ✘  $*${RESET}"; }
_info() { echo -e "${CYAN}  →  ${WHITE}$*${RESET}"; }
_warn() { echo -e "${YELLOW}  ⚠  $*${RESET}"; }

_banner() {
    clear
    echo -e "${GREEN}"
    echo "  ███████╗██╗   ██╗██╗     ██╗         ███╗   ██╗███████╗████████╗"
    echo "  ██╔════╝██║   ██║██║     ██║         ████╗  ██║██╔════╝╚══██╔══╝"
    echo "  █████╗  ██║   ██║██║     ██║         ██╔██╗ ██║█████╗     ██║   "
    echo "  ██╔══╝  ██║   ██║██║     ██║         ██║╚██╗██║██╔══╝     ██║   "
    echo "  ██║     ╚██████╔╝███████╗███████╗    ██║ ╚████║███████╗   ██║   "
    echo "  ╚═╝      ╚═════╝ ╚══════╝╚══════╝    ╚═╝  ╚═══╝╚══════╝   ╚═╝   "
    echo -e "${CYAN}              Full Network Scanner  v2.0${RESET}"
    echo ""
}

# ── nmap check / install ──────────────────────────────────────
_require_nmap() {
    if command -v nmap &>/dev/null; then return; fi
    _warn "nmap not found. Attempting install..."
    if command -v pkg &>/dev/null; then
        pkg install -y nmap
    elif command -v apt-get &>/dev/null; then
        sudo apt-get install -y nmap
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm nmap
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y nmap
    else
        _err "Cannot install nmap automatically. Please install it manually."
        exit 1
    fi
}

# ── run scan ──────────────────────────────────────────────────
_run_scan() {
    local label="$1"
    local target="$2"
    shift 2
    local nmap_args=("$@")

    local ts
    ts=$(date +"%Y%m%d_%H%M%S")
    local outfile="${OUTPUT_DIR}/scan_${ts}.gnmap"
    local outfile_normal="${OUTPUT_DIR}/scan_${ts}.txt"

    echo ""
    _info "Scan    : $label"
    _info "Target  : $target"
    _info "Args    : ${nmap_args[*]}"
    _info "Output  : $outfile_normal"
    echo ""

    sudo nmap "${nmap_args[@]}" "$target" \
        -oG "$outfile" \
        -oN "$outfile_normal" \
        && _ok "Scan complete → $outfile_normal" \
        || _err "Scan failed."

    echo ""
    _info "Results preview:"
    echo -e "${DIM}"
    grep -v "^#" "$outfile_normal" | head -40 || true
    echo -e "${RESET}"
}


# ── scan menu ─────────────────────────────────────────────────
_show_menu() {
    echo -e "${YELLOW}  Select scan mode:${RESET}"
    echo ""
    echo -e "  ${CYAN} 1${RESET}. Normal scan"
    echo -e "  ${CYAN} 2${RESET}. Stealth scan              ${DIM}(-sS)${RESET}"
    echo -e "  ${CYAN} 3${RESET}. Aggressive scan            ${DIM}(-A)${RESET}"
    echo -e "  ${CYAN} 4${RESET}. IPv6 scan                  ${DIM}(-6)${RESET}"
    echo -e "  ${CYAN} 5${RESET}. Ping scan only             ${DIM}(-sn)${RESET}"
    echo -e "  ${CYAN} 6${RESET}. TCP SYN ping               ${DIM}(-PS)${RESET}"
    echo -e "  ${CYAN} 7${RESET}. TCP ACK ping               ${DIM}(-PA)${RESET}"
    echo -e "  ${CYAN} 8${RESET}. UDP scan                   ${DIM}(-sU)${RESET}"
    echo -e "  ${CYAN} 9${RESET}. SCTP INIT ping             ${DIM}(-PY)${RESET}"
    echo -e "  ${CYAN}10${RESET}. ICMP echo ping             ${DIM}(-PE)${RESET}"
    echo -e "  ${CYAN}11${RESET}. ARP scan                   ${DIM}(-PR)${RESET}"
    echo -e "  ${CYAN}12${RESET}. Traceroute                 ${DIM}(--traceroute)${RESET}"
    echo -e "  ${CYAN}13${RESET}. Idle zombie scan           ${DIM}(-sI <zombie>)${RESET}"
    echo -e "  ${CYAN}14${RESET}. Spoof MAC address          ${DIM}(--spoof-mac)${RESET}"
    echo -e "  ${CYAN}15${RESET}. Service version detection  ${DIM}(-sV)${RESET}"
    echo -e "  ${CYAN}16${RESET}. RPC scan                   ${DIM}(-sR)${RESET}"
    echo -e "  ${CYAN}17${RESET}. OS detection               ${DIM}(-O)${RESET}"
    echo -e "  ${CYAN}18${RESET}. Bad checksum               ${DIM}(--badsum)${RESET}"
    echo -e "  ${CYAN}19${RESET}. Decoy scan                 ${DIM}(-D RND:<n>)${RESET}"
    echo -e "  ${CYAN}20${RESET}. Force reverse DNS          ${DIM}(-R)${RESET}"
    echo -e "  ${CYAN}21${RESET}. IP protocol ping           ${DIM}(-PO)${RESET}"
    echo -e "  ${CYAN}22${RESET}. Specify source port        ${DIM}(--source-port)${RESET}"
    echo -e "  ${CYAN}23${RESET}. Specify DNS servers        ${DIM}(--dns-servers)${RESET}"
    echo -e "  ${CYAN}24${RESET}. System DNS lookup          ${DIM}(--system-dns)${RESET}"
    echo -e "  ${CYAN}25${RESET}. OS scan guess              ${DIM}(-O --osscan-guess)${RESET}"
    echo -e "  ${CYAN}26${RESET}. Custom MTU                 ${DIM}(--mtu)${RESET}"
    echo -e "  ${CYAN}27${RESET}. Custom nmap query"
    echo -e "  ${RED}  0${RESET}. Exit"
    echo ""
}

# ── main ──────────────────────────────────────────────────────
_banner
_require_nmap

echo -e "${WHITE}  Enter target IP, hostname, or CIDR range:${RESET}"
read -rp "  Target: " TARGET

if [[ -z "$TARGET" ]]; then
    _err "No target specified."
    exit 1
fi

while true; do
    _banner
    _info "Target: $TARGET"
    echo ""
    _show_menu

    read -rp "  Mode: " OPTION

    case "$OPTION" in
        0)
            _info "Exiting."
            exit 0
            ;;
        1)
            _run_scan "Normal scan" "$TARGET"
            ;;
        2)
            _run_scan "Stealth scan" "$TARGET" -sS
            ;;
        3)
            _run_scan "Aggressive scan" "$TARGET" -A
            ;;
        4)
            _run_scan "IPv6 scan" "$TARGET" -6
            ;;
        5)
            _run_scan "Ping scan" "$TARGET" -sn
            ;;
        6)
            _run_scan "TCP SYN ping" "$TARGET" -PS
            ;;
        7)
            _run_scan "TCP ACK ping" "$TARGET" -PA
            ;;
        8)
            _run_scan "UDP scan" "$TARGET" -sU
            ;;
        9)
            _run_scan "SCTP INIT ping" "$TARGET" -PY
            ;;
        10)
            _run_scan "ICMP echo ping" "$TARGET" -PE
            ;;
        11)
            _run_scan "ARP scan" "$TARGET" -PR
            ;;
        12)
            _run_scan "Traceroute" "$TARGET" --traceroute
            ;;
        13)
            read -rp "  Enter zombie host: " ZOMBIE
            [[ -z "$ZOMBIE" ]] && { _err "Zombie required."; continue; }
            _run_scan "Idle zombie scan" "$TARGET" -sI "$ZOMBIE"
            ;;
        14)
            read -rp "  Enter MAC / vendor / 0 (random): " SPOOFMAC
            [[ -z "$SPOOFMAC" ]] && { _err "MAC required."; continue; }
            _run_scan "Spoof MAC scan" "$TARGET" --spoof-mac "$SPOOFMAC"
            ;;
        15)
            _run_scan "Service version detection" "$TARGET" -sV
            ;;
        16)
            _run_scan "RPC scan" "$TARGET" -sR
            ;;
        17)
            _run_scan "OS detection" "$TARGET" -O
            ;;
        18)
            _run_scan "Bad checksum" "$TARGET" --badsum
            ;;
        19)
            read -rp "  Number of decoys (e.g. 5): " RNDNUM
            [[ -z "$RNDNUM" ]] && { _err "Number required."; continue; }
            _run_scan "Decoy scan" "$TARGET" -D "RND:${RNDNUM}"
            ;;
        20)
            _run_scan "Force reverse DNS" "$TARGET" -R
            ;;
        21)
            _run_scan "IP protocol ping" "$TARGET" -PO
            ;;
        22)
            read -rp "  Enter source port: " SRCPORT
            [[ -z "$SRCPORT" ]] && { _err "Port required."; continue; }
            _run_scan "Source port scan" "$TARGET" --source-port "$SRCPORT"
            ;;
        23)
            read -rp "  Enter DNS server(s) (comma-separated): " DNSSERVERS
            [[ -z "$DNSSERVERS" ]] && { _err "DNS servers required."; continue; }
            _run_scan "Custom DNS servers" "$TARGET" --dns-servers "$DNSSERVERS"
            ;;
        24)
            _run_scan "System DNS lookup" "$TARGET" --system-dns
            ;;
        25)
            _run_scan "OS scan + guess" "$TARGET" -O --osscan-guess
            ;;
        26)
            read -rp "  Enter MTU (multiple of 8, e.g. 24): " MTUVAL
            [[ -z "$MTUVAL" ]] && { _err "MTU required."; continue; }
            _run_scan "Custom MTU" "$TARGET" --mtu "$MTUVAL"
            ;;
        27)
            read -rp "  Enter custom nmap flags: " CUSTOMQUERY
            [[ -z "$CUSTOMQUERY" ]] && { _err "Query required."; continue; }
            # shellcheck disable=SC2086
            _run_scan "Custom query" "$TARGET" $CUSTOMQUERY
            ;;
        *)
            _err "Invalid option: $OPTION"
            ;;
    esac

    echo ""
    read -rp "  Press Enter to return to menu, or Ctrl+C to exit..."
done
