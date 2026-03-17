#!/bin/bash

# ─────────────────────────────────────────────
#  Nmap Interactive Scanner — v2.0
# ─────────────────────────────────────────────

WHITE='\033[0;37m'
RED='\033[0;31m'
CYAN='\033[0;36m'
GREEN='\033[0;92m'
YELLOW='\033[1;33m'
NC='\033[0m'

OUTPUT_DIR="$HOME/nmap_scans"
mkdir -p "$OUTPUT_DIR"

banner() {
  clear
  echo -e "${GREEN}"
  echo "  ███╗   ██╗███╗   ███╗ █████╗ ██████╗ "
  echo "  ████╗  ██║████╗ ████║██╔══██╗██╔══██╗"
  echo "  ██╔██╗ ██║██╔████╔██║███████║██████╔╝"
  echo "  ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ "
  echo "  ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     "
  echo "  ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     "
  echo -e "${CYAN}       Interactive Network Scanner v2.0${NC}"
  echo ""
}

check_nmap() {
  if ! command -v nmap &>/dev/null; then
    echo -e "${YELLOW}nmap not found. Installing...${NC}"
    pkg install -y nmap
  fi
}

show_menu() {
  echo -e "${WHITE}Scan Modes:${NC}"
  echo -e "  ${GREEN} 1${NC}. Normal scan"
  echo -e "  ${GREEN} 2${NC}. Stealth (TCP Connect)"
  echo -e "  ${GREEN} 3${NC}. Aggressive (-A)"
  echo -e "  ${GREEN} 4${NC}. IPv6"
  echo -e "  ${GREEN} 5${NC}. Ping sweep"
  echo -e "  ${GREEN} 6${NC}. TCP SYN ping"
  echo -e "  ${GREEN} 7${NC}. TCP ACK ping"
  echo -e "  ${GREEN} 8${NC}. UDP ping"
  echo -e "  ${GREEN} 9${NC}. SCTP Init ping"
  echo -e "  ${GREEN}10${NC}. ICMP echo"
  echo -e "  ${GREEN}11${NC}. ARP scan"
  echo -e "  ${GREEN}12${NC}. Traceroute"
  echo -e "  ${GREEN}13${NC}. Idle/Zombie scan"
  echo -e "  ${GREEN}14${NC}. Spoof MAC"
  echo -e "  ${GREEN}15${NC}. Service version detection"
  echo -e "  ${GREEN}16${NC}. RPC scan"
  echo -e "  ${GREEN}17${NC}. OS detection"
  echo -e "  ${GREEN}18${NC}. Bad checksum"
  echo -e "  ${GREEN}19${NC}. Decoy scan"
  echo -e "  ${GREEN}20${NC}. Force reverse DNS"
  echo -e "  ${GREEN}21${NC}. IP protocol ping"
  echo -e "  ${GREEN}22${NC}. Custom source port"
  echo -e "  ${GREEN}23${NC}. Custom DNS servers"
  echo -e "  ${GREEN}24${NC}. System DNS lookup"
  echo -e "  ${GREEN}25${NC}. OS guess"
  echo -e "  ${GREEN}26${NC}. MTU probe"
  echo -e "  ${GREEN}27${NC}. Custom query"
  echo -e "  ${GREEN} 0${NC}. Exit"
  echo ""
}

run_scan() {
  local target="$1" mode="$2"
  local timestamp
  timestamp=$(date '+%Y%m%d_%H%M%S')
  local outfile="$OUTPUT_DIR/scan_${timestamp}.gnmap"

  echo -e "${CYAN}Target: $target${NC}"
  echo -e "${CYAN}Output: $outfile${NC}"
  echo ""

  case "$mode" in
    1)  nmap "$target" -oG "$outfile" ;;
    2)  nmap -sT "$target" -oG "$outfile" ;;
    3)  nmap -A "$target" -oG "$outfile" ;;
    4)  nmap -6 "$target" -oG "$outfile" ;;
    5)  nmap -sn "$target" -oG "$outfile" ;;
    6)  nmap -PS "$target" -oG "$outfile" ;;
    7)  nmap -PA "$target" -oG "$outfile" ;;
    8)  nmap -PU "$target" -oG "$outfile" ;;
    9)  nmap -PY "$target" -oG "$outfile" ;;
    10) nmap -PE "$target" -oG "$outfile" ;;
    11) nmap -PR "$target" -oG "$outfile" ;;
    12) nmap --traceroute "$target" -oG "$outfile" ;;
    13)
        read -rp "Enter zombie host: " zombie
        nmap -sI "$zombie" "$target" -oG "$outfile" ;;
    14)
        read -rp "Enter MAC/vendor/0 for random: " mac
        nmap --spoof-mac "$mac" "$target" -oG "$outfile" ;;
    15) nmap -sV "$target" -oG "$outfile" ;;
    16) nmap -sR "$target" -oG "$outfile" ;;
    17) nmap -O "$target" -oG "$outfile" ;;
    18) nmap --badsum "$target" -oG "$outfile" ;;
    19)
        read -rp "Enter number of decoys (RND:N): " rnd
        nmap -D "RND:$rnd" "$target" -oG "$outfile" ;;
    20) nmap -R "$target" -oG "$outfile" ;;
    21) nmap -PO "$target" -oG "$outfile" ;;
    22)
        read -rp "Enter source port: " sport
        nmap --source-port "$sport" "$target" -oG "$outfile" ;;
    23)
        read -rp "Enter DNS servers (comma-separated): " dns
        nmap --dns-servers "$dns" "$target" -oG "$outfile" ;;
    24) nmap --system-dns "$target" -oG "$outfile" ;;
    25) nmap -O --osscan-guess "$target" -oG "$outfile" ;;
    26)
        read -rp "Enter MTU value: " mtu
        nmap --mtu "$mtu" "$target" -oG "$outfile" ;;
    27)
        read -rp "Enter custom nmap flags: " flags
        # shellcheck disable=SC2086
        nmap $flags "$target" -oG "$outfile" ;;
    0)  echo -e "${GREEN}Goodbye!${NC}"; exit 0 ;;
    *)  echo -e "${RED}Invalid option.${NC}"; return ;;
  esac

  echo ""
  echo -e "${GREEN}Scan complete. Results saved to: $outfile${NC}"
  echo ""
  echo -e "${CYAN}── Results Preview ──────────────────────${NC}"
  cat "$outfile"
}

# ── Main ────────────────────────────────────────────────────
banner
check_nmap

read -rp "$(echo -e "${GREEN}Enter target IP/hostname/range: ${NC}")" target

if [ -z "$target" ]; then
  echo -e "${RED}No target provided. Exiting.${NC}"
  exit 1
fi

while true; do
  echo ""
  show_menu
  read -rp "$(echo -e "${YELLOW}Select mode [0-27]: ${NC}")" option
  run_scan "$target" "$option"

  echo ""
  read -rp "$(echo -e "${CYAN}Scan another mode on same target? [y/N]: ${NC}")" again
  [[ "$again" =~ ^[Yy]$ ]] || break
done
