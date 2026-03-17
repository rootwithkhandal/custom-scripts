#!/bin/bash

# ─────────────────────────────────────────────
#  WiFi Network Scanner — v2.0
#  Scans local network for connected devices
# ─────────────────────────────────────────────

WHITE='\033[0;37m'
RED='\033[0;31m'
CYAN='\033[0;36m'
GREEN='\033[0;92m'
YELLOW='\033[1;33m'
NC='\033[0m'

OUTPUT_DIR="$HOME/wifi_scans"
mkdir -p "$OUTPUT_DIR"

banner() {
  clear
  echo -e "${GREEN}"
  echo "  ╔══════════════════════════════════════╗"
  echo "  ║      WiFi Network Scanner  v2.0      ║"
  echo "  ║   Discover devices on your network   ║"
  echo "  ╚══════════════════════════════════════╝"
  echo -e "${NC}"
}

check_deps() {
  local missing=()
  for dep in arp-scan nmap ip; do
    command -v "$dep" &>/dev/null || missing+=("$dep")
  done
  if [ ${#missing[@]} -gt 0 ]; then
    echo -e "${YELLOW}Installing missing tools: ${missing[*]}${NC}"
    pkg install -y "${missing[@]}"
  fi
}

detect_interface() {
  # Try wlan0 first, then fall back to any active interface
  if ip link show wlan0 &>/dev/null; then
    echo "wlan0"
  else
    ip -o link show up | awk -F': ' '{print $2}' | grep -v lo | head -1
  fi
}

show_network_info() {
  local iface="$1"
  echo -e "${CYAN}Interface : ${WHITE}$iface${NC}"
  local ip_addr
  ip_addr=$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{print $2}')
  echo -e "${CYAN}IP/CIDR   : ${WHITE}${ip_addr:-N/A}${NC}"
  local gateway
  gateway=$(ip route | awk '/default/{print $3}' | head -1)
  echo -e "${CYAN}Gateway   : ${WHITE}${gateway:-N/A}${NC}"
  echo ""
}

arp_scan() {
  local iface="$1"
  local timestamp
  timestamp=$(date '+%Y%m%d_%H%M%S')
  local outfile="$OUTPUT_DIR/wifi_scan_$timestamp.txt"

  echo -e "${GREEN}Running ARP scan on $iface...${NC}"
  echo ""

  arp-scan --interface="$iface" --localnet 2>/dev/null | tee "$outfile"

  local count
  count=$(grep -cE '([0-9a-f]{2}:){5}[0-9a-f]{2}' "$outfile" 2>/dev/null || echo 0)
  echo ""
  echo -e "${GREEN}Devices found: $count${NC}"
  echo -e "${CYAN}Results saved: $outfile${NC}"
}

nmap_scan() {
  local iface="$1"
  local subnet
  subnet=$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{print $2}')

  if [ -z "$subnet" ]; then
    echo -e "${RED}Could not determine subnet for $iface.${NC}"
    return
  fi

  local timestamp
  timestamp=$(date '+%Y%m%d_%H%M%S')
  local outfile="$OUTPUT_DIR/nmap_scan_$timestamp.txt"

  echo -e "${GREEN}Running Nmap ping sweep on $subnet...${NC}"
  nmap -sn "$subnet" -oN "$outfile" 2>/dev/null
  cat "$outfile"
  echo -e "${CYAN}Results saved: $outfile${NC}"
}

# ── Main ────────────────────────────────────────────────────
banner
check_deps

IFACE=$(detect_interface)
echo -e "${CYAN}Detected interface: ${WHITE}$IFACE${NC}"
read -rp "$(echo -e "${YELLOW}Use this interface? [Y/n] or enter custom: ${NC}")" iface_input

if [[ -n "$iface_input" && "$iface_input" != "y" && "$iface_input" != "Y" ]]; then
  IFACE="$iface_input"
fi

echo ""
show_network_info "$IFACE"

echo -e "${WHITE}Scan method:${NC}"
echo -e "  ${GREEN}1${NC}. ARP scan (fast, layer 2)"
echo -e "  ${GREEN}2${NC}. Nmap ping sweep (detailed)"
echo -e "  ${GREEN}3${NC}. Both"
echo ""
read -rp "$(echo -e "${YELLOW}Select [1-3]: ${NC}")" method

case "$method" in
  1) arp_scan "$IFACE" ;;
  2) nmap_scan "$IFACE" ;;
  3) arp_scan "$IFACE"; echo ""; nmap_scan "$IFACE" ;;
  *) echo -e "${RED}Invalid option.${NC}"; exit 1 ;;
esac
