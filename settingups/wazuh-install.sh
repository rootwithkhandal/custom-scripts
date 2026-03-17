#!/usr/bin/env bash
# wazuh-install.sh — v1.0
# Automated Wazuh SIEM single-node installation
# Installs: Wazuh Indexer + Wazuh Server (Manager + Filebeat) + Wazuh Dashboard
#
# Supported: Ubuntu 20.04/22.04/24.04, Debian 10/11/12, CentOS/RHEL 7/8/9
# Requires : x86_64 or aarch64, root, internet access
#
# Usage:
#   sudo bash wazuh-install.sh              # full install
#   sudo bash wazuh-install.sh --uninstall  # remove everything
#   sudo bash wazuh-install.sh --status     # check service status

set -euo pipefail

# ── config ────────────────────────────────────────────────────
WAZUH_VERSION="4.14"
INSTALL_SCRIPT_URL="https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"
PASSWORDS_TOOL_URL="https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-passwords-tool.sh"
WORK_DIR="/tmp/wazuh-setup"

# ── colors ────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;92m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
DIM='\033[2m'
RESET='\033[0m'

# ── helpers ───────────────────────────────────────────────────
_ok()   { echo -e "${GREEN}  ✔  ${WHITE}$*${RESET}"; }
_err()  { echo -e "${RED}  ✘  $*${RESET}"; exit 1; }
_info() { echo -e "${CYAN}  →  ${WHITE}$*${RESET}"; }
_warn() { echo -e "${YELLOW}  ⚠  $*${RESET}"; }
_step() { echo -e "\n${GREEN}━━━  ${WHITE}$*${RESET}\n"; }

_banner() {
    clear
    echo -e "${GREEN}"
    echo "  ██╗    ██╗ █████╗ ███████╗██╗   ██╗██╗  ██╗"
    echo "  ██║    ██║██╔══██╗╚════██║██║   ██║██║  ██║"
    echo "  ██║ █╗ ██║███████║    ██╔╝██║   ██║███████║"
    echo "  ██║███╗██║██╔══██║   ██╔╝ ██║   ██║██╔══██║"
    echo "  ╚███╔███╔╝██║  ██║   ██║  ╚██████╔╝██║  ██║"
    echo "   ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝"
    echo -e "${CYAN}         SIEM Auto-Installer  v1.0${RESET}"
    echo -e "${DIM}         Wazuh ${WAZUH_VERSION} — Single Node${RESET}"
    echo ""
}

# ── root check ────────────────────────────────────────────────
_require_root() {
    if [[ $EUID -ne 0 ]]; then
        _err "Run as root: sudo bash $0"
    fi
}

# ── OS detection ──────────────────────────────────────────────
_detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-0}"
        OS_NAME="${PRETTY_NAME:-unknown}"
    else
        _err "Cannot detect OS. /etc/os-release not found."
    fi

    case "$OS_ID" in
        ubuntu|debian|linuxmint)
            PKG_MGR="apt"
            ;;
        centos|rhel|rocky|almalinux|fedora)
            PKG_MGR="yum"
            command -v dnf &>/dev/null && PKG_MGR="dnf"
            ;;
        *)
            _warn "Untested OS: $OS_NAME. Proceeding anyway..."
            PKG_MGR="apt"
            ;;
    esac

    _info "OS      : $OS_NAME"
    _info "Pkg mgr : $PKG_MGR"
}

# ── architecture check ────────────────────────────────────────
_check_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64|aarch64|arm64) ;;
        *) _err "Unsupported architecture: $ARCH. Wazuh requires x86_64 or aarch64." ;;
    esac
    _info "Arch    : $ARCH"
}

# ── minimum resource check ────────────────────────────────────
_check_resources() {
    # RAM — Wazuh recommends 4 GB minimum
    local ram_kb
    ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local ram_gb=$(( ram_kb / 1024 / 1024 ))

    # Disk — recommend 50 GB free
    local disk_gb
    disk_gb=$(df -BG / | awk 'NR==2{gsub("G",""); print $4}')

    _info "RAM     : ${ram_gb} GB available"
    _info "Disk    : ${disk_gb} GB free on /"

    if (( ram_gb < 4 )); then
        _warn "Less than 4 GB RAM detected (${ram_gb} GB). Wazuh may run slowly."
        echo -ne "${YELLOW}  Continue anyway? [y/N]: ${RESET}"
        read -r confirm
        [[ "$confirm" =~ ^[Yy]$ ]] || exit 0
    fi

    if (( disk_gb < 20 )); then
        _warn "Less than 20 GB free disk space (${disk_gb} GB). Wazuh needs space for logs."
        echo -ne "${YELLOW}  Continue anyway? [y/N]: ${RESET}"
        read -r confirm
        [[ "$confirm" =~ ^[Yy]$ ]] || exit 0
    fi
}

# ── dependency check ──────────────────────────────────────────
_install_deps() {
    _step "Installing dependencies"

    if [[ "$PKG_MGR" == "apt" ]]; then
        apt-get update -qq
        apt-get install -y -qq curl tar gzip coreutils
    else
        $PKG_MGR install -y curl tar gzip coreutils
    fi

    _ok "Dependencies ready"
}

# ── download Wazuh installer ──────────────────────────────────
_download_installer() {
    _step "Downloading Wazuh ${WAZUH_VERSION} installer"

    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"

    _info "URL: $INSTALL_SCRIPT_URL"
    curl -sO "$INSTALL_SCRIPT_URL" || _err "Failed to download wazuh-install.sh"
    chmod 744 wazuh-install.sh

    _ok "Installer downloaded → ${WORK_DIR}/wazuh-install.sh"
}

# ── run installation ──────────────────────────────────────────
_run_install() {
    _step "Running Wazuh all-in-one installation"
    _info "This installs: Wazuh Indexer + Manager + Filebeat + Dashboard"
    _info "This will take 5–15 minutes depending on your connection..."
    echo ""

    cd "$WORK_DIR"
    bash wazuh-install.sh -a 2>&1 | tee wazuh-install.log

    _ok "Installation complete"
    _info "Log saved → ${WORK_DIR}/wazuh-install.log"
}

# ── extract credentials ───────────────────────────────────────
_show_credentials() {
    _step "Retrieving credentials"

    # Wazuh installer stores credentials in wazuh-passwords.txt inside a tar
    local tar_file="${WORK_DIR}/wazuh-install-files.tar"
    local creds_file="${WORK_DIR}/wazuh-passwords.txt"

    if [[ -f "$tar_file" ]]; then
        tar -xOf "$tar_file" wazuh-install-files/wazuh-passwords.txt \
            > "$creds_file" 2>/dev/null || true
    fi

    if [[ -f "$creds_file" ]]; then
        echo ""
        echo -e "${GREEN}  ┌─────────────────────────────────────────┐${RESET}"
        echo -e "${GREEN}  │         WAZUH CREDENTIALS               │${RESET}"
        echo -e "${GREEN}  └─────────────────────────────────────────┘${RESET}"
        grep -E "(admin|kibanaserver|wazuh|indexer)" "$creds_file" \
            | grep -E "password|Password" \
            | while IFS= read -r line; do
                echo -e "  ${CYAN}${line}${RESET}"
              done
        echo ""
        _info "Full credentials saved → $creds_file"
    else
        _warn "Could not extract credentials automatically."
        _info "Run: sudo tar -xOf ${tar_file} wazuh-install-files/wazuh-passwords.txt"
    fi
}

# ── service status ────────────────────────────────────────────
_check_status() {
    _step "Wazuh service status"

    local services=("wazuh-manager" "wazuh-indexer" "wazuh-dashboard" "filebeat")

    for svc in "${services[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo -e "  ${GREEN}✔  ${WHITE}${svc}${RESET}  ${DIM}running${RESET}"
        elif systemctl list-units --all --quiet "$svc" 2>/dev/null | grep -q "$svc"; then
            echo -e "  ${RED}✘  ${WHITE}${svc}${RESET}  ${DIM}stopped${RESET}"
        else
            echo -e "  ${YELLOW}–  ${WHITE}${svc}${RESET}  ${DIM}not installed${RESET}"
        fi
    done
}

# ── show access info ──────────────────────────────────────────
_show_access() {
    local ip
    ip=$(hostname -I | awk '{print $1}')

    echo ""
    echo -e "${GREEN}  ┌─────────────────────────────────────────────────┐${RESET}"
    echo -e "${GREEN}  │              ACCESS INFORMATION                 │${RESET}"
    echo -e "${GREEN}  └─────────────────────────────────────────────────┘${RESET}"
    echo -e "  ${CYAN}Dashboard URL  :${WHITE} https://${ip}${RESET}"
    echo -e "  ${CYAN}Default user   :${WHITE} admin${RESET}"
    echo -e "  ${CYAN}API port       :${WHITE} 55000${RESET}"
    echo -e "  ${CYAN}Indexer port   :${WHITE} 9200${RESET}"
    echo -e "  ${CYAN}Agent port     :${WHITE} 1514 (UDP/TCP)${RESET}"
    echo -e "  ${CYAN}Syslog port    :${WHITE} 514${RESET}"
    echo ""
    echo -e "  ${DIM}Accept the self-signed certificate in your browser.${RESET}"
    echo ""
}

# ── uninstall ─────────────────────────────────────────────────
_uninstall() {
    _step "Uninstalling Wazuh"

    if [[ ! -f "${WORK_DIR}/wazuh-install.sh" ]]; then
        _info "Re-downloading installer for uninstall..."
        mkdir -p "$WORK_DIR"
        cd "$WORK_DIR"
        curl -sO "$INSTALL_SCRIPT_URL"
        chmod 744 wazuh-install.sh
    fi

    cd "$WORK_DIR"
    echo -ne "${YELLOW}  This will remove Wazuh completely. Are you sure? [y/N]: ${RESET}"
    read -r confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { _info "Aborted."; exit 0; }

    bash wazuh-install.sh --uninstall
    _ok "Wazuh uninstalled."
}

# ── firewall rules ────────────────────────────────────────────
_configure_firewall() {
    _step "Configuring firewall rules"

    # Wazuh ports
    local ports=(443 9200 55000 1514 1515 514)

    if command -v ufw &>/dev/null; then
        for port in "${ports[@]}"; do
            ufw allow "$port" &>/dev/null && _ok "ufw: allowed port $port"
        done
        ufw --force enable &>/dev/null || true

    elif command -v firewall-cmd &>/dev/null; then
        for port in "${ports[@]}"; do
            firewall-cmd --permanent --add-port="${port}/tcp" &>/dev/null || true
            firewall-cmd --permanent --add-port="${port}/udp" &>/dev/null || true
        done
        firewall-cmd --reload &>/dev/null
        _ok "firewalld: ports opened"

    else
        _warn "No firewall manager found (ufw/firewalld). Open ports manually:"
        _info "Ports needed: ${ports[*]}"
    fi
}

# ── usage ─────────────────────────────────────────────────────
_usage() {
    echo ""
    echo -e "  ${WHITE}Usage:${RESET}"
    echo -e "    ${CYAN}sudo bash wazuh-install.sh${RESET}              Full install"
    echo -e "    ${CYAN}sudo bash wazuh-install.sh --uninstall${RESET}  Remove Wazuh"
    echo -e "    ${CYAN}sudo bash wazuh-install.sh --status${RESET}     Check services"
    echo ""
}

# ── main ──────────────────────────────────────────────────────
_banner
_require_root

case "${1:-}" in
    --uninstall|-u)
        _detect_os
        _uninstall
        exit 0
        ;;
    --status|-s)
        _check_status
        _show_access
        exit 0
        ;;
    --help|-h)
        _usage
        exit 0
        ;;
    "")
        # full install
        ;;
    *)
        _err "Unknown option: $1"
        ;;
esac

# ── full install flow ─────────────────────────────────────────
_step "Pre-flight checks"
_detect_os
_check_arch
_check_resources

_install_deps
_download_installer
_run_install
_configure_firewall
_check_status
_show_credentials
_show_access

echo -e "${GREEN}  ✔  Wazuh ${WAZUH_VERSION} installation complete.${RESET}"
echo -e "${DIM}  Logs: ${WORK_DIR}/wazuh-install.log${RESET}"
echo ""
