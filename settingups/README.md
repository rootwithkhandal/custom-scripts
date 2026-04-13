# settingups/

Environment setup scripts for Python modules, Ubuntu dev environments, and SIEM deployment.

## Scripts

| Script | Description |
|--------|-------------|
| `python_modules.sh` | Installs a large set of Python security/ML/networking modules via pip3 |
| `ubuntu-setup.sh` | Full Ubuntu dev environment setup — SSH/GPG keys, Docker, ZSH, NVM, dotfiles |
| `wazuh-install.sh` | Automated Wazuh SIEM single-node installer — Indexer + Manager + Dashboard |

---

## python_modules.sh

Installs common Python packages used across this toolkit and beyond.

```bash
bash python_modules.sh
```

**Packages installed:**

| Category | Packages |
|----------|----------|
| Networking | `scapy` `rawsocketpy` `python-nmap` `requests` `mechanize` |
| Web | `beautifulsoup4` `bs4` |
| Crypto | `pycrypto` `cryptography` |
| ML / AI | `scikit-learn` `tensorflow` `keras` `torch` `Theano` `numpy` `pandas` `matplotlib` `plotly` |
| Security | `yara-python` `pwntools` `pymetasploit3` `pscan` |
| Misc | `paramiko` `PyAutoGUI` `tornado` `Twisted` `Faker` `plists` `python-time` |

> Note: Some packages (tensorflow, torch, Theano) are large and may take a while. Run on a good connection.

---

## ubuntu-setup.sh

Full Ubuntu workstation setup. Run once on a fresh install.

```bash
bash ubuntu-setup.sh
```

**What it does:**

1. Generates an ED25519 SSH key and displays the public key (add to GitHub)
2. Generates a GPG key (RSA 4096) and displays it (add to GitHub)
3. Clones and installs dotfiles from `wildlyinaccurate/dotfiles`
4. Adds repositories: Firefox Aurora, Google Chrome, Docker
5. Installs packages: Docker, ZSH, git, htop, keychain, FiraCode font, Chrome
6. Installs snap packages: VS Code, Spotify, Sublime Text
7. Configures Docker (no-sudo group, enable on boot)
8. Installs NVM + latest Node.js
9. Installs oh-my-zsh
10. Installs terminal color themes
11. Configures git GPG signing key

> This script is tailored for Ubuntu. Adapt repository URLs and package names for other distros.

---

## wazuh-install.sh

Automated single-node Wazuh SIEM installer. Installs Wazuh Indexer, Manager (+ Filebeat), and Dashboard in one shot using the official Wazuh install script.

Supported OS: Ubuntu 20.04/22.04/24.04, Debian 10/11/12, CentOS/RHEL 7/8/9
Architecture: x86_64 or aarch64
Minimum specs: 4 GB RAM, 20 GB free disk

```bash
# full install
sudo bash settingups/wazuh-install.sh

# check service status
sudo bash settingups/wazuh-install.sh --status

# uninstall everything
sudo bash settingups/wazuh-install.sh --uninstall
```

**What it does:**

1. Detects OS and package manager
2. Checks RAM and disk space (warns if below minimum)
3. Installs `curl`, `tar`, `gzip` dependencies
4. Downloads the official Wazuh installer from `packages.wazuh.com`
5. Runs all-in-one install (Indexer + Manager + Filebeat + Dashboard)
6. Opens required firewall ports (ufw or firewalld)
7. Displays service status and access credentials

**Ports opened:**

| Port | Service |
|------|---------|
| 443 | Wazuh Dashboard (HTTPS) |
| 9200 | Wazuh Indexer |
| 55000 | Wazuh API |
| 1514 | Agent communication |
| 1515 | Agent enrollment |
| 514 | Syslog |

After install, access the dashboard at `https://<your-ip>` — accept the self-signed certificate. Credentials are printed at the end and saved to `/tmp/wazuh-setup/wazuh-passwords.txt`.
