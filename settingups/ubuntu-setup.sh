#!/usr/bin/env bash

# Generate an ED25519 key and display the public key
ssh-keygen -o -a 100 -t ed25519
cat ~/.ssh/id_ed25519.pub

read -p 'You should add your public key to GitHub now. Press any key to continue...'
read -p 'Now you will generate a GPG key. Please use RSA/RSA with a keysize of 4096 bits. Press any key to continue...'

gpg --default-new-key-algo rsa4096 --gen-key
new_key=$(gpg --list-secret-keys --with-colons | cut -d: -f5)
gpg --armor --export $new_key

read -p 'You should add your GPG key to GitHub now. Press any key to continue...'

# Install packages required to add custom repositories and clone dotfiles
sudo apt-get update
sudo apt-get -y install apt-transport-https curl gnupg-agent

# Install dotfiles
git clone git@github.com:wildlyinaccurate/dotfiles.git ~/.dotfiles
~/.dotfiles/install.sh

# Add custom repositories
# Firefox
sudo add-apt-repository ppa:ubuntu-mozilla-daily/firefox-aurora

# Google Chrome
echo deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main | sudo tee /etc/apt/sources.list.d/google.list
wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add -

# Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add - 
echo deb [arch=amd64] https://download.docker.com/linux/ubuntu disco stable | sudo tee /etc/apt/sources.list.d/docker.list
sudo curl -L "https://github.com/docker/compose/releases/download/1.25.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install new packages
sudo apt-get update

# Packages
packages=(
  ack-grep
  docker-ce
  docker-ce-cli
  containerd.io
  fonts-firacode
  git
  google-chrome-unstable
  htop
  keychain
  zsh
  zsh-syntax-highlighting
)

sudo apt-get -y install ${packages[@]}

# Install packages that are available via snapd
sudo snap install --classic code
sudo snap install --classic spotify
sudo snap install --classic sublime-text

# Don't require sudo for Docker
sudo groupadd docker
sudo usermod -aG docker $USER

# Run Docker on boot
sudo systemctl enable docker

# Install NVM and Node
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.35.1/install.sh | bash
source ~/.bashrc
nvm install node

# Install oh-my-zsh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"

# Install some sweet terminal themes
read -p 'The next command will ask you to choose which terminal themes you want. I recommend "100 101 140 149 151". Press any key to continue...'
bash -c  "$(wget -qO- https://git.io/vQgMr)"

# Update all other packages
sudo apt-get -y dist-upgrade

# Add GPG signing key to git
git config --global user.signingkey $new_key

# OMG FINALLY
echo 'ALL DONE!'
echo ''
echo '▒▒▒▒▒▒▒▒█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█ '
echo '▒▒▒▒▒▒▒█░▒▒▒▒▒▒▒▓▒▒▓▒▒▒▒▒▒▒░█ '
echo '▒▒▒▒▒▒▒█░▒▒▓▒▒▒▒▒▒▒▒▒▄▄▒▓▒▒░█░▄▄ '
echo '▒▒▄▀▀▄▄█░▒▒▒▒▒▒▓▒▒▒▒█░░▀▄▄▄▄▄▀░░█ '
echo '▒▒█░░░░█░▒▒▒▒▒▒▒▒▒▒▒█░░░░░░░░░░░█ '
echo '▒▒▒▀▀▄▄█░▒▒▒▒▓▒▒▒▓▒█░░░█▒░░░░█▒░░█ '
echo '▒▒▒▒▒▒▒█░▒▓▒▒▒▒▓▒▒▒█░░░░░░░▀░░░░░█ '
echo '▒▒▒▒▒▄▄█░▒▒▒▓▒▒▒▒▒▒▒█░░█▄▄█▄▄█░░█ '
echo '▒▒▒▒█░░░█▄▄▄▄▄▄▄▄▄▄█░█▄▄▄▄▄▄▄▄▄█ '
echo '▒▒▒▒█▄▄█░░█▄▄█░░░░░░█▄▄█░░█▄▄'