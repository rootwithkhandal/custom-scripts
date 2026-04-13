#!/bin/bash
white='\033[0;37m' 
red='\033[0;31m'
cyan='\033[0;33m'
green='\033[0;92m'



echo -e "${cyan} Checking Requirements ${white}"
echo -e ""
sudo apt-get install -y arp-scan
sudo apt-get install -y netdiscover
sudo apt install -y nmap
clear
echo -e "${cyan} All Modules Installed ${white}"
echo -e ""
echo -e "${cyan} Requirement Fullfilled ${white}"
echo -e ""

echo -e "${cyan} OPTIONS:  ${white}"
echo -e ""
echo -e "${white}   1. localnetwork ${cyan} using arpscan localnet on wlan0 "
echo -e "${white}   2. other network ${cyan} using netdiscover on port 24 "

echo -e "${green}"
read -p "option: " option


if [ $option -eq 1 ]
then
    echo -e "" 
    echo -e "${cyan} scanning wifi ${red}"
    sudo arp-scan --interface=wlan0 --localnet
       
 elif [ $option -eq 2 ]
    then
        echo -e "${green}"
        read -p "Enter your Wifi IP-Address: " input
        echo -e "${green} enter the ip address : $input"
        echo -e "${cyan} scanning wifi ${red}"
        sudo netdiscover -r $input/24
else
    echo -e "${red}"
    sudo nmap localhost

fi

