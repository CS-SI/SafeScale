#!/bin/bash
set -Eeuo pipefail

sudo apt-get update

# check sysctl is installed
if ! [ -x "$(command -v sysctl)" ]; then
  sudo apt-get install -y sysctl
fi

# allow ip forwarding
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo sysctl -p

# check iptables-persistent is installed
if ! [ -x "$(command -v iptables-persistent)" ]; then
  # force install in not interactive mode, assume yes
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q iptables-persistent
fi
