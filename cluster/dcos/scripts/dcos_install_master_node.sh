#!/usr/bin/env bash
#
# Installs and configure a master node
# This script must be executed on server to configure as master node

# Get install script from bootstrap server
mkdir /tmp/dcos && cd /tmp/dcos
curl -O http://{{.bootstrap_ip}}:{{.bootstrap_port}}/dcos_install.sh

# Launch installation
sudo bash dcos_install.sh master

#  Do some cleanup
#rm -rf /tmp/dcos
