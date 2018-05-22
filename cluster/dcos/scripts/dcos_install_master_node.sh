#!/usr/bin/env bash
#
# Installs and configure a master node
# This script must be executed on server to configure as master node

# Installs and configures everything needed on any node
{{.IncludeInstallCommons}}

# Get install script from bootstrap server
mkdir /tmp/dcos && cd /tmp/dcos
curl -O http://{{.BootstrapIP}}:{{.BootstrapPort}}/dcos_install.sh

# Launch installation
sudo bash dcos_install.sh master

#  Do some cleanup
#rm -rf /tmp/dcos
