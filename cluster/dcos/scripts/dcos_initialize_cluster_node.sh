#!/usr/bin/env bash
#
# Initializes a cluster node

# Get install script from bootstrap server
mkdir -p /tmp/dcos
cd /tmp/dcos
curl -O http://{{.BootstrapIP}}:{{.BootstrapPort}}/dcos_install.sh

# Launch installation
sudo bash dcos_install.sh {{.NodeType}}

#  Do some cleanup
rm -rf /tmp/dcos
