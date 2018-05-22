<<<<<<< HEAD
#!/usr/bin/env bash
#
# Installs and configure a DCOS agent node
# This script must be executed on agent node.
|||||||
=======
#!/usr/bin/env bash
#
# Installs and configure a DCOS agent node
# This script must be executed on agent node.

if [ "{{.public_node}}" = "yes" ]; then
    MODE=slave_public
else
    MODE=slave
fi

# Get install script from bootstrap server
mkdir /tmp/dcos && cd /tmp/dcos
curl -O http://{{.bootstrap_ip}}:{{.bootstrap_port}}/dcos_install.sh

# Launch installation
sudo bash dcos_install.sh $MODE

#rm -rf /tmp/docs
exit 0
>>>>>>> dcos
