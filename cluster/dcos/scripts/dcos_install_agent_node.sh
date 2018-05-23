
#!/usr/bin/env bash
#
# Installs and configure a DCOS agent node
# This script must be executed on agent node.

# Installs and configures everything needed on any node
{{.IncludeInstallCommons}}

if [ "{{.PublicNode}}" = "yes" ]; then
    MODE=slave_public
else
    MODE=slave
fi

# Get install script from bootstrap server
mkdir /tmp/dcos && cd /tmp/dcos
curl -O http://{{.BootstrapIP}}:{{.BootstrapPort}}/dcos_install.sh || exit 1

# Launch installation
bash dcos_install.sh $MODE
retcode=$?

#rm -rf /tmp/dcos
exit $retcode
