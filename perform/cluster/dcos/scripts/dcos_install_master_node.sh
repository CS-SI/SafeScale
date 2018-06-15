#!/usr/bin/env bash
#
# Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Installs and configure a master node
# This script must be executed on server to configure as master node

# Redirects outputs to /var/tmp/install_master_node.log
exec 1<&-
exec 2<&-
exec 1<>/var/tmp/install_master_node.log
exec 2>&1

# Installs and configures everything needed on any node
{{.IncludeInstallCommons}}

# Installs graphical environment
yum install -y tigervnc-server xfce4

# Installs SafeScale containers
curl -q http://{{ .BootstrapIP }}:{{ .BootstrapPort }}/docker/guacamole.tar.gz 2>/dev/null | docker image load || {
    retcode=$?
    echo "Failed to load guacamole docker image"
    exit $retcode
}
curl -q http://{{ .BootstrapIP }}:{{ .BootstrapPort }}/docker/proxy.tar.gz 2>/dev/null | docker image load || {
    retcode=$?
    echo "Failed to load proxy docker image"
    exit $retcode
}

# Get install script from bootstrap server
mkdir /usr/local/dcos && cd /usr/local/dcos
curl -q -O http://{{ .BootstrapIP }}:{{ .BootstrapPort }}/dcos_install.sh || {
    retcode=$?
    echo "Failed to download dcos_install.sh from Bootstrap server"
    exit $retcode
}

# Get the dcos binary
curl -q -o ~cladm/.local/bin/dcos http://{{ .BootstrapIP }}:{{ .BootstrapPort }}/dcos.bin || {
    retcode=$?
    echo "Failed to download dcos binary from Bootstrap server"
    exit $retcode
}
chmod ug+rx ~cladm/.local/bin/dcos
chown -R cladm:cladm ~cladm

# Launch installation
bash dcos_install.sh master || {
    retcode=$?
    echo "Failed to install DCOS on master"
    exit $retcode
}

# Sets the url of the dcos master
sudo -u cladm -i dcos config set core.dcos_url http://localhost

# Starts containers for RemoteDesktop
curl -q -o dcos-master.yml http://{{ .BootstrapIP }}:{{ .BootstrapPort }}/docker/dcos-master.yml || {
    retcode=$?
    echo "Failed to download dcos-master.yml from Bootstrap server"
    exit $retcode
}
/usr/local/bin/docker-compose -f /usr/local/dcos/dcos-master.yml up -d || {
    retcode=$?
    echo "Failed to start standalone docker containers"
    exit $retcode
}

exit $?