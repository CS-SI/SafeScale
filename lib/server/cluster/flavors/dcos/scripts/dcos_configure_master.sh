#!/usr/bin/env bash -x
#
# Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

# Redirects outputs to dcos_configure_master.log
rm -f /opt/safescale/var/log/dcos_configure_master.log
exec 1<&-
exec 2<&-
exec 1<>/opt/safescale/var/log/dcos_configure_master.log
exec 2>&1

{{ .reserved_BashLibrary }}

###############################################
### Defining functions used asynchronously ###
###############################################

# Get install script from Bootstrap server
download_dcos_install() {
    mkdir -p ${SF_VARDIR}/dcos
    [ ! -f ${SF_VARDIR}/dcos/dcos_install.sh ] && {
        local URL=http://{{ .BootstrapIP }}:{{ .BootstrapPort }}/dcos_install.sh
        sfRetry 10m 5 curl -kqSsL -o ${SF_VARDIR}/dcos/dcos_install.sh $URL || exit $?
    }
    exit 0
}
export -f download_dcos_install

# Get the dcos binary from Bootstrap server
download_dcos_binary() {
    [ ! -f ~cladm/.local/bin/dcos ] && {
        local URL=http://{{ .BootstrapIP }}:{{ .BootstrapPort }}/dcos.bin
        sfRetry 10m 5 curl -qkSsL -o ~cladm/.local/bin/dcos $URL || exit $?
        chmod ug+rx ~cladm/.local/bin/dcos
        chown -R cladm:cladm ~cladm
    }
    exit 0
}
export -f download_dcos_binary

# Get the kubectl binary from Bootstrap server
download_kubectl_binary() {
    [ ! -f ~cladm/.local/bin/kubectl ] && {
        local URL=http://{{ .BootstrapIP }}:{{ .BootstrapPort }}/kubectl.bin
        sfRetry 10m 5 curl -qkSsL -o ~cladm/.local/bin/kubectl $URL || exit $?
        chmod ug+rx ~cladm/.local/bin/kubectl
        chown -R cladm:cladm ~cladm
    }
    exit 0
}
export -f download_kubectl_binary

########################################
### Launch background download tasks ###
########################################

sfAsyncStart DDI 10m bash -c download_dcos_install
sfAsyncStart DDB 10m bash -c download_dcos_binary
sfAsyncStart DKB 10m bash -c download_kubectl_binary

#########################
### DCOS installation ###
#########################

echo "Waiting for DCOS Installer download..."
sfAsyncWait DDI || exit 192

# Needed modules for DCOS
for i in raid1 dm_raid; do
    echo $i >>/etc/modules
    modprobe $i
done

# Launch DCOS installation
cd ${SF_VARDIR}/dcos
bash ./dcos_install.sh master || exit 193

# Sets the url of the dcos master
echo "Waiting for DCOS cli download..."
sfAsyncWait DDB || exit 194
cat >>~cladm/.bashrc <<-EOF
# Makes sure dcos is configured correctly
dcos cluster setup http://master.mesos/ &>/dev/null
EOF
chown -R cladm:cladm ~cladm

########################################################
### awaits the end of the download of kubectl binary ###
########################################################

echo "Waiting for kubectl download..."
sfAsyncWait DKB || exit 195

### Done
echo
echo "Master configured successfully."
exit 0