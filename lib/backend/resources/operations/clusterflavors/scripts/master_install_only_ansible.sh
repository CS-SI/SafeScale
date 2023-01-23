#!/bin/bash -x

# Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

# Redirects outputs to /opt/safescale/var/log/node_install_requirements.log
LOGFILE=/opt/safescale/var/log/node_install_requirements.log

### All output to one file and all output to the screen
exec > >(tee -a ${LOGFILE} /opt/safescale/var/log/ss.log) 2>&1
set -x

# shellcheck disable=SC1009
# shellcheck disable=SC1073
# shellcheck disable=SC1054
{{ .reserved_BashLibrary }}

#### Installs and configure common tools for any kind of nodes ####

install_ansible() {
case $LINUX_KIND in
    ubuntu)
        export DEBIAN_FRONTEND=noninteractive
        sfApt update
        apt-cache showpkg software-properties-common && apt-get install --no-install-recommends -y software-properties-common
        apt-cache showpkg python-software-properties && apt-get install --no-install-recommends -y python-software-properties
        apt-add-repository --yes --update ppa:ansible/ansible
        fApt update
        sfApt install -y ansible
        sfApt install -y git
        ;;
    debian)
        export DEBIAN_FRONTEND=noninteractive
        sfApt update
        echo "deb http://ppa.launchpad.net/ansible/ansible/ubuntu trusty main" >> /etc/apt/sources.list
        sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 93C4A3FD7BB9C367 -y
        sfApt update
        sfApt install -y ansible
        sfApt install -y git
        ;;
    centos|redhat|rhel)
        if [[ -n $(which dnf) ]]; then
            sfYum install --enablerepo=epel -y ansible || sfFail 192
            sfYum install -y git || sfFail 192
        else
            sfYum install -y ansible || sfFail 192
            sfYum install -y git || sfFail 192
        fi
        ;;
    fedora)
        if [[ -n $(which dnf) ]]; then
            sfYum install -y ansible || sfFail 192
            sfYum install -y git || sfFail 192
        else
            sfYum install -y ansible || sfFail 192
            sfYum install -y git || sfFail 192
        fi
        ;;
    *)
        echo "Unsupported operating system '$LINUX_KIND'"
        sfFail 195
        ;;
esac


mkdir -p ${SF_ETCDIR}/ansible/inventory
chmod -R ug+rw-x,o+r-wx ${SF_ETCDIR}/ansible

cat >${SF_ETCDIR}/ansible/ansible.cfg <<-EOF
[defaults]
inventory = ${SF_ETCDIR}/ansible/inventory/_static.yml
remote_tmp = ${SF_TMPDIR}/ansible-\${USER}
log_path = ${SF_LOGDIR}/ansible.log
EOF

cat >${SF_ETCDIR}/ansible/inventory/_static.yml <<-EOF
...
all:
    hosts:
        {{ .Hostname }}:
            ansible_host: {{ .HostIP }}

    vars:
        ansible_user: {{ .Username }}
EOF

cat >${SF_ETCDIR}/ansible/pathes.cfg <<-EOF
sf_base_dir: "/opt/safescale"
sf_etc_dir: "{{ "{{ sf_base_dir }}/etc" }}"
sf_var_dir: "{{ "{{ sf_base_dir }}/var" }}"
sf_tmp_dir: "{{ "{{ sf_var_dir }}/tmp" }}"
sf_log_dir: "{{ "{{ sf_var_dir }}/log" }}"
sf_state_dir: "{{ "{{ sf_var_dir }}/state" }}"
EOF

cat >${SF_ETCDIR}/ansible/host.cfg <<-EOF
host_private_ip: "{{ .HostIP }}"
EOF

cat >${SF_ETCDIR}/ansible/network.cfg <<-EOF
cidr: "{{ .CIDR }}"
primary_gateway_private_ip: "{{ .PrimaryGatewayIP }}"
primary_gateway_public_ip: "{{ .PrimaryPublicIP }}"
endpoint_ip: "{{ .EndpointIP }}"
{{- if .DefaultRouteIP }}
default_route_ip: "{{ .DefaultRouteIP }}"
{{- else }}
default_route_ip: "{{ .PrimaryGatewayIP }}"
{{- end }}
{{ if .SecondaryGatewayIP }}secondary_gateway_private_ip: "{{ .SecondaryGatewayIP }}"{{ end }}
{{ if .SecondaryPublicIP }}secondary_gateway_public_ip: "{{ .SecondaryPublicIP }}"{{ end }}
EOF

chown -R {{ .Username }}:root ${SF_ETCDIR}/ansible
chmod -R ug+rwx,o+rx-w ${SF_ETCDIR}/ansible
find ${SF_ETCDIR}/ansible -type d -exec chmod a+x {} \;
}
export -f install_ansible

install_ansible || sfFail $? "Problem installing ansible"

sfExit
