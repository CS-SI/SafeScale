#!/bin/bash -x

# Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

{{ .reserved_BashLibrary }}

#### Installs and configure common tools for any kind of nodes ####

install_common_requirements() {
  echo "Installing common requirements..."

  export LANG=C

  # Disable SELinux
  if [[ -n $(command -v getenforce) ]]; then
    act=0
    getenforce | grep "Disabled" || act=1
    if [ $act -eq 1 ]; then
      if [[ -n $(command -v setenforce) ]]; then
        setenforce 0 || fail 201 "Error setting selinux in Disabled mode"
        sed -i 's/^SELINUX=enforcing$/SELINUX=disabled/' /etc/selinux/config
      fi
    fi
  fi

  # Creates user {{.ClusterAdminUsername}}
  useradd -s /bin/bash -m -d /home/{{.ClusterAdminUsername}} {{.ClusterAdminUsername}}
  groupadd -r -f docker &> /dev/null
  usermod -aG docker {{.ClusterAdminUsername}}
  echo -e "{{ .ClusterAdminPassword }}\n{{ .ClusterAdminPassword }}" | passwd {{.ClusterAdminUsername}}
  mkdir -p ~{{.ClusterAdminUsername}}/.ssh && chmod 0700 ~{{.ClusterAdminUsername}}/.ssh
  echo "{{ .SSHPublicKey }}" > ~{{.ClusterAdminUsername}}/.ssh/authorized_keys
  echo "{{ .SSHPrivateKey }}" > ~{{.ClusterAdminUsername}}/.ssh/id_rsa
  chmod 0400 ~{{.ClusterAdminUsername}}/.ssh/*
  echo "{{.ClusterAdminUsername}} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/10-admins
  chmod o-rwx /etc/sudoers.d/10-admins

  chown -R {{ .ClusterAdminUsername}}:{{.ClusterAdminUsername}} ~{{.ClusterAdminUsername}}

  for i in ~{{.ClusterAdminUsername}}/.hushlogin ~{{.ClusterAdminUsername}}/.cloud-warnings.skip; do
    touch $i
    chown root:{{.ClusterAdminUsername}} $i
    chmod ug+r-wx,o-rwx $i
  done

  # Enable overlay module
  echo overlay > /etc/modules-load.d/10-overlay.conf

  # Loads overlay module
  modprobe overlay

  echo "Node common requirements successfully installed."
}
export -f install_common_requirements

# /usr/bin/time -p bash -c -x install_common_requirements
install_common_requirements || sfFail $? "Problem installing common requirements"

sfExit
