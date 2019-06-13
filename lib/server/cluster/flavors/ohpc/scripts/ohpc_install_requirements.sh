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

#### Installs and configure common tools for any kind of nodes ####

install_common_requirements() {
    echo "Installing common requirements..."

    export LANG=C

    # Disable SELinux
    setenforce 0
    sed -i 's/^SELINUX=.*$/SELINUX=disabled/g' /etc/selinux/config

    # Upgrade to last CentOS revision
    yum upgrade --assumeyes --tolerant && \
    yum update --assumeyes
    [ $? -ne 0 ] && exit {{ errcode "SystemUpdate" }}

    # Create group nogroup
    groupadd nogroup &>/dev/null

    # Creates user cladm
    useradd -s /bin/bash -m -d /home/cladm cladm
    groupadd -r -f docker &>/dev/null
    usermod -aG docker cladm
    echo "cladm:{{ .CladmPassword }}" | chpasswd
    mkdir -p ~cladm/.ssh && chmod 0700 ~cladm/.ssh
    echo "{{ .SSHPublicKey }}" >~cladm/.ssh/authorized_keys
    echo "{{ .SSHPrivateKey }}" >~cladm/.ssh/id_rsa
    chmod 0400 ~cladm/.ssh/*
    echo "cladm ALL=(ALL) NOPASSWD:ALL" >>/etc/sudoers.d/10-admins
    chmod o-rwx /etc/sudoers.d/10-admins

    mkdir -p ~cladm/.local/bin && find ~cladm/.local -exec chmod 0770 {} \;
    cat >>~cladm/.bashrc <<-'EOF'
        pathremove() {
            local IFS=':'
            local NEWPATH
            local DIR
            local PATHVARIABLE=${2:-PATH}
            for DIR in ${!PATHVARIABLE} ; do
                [ "$DIR" != "$1" ] && NEWPATH=${NEWPATH:+$NEWPATH:}$DIR
            done
            export $PATHVARIABLE="$NEWPATH"
        }
        pathprepend() {
            pathremove $1 $2
            local PATHVARIABLE=${2:-PATH}
            export $PATHVARIABLE="$1${!PATHVARIABLE:+:${!PATHVARIABLE}}"
        }
        pathappend() {
            pathremove $1 $2
            local PATHVARIABLE=${2:-PATH}
            export $PATHVARIABLE="${!PATHVARIABLE:+${!PATHVARIABLE}:}$1"
        }
        pathprepend $HOME/.local/bin
        pathappend /opt/mesosphere/bin
EOF
    chown -R cladm:cladm ~cladm

    for i in ~cladm/.hushlogin ~cladm/.cloud-warnings.skip; do
        touch $i
        chown root:cladm $i
        chmod ug+r-wx,o-rwx $i
    done

    # Enable overlay module
    echo overlay >/etc/modules-load.d/10-overlay.conf

    # Loads overlay module
    modprobe overlay

    echo "Common requirements successfully installed."
}
export -f install_common_requirements

yum makecache fast
yum install -y wget curl time rclone jq unzip
/usr/bin/time -p bash -c install_common_requirements
