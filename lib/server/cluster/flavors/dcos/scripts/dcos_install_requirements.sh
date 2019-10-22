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

#### Installs and configure common tools for any kind of nodes ####

install_common_requirements() {
    echo "Installing common requirements..."

    export LANG=C

    # Disable SELinux
    if [[ -n $(command -v setenforce) ]]; then
	      setenforce 0 || fail 201 "Error setting selinux in disabled mode"
        sed -i 's/^SELINUX=enforcing$/SELINUX=disabled/' /etc/selinux/config
    fi

    # Upgrade to last CentOS revision
    rm -rf /usr/lib/python2.7/site-packages/backports.ssl_match_hostname-3.5.0.1-py2.7.egg-info && \
    yum install -y python-backports-ssl_match_hostname && \
    yum upgrade --assumeyes --tolerant && \
    yum update --assumeyes
    [ $? -ne 0 ] && exit 192

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

    # Disables installation of docker-python from yum and adds some requirements
    yum remove -y python-docker-py &>/dev/null
    yum install -y yum-versionlock yum-utils tar xz curl wget unzip ipset pigz bind-utils jq rclone && \
    yum versionlock exclude python-docker-py || exit 193

    # Installs PIP
    yum install -y epel-release && \
    yum makecache fast && \
    yum install -y python-pip || yum install -y python2-pip || exit 194

    # Installs docker-python with pip
    pip install -q docker-py==1.10.6 || exit 195

    # Enable overlay module
    echo overlay >/etc/modules-load.d/10-overlay.conf

    # Loads overlay module
    modprobe overlay

    # Mesos needs a subversion release > 1.8
    cat >/etc/yum.repos.d/wandisco-svn.repo <<-'EOF'
[WANdiscoSVN]
name=WANdisco SVN Repo 1.9
enabled=1
baseurl=http://opensource.wandisco.com/centos/7/svn-1.9/RPMS/$basearch/
gpgcheck=1
gpgkey=http://opensource.wandisco.com/RPM-GPG-KEY-WANdisco
EOF
    yum install -y subversion

    echo "Common requirements successfully installed."
}
export -f install_common_requirements

yum makecache fast
yum install -y time
/usr/bin/time -p bash -c install_common_requirements
