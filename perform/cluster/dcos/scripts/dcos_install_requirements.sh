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

#### Installs and configure common tools for any kind of nodes ####


install_common_requirements() {
    echo "Installing common requirements..."

    export LANG=C

    # Disable SELinux
    setenforce 0
    sed -i 's/^SELINUX=.*$/SELINUX=disabled/g' /etc/selinux/config

    # Configure Firewall to accept all traffic from/to the private network
    iptables -t filter -A INPUT -s {{ .CIDR }} -j ACCEPT
    save_iptables_rules

    # Upgrade to last CentOS revision
    rm -rf /usr/lib/python2.7/site-packages/backports.ssl_match_hostname-3.5.0.1-py2.7.egg-info && \
    yum install -y python-backports-ssl_match_hostname && \
    yum upgrade --assumeyes --tolerant && \
    yum update --assumeyes
    [ $? -ne 0 ] && exit {{ errcode "SystemUpdate" }}

    # Create group nogroup
    groupadd nogroup &>/dev/null

    # Disables installation of docker-python from yum and adds some requirements
    yum remove -y python-docker-py &>/dev/null
    yum install -y yum-versionlock yum-utils tar xz curl wget unzip ipset pigz bind-utils && \
    yum versionlock exclude python-docker-py
    [ $? -ne 0 ] && exit {{ errcode "ToolsInstall" }}

    # Installs PIP
    yum install -y epel-release && \
    yum makecache fast && \
    yum install -y python-pip
    [ $? -ne 0 ] && exit {{ errcode "PipInstall" }}

    # Installs docker-python with pip
    pip install -q docker-py==1.10.6
    [ $? -ne 0 ] && exit {{ errcode "DockerPyInstall" }}

    # Enable overlay module
    echo overlay >/etc/modules-load.d/10-overlay.conf

    # Loads overlay module
    modprobe overlay

    # Creates docker systemd directory
    mkdir -p /etc/systemd/system/docker.service.d && chmod 0755 /etc/systemd/system/docker.service.d

    # Configure docker to use overlay driver
    echo >/etc/systemd/system/docker.service.d/override.conf <<-'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd --storage-driver=overlay --log-driver=none
EOF

    # Installs docker
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo && \
    yum install -y docker-ce-17.06.2.ce
    [ $? -ne 0 ] && exit {{ errcode "DockerInstall" }}

    # Enable docker at boot
    systemctl enable docker.service
    systemctl start docker

    # Enables admin user to use docker CLI
    usermod -aG docker gpac

    # Installs docker-compose
    curl -sS -q -L https://github.com/docker/compose/releases/download/1.21.2/docker-compose-$(uname -s)-$(uname -m) -o /usr/local/bin/docker-compose
    [ $? -ne 0 ] && exit {{ errcode "DockerComposeDownload"  }}
    chmod a+rx /usr/local/bin/docker-compose
    [ -f /bin/docker-compose ] && mv -f /bin/docker-compose /bin/docker-compose.notused

    # Creates user cladm
    useradd -s /bin/bash -m -d /home/cladm cladm
    usermod -aG docker cladm
    echo "cladm:{{ .CladmPassword }}" | chpasswd
    mkdir -p /home/cladm/.ssh && chmod 0700 /home/cladm/.ssh
    mkdir -p /home/cladm/.local/bin && find /home/cladm/.local -exec chmod 0770 {} \;
    cat >>/home/cladm/.bashrc <<-'EOF'
pathremove() {
        local IFS=':'
        local NEWPATH
        local DIR
        local PATHVARIABLE=${2:-PATH}
        for DIR in ${!PATHVARIABLE} ; do
                if [ "$DIR" != "$1" ] ; then
                  NEWPATH=${NEWPATH:+$NEWPATH:}$DIR
                fi
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
    chown -R cladm:cladm /home/cladm

    echo "Common requirements successfully installed."
}
export -f install_common_requirements

yum makecache fast
yum install -y wget time rclone
/usr/bin/time -p bash -c install_common_requirements
