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
    setenforce 0 &>/dev/null
    sed -i 's/^SELINUX=.*$/SELINUX=disabled/g' /etc/selinux/config &>/dev/null

    # Creates user {{.ClusterAdminUsername}}
    useradd -s /bin/bash -m -d /home/{{.ClusterAdminUsername}} {{.ClusterAdminUsername}}
    groupadd -r -f docker &>/dev/null
    usermod -aG docker {{.ClusterAdminUsername}}
    echo -e "{{ .ClusterAdminPassword }}\n{{ .ClusterAdminPassword }}" | passwd {{.ClusterAdminUsername}}
    mkdir -p ~{{.ClusterAdminUsername}}/.ssh && chmod 0700 ~{{.ClusterAdminUsername}}/.ssh
    echo "{{ .SSHPublicKey }}" >~{{.ClusterAdminUsername}}/.ssh/authorized_keys
    echo "{{ .SSHPrivateKey }}" >~{{.ClusterAdminUsername}}/.ssh/id_rsa
    chmod 0400 ~{{.ClusterAdminUsername}}/.ssh/*
    echo "{{.ClusterAdminUsername}} ALL=(ALL) NOPASSWD:ALL" >>/etc/sudoers.d/10-admins
    chmod o-rwx /etc/sudoers.d/10-admins

    mkdir -p ~{{.ClusterAdminUsername}}/.local/bin && find ~{{.ClusterAdminUsername}}/.local -exec chmod 0770 {} \;
    cat >>~{{.ClusterAdminUsername}}/.bashrc <<-'EOF'
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
        pathprepend /usr/local/bin
EOF
    chown -R {{ .ClusterAdminUsername}}:{{.ClusterAdminUsername}} ~{{.ClusterAdminUsername}}

    for i in ~{{.ClusterAdminUsername}}/.hushlogin ~{{.ClusterAdminUsername}}/.cloud-warnings.skip; do
        touch $i
        chown root:{{.ClusterAdminUsername}} $i
        chmod ug+r-wx,o-rwx $i
    done

    # Enable overlay module
    echo overlay >/etc/modules-load.d/10-overlay.conf

    # Loads overlay module
    modprobe overlay

    echo "Common requirements successfully installed."
}
export -f install_common_requirements

case $(sfGetFact "linux_kind") in
    debian|ubuntu)
        sfRetry 3m 5 "sfApt update && sfApt install -y wget curl time jq unzip"
        curl -kqSsL -O https://downloads.rclone.org/rclone-current-linux-amd64.zip && \
        unzip rclone-current-linux-amd64.zip && \
        cp rclone-*-linux-amd64/rclone /usr/local/bin && \
        mkdir -p /usr/local/share/man/man1 && \
        cp rclone-*-linux-amd64/rclone.1 /usr/local/share/man/man1/ && \
        rm -rf rclone-* && \
        chown root:root /usr/local/bin/rclone && \
        chmod 755 /usr/local/bin/rclone && \
        mandb
        ;;
    redhat|centos)
        yum makecache fast
        yum install -y wget curl time rclone jq unzip
        ;;
    fedora)
        dnf install wget curl time rclone jq unzip
        ;;
    *)
        echo "Unmanaged linux distribution type '$(sfGetFact "linux_kind")'"
        exit 1
        ;;
esac

/usr/bin/time -p bash -c -x install_common_requirements
