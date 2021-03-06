#!/bin/bash
#
# Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

#{{.Revision}}

{{.Header}}

function print_error() {
    read line file <<<$(caller)
    echo "An error occurred in line $line of file $file:" "{"`sed "${line}q;d" "$file"`"}" >&2
    {{.ExitOnError}}
}
trap print_error ERR

function fail() {
    echo "PROVISIONING_ERROR: $1"
    echo -n "$1,${LINUX_KIND},$(date +%Y/%m/%d-%H:%M:%S)" >/opt/safescale/var/state/user_data.init.done
    (sync; echo 3 > /proc/sys/vm/drop_caches; sleep 2) || true
    exit $1
}

mkdir -p /opt/safescale/etc /opt/safescale/bin &>/dev/null
mkdir -p /opt/safescale/var/log &>/dev/null
mkdir -p /opt/safescale/var/run /opt/safescale/var/state /opt/safescale/var/tmp &>/dev/null

LOGFILE=/opt/safescale/var/log/user_data.init.log

### All output to one file and all output to the screen
exec > >(tee -a ${LOGFILE} /var/log/ss.log) 2>&1
set -x

LINUX_KIND=
VERSION_ID=

function sfDetectFacts() {
    [ -f /etc/os-release ] && {
        . /etc/os-release
        LINUX_KIND=$ID
    } || {
        command -v lsb_release &>/dev/null && {
            LINUX_KIND=$(lsb_release -is)
            LINUX_KIND=${LINUX_KIND,,}
            VERSION_ID=$(lsb_release -rs | cut -d. -f1)
        } || {
            [ -f /etc/redhat-release ] && {
                LINUX_KIND=$(cat /etc/redhat-release | cut -d' ' -f1)
                LINUX_KIND=${LINUX_KIND,,}
                VERSION_ID=$(cat /etc/redhat-release | cut -d' ' -f3 | cut -d. -f1)
            }
        }
    }
}
sfDetectFacts

function create_user() {
echo "Creating user {{.User}}..."
    if getent passwd {{.User}}; then
        echo "User {{.User}} already exists !"
        useradd {{.User}} --home-dir /home/{{.User}} --shell /bin/bash --comment "" --create-home || true
    else
        useradd {{.User}} --home-dir /home/{{.User}} --shell /bin/bash --comment "" --create-home
    fi
    # This password will be changed at phase 2 and can be used only from console (not remotely)
    echo "{{.User}}:safescale" | chpasswd

    if getent group docker; then
        echo "Group docker already exists !"
    else
        groupadd -r docker
    fi
    usermod -aG docker {{.User}}
    SUDOERS_FILE=/etc/sudoers.d/{{.User}}
    [ ! -d "$(dirname $SUDOERS_FILE)" ] && SUDOERS_FILE=/etc/sudoers
    cat >>$SUDOERS_FILE <<-'EOF'
Defaults:{{.User}} !requiretty
{{.User}} ALL=(ALL) NOPASSWD:ALL
EOF

    mkdir /home/{{.User}}/.ssh
    echo "{{.FirstPublicKey}}" >/home/{{.User}}/.ssh/authorized_keys
    echo "{{.FirstPrivateKey}}" >/home/{{.User}}/.ssh/id_rsa
    chmod 0700 /home/{{.User}}/.ssh
    chmod -R 0600 /home/{{.User}}/.ssh/*
    cat /home/{{.User}}/.ssh/id_rsa

    cat >>/home/{{.User}}/.bashrc <<-'EOF'
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
pathappend /opt/safescale/bin
EOF

    chown -R {{.User}}:{{.User}} /opt/safescale
    chmod -R 0640 /opt/safescale
    find /opt/safescale -type d -exec chmod a+rx {} \;
    chmod 1777 /opt/safescale/var/tmp

    chown -R {{.User}}:{{.User}} /home/{{.User}}

    for i in /home/{{.User}}/.hushlogin /home/{{.User}}/.cloud-warnings.skip; do
        touch $i
        chown root:{{.User}} $i
        chmod ug+r-wx,o-rwx $i
    done

    echo done
}

function put_hostname_in_hosts() {
    echo "{{ .HostName }}" >/etc/hostname
    hostname {{ .HostName }}
    SHORT_HOSTNAME=$(hostname -s)
    [[ "$SHORT_HOSTNAME" == "{{ .HostName }}" ]] && return
    ping -n -c1 -w5 $SHORT_HOSTNAME 2>/dev/null || sed -i -nr '/^127.0.1.1/!p;$a127.0.1.1\t'"${SHORT_HOSTNAME}" /etc/hosts
}

# Disable cloud-init automatic network configuration to be sure our configuration won't be replaced
function disable_cloudinit_network_autoconf() {
    fname=/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
    mkdir -p $(dirname $fname)
    echo "network: {config: disabled}" >$fname
}

function secure_sshd() {
    sed -i '/^.*PasswordAuthentication / s/^.*$/PasswordAuthentication no/' /etc/ssh/sshd_config && \
    sed -i '/^.*ChallengeResponseAuthentication / s/^.*$/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config && \
    sed -i '/^.*PubkeyAuthentication / s/^.*$/PubkeyAuthentication yes/' /etc/ssh/sshd_config && \
    systemctl restart sshd
}
function disable_services() {
    case $LINUX_KIND in
        debian|ubuntu)
            if [[ -n $(command -v systemctl) ]]; then
                systemctl stop apt-daily.service &>/dev/null
                systemctl kill --kill-who=all apt-daily.service &>/dev/null
            fi
            if [[ -n $(command -v system) ]]; then
                which system && service stop apt-daily.service &>/dev/null
            fi
            ;;
    esac
}

# ---- Main

export DEBIAN_FRONTEND=noninteractive

put_hostname_in_hosts
disable_cloudinit_network_autoconf
disable_services
secure_sshd
create_user

touch /etc/cloud/cloud-init.disabled

echo -n "0,linux,${LINUX_KIND},${VERSION_ID},$(hostname),$(date +%Y/%m/%d-%H:%M:%S)" >/opt/safescale/var/state/user_data.init.done

(sync; echo 3 > /proc/sys/vm/drop_caches; sleep 2) || true

set +x
exit 0
