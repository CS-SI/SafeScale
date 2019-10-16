#!/usr/bin/env bash
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
# Installs and configures

{{.BashHeader}}

function print_error() {
    ec=$?
    read line file <<<$(caller)
    echo "An error occurred in line $line of file $file (exit code $ec) :" "{"`sed "${line}q;d" "$file"`"}" >&2
}
trap print_error ERR

function dns_fallback {
    grep nameserver /etc/resolv.conf && return 0
    echo -e "nameserver 1.1.1.1\n" > /tmp/resolv.conf
    sudo cp /tmp/resolv.conf /etc/resolv.conf
    return 0
}

function finishPreviousInstall() {
    local unfinished=$(dpkg -l | grep -v ii | grep -v rc | tail -n +4 | wc -l)
    if [[ "$unfinished" == 0 ]]; then echo "good"; else sudo dpkg --configure -a --force-all; fi
    return 0
}

dns_fallback

{{.reserved_BashLibrary}}

echo "Install NFS client"
case $LINUX_KIND in
    debian|ubuntu)
        export DEBIAN_FRONTEND=noninteractive
        touch /var/log/lastlog
        chgrp utmp /var/log/lastlog
        chmod 664 /var/log/lastlog
        sfWaitForApt
        finishPreviousInstall

        sfRetry 3m 5 "sfWaitForApt && apt -y update"
        sfRetry 5m 5 "sfWaitForApt && apt-get install -qqy nfs-common"
        ;;

    rhel|centos)
        yum makecache fast
        yum install -y nfs-utils
        setsebool -P use_nfs_home_dirs 1
        sfFirewallAdd --add-service=nfs
        sfFirewallAdd --add-service=mountd
        sfFirewallAdd --add-service=rpc-bind
        sfFirewallReload
        systemctl restart rpcbind
        systemctl restart nfs-server
        systemctl restart nfs
        ;;

    *)
        echo "Unsupported OS flavor '$LINUX_KIND'!"
        exit 1
esac
