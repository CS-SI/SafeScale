#!/usr/bin/env bash
#
# nfs_server_install.sh
#
# Installs and configures a NFS Server service

{{.CommonTools}}

echo "Install NFS server"

case $LINUX_KIND in
    debian|ubuntu)
        export DEBIAN_FRONTEND=noninteractive
        touch /var/log/lastlog
        chgrp utmp /var/log/lastlog
        chmod 664 /var/log/lastlog

        # VPL: I encountered the case where apt is locked between update and install... (!)
        wait_for_apt && apt-get update && wait_for_apt && apt-get install -qqy nfs-common nfs-kernel-server
        ;;

    rhel|centos)
        yum make-cache fast
        yum install -y nfs-kernel-server nfs-common
        ;;

    *)
        echo "Unsupported operating system '$OS_FLAVOR'"
        exit 1
        ;;
esac
exit 0