#!/usr/bin/env bash
#
# Installs and configures

{{.CommonTools}}

echo "Install NFS client"
case $LINUX_KIND in
    debian|ubuntu)
        export DEBIAN_FRONTEND=noninteractive
        touch /var/log/lastlog
        chgrp utmp /var/log/lastlog
        chmod 664 /var/log/lastlog

        wait_for_apt && apt-get -y update && wait_for_apt && apt-get install -qqy nfs-common
        ;;

    rhel|centos)
        yum make-cache fast
        yum install -y nfs-server
        ;;

    *)
        echo "Unsupported OS flavor '$LINUX_KIND'!"
        exit 1
esac

exit 0