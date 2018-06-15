#!/usr/bin/env bash
#
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

# Redirects outputs to /var/tmp/user_data.log
exec 1<&-
exec 2<&-
exec 1<>/var/tmp/user_data.log
exec 2>&1

create_user() {
    echo "Creating user {{.User}}..."
    useradd {{.User}} --home-dir /home/{{.User}} --shell /bin/bash --comment "" --create-home
    echo "{{.User}} ALL=(ALL) NOPASSWD:ALL" >>/etc/sudoers

    # Sets ssh conf
    mkdir /home/{{.User}}/.ssh
    echo "{{.Key}}" >>/home/{{.User}}/.ssh/authorized_keys
    chmod 0700 /home/{{.User}}/.ssh
    chmod -R 0600 /home/{{.User}}/.ssh/*

    # Create flag file to deactivate Welcome message on ssh
    touch /home/{{.User}}/.hushlogin

    # Ensures ownership
    chown -R gpac:gpac /home/{{.User}}
    echo done
}

configure_network_debian() {
    echo "Configuring network (debian-based)..."
    rm -f /etc/network/interfaces.d/50-cloud-init.cfg
    mkdir -p /etc/network/interfaces.d
    # Configure all network interfaces in dhcp
    for IF in $(ls /sys/class/net); do
        if [ $IF != "lo" ]; then
            echo "auto ${IF}" >> /etc/network/interfaces.d/50-cloud-init.cfg
            echo "iface ${IF} inet dhcp" >> /etc/network/interfaces.d/50-cloud-init.cfg
        fi
    done

    systemctl restart networking
    echo done
}

configure_network_netplan() {
    echo "Configuring network (netplan-based)..."

    mv -f /etc/netplan /etc/netplan.orig
    mkdir -p /etc/netplan
    cat <<EOF >/etc/netplan/50-cloud-init.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens3:
      dhcp4: true
    ens4:
      dhcp4: true
{{if .GatewayIP}}
      gateway4: {{.GatewayIP}}
{{end}}
EOF
    netplan generate
    netplan apply

    echo done
}

configure_network_redhat() {
    echo "Configuring network (redhat-based)..."

    # Configure all network interfaces in dhcp
    for IF in $(ls /sys/class/net); do
        if [ $IF != "lo" ]; then
            cat >/etc/sysconfig/network-scripts/ifcfg-$IF <<-EOF
DEVICE=$IF
BOOTPROTO=dhcp
ONBOOT=yes
EOF
        fi
    done
    systemctl restart network

    # Determines which interface must be used as default route
    PUBLIC_IP=$(curl ipinfo.io/ip 2>/dev/null)
    ROUTE_IF=eth0
    for IF in $(ls /sys/class/net); do
        [ $IF != "lo" ] && [ "$(ifconfig $IF | grep 'inet ' | tr -s ' ' ' ' | cut -d' ' -f3)" = "$PUBLIC_IP" ] && {
            ROUTE_IF=$IF
            break
        }
    done
    for IF in $(ls /sys/class/net); do
        [ $IF != "lo" ] && [ $IF != $ROUTE_IF ] && echo 'DEFROUTE="no"' >>/etc/sysconfig/network-scripts/ifcfg-$IF
    done
    systemctl restart network

    echo done
}

configure_as_gateway() {
    echo "Configuring host as gateway..."
    PUBLIC_IP=$(curl ipinfo.io/ip)
    PUBLIC_IF=$(netstat -ie | grep -B1 ${PUBLIC_IP} | head -n1 | awk '{print $1}')

    PRIVATE_IP=
    for IF in $(ls /sys/class/net); do
        if [ ${IF} != "lo" ] && [ ${IF} != "${PUBLIC_IF}" ]; then
            PRIVATE_IP=$(ip a |grep ${IF} | grep inet | awk '{print $2}' | cut -d '/' -f1)
        fi
    done

    [ -z ${PRIVATE_IP} ] && return 1

    PRIVATE_IF=$(netstat -ie | grep -B1 ${PRIVATE_IP} | head -n1 | awk '{print $1}')

    if [ ! -z $PRIVATE_IF ]; then
        sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
        sysctl -p /etc/sysctl.conf

        cat <<- EOF >/sbin/routing
#!/bin/sh -
echo "activate routing"
iptables -t nat -A POSTROUTING -o ${PUBLIC_IF} -j MASQUERADE
iptables -A FORWARD -i ${PRIVATE_IF} -o ${PUBLIC_IF} -j ACCEPT
iptables -A FORWARD -i ${PUBLIC_IF} -o ${PRIVATE_IF} -m state --state RELATED,ESTABLISHED -j ACCEPT
EOF

        cat <<- EOF >/etc/systemd/system/routing.service
[Unit]
Description=activate routing from ${PRIVATE_IF} to ${PUBLIC_IF}
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/routing

[Install]
WantedBy=multi-user.target
EOF

        if [ -z $PUBLIC_IF ]; then
            sed -i 's/-o //g; s/-i //g' /sbin/routing
            sed -i 's/(Description=.*) to[[:space:]*$/\\1/g' /etc/systemd/system/routing.service
        fi

        chmod u+x /sbin/routing

        systemctl enable routing
        systemctl start routing
    fi

    echo done
}

configure_dns_legacy() {
    cat <<-EOF > /etc/resolv.conf
{{.ResolveConf}}
EOF
}

configure_dns_resolvconf() {
    cat <<-EOF >/etc/resolvconf/resolv.conf.d/original
{{.ResolveConf}}
EOF
    rm -f /etc/resolvconf/resolv.conf.d/tail
    cd /etc/resolvconf/resolv.conf.d && /etc/resolvconf/update.d/libc
}

configure_gateway() {
    echo "Configuring default router to {{.GatewayIP}}"

    route del -net default

    cat <<- EOF > /sbin/gateway
#!/bin/sh -
echo "configure default gateway"
/sbin/route add default gw {{.GatewayIP}}

EOF
    chmod u+x /sbin/gateway
    cat <<- EOF > /etc/systemd/system/gateway.service
Description=create default gateway
After=network.target

[Service]
ExecStart=/sbin/gateway

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable gateway
    systemctl start gateway

    echo done
}

LINUX_KIND=$(cat /etc/os-release | grep "^ID=" | cut -d= -f2 | sed 's/"//g')
VERSION_ID=$(cat /etc/os-release | grep "^VERSION_ID=" | cut -d= -f2 | sed 's/"//g')

case $LINUX_KIND in
    debian)
        create_user
        {{if .ConfIF}}
        configure_network_debian
        {{end}}
        {{if .IsGateway}}
        configure_as_gateway
        {{end}}
        {{if .AddGateway}}
        configure_gateway
        configure_dns_legacy
        {{end}}
        ;;

    ubuntu)
        create_user
        {{if .ConfIF}}
        if [[ "$VERSION_ID" = "17.10" || "$VERSION_ID" = "18.04" ]]; then
            configure_network_netplan
        else
            configure_network_debian
        fi
        {{end}}
        {{if .IsGateway}}
        configure_as_gateway
        {{end}}
        {{if .AddGateway}}
        configure_gateway
        configure_dns_resolvconf
        {{end}}
        ;;

    redhat|centos)
        create_user
        {{if .ConfIF}}
        configure_network_redhat
        {{end}}
        {{if .IsGateway}}
        configure_as_gateway
        {{end}}
        {{if .AddGateway}}
        configure_gateway
        configure_dns_legacy
        {{end}}
        ;;
    *)
        echo "Unsupported Linux distribution '$LINUX_KIND'!"
        exit 1
        ;;
esac

exit 0
