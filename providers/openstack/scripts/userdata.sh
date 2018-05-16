#!/bin/bash

# Redirects outputs to /var/tmp/user_data.log
exec 1<&-
exec 2<&-
exec 1<>/var/tmp/user_data.log
exec 2>&1

create_user() {
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
}

configure_network_debian() {
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
# Restart network interfaces except lo
#    for IF in $(ls /sys/class/net); do
#     if [ $IF != "lo" ]; then
#         IF_UP = $(ip a |grep ${IF} | grep 'state UP' | wc -l)
#         if [ ${IF_UP} = "1" ]; then
#             ifconfig ${IF} down
#         fi
#         ifconfig ${IF} up
#     fi
# done
}

configure_network_netplan() {
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
EOF
    netplan generate
    netplan apply
}

configure_network_redhat() {
    rm -f /etc/sysconfig/network-scripts/ifcfg-eth0
#    mkdir -p /etc/network/interfaces.d
    # Configure all network interfaces in dhcp
    for IF in $(ls /sys/class/net); do
        if [ $IF != "lo" ]; then
            cat <<EOF >/etc/sysconfig/network-scripts/ifcfg-$IF
EOF
        fi
        done

    systemctl restart networking
# Restart network interfaces except lo
#    for IF in $(ls /sys/class/net); do
#     if [ $IF != "lo" ]; then
#         IF_UP = $(ip a |grep ${IF} | grep 'state UP' | wc -l)
#         if [ ${IF_UP} = "1" ]; then
#             ifconfig ${IF} down
#         fi
#         ifconfig ${IF} up
#     fi
# done
}

configure_as_gateway() {
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

configure_gateway() {
    echo "AddGateway"

    GW=$(ip route show | grep default | cut -d ' ' -f3)
    if [ -z $GW ]; then

        cat <<-EOF > /etc/resolv.conf.gw
{{.ResolveConf}}
EOF

        cat <<- EOF > /sbin/gateway
#!/bin/sh -
echo "configure default gateway"
/sbin/route add default gw {{.GatewayIP}}
cp /etc/resolv.conf.gw /etc/resolv.conf
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
    fi
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
        {{end}}
        ;;

    redhat|centos)
        create_user
        {{if .IsGateway}}
        configure_as_gateway
        {{end}}
        {{if .AddGateway}}
        configure_gateway
        {{end}}
        ;;
    *)
        echo "Unsupported Linux distribution '$LINUX_KIND'!"
        exit 1
        ;;
esac

exit 0