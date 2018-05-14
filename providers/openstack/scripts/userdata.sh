#!/bin/bash

adduser {{.User}} -gecos "" --disabled-password
echo "{{.User}} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

mkdir /home/{{.User}}/.ssh
echo "{{.Key}}" > /home/{{.User}}/.ssh/authorized_keys

# Create flag file to deactivate Welcome message on ssh
touch /home/{{.User}}/.hushlogin

echo "{{.ConfIF}}"

# Network interfaces configuration
{{ if .ConfIF }}
rm -f /etc/network/interfaces.d/50-cloud-init.cfg
mkdir -p /etc/network/interfaces.d
# Configure all network interfaces in dhcp
for IF in $(ls /sys/class/net)
do
   if [ $IF != "lo" ]
   then
        echo "auto ${IF}" >> /etc/network/interfaces.d/50-cloud-init.cfg
        echo "iface ${IF} inet dhcp" >> /etc/network/interfaces.d/50-cloud-init.cfg
   fi
done

systemctl restart networking
# Restart networkk interfaces except lo
# for IF in $(ls /sys/class/net)
# do
#     if [ $IF != "lo" ]
#     then
#         IF_UP = $(ip a |grep ${IF} | grep 'state UP' | wc -l)
#         if [ ${IF_UP} = "1" ]
#         then
#             ifconfig ${IF} down
#         fi
#         ifconfig ${IF} up
#     fi
# done
{{ end }}



# Acitvates IP forwarding
{{ if .IsGateway }}

PUBLIC_IP=$(curl ipinfo.io/ip)
PUBLIC_IF=$(netstat -ie | grep -B1 ${PUBLIC_IP} | head -n1 | awk '{print $1}')

PRIVATE_IP=''
for IF in $(ls /sys/class/net)
do
   if [ ${IF} != "lo" ] && [ ${IF} != ${PUBLIC_IF} ]
   then
        PRIVATE_IP=$(ip a |grep ${IF} | grep inet | awk '{print $2}' | cut -d '/' -f1)
   fi
done

if [ -z ${PRIVATE_IP} ]
then
    exit 1
fi
PRIVATE_IF=$(netstat -ie | grep -B1 ${PRIVATE_IP} | head -n1 | awk '{print $1}')

if [ ! -z $PUBLIC_IF ] && [ ! -z $PRIVATE_IF ]
then
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
sysctl -p /etc/sysctl.conf

cat <<- EOF > /sbin/routing
#!/bin/sh -
echo "activate routing"
iptables -t nat -A POSTROUTING -o ${PUBLIC_IF} -j MASQUERADE
iptables -A FORWARD -i ${PRIVATE_IF} -o ${PUBLIC_IF} -j ACCEPT
iptables -A FORWARD -i ${PUBLIC_IF} -o ${PRIVATE_IF} -m state --state RELATED,ESTABLISHED -j ACCEPT
EOF
chmod u+x /sbin/routing
cat <<- EOF > /etc/systemd/system/routing.service
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

systemctl enable routing
systemctl start routing
fi

{{ end }}

# Acitvates IP forwarding
{{ if .AddGateway }}
echo "AddGateway"

#GW=$(ip route show | grep default | cut -d ' ' -f3)
#if [ -z $GW ]
#then

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

#fi

{{ end }}
