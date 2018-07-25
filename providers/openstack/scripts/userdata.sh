#!/bin/bash
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

detect_facts() {
   local -g LINUX_KIND=$(cat /etc/os-release | grep "^ID=" | cut -d= -f2 | sed 's/"//g')
   local -g VERSION_ID=$(cat /etc/os-release | grep "^VERSION_ID=" | cut -d= -f2 | sed 's/"//g')
}
detect_facts

# Some functions and global variables related to iptables (the idea being to reduce size of generated
# user_data.sh script transmitted to the host)
fw_i_accept() {
    iptables -A INPUT -j ACCEPT $*
}
fw_f_accept() {
    iptables -A FORWARD -j ACCEPT $*
}

PR_IP=
PR_IF=
PU_IP=
PU_IF=
i_PR_IF=
i_PU_IF=
o_PR_IF=
o_PU_IF=

save_iptables_rules() {
   case $LINUX_KIND in
       rhel|centos) iptables-save >/etc/sysconfig/iptables ;;
       debian|ubuntu) iptables-save >/etc/iptables/rules.v4 ;;
   esac
}

# Creates user gpac
create_user() {
    echo "Creating user {{ .User }}..."
    useradd {{ .User }} --home-dir /home/{{ .User }} --shell /bin/bash --comment "" --create-home
    echo "gpac:{{ .Password }}" | chpasswd
    echo "{{ .User }} ALL=(ALL) NOPASSWD:ALL" >>/etc/sudoers

    # Sets ssh config
    mkdir /home/{{ .User }}/.ssh
    echo "{{ .Key }}" >>/home/{{ .User }}/.ssh/authorized_keys
    chmod 0700 /home/{{ .User }}/.ssh
    chmod -R 0600 /home/{{ .User }}/.ssh/*

    # Create flag file to deactivate Welcome message on ssh
    touch /home/{{ .User }}/.hushlogin

    # Ensures ownership
    chown -R {{ .User }}:{{ .User }} /home/{{ .User }}
    echo done
}

# Configure network for Debian distribution
configure_network_debian() {
    echo "Configuring network (debian-based)..."
    local path=/etc/network/interfaces.d
    local cfg=$path/50-cloud-init.cfg
    rm -f $cfg
    mkdir -p $path
    # Configure all network interfaces in dhcp
    for IF in $(ls /sys/class/net); do
        if [ $IF != "lo" ]; then
            echo "auto ${IF}" >>$cfg
            echo "iface ${IF} inet dhcp" >>$cfg
        fi
    done

    systemctl restart networking
    echo done
}

# Configure network using netplan
configure_network_netplan() {
    echo "Configuring network (netplan-based)..."

    mv -f /etc/netplan /etc/netplan.orig
    mkdir -p /etc/netplan
    cat <<-'EOF' >/etc/netplan/50-cloud-init.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens3:
      dhcp4: true
    ens4:
      dhcp4: true
{{- if .GatewayIP }}
      gateway4: {{ .GatewayIP }}
{{- end }}
EOF
    netplan generate
    netplan apply

    echo done
}

# Configure network for redhat-like distributions (rhel, centos, ...)
configure_network_redhat() {
    echo "Configuring network (redhat-like)..."

    # We don't want NetworkManager
    systemctl disable NetworkManager &>/dev/null
    systemctl stop NetworkManager &>/dev/null
    yum remove -y NetworkManager &>/dev/null
    systemctl restart network

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

    echo done
}

reset_iptables() {
    case $LINUX_KIND in
        debian|ubuntu)
            systemctl stop ufw &>/dev/null
            systemctl disable ufw &>/dev/null
            apt purge ufw &>/dev/null
            apt install -y iptables-persistent
            ;;

        rhel|centos)
            systemctl disable firewalld &>/dev/null
            systemctl stop firewalld &>/dev/null
            systemctl mask firewalld &>/dev/null
            yum remove -y firewalld &>/dev/null
            yum install -y iptables-services
            systemctl enable iptables
            systemctl enable ip6tables
            systemctl start iptables
            systemctl start ip6tables
            ;;
    esac

    # We flush the current firewall rules possibly introduced by iptables service
    iptables-save | awk '/^[*]/ { print $1 }
                         /^:[A-Z]+ [^-]/ { print $1 " ACCEPT" ; }
                         /COMMIT/ { print $0; }' | iptables-restore
}

install_squid() {
    case $LINUX_KIND in
        rhel|centos)
            yum install -y squid;;
        debian|ubuntu)
            apt-get install -y squid;;
    esac

    for IF in lo $PR_IF; do
        iptables -t nat -A PREROUTING -i $IF -p tcp -m multiport --dport 80,443 -j REDIRECT --to-port 3128
        fw_i_accept -m state --state NEW,ESTABLISHED,RELATED -i $IF -p tcp --dport 3128
    done
    #iptables -A OUTPUT -j ACCEPT -m state --state NEW,ESTABLISHED,RELATED -o $PU_IF -p tcp --dport 80
    fw_i_accept -m state --state ESTABLISHED,RELATED $i_PU_IF -p tcp -m multiport --sport 80,443
    #iptables -A OUTPUT -j ACCEPT -m state --state ESTABLISHED,RELATED -o $PR_IF -p tcp --sport 80
}

configure_as_gateway() {
    echo "Configuring host as gateway..."

    reset_iptables

    # Change default policy for table filter chain INPUT to be DROP (block everything)
    iptables -P INPUT DROP
    # Opens up the required (loopback comm, ping, ssh, established connection)
    fw_i_accept -i lo
    fw_i_accept -p icmp --icmp-type 8 -s 0/0 -m state --state NEW,ESTABLISHED,RELATED
    fw_i_accept -p icmp --icmp-type 0 -s 0/0 -m state --state ESTABLISHED,RELATED
    fw_i_accept -m conntrack --ctstate ESTABLISHED,RELATED
    fw_i_accept -p tcp --dport ssh

    PU_IP=$(curl ipinfo.io/ip 2>/dev/null)
    PU_IF=$(netstat -ie | grep -B1 ${PU_IP} | head -n1 | awk '{print $1}')
    PU_IF=${PU_IF%%:}

    for IF in $(ls /sys/class/net); do
        if [ ${IF} != "lo" ] && [ ${IF} != "${PU_IF}" ]; then
            PR_IP=$(ip a |grep ${IF} | grep inet | awk '{print $2}' | cut -d '/' -f1)
        fi
    done

    [ -z ${PR_IP} ] && return 1

    PR_IF=$(netstat -ie | grep -B1 ${PR_IP} | head -n1 | awk '{print $1}')
    PR_IF=${PR_IF%%:}

    if [ ! -z $PR_IF ]; then
        # Enable forwarding
        for i in /etc/sysctl.d/* /etc/sysctl.conf; do
            grep -v "net.ipv4.ip_forward=" $i >${i}.new
            mv -f ${i}.new ${i}
        done
        echo "net.ipv4.ip_forward=1" >/etc/sysctl.d/98-forward.conf
        systemctl restart systemd-sysctl

        # Routing
        o_PR_IF="-o $PR_IF"
        i_PR_IF="-i $PR_IF"
        [ ! -z $PU_IF ] && o_PU_IF="-o $PU_IF" && i_PU_IF="-i $PU_IF"
        iptables -t nat -A POSTROUTING -j MASQUERADE $o_PU_IF
        fw_f_accept $i_PR_IF $o_PU_IF
        fw_f_accept $i_PU_IF $o_PR_IF -m state --state RELATED,ESTABLISHED
    fi

    #install_squid

    save_iptables_rules

    echo done
}

configure_dns_legacy() {
    echo "Configuring /etc/resolv.conf..."

    cat <<-'EOF' >/etc/resolv.conf
{{- if .DNSServers }}
  {{- range .DNSServers }}
nameserver {{ . }}
  {{- end }}
{{- end }}
EOF
}

configure_dns_resolvconf() {
    echo "Configuring resolvconf..."

    cat <<-'EOF' >/etc/resolvconf/resolv.conf.d/original
{{- if .DNSServers }}
  {{- range .DNSServers }}
nameserver {{ . }}
  {{- end }}
{{- end }}
EOF
    rm -f /etc/resolvconf/resolv.conf.d/tail
    cd /etc/resolvconf/resolv.conf.d && /etc/resolvconf/update.d/libc
}

configure_dns_systemd_resolved() {
    echo "Configuring systemd-resolved..."

    cat <<-'EOF' >/etc/systemd/resolved.conf
[Resolve]
{{- if .DNSServers }}
DNS={{ range .DNSServers }}{{ . }} {{ end }}
{{- else }}
DNS=
{{- end}}
#FallbackDNS=
#Domains=
#LLMNR=no
#MulticastDNS=no
#DNSSEC=no
Cache=yes
DNSStubListener=yes
EOF
    systemctl restart systemd-resolved
}

configure_gateway() {
    echo "Configuring default router to {{ .GatewayIP }}"

    reset_iptables

    route del -net default

    cat <<-'EOF' > /sbin/gateway
#!/bin/sh -
echo "configure default gateway"
/sbin/route add -net default gw {{ .GatewayIP }}
EOF
    chmod u+x /sbin/gateway
    cat <<-'EOF' > /etc/systemd/system/gateway.service
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

case $LINUX_KIND in
    debian|ubuntu)
        create_user
        {{- if .ConfIF }}
        systemctl status systemd-networkd &>/dev/null && configure_network_netplan || configure_network_debian
        {{- end }}
        {{- if .IsGateway }}
        configure_as_gateway
        {{- else if .AddGateway }}
        systemctl status systemd-resolved &>/dev/null && configure_dns_systemd_resolved || configure_dns_resolvconf
        configure_gateway
        {{- end }}
        ;;

    redhat|centos)
        create_user
        {{- if .ConfIF }}
        configure_network_redhat
        {{- end }}
        {{- if .IsGateway }}
        configure_as_gateway
        {{- else if .AddGateway }}
        configure_dns_legacy
        configure_gateway
        {{- end }}
        ;;
    *)
        echo "Unsupported Linux distribution '$LINUX_KIND'!"
        exit 1
        ;;
esac

>/var/tmp/userdata.done
exit 0
