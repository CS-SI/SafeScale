#!/bin/bash
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

set -u -o pipefail

function print_error {
    read line file <<<$(caller)
    echo "An error occurred in line $line of file $file:" "{"`sed "${line}q;d" "$file"`"}" >&2
}
trap print_error ERR

# Redirects outputs to /var/tmp/user_data.log
exec 1<&-
exec 2<&-
exec 1<>/var/tmp/user_data.log
exec 2>&1
set -x

sfDetectFacts() {
   local -g LINUX_KIND=$(cat /etc/os-release | grep "^ID=" | cut -d= -f2 | sed 's/"//g')
   local -g VERSION_ID=$(cat /etc/os-release | grep "^VERSION_ID=" | cut -d= -f2 | sed 's/"//g')
}
sfDetectFacts

sfFinishPreviousInstall() {
    local unfinished=$(dpkg -l | grep -v ii | grep -v rc | tail -n +4 | wc -l)
    if [[ "$unfinished" == 0 ]]; then echo "good"; else sudo dpkg --configure -a --force-all; fi
}
export -f sfFinishPreviousInstall

sfWaitForApt() {
    sfWaitLockfile apt /var/{lib/{dpkg,apt/lists},cache/apt/archives}/lock
}

sfWaitLockfile() {
    local ROUNDS=600
    name=$1
    shift
    params=$@
    echo "check $name lock"
    echo ${params}
    if fuser ${params} &>/dev/null; then
        echo "${name} is locked, waiting... "
        local i
        for i in $(seq $ROUNDS); do
            sleep 6
            fuser ${params} &>/dev/null || break
        done
        if [ $i -ge $ROUNDS ]; then
            echo "Timed out waiting (1 hour!) for ${name} lock!"
            exit 100
        else
            t=$(($i*6))
            echo "${name} is unlocked (waited $t seconds), continuing."
        fi
    else
        echo "${name} is ready"
    fi
}

fw_i_accept() {
    iptables -A INPUT -j ACCEPT $*
}
fw_f_accept() {
    iptables -A FORWARD -j ACCEPT $*
}

PR_IPs=
PR_IFs=
PU_IP=
PU_IF=
i_PR_IF=
o_PR_IF=

sfSaveIptablesRules() {
   case $LINUX_KIND in
       rhel|centos) iptables-save >/etc/sysconfig/iptables;;
       debian|ubuntu) iptables-save >/etc/iptables/rules.v4;;
   esac
}

create_user() {
    echo "Creating user {{.User}}..."
    useradd {{.User}} --home-dir /home/{{.User}} --shell /bin/bash --comment "" --create-home
    echo "{{.User}}:{{.Password}}" | chpasswd
    groupadd -r docker
    usermod -aG docker {{.User}}
    SUDOERS_FILE=/etc/sudoers.d/{{.User}}
    [ ! -d "$(dirname $SUDOERS_FILE)" ] && SUDOERS_FILE=/etc/sudoers
    cat >>$SUDOERS_FILE <<-'EOF'
Defaults:{{.User}} !requiretty
{{.User}} ALL=(ALL) NOPASSWD:ALL
EOF

    mkdir /home/{{.User}}/.ssh
    echo "{{.PublicKey}}" >>/home/{{.User}}/.ssh/authorized_keys
    echo "{{.PrivateKey}}" >/home/{{.User}}/.ssh/id_rsa
    chmod 0700 /home/{{.User}}/.ssh
    chmod -R 0600 /home/{{.User}}/.ssh/*

    for i in /home/{{.User}}/.hushlogin /home/{{.User}}/.cloud-warnings.skip; do
        touch $i
        chown root:{{.User}} $i
        chmod ug+r-wx,o-rwx $i
    done

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
EOF

    chown -R {{.User}}:{{.User}} /home/{{.User}}
    echo done
}

# Don't request dns name servers from DHCP server
configure_dhcp_client() {
    sed -i -e 's/, domain-name-servers//g' /etc/dhcp/dhclient.conf
}

# Configure network for Debian distribution
configure_network_debian() {
    echo "Configuring network (debian-based)..."
    local path=/etc/network/interfaces.d
    local cfg=$path/50-cloud-init.cfg
    rm -f $cfg
    mkdir -p $path

    for IF in $(get_nic_names); do
        echo "auto ${IF}" >>$cfg
        echo "iface ${IF} inet dhcp" >>$cfg
    done

    configure_dhcp_client

    /sbin/dhclient || true
    systemctl restart networking
    echo done
}

# search for network device names
get_nic_names() {
    echo $(for i in $(find /sys/devices -name net -print | grep -v virtual); do ls $i; done)
}

ip2long() {
    IFS=. read -r a b c d <<<$*
    echo $((a * 256 ** 3 + b * 256 ** 2 + c * 256 + d))
}

is_ip_private() {
    ip=$1
    ipv=$(ip2long $ip)
    for r in "192.168.0.0-192.168.255.255" "172.16.0.0-172.31.255.255" "10.0.0.0-10.255.255.255"; do
        bv=$(ip2long $(cut -d- -f1 <<<$r))
        ev=$(ip2long $(cut -d- -f2 <<<$r))
        [ $ipv -ge $bv -a $ipv -le $ev ] && return 0
    done
    return 1
}

substring_diff() {
    read -a l1 <<<$1
    read -a l2 <<<$2
    echo ${l1[@]} ${l2[@]} | tr ' ' '\n' | sort | uniq -u
}

# Configure network using netplan
configure_network_netplan() {
    echo "Configuring network (netplan-based)..."

    mv -f /etc/netplan /etc/netplan.orig
    mkdir -p /etc/netplan
    NICS=$(get_nic_names)
    fname=/etc/netplan/50-cloud-init.yaml
    cat <<-'EOF' >$fname
network:
  version: 2
  renderer: networkd
  ethernets:
EOF
    for i in $NICS; do
        cat <<-EOF >>$fname
    $i:
      dhcp4: true
EOF
    done
{{- if .GatewayIP }}
    cat <<-'EOF' >>$fname
      gateway4: {{.GatewayIP}}
EOF
{{- end }}

    netplan generate
    configure_dhcp_client
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
    #systemctl restart network

    # Configure all network interfaces in dhcp
    for IF in $(ls /sys/class/net); do
        if [ $IF != "lo" ]; then
            cat >/etc/sysconfig/network-scripts/ifcfg-$IF <<-EOF
DEVICE=$IF
BOOTPROTO=dhcp
ONBOOT=yes
EOF
            {{- if .DNSServers }}
            i=1
            {{- range .DNSServers }}
            echo "DNS$i={{ . }}" >>/etc/sysconfig/network-scripts/ifcfg-$IF
            i=$((i+1))
            {{- end }}
            {{- else }}
            echo "DNS1=1.1.1.1" >>/etc/sysconfig/network-scripts/ifcfg-$IF
            {{- end }}
        fi
    done
    # Disable resolv.conf by dhcp
    mkdir -p /etc/dhcp
    HOOK_FILE=/etc/dhcp/dhclient-enter-hooks
    cat >>$HOOK_FILE <<EOF
make_resolv_conf() {
    :
}
EOF
    chmod +x $HOOK_FILE
    systemctl restart network

    echo done
}

reset_fw() {
    case $LINUX_KIND in
        debian|ubuntu)
            systemctl stop ufw &>/dev/null
            systemctl disable ufw &>/dev/null
            sfWaitForApt && apt purge -q ufw &>/dev/null
            ;;

        rhel|centos)
            systemctl disable firewalld &>/dev/null
            systemctl stop firewalld &>/dev/null
            systemctl mask firewalld &>/dev/null
            yum remove -y firewalld &>/dev/null
            ;;
    esac

}

enable_iptables() {
    case $LINUX_KIND in
        debian|ubuntu)
            sfWaitForApt && apt update
            sfWaitForApt && apt install -y -q iptables-persistent
            [ $? -ne 0 ] && {
                mkdir -p /etc/iptables /etc/network/if-pre-up.d
                cd /etc/network/if-pre-up.d
                cat >iptables <<-'EOF'
#!/bin/sh
DIR=/etc/iptables
mkdir -p $DIR
[ -f $DIR/rules.v4 ] && iptables-restore <$DIR/rules.v4
EOF
                chmod a+rx iptables
            }
            ;;

        rhel|centos)
            yum install -y iptables-services
            systemctl enable iptables
            systemctl enable ip6tables
            systemctl start iptables
            systemctl start ip6tables
            ;;
    esac

    # We flush the current firewall rules possibly introduced by iptables pkg
    iptables -F
    sfSaveIptablesRules
}

configure_as_gateway() {
    echo "Configuring host as gateway..."

    echo "removing ufw and reset fW rules"
    reset_fw
    echo "enabling iptables"
    enable_iptables

    echo "configuring iptables"
    # Change default policy for table filter chain INPUT to be DROP (block everything)
    iptables -P INPUT DROP
    # Opens up the required (loopback comm, ping, ssh, established connection)
    fw_i_accept -i lo
    fw_i_accept -p icmp --icmp-type 8 -s 0/0 -m state --state NEW,ESTABLISHED,RELATED
    fw_i_accept -p icmp --icmp-type 0 -s 0/0 -m state --state ESTABLISHED,RELATED
    fw_i_accept -m conntrack --ctstate ESTABLISHED,RELATED
    fw_i_accept -p tcp --dport ssh

    nics=$(get_nic_names)
    for IF in $nics; do
        IP=$(ip a | grep $IF | grep inet | awk '{print $2}' | cut -d '/' -f1)
        [ ! -z $IP ] && {
            is_ip_private $IP && {
                PR_IFs="$PR_IFs $IF"
                PR_IPs="$PR_IPs $IP"
            }
        }
    done

    [ -z $PR_IPs ] && echo "no private ip!" && return 1

    PU_IFs=$(substring_diff "$nics" "$PR_IFs" )
    if [ -z $PU_IFs ]; then
        PU_IP=$(curl ipinfo.io/ip 2>/dev/null)
        PU_IF=$(netstat -ie | grep -B1 $PU_IP | head -n1 | awk '{print $1}')
    else
        PU_IP=$(ip route get 8.8.8.8 | awk -F"dev " 'NR==1{split($2,a," ");print a[1]}' 2>/dev/null)
        PU_IF=${PU_IF%%:}
    fi

    if [ ! -z $PR_IFs ]; then
        # Enable forwarding
        for i in /etc/sysctl.d/* /etc/sysctl.conf; do
            grep -v "net.ipv4.ip_forward=" $i >${i}.new
            mv -f ${i}.new ${i}
        done
        echo "net.ipv4.ip_forward=1" >/etc/sysctl.d/98-forward.conf
        systemctl restart systemd-sysctl

        # Routing
        for IF in $PR_IFs; do
            o_PR_IF="-o $IF"
            i_PR_IF="-i $IF"
            o_PU_IF=
            i_PU_IF=
            [ ! -z $PU_IF ] && o_PU_IF="-o $PU_IF" && i_PU_IF="-i $PU_IF"
            iptables -t nat -A POSTROUTING -j MASQUERADE $o_PU_IF
            fw_f_accept $i_PR_IF $o_PU_IF -s {{ .CIDR }}
            fw_f_accept $i_PU_IF $o_PR_IF -m state --state RELATED,ESTABLISHED
        done
    fi

    sfSaveIptablesRules

    grep -vi AllowTcpForwarding /etc/ssh/sshd_config >/etc/ssh/sshd_config.new
    echo "AllowTcpForwarding yes" >>/etc/ssh/sshd_config.new
    mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config
    systemctl restart ssh

    echo done
}

configure_dns_legacy() {
    echo "Configuring /etc/resolv.conf..."
    rm -f /etc/resolv.conf
    {{- if .DNSServers }}
    if [[ -e /etc/dhcp/dhclient.conf ]]; then echo "prepend domain-name-servers {{range .DNSServers}}{{.}} {{end}};" >> /etc/dhcp/dhclient.conf; else echo "Dhclient.conf not modified"; fi
    {{- else }}
    if [[ -e /etc/dhcp/dhclient.conf ]]; then echo "prepend domain-name-servers 1.1.1.1;" >> /etc/dhcp/dhclient.conf; else echo "Dhclient.conf not modified"; fi
    {{- end }}
    cat <<-'EOF' >/etc/resolv.conf
{{- if .DNSServers }}
  {{- range .DNSServers }}
nameserver {{ . }}
  {{- end }}
{{- else }}
nameserver 1.1.1.1
{{- end }}
EOF
    echo done
}

configure_dns_resolvconf() {
    echo "Configuring resolvconf..."

    cat <<-'EOF' >/etc/resolvconf/resolv.conf.d/head
{{- if .DNSServers }}
  {{- range .DNSServers }}
nameserver {{ . }}
  {{- end }}
{{- else }}
nameserver 1.1.1.1
{{- end }}
EOF
    #rm -f /etc/resolvconf/resolv.conf.d/tail
    resolvconf -u
    echo done
}

configure_dns_systemd_resolved() {
    echo "Configuring systemd-resolved..."

{{- if not .GatewayIP }}
    rm -f /etc/resolv.conf
    ln -s /run/systemd/resolve/resolv.conf /etc
{{- end }}

    cat <<-'EOF' >/etc/systemd/resolved.conf
[Resolve]
{{- if .DNSServers }}
DNS={{ range .DNSServers }}{{ . }} {{ end }}
{{- else }}
DNS=1.1.1.1
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
    echo done
}

configure_gateway() {
    echo "Configuring default route by {{ .GatewayIP }}"

    reset_fw
    route del -net default &>/dev/null

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
Restart=on-failure
StartLimitIntervalSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable gateway
    systemctl start gateway

    enable_iptables

    echo done
}

configure_gateway_redhat() {
    echo "Configuring default router to {{ .GatewayIP }}"

    reset_fw

    route del -net default &>/dev/null
    route add default gw {{.GatewayIP}}
    echo "GATEWAY={{.GatewayIP}}" >/etc/sysconfig/network

    enable_iptables

    echo done
}

install_drivers_nvidia() {
    case $LINUX_KIND in
        ubuntu)
            add-apt-repository -y ppa:graphics-drivers &>/dev/null
            apt update &>/dev/null
            apt -y install nvidia-410 &>/dev/null || apt -y install nvidia-driver-410 &>/dev/null
            ;;
        debian)
            if [ ! -f /etc/modprobe.d/blacklist-nouveau.conf ]; then
                echo -e "blacklist nouveau\nblacklist lbm-nouveau\noptions nouveau modeset=0\nalias nouveau off\nalias lbm-nouveau off" >>/etc/modprobe.d/blacklist-nouveau.conf
                rmmod nouveau
            fi
            apt update &>/dev/null && apt install -y dkms build-essential linux-headers-$(uname -r) gcc make &>/dev/null
            dpkg --add-architecture i386 &>/dev/null
            apt update &>/dev/null && apt install -y lib32z1 lib32ncurses5 &>/dev/null
            wget http://us.download.nvidia.com/XFree86/Linux-x86_64/410.78/NVIDIA-Linux-x86_64-410.78.run &>/dev/null
            bash NVIDIA-Linux-x86_64-410.78.run -s
            ;;
        centos)
            if [ ! -f /etc/modprobe.d/blacklist-nouveau.conf ]; then
                echo -e "blacklist nouveau\noptions nouveau modeset=0" >>/etc/modprobe.d/blacklist-nouveau.conf
                dracut --force
                rmmod nouveau
            fi
            yum -y -q install kernel-devel.$(uname -i) kernel-headers.$(uname -i) gcc make &>/dev/null
            wget http://us.download.nvidia.com/XFree86/Linux-x86_64/410.78/NVIDIA-Linux-x86_64-410.78.run
            bash NVIDIA-Linux-x86_64-410.78.run -s
            rm NVIDIA-Linux-x86_64-410.78.run
            ;;
        *)
            echo "Unsupported Linux distribution '$LINUX_KIND'!"
            exit 1
            ;;
    esac
}

install_packages() {
     case $LINUX_KIND in
        ubuntu|debian)
            apt install -y -qq pciutils &>/dev/null
            ;;
        redhat|centos)
            yum install -y -q pciutils wget &>/dev/null
            ;;
        *)
            echo "Unsupported Linux distribution '$LINUX_KIND'!"
            exit 1
            ;;
     esac
}

# Disable cloud-init automatic network configuration to be sure our configuration won't be replaced
disable_cloudinit_network_autoconf() {
    fname=/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
    mkdir -p $(dirname $fname)
    echo "network: {config: disabled}" >$fname
}

# ---- Main

disable_cloudinit_network_autoconf

case $LINUX_KIND in
    debian|ubuntu)
        export DEBIAN_FRONTEND=noninteractive
        systemctl stop apt-daily.service &>/dev/null
        systemctl kill --kill-who=all apt-daily.service &>/dev/null

        create_user

        systemctl status systemd-resolved &>/dev/null && configure_dns_systemd_resolved || {
            systemctl status resolvconf &>/dev/null && configure_dns_resolvconf || \
            configure_dns_legacy
        }

        {{- if .ConfIF }}
        which netplan &>/dev/null && {
            configure_network_netplan && sleep 5
        } || {
            systemctl status networking &>/dev/null && configure_network_debian
        }
        {{- end }}

        {{- if .IsGateway }}
        configure_as_gateway
        {{- end }}

        {{- if .AddGateway }}
        configure_gateway
        {{- end }}

        ;;

    redhat|centos)
        create_user
        {{- if .ConfIF }}
        configure_network_redhat
        {{- end }}
        configure_dns_legacy
        {{- if .IsGateway }}
        configure_as_gateway
        {{- end }}
        {{- if .AddGateway }}
        configure_gateway_redhat
        {{- end }}
        ;;
    *)
        echo "Unsupported Linux distribution '$LINUX_KIND'!"
        exit 1
        ;;
esac

touch /etc/cloud/cloud-init.disabled
install_packages
lspci | grep -i nvidia &>/dev/null && install_drivers_nvidia

echo -n "${LINUX_KIND},$(date +%Y/%m/%d-%H:%M:%S)" >/var/tmp/user_data.done
set +x
systemctl reboot
exit 0
