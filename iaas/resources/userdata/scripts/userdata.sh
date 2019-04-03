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

{{.BashHeader}}

print_error() {
    read line file <<<$(caller)
    echo "An error occurred in line $line of file $file:" "{"`sed "${line}q;d" "$file"`"}" >&2
}
trap print_error ERR

fail() {
    echo -n "$1,${LINUX_KIND},$(date +%Y/%m/%d-%H:%M:%S)" >/var/tmp/user_data.done
    exit $1
}

# Redirects outputs to /var/tmp/user_data.log
exec 1<&-
exec 2<&-
exec 1<>/var/tmp/user_data.log
exec 2>&1
set -x

LINUX_KIND=
VERSION_ID=

sfDetectFacts() {
    [ -f /etc/os-release ] && {
        . /etc/os-release
        LINUX_KIND=$ID
    } || {
        which lsb_release &>/dev/null && {
            LINUX_KIND=$(lsb_release -is)
            LINUX_KIND=${LINUX_KIND,,}
            VERSION_ID=$(lsb_release -rs | cut -d. -f1)
        } || {
            [ -f /etc/redhat-release ] && {
                LINUX_KIND=$(cat /etc/redhat-release | cut -d' ' -f1)
                LINUX_KID=${LINUX_KIND,,}
                VERSION_ID=$(cat /etc/redhat-release | cut -d' ' -f3 | cut -d. -f1)
            }
        }
    }
}
sfDetectFacts

sfFinishPreviousInstall() {
    local unfinished=$(dpkg -l | grep -v ii | grep -v rc | tail -n +4 | wc -l)
    if [[ "$unfinished" == 0 ]]; then echo "good"; else sudo dpkg --configure -a --force-all; fi
}
export -f sfFinishPreviousInstall

sfWaitForApt() {
    sfFinishPreviousInstall || true
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

sfSaveIptablesRules() {
   case $LINUX_KIND in
       rhel|centos) iptables-save >/etc/sysconfig/iptables;;
       debian|ubuntu) iptables-save >/etc/iptables/rules.v4;;
   esac
}

fw_i_accept() {
    iptables -A INPUT -j ACCEPT $*
}

fw_f_accept() {
    iptables -A FORWARD -j ACCEPT $*
}

reset_fw() {
    case $LINUX_KIND in
        debian|ubuntu)
            systemctl stop ufw &>/dev/null
            systemctl disable ufw &>/dev/null
            sfWaitForApt && {
                apt purge -qy ufw &>/dev/null || fail 192
            }
            sfWaitForApt && apt update
            sfWaitForApt && {
                apt install -qy iptables-persistent || {
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
            }
            ;;

        rhel|centos)
            [ $VERSION_ID ge 7 ] && {
                systemctl disable firewalld &>/dev/null
                systemctl stop firewalld &>/dev/null
                systemctl mask firewalld &>/dev/null
                yum remove -y firewalld &>/dev/null || fail 193
                yum install -y iptables-services || fail 194
                systemctl enable iptables
                systemctl enable ip6tables
                systemctl start iptables
                systemctl start ip6tables
            }
            ;;
    esac

    # We flush the current firewall rules possibly introduced by iptables pkg
    iptables -F
    sfSaveIptablesRules
}

NICS=
# PR_IPs=
PR_IFs=
PU_IP=
PU_IF=
i_PR_IF=
o_PR_IF=

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
# Don't update default route
configure_dhclient() {
    sed -i -e 's/, domain-name-servers//g' /etc/dhcp/dhclient.conf

    HOOK_FILE=/etc/dhcp/dhclient-enter-hooks
    cat >>$HOOK_FILE <<-EOF
make_resolv_conf() {
    :
}

{{- if not .IsGateway }}
unset new_routers
{{- end}}
EOF
    chmod +x $HOOK_FILE
}

ip2long() {
    local a b c d
    IFS=. read -r a b c d <<<$*
    echo $(((((((a << 8) | b) << 8) | c) << 8) | d))
}

long2ip() {
    local ui32=$1
    local ip n
    for n in 1 2 3 4; do
        ip=$((ui32 & 0xff))${ip:+.}$ip
        ui32=$((ui32 >> 8))
    done
    echo $ip
}

cidr2netmask() {
    local bits=${1#*/}
    local mask=$((0xffffffff << (32-$bits)))
    long2ip $mask
}

cidr2broadcast()
{
    local base=${1%%/*}
    local bits=${1#*/}
    local long=$(ip2long $base); shift
    local mask=$((0xffffffff << (32-$bits))); shift
    long2ip $((long | ~mask))
}

cidr2network()
{
    local base=${1%%/*}
    local bits=${1#*/}
    local long=$(ip2long $base); shift
    local mask=$((0xffffffff << (32-$bits))); shift
    long2ip $((long & mask))
}

cidr2iprange() {
    local network=$(cidr2network $1)
    local broadcast=$(cidr2broadcast $1)
    echo ${network}-${broadcast}
}

is_ip_private() {
    ip=$1
    ipv=$(ip2long $ip)

{{ if .EmulatedPublicNet}}
    r=$(cidr2iprange {{ .EmulatedPublicNet }})
    bv=$(ip2long $(cut -d- -f1 <<<$r))
    ev=$(ip2long $(cut -d- -f2 <<<$r))
    [ $ipv -ge $bv -a $ipv -le $ev ] && return 0
{{- end }}
    for r in "192.168.0.0-192.168.255.255" "172.16.0.0-172.31.255.255" "10.0.0.0-10.255.255.255"; do
        bv=$(ip2long $(cut -d- -f1 <<<$r))
        ev=$(ip2long $(cut -d- -f2 <<<$r))
        [ $ipv -ge $bv -a $ipv -le $ev ] && return 0
    done
    return 1
}

identify_nics() {
    NICS=$(for i in $(find /sys/devices -name net -print | grep -v virtual); do ls $i; done)
    NICS=${NICS/[[:cntrl:]]/ }

    for IF in $NICS; do
        IP=$(ip a | grep $IF | grep inet | awk '{print $2}' | cut -d '/' -f1)
        [ ! -z $IP ] && {
            is_ip_private $IP && {
                PR_IFs="$PR_IFs $IF"
                # PR_IPs="$PR_IPs $IP"
            }
        }
    done
    PR_IFs=$(echo $PR_IFs | xargs)
    # PR_IPs=$(echo $PR_IPs | xargs)

    # PU_IFs=$(substring_diff "$NICS" "$PR_IFs" )
    # if [ -z $PU_IFs ]; then
    #     PU_IP=$(curl ipinfo.io/ip 2>/dev/null)
    # else
    #     PU_IP=$(ip route get 8.8.8.8 | awk -F"dev " 'NR==1{split($2,a," ");print a[1]}' 2>/dev/null)
    # fi
    PU_IF=$(ip route get 8.8.8.8 | awk -F"dev " 'NR==1{split($2,a," ");print a[1]}' 2>/dev/null)
    PU_IP=$(ip a | grep $PU_IF | grep inet | awk '{print $2}' | cut -d '/' -f1)
    [ is_ip_private $PU_IP ] && PU_IF= && PU_IP=
    # [ ! z $PU_IP ] && {
    #     PU_IF=$(netstat -ie | grep -B1 $PU_IP | head -n1 | awk '{print $1}')
    #     PU_IF=${PU_IF%%:}
    # }
    [ -z $PR_IFs ] && PR_IFs=$(substring_diff "$NICS" "$PU_IF")

    echo "NICS identified: $NICS"
    echo "    private NIC(s): $PR_IFs"
    echo "    public NIC: $PU_IF"
    echo
}

substring_diff() {
    read -a l1 <<<$1
    read -a l2 <<<$2
    echo ${l1[@]} ${l2[@]} | tr ' ' '\n' | sort | uniq -u
}

# configure_gateway_by_service() {
#     route del -net default &>/dev/null

#     cat <<-'EOF' > /sbin/gateway
# #!/bin/sh -
# echo "configure default gateway"
# /sbin/route add -net default gw {{ .GatewayIP }}
# EOF
#     chmod u+x /sbin/gateway
#     cat <<-'EOF' > /etc/systemd/system/gateway.service
# Description=create default gateway
# After=network.target

# [Service]
# ExecStart=/sbin/gateway
# Restart=on-failure
# StartLimitIntervalSec=10

# [Install]
# WantedBy=multi-user.target
# EOF

#     systemctl enable gateway
#     systemctl start gateway
# }

# Configure network for Debian distribution
configure_network_debian() {
    echo "Configuring network (debian-like)..."

{{- if .AddGateway }}
    # Needs to configure quickly gateway on private hosts to be able to update packages
    route del -net default &>/dev/null
    route add -net default gw {{ .GatewayIP }}
{{- end}}

    reset_fw

    local path=/etc/network/interfaces.d
    mkdir -p $path
    local cfg=$path/50-cloud-init.cfg
    rm -f $cfg

    for IF in $NICS; do
        if [ "$IF" = "$PU_IF" ]; then
            cat <<-EOF >$path/10-$IF-public.cfg
auto ${IF}
iface ${IF} inet dhcp
EOF
        else
            cat <<-EOF >$path/11-$IF-private.cfg
auto ${IF}
iface ${IF} inet dhcp
{{- if .AddGateway }}
  up route add -net default gw {{ .GatewayIP }} || true
{{- end}}
EOF
        fi
    done

    configure_dhclient

    /sbin/dhclient || true
    systemctl restart networking

    echo done
}

# Configure network using systemd-networkd
configure_network_systemd_networkd() {
    echo "Configuring network (using netplan and systemd-networkd)..."

    mkdir -p /etc/netplan
    rm -f /etc/netplan/*

{{- if .AddGateway }}
    # Needs to configure quickly gateway to be able to update packages
    route del -net default &>/dev/null
    route add -net default gw {{ .GatewayIP }}
{{- end}}

    # Update netplan to last available release
    case $LINUX_KIND in
        debian)
            sfWaitForApt && {
                apt update && apt install -qy netplan.io || fail 196
            }
            ;;
        ubuntu)
            echo "deb http://archive.ubuntu.com/ubuntu/ bionic-proposed main" >/etc/apt/sources.list.d/bionic-proposed.list
            sfWaitForApt && {
                apt update && apt install -qy netplan.io || fail 197
            }
            ;;
        redhat|centos)
            yum install -y netplan.io || fail 198
            ;;
        *)
            echo "unsupported Linux distribution '$LINUX_KIND'"
            fail 199
            ;;
    esac

    reset_fw

    # Recreate netplan configuration with last netplan version and more settings
    for IF in $NICS; do
        if [ "$IF" = "$PU_IF" ]; then
            cat <<-EOF >/etc/netplan/10-$IF-public.yaml
network:
  version: 2
  renderer: networkd

  ethernets:
    $IF:
      dhcp4: true
      dhcp6: false
      critical: true
      dhcp4-overrides:
        use-dns: false
        use-routes: true
EOF
        else
            cat <<-EOF >/etc/netplan/11-$IF-private.yaml
network:
  version: 2
  renderer: networkd

  ethernets:
    $IF:
      dhcp4: true
      dhcp6: false
      critical: true
      dhcp4-overrides:
        use-dns: false
        use-routes: false
{{- if .AddGateway }}
      routes:
      - to: 0.0.0.0/0
        via: {{ .GatewayIP }}
        scope: global
        on-link: true
{{- end}}
EOF
        fi
    done
    netplan generate && netplan apply || fail 200

    configure_dhclient

    systemctl restart systemd-networkd

    echo done
}

# Configure network for redhat7-like distributions (rhel, centos, ...)
configure_network_redhat() {
    echo "Configuring network (redhat-like)..."

    if [ -z $VERSION_ID ]; then
        disable_svc() {
            chkconfig $1 off
        }
        stop_svc() {
            service $1 stop
        }
        start_svc() {
            service $1 start
        }
    else
        disable_svc() {
            systemctl disable $1
        }
        stop_svc() {
            systemctl stop $1
        }
        start_svc() {
            systemct start $1
        }
    fi

{{- if .AddGateway }}
    # Needs to configure quickly gateway to be able to update packages
    route del -net default &>/dev/null
    route add -net default gw {{ .GatewayIP }}
{{- end}}

    reset_fw

    # We don't want NetworkManager
    disable_svc NetworkManager &>/dev/null
    stop_svc NetworkManager &>/dev/null
    yum remove -y NetworkManager &>/dev/null

    # Configure all network interfaces in dhcp
    for IF in $NICS; do
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

    configure_dhclient

{{- if .AddGateway }}
    echo "GATEWAY={{ .GatewayIP }}" >/etc/sysconfig/network
{{- end }}

    case $VERSION_ID in
        6) start_svc network;;
        7) start_svc systemd-networkd;;
    esac

    echo done
}

add_common_repos() {
    case $LINUX_KIND in
        debian)
            ;;
        ubuntu)
            sfFinishPreviousInstall
            add-apt-repository universe -y || return 1
            ;;
        rhel|centos)
            ;;
    esac
    return 0
}

check_for_network() {
    case $LINUX_KIND in
        debian)
            ping -c 5 archive.debian.org || return 1
            ;;
        ubuntu)
            ping -c 5 archive.ubuntu.com || return 1
            ;;
        rhel|centos)
            ping -c 5 www.google.com || return 1
            ;;
    esac
    return 0
}

put_hostname_in_hosts() {
    HON=$(hostname)
    ping $HON -c 5 2>/dev/null || echo "127.0.1.1 $HON" >>/etc/hosts
}

configure_as_gateway() {
    echo "Configuring host as gateway..."

    echo "configuring iptables"
    # Change default policy for table filter chain INPUT to be DROP (block everything)
    iptables -P INPUT DROP
    # Opens up the required (loopback comm, ping, ssh, established connection)
    fw_i_accept -i lo
    fw_i_accept -p icmp --icmp-type 8 -s 0/0 -m state --state NEW,ESTABLISHED,RELATED
    fw_i_accept -p icmp --icmp-type 0 -s 0/0 -m state --state ESTABLISHED,RELATED
    fw_i_accept -m conntrack --ctstate ESTABLISHED,RELATED
    fw_i_accept -p tcp --dport ssh

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

    resolvconf -u
    echo done
}

configure_dns_systemd_resolved() {
    echo "Configuring systemd-resolved..."

{{- if not .AddGateway }}
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
Cache=yes
DNSStubListener=yes
EOF
    systemctl restart systemd-resolved
    echo done
}

install_drivers_nvidia() {
    case $LINUX_KIND in
        ubuntu)
            add-apt-repository -y ppa:graphics-drivers &>/dev/null
            sfWaitForApt && apt update &>/dev/null
            sfWaitForApt && apt -y install nvidia-410 &>/dev/null || {
                sfWaitForAPt && apt -y install nvidia-driver-410 &>/dev/null || fail 201
            }
            ;;

        debian)
            if [ ! -f /etc/modprobe.d/blacklist-nouveau.conf ]; then
                echo -e "blacklist nouveau\nblacklist lbm-nouveau\noptions nouveau modeset=0\nalias nouveau off\nalias lbm-nouveau off" >>/etc/modprobe.d/blacklist-nouveau.conf
                rmmod nouveau
            fi
            sfWaitForApt && apt update &>/dev/null
            sfWaitForApt && apt install -y dkms build-essential linux-headers-$(uname -r) gcc make &>/dev/null || fail 202
            dpkg --add-architecture i386 &>/dev/null
            sfWaitForApt && apt update &>/dev/null
            sfWaitForApt && apt install -y lib32z1 lib32ncurses5 &>/dev/null || fail 203
            wget http://us.download.nvidia.com/XFree86/Linux-x86_64/410.78/NVIDIA-Linux-x86_64-410.78.run &>/dev/null || fail 204
            bash NVIDIA-Linux-x86_64-410.78.run -s || fail 205
            ;;

        redhat|centos)
            if [ ! -f /etc/modprobe.d/blacklist-nouveau.conf ]; then
                echo -e "blacklist nouveau\noptions nouveau modeset=0" >>/etc/modprobe.d/blacklist-nouveau.conf
                dracut --force
                rmmod nouveau
            fi
            yum -y -q install kernel-devel.$(uname -i) kernel-headers.$(uname -i) gcc make &>/dev/null || fail 206
            wget http://us.download.nvidia.com/XFree86/Linux-x86_64/410.78/NVIDIA-Linux-x86_64-410.78.run || fail 207
            bash NVIDIA-Linux-x86_64-410.78.run -s || fail 208
            rm -f NVIDIA-Linux-x86_64-410.78.run
            ;;
        *)
            echo "Unsupported Linux distribution '$LINUX_KIND'!"
            fail 209
            ;;
    esac
}

install_packages() {
     case $LINUX_KIND in
        ubuntu|debian)
            sfFinishPreviousInstall || true
            sfWaitForApt && apt install -y -qq pciutils &>/dev/null || fail 210
            ;;
        redhat|centos)
            yum install -y -q pciutils wget &>/dev/null || fail 211
            ;;
        *)
            echo "Unsupported Linux distribution '$LINUX_KIND'!"
            fail 212
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

export DEBIAN_FRONTEND=noninteractive

disable_cloudinit_network_autoconf
add_common_repos
identify_nics

case $LINUX_KIND in
    debian|ubuntu)
        systemctl stop apt-daily.service &>/dev/null
        systemctl kill --kill-who=all apt-daily.service &>/dev/null

        create_user

        systemctl status systemd-resolved &>/dev/null && {
            configure_dns_systemd_resolved
        } || {
            systemctl status resolvconf &>/dev/null && {
                configure_dns_resolvconf
            } || {
                configure_dns_legacy
            }
        }

        systemctl status systemd-networkd &>/dev/null && {
            configure_network_systemd_networkd
        } || {
            systemctl status networking &>/dev/null && {
                configure_network_debian
            } || {
                echo "PROVISIONING_ERROR: failed to determine how to configure network"
                fail 213
            }
        }
        ;;

    redhat|centos)
        create_user

        systemctl status systemd-resolved &>/dev/null && {
            configure_dns_systemd_resolved
        } || {
            systemctl status resolvconf &>/dev/null && {
                configure_dns_resolvconf
            } || {
                configure_dns_legacy
            }
        }

        systemctl status systemd-networkd &>/dev/null && {
            configure_network_systemd_networkd
        } || configure_network_redhat
        ;;

    *)
        echo "Unsupported Linux distribution '$LINUX_KIND'!"
        fail 214
        ;;
esac

{{- if .IsGateway }}
configure_as_gateway
{{- end }}

check_for_network || {
    echo "PROVISIONING_ERROR: no network connectivity"
    fail 215
}

put_hostname_in_hosts

touch /etc/cloud/cloud-init.disabled
install_packages
lspci | grep -i nvidia &>/dev/null && install_drivers_nvidia

echo -n "0,linux,${LINUX_KIND},$(date +%Y/%m/%d-%H:%M:%S)" >/var/tmp/user_data.done
set +x
systemctl reboot
exit 0
