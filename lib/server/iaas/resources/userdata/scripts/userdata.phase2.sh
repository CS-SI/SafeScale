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

#{{.Revision}}

{{.Header}}

print_error() {
    ec=$?
    read line file <<<$(caller)
    echo "An error occurred in line $line of file $file (exit code $ec) :" "{"`sed "${line}q;d" "$file"`"}" >&2
    {{.ExitOnError}}
}
trap print_error ERR

fail() {
    if [ -z "$2" ]
    then
      if [ $1 -ne 0 ]; then
        echo "PROVISIONING_ERROR: $1"
      fi
    else
      if [ $1 -ne 0 ]; then
        echo "PROVISIONING_ERROR: $1: $2"
      fi
    fi
    echo -n "$1,${LINUX_KIND},${VERSION_ID},$(hostname),$(date +%Y/%m/%d-%H:%M:%S)" >/opt/safescale/var/state/user_data.phase2.done
    # For compatibility with previous user_data implementation (until v19.03.x)...
    ln -s ${SF_VARDIR}/state/user_data.phase2.done /var/tmp/user_data.done
    exit $1
}

# Redirects outputs to /opt/safescale/log/user_data.phase2.log
exec 1<&-
exec 2<&-
exec 1<>/opt/safescale/var/log/user_data.phase2.log
exec 2>&1
set -x

# Tricks BashLibrary's waitUserData to believe the current phase (2) is already done
>/opt/safescale/var/state/user_data.phase2.done
# Includes the BashLibrary
{{ .BashLibrary }}

reset_fw() {
    case $LINUX_KIND in
        debian|ubuntu)
            sfApt update &>/dev/null
            sfApt install -qy firewalld || return 1

            systemctl stop ufw
            systemctl start firewalld || return 1
            systemctl disable ufw
            systemctl enable firewalld
            sfApt purge -qy ufw &>/dev/null || return 1
            ;;

        rhel|centos)
            # firewalld may not be installed
            if ! systemctl is-active firewalld &>/dev/null; then
                if ! systemctl status firewalld &>/dev/null; then
                    yum install -qy firewalld || return 1
                fi
                systemctl enable firewalld &>/dev/null
                systemctl start firewalld &>/dev/null
            fi
            ;;
    esac

    # Clear interfaces attached to zones
    for zone in $(sfFirewall --get-active-zones | grep -v interfaces | grep -v sources); do
        for nic in $(sfFirewall --zone=$zone --list-interfaces); do
            sfFirewallAdd --zone=$zone --remove-interface=$nic &>/dev/null
        done
    done

    # Attach Internet interface or source IP to zone public if host is gateway
    [ ! -z $PU_IF ] && {
        sfFirewallAdd --zone=public --add-interface=$PU_IF || return 1
    }
    {{- if or .PublicIP .IsGateway }}
    [ -z $PU_IF ] && {
        sfFirewallAdd --zone=public --add-source=${PU_IP}/32 || return 1
    }
    {{- end }}
    # Attach LAN interfaces to zone trusted
    [ ! -z $PR_IFs ] && {
        for i in $PR_IFs; do
            sfFirewallAdd --zone=trusted --add-interface=$PR_IFs || return 1
        done
    }
    # Attach lo interface to zone trusted
    sfFirewallAdd --zone=trusted --add-interface=lo || return 1
    # Allow service ssh on public zone
    sfFirewallAdd --zone=public --add-service=ssh
    # Save current fw settings as permanent
    sfFirewallReload
}

NICS=
# PR_IPs=
PR_IFs=
PU_IP=
PU_IF=
i_PR_IF=
o_PR_IF=

# Don't request dns name servers from DHCP server
# Don't update default route
configure_dhclient() {
    # kill any dhclient process already running
    pkill dhclient || true

    [ -f /etc/dhcp/dhclient.conf ] && (sed -i -e 's/, domain-name-servers//g' /etc/dhcp/dhclient.conf || true)

    if [ -d /etc/dhcp/ ]; then
        HOOK_FILE=/etc/dhcp/dhclient-enter-hooks
        cat >>$HOOK_FILE <<-EOF
make_resolv_conf() {
    :
}

{{- if .AddGateway }}
unset new_routers
{{- end}}
EOF
        chmod +x $HOOK_FILE
    fi
}

is_ip_private() {
    ip=$1
    ipv=$(sfIP2long $ip)

{{ if .EmulatedPublicNet}}
    r=$(sfCidr2iprange {{ .EmulatedPublicNet }})
    bv=$(sfIP2long $(cut -d- -f1 <<<$r))
    ev=$(sfIP2long $(cut -d- -f2 <<<$r))
    [ $ipv -ge $bv -a $ipv -le $ev ] && return 0
{{- end }}
    for r in "192.168.0.0-192.168.255.255" "172.16.0.0-172.31.255.255" "10.0.0.0-10.255.255.255"; do
        bv=$(sfIP2long $(cut -d- -f1 <<<$r))
        ev=$(sfIP2long $(cut -d- -f2 <<<$r))
        [ $ipv -ge $bv -a $ipv -le $ev ] && return 0
    done
    return 1
}

identify_nics() {
    NICS=$(for i in $(find /sys/devices -name net -print | grep -v virtual); do ls $i; done)
    NICS=${NICS/[[:cntrl:]]/ }

    for IF in $NICS; do
        IP=$(ip a | grep $IF | grep inet | awk '{print $2}' | cut -d '/' -f1) || true
        [ ! -z $IP ] && is_ip_private $IP && PR_IFs="$PR_IFs $IF"
    done
    PR_IFs=$(echo $PR_IFs | xargs) || true
    PU_IF=$(ip route get 8.8.8.8 | awk -F"dev " 'NR==1{split($2,a," ");print a[1]}' 2>/dev/null) || true
    PU_IP=$(ip a | grep $PU_IF | grep inet | awk '{print $2}' | cut -d '/' -f1) || true
    if [ ! -z $PU_IP ]; then
        if is_ip_private $PU_IP; then
            PU_IF=

            NO404=$(curl -s -o /dev/null -w "%{http_code}" http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null | grep 404) || true
            if [ -z $NO404 ]; then
                # Works with FlexibleEngine and potentially with AWS (not tested yet)
                PU_IP=$(curl http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null) || true
                [ -z $PU_IP ] && PU_IP=$(curl ipinfo.io/ip 2>/dev/null)
            fi
        fi
    fi
    [ -z $PR_IFs ] && PR_IFs=$(substring_diff "$NICS" "$PU_IF")

    # Keeps track of interfaces identified for future scripting use
    echo "$PR_IFs" >${SF_VARDIR}/state/private_nics
    echo "$PU_IF" >${SF_VARDIR}/state/public_nics

    echo "NICS identified: $NICS"
    echo "    private NIC(s): $PR_IFs"
    echo "    public NIC: $PU_IF"
    echo
}

substring_diff() {
    read -a l1 <<<$1
    read -a l2 <<<$2
    echo "${l1[@]}" "${l2[@]}" | tr ' ' '\n' | sort | uniq -u
}

# If host isn't a gateway, we need to configure temporarily and manually gateway on private hosts to be able to update packages
ensure_network_connectivity() {
    {{- if .AddGateway }}
        route del -net default &>/dev/null
        route add -net default gw {{ .DefaultRouteIP }}
    {{- else }}
    :
    {{- end}}
}

configure_dns() {
    if systemctl status systemd-resolved &>/dev/null; then
        configure_dns_systemd_resolved
    elif systemctl status resolvconf &>/dev/null; then
        configure_dns_resolvconf
    else
        configure_dns_legacy
    fi
}

configure_network() {
    case $LINUX_KIND in
        debian|ubuntu)
            if systemctl status systemd-networkd &>/dev/null; then
                configure_network_systemd_networkd
            elif systemctl status networking &>/dev/null; then
                configure_network_debian
            else
                echo "PROVISIONING_ERROR: failed to determine how to configure network"
                fail 192
            fi
            ;;

        redhat|centos)
            # Network configuration
            if systemctl status systemd-networkd &>/dev/null; then
                configure_network_systemd_networkd
            else
                configure_network_redhat
            fi
            ;;

        *)
            echo "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND'!"
            fail 193
            ;;
    esac

    {{- if .IsGateway }}
    configure_as_gateway || fail 194
    install_keepalived || fail 195
    {{- end }}

    check_for_network || {
        echo "PROVISIONING_ERROR: missing or incomplete network connectivity"
        fail 196
    }
}

# Configure network for Debian distribution
configure_network_debian() {
    echo "Configuring network (debian-like)..."

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
  up route add -net default gw {{ .DefaultRouteIP }} || true
{{- end}}
EOF
        fi
    done

    configure_dhclient

    /sbin/dhclient || true
    systemctl restart networking

    reset_fw || fail 197

    echo done
}

# Configure network using systemd-networkd
configure_network_systemd_networkd() {
    echo "Configuring network (using netplan and systemd-networkd)..."

    mkdir -p /etc/netplan
    rm -f /etc/netplan/*

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
{{- if .AddGateway }}
        use-routes: false
      routes:
      - to: 0.0.0.0/0
        via: {{ .DefaultRouteIP }}
        scope: global
        on-link: true
{{- else }}
        use-routes: true
{{- end}}
EOF
        fi
    done
    netplan generate && netplan apply || fail 198

    configure_dhclient

    systemctl restart systemd-networkd

    reset_fw || fail 199

    echo done
}

# Configure network for redhat7-like distributions (rhel, centos, ...)
configure_network_redhat() {
    echo "Configuring network (redhat-like)..."

    if [ -z $VERSION_ID -o $VERSION_ID -lt 7 ]; then
        disable_svc() {
            chkconfig $1 off
        }
        enable_svc() {
            chkconfig $1 on
        }
        stop_svc() {
            service $1 stop
        }
        restart_svc() {
            service $1 restart
        }
    else
        disable_svc() {
            systemctl disable $1
        }
        enable_svc() {
            systemctl enable $1
        }
        stop_svc() {
            systemctl stop $1
        }
        restart_svc() {
            systemctl restart $1
        }
    fi


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
    echo "GATEWAY={{ .DefaultRouteIP }}" >/etc/sysconfig/network
    {{- end }}

    enable_svc network
    restart_svc network

    reset_fw || fail 200

    echo done
}

check_for_ip() {
    ip=$(ip -f inet -o addr show $1 | cut -d' ' -f7 | cut -d' ' -f1)
    [ -z "$ip" ] && echo "Failure checking for ip '$ip' when evaluating '$1'" && return 1
    return 0
}

# Checks network is set correctly
# - DNS and routes (by pinging a FQDN)
# - IP address on "physical" interfaces
check_for_network() {
    if command -v wget; then
      wget -T 30 -O /dev/null www.google.com &>/dev/null || return 1
    else
      ping -n -c1 -w30 -i5 www.google.com || return 1
    fi
    [ ! -z "$PU_IF" ] && {
        check_for_ip $PU_IF || return 1
    }
    for i in $PR_IFs; do
        check_for_ip $i || return 1
    done
    return 0
}

configure_as_gateway() {
    echo "Configuring host as gateway..."

    if [ ! -z $PR_IFs ]; then
        # Enable forwarding
        for i in /etc/sysctl.d/* /etc/sysctl.conf; do
            grep -v "net.ipv4.ip_forward=" $i >${i}.new
            mv -f ${i}.new ${i}
        done
        cat >/etc/sysctl.d/21-gateway.conf <<-EOF
net.ipv4.ip_forward=1
net.ipv4.ip_nonlocal_bind=1
EOF
        case $LINUX_KIND in
            ubuntu) systemctl restart systemd-sysctl;;
            *)      sysctl -p;;
        esac
    fi

    if [ ! -z $PU_IF ]; then
        # Dedicated public interface available...

        # Allows ping
        sfFirewallAdd --direct --add-rule ipv4 filter INPUT 0 -p icmp -m icmp --icmp-type 8 -s 0.0.0.0/0 -d 0.0.0.0/0 -j ACCEPT
        # Allows masquerading on public zone
        sfFirewallAdd --zone=public --add-masquerade
    fi
    # Enables masquerading on trusted zone (mainly for docker networks)
    sfFirewallAdd --zone=trusted --add-masquerade

    # Allows default services on public zone
    sfFirewallAdd --zone=public --add-service=ssh 2>/dev/null
    # Applies fw rules
    sfFirewallReload

    grep -vi AllowTcpForwarding /etc/ssh/sshd_config >/etc/ssh/sshd_config.new
    echo "AllowTcpForwarding yes" >>/etc/ssh/sshd_config.new
    mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config
    systemctl restart ssh

    echo done
}

install_keepalived() {
    case $LINUX_KIND in
        ubuntu|debian)
            sfApt update && sfApt -y install keepalived || return 1
            ;;

        redhat|centos)
            yum install -qy keepalived || return 1
            ;;
        *)
            echo "Unsupported Linux distribution '$LINUX_KIND'!"
            return 1
            ;;
    esac

    NETMASK=$(echo {{ .CIDR }} | cut -d/ -f2)

    cat >/etc/keepalived/keepalived.conf <<-EOF
vrrp_instance vrrp_group_gws_internal {
    state BACKUP
    interface ${PR_IFs[0]}
    virtual_router_id 1
    priority {{ if eq .IsPrimaryGateway true }}151{{ else }}100{{ end }}
    nopreempt
    advert_int 2
    authentication {
        auth_type PASS
        auth_pass password
    }
{{ if eq .IsPrimaryGateway true }}
    # Unicast specific option, this is the IP of the interface keepalived listens on
    unicast_src_ip {{ .PrimaryGatewayPrivateIP }}
    # Unicast specific option, this is the IP of the peer instance
    unicast_peer {
        {{ .SecondaryGatewayPrivateIP }}
    }
{{ else }}
    unicast_src_ip {{ .SecondaryGatewayPrivateIP }}
    unicast_peer {
        {{ .PrimaryGatewayPrivateIP }}
    }
{{ end }}
    virtual_ipaddress {
        {{ .PrivateVIP }}/${NETMASK}
    }
}

# vrrp_instance vrrp_group_gws_external {
#     state BACKUP
#     interface ${PU_IF}
#     virtual_router_id 2
#     priority {{ if eq .IsPrimaryGateway true }}151{{ else }}100{{ end }}
#     nopreempt
#     advert_int 2
#     authentication {
#         auth_type PASS
#         auth_pass password
#     }
#     virtual_ipaddress {
#         {{ .PublicVIP }}/${NETMASK}
#     }
# }
EOF

    if [ "$(sfGetFact "use_systemd")" = "1" ]; then
        # Use systemd to ensure keepalived is restarted if network is restarted
        # (otherwise, keepalived is in undetermined state)
        mkdir -p /etc/systemd/system/keepalived.service.d
        cat >/etc/systemd/system/keepalived.service.d/override.conf <<EOF
[Unit]
Requires=network.service
PartOf=network.service
EOF

        systemctl daemon-reload
    fi

    sfService enable keepalived && sfService restart keepalived || return 1
    return 0
}

configure_dns_legacy() {
    echo "Configuring /etc/resolv.conf..."
    rm -f /etc/resolv.conf
    {{- if .DNSServers }}
    if [[ -e /etc/dhcp/dhclient.conf ]]; then
        dnsservers=
        for i in {{range .DNSServers}} {{end}}; do
            [ ! -z $dnsservers ] && dnsservers="$dnsservers, "
        done
        [ ! -z $dnsservers ] && echo "prepend domain-name-servers $dnsservers;" >>/etc/dhcp/dhclient.conf
    else
        echo "dhclient.conf not modified";
    fi
    {{- else }}
    if [[ -e /etc/dhcp/dhclient.conf ]]; then
        echo "prepend domain-name-servers 1.1.1.1;" >>/etc/dhcp/dhclient.conf
    else
        echo "/etc/dhcp/dhclient.conf not modified"
    fi
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

{{- if not .DefaultRouteIP }}
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
            sfFinishPreviousInstall
            add-apt-repository -y ppa:graphics-drivers &>/dev/null
            sfApt update
            sfApt -y install nvidia-410 &>/dev/null || {
                sfApt -y install nvidia-driver-410 &>/dev/null || fail 201
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
            # if there is a version mismatch between kernel sources and running kernel, building the driver would require 2 reboots to get it done, right now this is unsupported
            if [ $(uname -r) == $(yum list installed | grep kernel-headers | awk {'print $2'}).$(uname -i) ]; then
                bash NVIDIA-Linux-x86_64-410.78.run -s || fail 208
            fi
            rm -f NVIDIA-Linux-x86_64-410.78.run
            ;;
        *)
            echo "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND'!"
            fail 209
            ;;
    esac
}

early_packages_update() {
    ensure_network_connectivity

    # Ensure IPv4 will be used before IPv6 when resolving hosts (the latter shouldn't work regarding the network configuration we set)
    cat >/etc/gai.conf <<-EOF
precedence ::ffff:0:0/96 100
scopev4 ::ffff:169.254.0.0/112  2
scopev4 ::ffff:127.0.0.0/104    2
scopev4 ::ffff:0.0.0.0/96       14
EOF

    case $LINUX_KIND in
        debian)
            # Disable interactive installations
            export DEBIAN_FRONTEND=noninteractive
            # # Force use of IPv4 addresses when installing packages
            # echo 'Acquire::ForceIPv4 "true";' >/etc/apt/apt.conf.d/99force-ipv4

            sfApt update
            # Force update of systemd, pciutils
            sfApt install -qy systemd pciutils || fail 210
            # systemd, if updated, is restarted, so we may need to ensure again network connectivity
            ensure_network_connectivity
            ;;

        ubuntu)
            # Disable interactive installations
            export DEBIAN_FRONTEND=noninteractive
            # # Force use of IPv4 addresses when installing packages
            # echo 'Acquire::ForceIPv4 "true";' >/etc/apt/apt.conf.d/99force-ipv4

            sfApt update
            # Force update of systemd, pciutils and netplan
            if dpkg --compare-versions $(sfGetFact "linux_version") ge 17.10; then
                sfApt install -y systemd pciutils netplan.io || fail 211
            else
                sfApt install -y systemd pciutils || fail 212
            fi
            # systemd, if updated, is restarted, so we may need to ensure again network connectivity
            ensure_network_connectivity

            # # Security updates ...
            # sfApt update &>/dev/null && sfApt install -qy unattended-upgrades && unattended-upgrades -v
            ;;

        redhat|centos)
            # # Force use of IPv4 addresses when installing packages
            # echo "ip_resolve=4" >>/etc/yum.conf

            # Force update of systemd and pciutils
            yum install -qy systemd pciutils yum-utils || fail 213
            # systemd, if updated, is restarted, so we may need to ensure again network connectivity
            ensure_network_connectivity

            # # install security updates
            # yum install -y yum-plugin-security yum-plugin-changelog && yum update -y --security
            ;;
    esac
    sfProbeGPU
}

install_packages() {
     case $LINUX_KIND in
        ubuntu|debian)
            sfApt install -y -qq jq zip time zip &>/dev/null || fail 214
            ;;
        redhat|centos)
            yum install --enablerepo=epel -y -q wget jq time zip &>/dev/null || fail 215
            ;;
        *)
            echo "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND'!"
            fail 216
            ;;
     esac
}

add_common_repos() {
    case $LINUX_KIND in
        ubuntu)
            sfFinishPreviousInstall
            add-apt-repository universe -y || return 1
            codename=$(sfGetFact "linux_codename")
            echo "deb http://archive.ubuntu.com/ubuntu/ ${codename}-proposed main" >/etc/apt/sources.list.d/${codename}-proposed.list
            ;;
        redhat|centos)
            # Install EPEL repo ...
            yum install -y epel-release
            # ... but don't enable it by default
            yum-config-manager --disablerepo=epel &>/dev/null || true
            ;;
    esac
}

configure_locale() {
    case $LINUX_KIND in
        ubuntu|debian) locale-gen en_US.UTF-8
                       ;;
    esac
    export LANGUAGE=en_US.UTF-8 LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8
}

force_dbus_restart() {
    case $LINUX_KIND in
        ubuntu)
            sudo sed -i 's/^RefuseManualStart=.*$/RefuseManualStart=no/g' /lib/systemd/system/dbus.service
            sudo systemctl daemon-reexec
            sudo systemctl restart dbus.service
            ;;
    esac
}

update_kernel_settings() {
    cat >/etc/sysctl.d/20-safescale.conf <<-EOF
vm.max_map_count=262144
EOF
    case $LINUX_KIND in
        ubuntu) systemctl restart systemd-sysctl;;
        *)      sysctl -p;;
    esac
}

# ---- Main

configure_locale
configure_dns
ensure_network_connectivity
add_common_repos
early_packages_update

identify_nics
configure_network

install_packages
lspci | grep -i nvidia &>/dev/null && install_drivers_nvidia

update_kernel_settings || fail 217

echo -n "0,linux,${LINUX_KIND},${VERSION_ID},$(hostname),$(date +%Y/%m/%d-%H:%M:%S)" >/opt/safescale/var/state/user_data.phase2.done
# For compatibility with previous user_data implementation (until v19.03.x)...
ln -s ${SF_VARDIR}/state/user_data.phase2.done /var/tmp/user_data.done

# !!! DON'T REMOVE !!! #insert_tag allows to add something just before exiting,
#                      but after the template has been realized (cf. libvirt Stack)
#insert_tag

force_dbus_restart

ls -lR /opt/safescale

set +x
exit 0
