#!/bin/bash
#
# Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

# Script customized for {{.ProviderName}} driver

{{.Header}}

print_error() {
    read line file <<<$(caller)
    echo "An error occurred in line $line of file $file:" "{"`sed "${line}q;d" "$file"`"}" >&2
    {{.ExitOnError}}
}
trap print_error ERR

fail() {
    echo "PROVISIONING_ERROR: $1"
    echo -n "$1,${LINUX_KIND},$(date +%Y/%m/%d-%H:%M:%S)" >/opt/safescale/var/state/user_data.netsec.done
    exit $1
}

# Redirects outputs to /opt/safescale/log/user_data.netsec.log
exec 1<&-
exec 2<&-
exec 1<>/opt/safescale/var/log/user_data.netsec.log
exec 2>&1
set -x

# Tricks BashLibrary's waitUserData to believe the current phase 'netsec' is already done (otherwise will deadlock)
>/opt/safescale/var/state/user_data.netsec.done
# Includes the BashLibrary
{{ .BashLibrary }}
rm -f /opt/safescale/var/state/user_data.netsec.done

reset_fw() {
    case $LINUX_KIND in
        debian|ubuntu)
            sfApt update &>/dev/null || return 1
            sfApt install -q -y firewalld || return 1

            systemctl stop ufw
            # systemctl start firewalld || return 1
            systemctl disable ufw
            # systemctl enable firewalld
            sfApt purge -q -y ufw &>/dev/null || return 1
            ;;

        rhel|centos)
            # firewalld may not be installed
            if ! systemctl is-active firewalld &>/dev/null; then
                if ! systemctl status firewalld &>/dev/null; then
                    yum install -q -y firewalld || return 1
                fi
                # systemctl enable firewalld &>/dev/null
                # systemctl start firewalld &>/dev/null
            fi
            ;;
    esac

    # # Clear interfaces attached to zones
    # for zone in $(sfFirewall --get-active-zones | grep -v interfaces | grep -v sources); do
    #     for nic in $(sfFirewall --zone=$zone --list-interfaces || true); do
    #         sfFirewallAdd --zone=$zone --remove-interface=$nic &>/dev/null || true
    #     done
    # done
    for zone in public trusted; do
        for nic in $(firewall-offline-cmd --zone=$zone --list-interfaces || true); do
            firewall-offline-cmd --zone=$zone --remove-interface=$nic &>/dev/null || true
        done
    done

    # Attach Internet interface or source IP to zone public if host is gateway
    [ ! -z $PU_IF ] && {
        firewall-offline-cmd --zone=public --add-interface=$PU_IF || return 1
    }
    {{- if or .PublicIP .IsGateway }}
    [ -z $PU_IF ] && {
        firewall-offline-cmd --zone=public --add-source=${PU_IP}/32 || return 1
    }
    {{- end }}

    # Sets the default target of packets coming from public interface to DROP
    firewall-offline-cmd --zone=public --set-target=DROP || return 1

    # Attach LAN interfaces to zone trusted
    [ ! -z $PR_IFs ] && {
        for i in $PR_IFs; do
            firewall-offline-cmd --zone=trusted --add-interface=$PR_IFs || return 1
        done
    }
    firewall-offline-cmd --zone=trusted --add-interface=lo || return 1

    # Allow service ssh on public zone
    firewall-offline-cmd --zone=public --add-service=ssh || return 1

    # Save current fw settings as permanent
    sfService enable firewalld
}

NICS=
# PR_IPs=
PR_IFs=
PU_IP=
PU_IF=
i_PR_IF=
o_PR_IF=
AWS=

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

    if [ ! -z $PU_IP ]; then
      if [ -z $PU_IF ]; then
        if [ -z $NO404 ]; then
          echo "It seems AWS"
          AWS=1
        else
          AWS=0
        fi
      fi
    fi

    if [ "{{.ProviderName}}" == "aws" ]; then
      echo "It actually IS AWS"
      AWS=1
    else
      echo "It is NOT AWS"
      AWS=0
    fi

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
    op=-1
    CONNECTED=$(curl -I www.google.com -m 5 | grep "200 OK") && op=$? || true
    [ $op -ne 0 ] && echo "ensure_network_connectivity started WITHOUT network..." || echo "ensure_network_connectivity started WITH network..."

    {{- if .AddGateway }}
        route del -net default &>/dev/null
        route add -net default gw {{ .DefaultRouteIP }}
    {{- else }}
    :
    {{- end}}

    op=-1
    CONNECTED=$(curl -I www.google.com -m 5 | grep "200 OK") && op=$? || true
    [ $op -ne 0 ] && echo "ensure_network_connectivity finished WITHOUT network..." || echo "ensure_network_connectivity finished WITH network..."
}

configure_dns() {
    if systemctl status systemd-resolved &>/dev/null; then
        echo "Configuring dns with resolved"
        configure_dns_systemd_resolved
    elif systemctl status resolvconf &>/dev/null; then
        echo "Configuring dns with resolvconf"
        configure_dns_resolvconf
    else
        echo "Configuring dns legacy"
        configure_dns_legacy
    fi
}

# adds entry in /etc/hosts corresponding to FQDN hostname with private IP
update_fqdn() {
    IF=${PR_IFs[0]}
    [ -z ${IF} ] && return
    IP=$(ip a | grep $IF | grep inet | awk '{print $2}' | cut -d '/' -f1) || true
    sed -i -nr "/^${IP}"'/!p/$a'"${IP}"'\t{{ .HostName }}' /etc/hosts
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
    {{- end }}

    update_fqdn

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
  up route add -net default gw {{ .DefaultRouteIP }}
{{- end}}
EOF
        fi
    done

    echo "Looking for network..."
    check_for_network || {
        echo "PROVISIONING_ERROR: failed network cfg 0"
        fail 197
    }

    configure_dhclient

    /sbin/dhclient || true

    echo "Looking for network..."
    check_for_network || {
        echo "PROVISIONING_ERROR: failed network cfg 1"
        fail 198
    }

    systemctl restart networking

    echo "Looking for network..."
    check_for_network || {
        echo "PROVISIONING_ERROR: failed network cfg 2"
        fail 199
    }

    reset_fw || fail 200

    echo done
}

# Configure network using systemd-networkd
configure_network_systemd_networkd() {
    echo "Configuring network (using netplan and systemd-networkd)..."

    {{- if .IsGateway }}
    ISGW=1
    {{- else}}
    ISGW=0
    {{- end}}

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

    if [ "{{.ProviderName}}" == "aws" ]; then
        echo "It actually IS AWS"
        AWS=1
    else
        echo "It is NOT AWS"
        AWS=0
    fi

    if [[ $AWS -eq 1 ]]; then
        if [[ $ISGW -eq 0 ]]; then
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
          use-dns: true
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
        use-dns: true
{{- if .AddGateway }}
        use-routes: true
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
        fi
    fi

    if [[ $AWS -eq 1 ]]; then
        echo "Looking for network..."
        check_for_network || {
            echo "PROVISIONING_ERROR: failed networkd cfg 0"
            fail 201
        }
    fi

    netplan generate && netplan apply || fail 198

    if [[ $AWS -eq 1 ]]; then
        echo "Looking for network..."
        check_for_network || {
            echo "PROVISIONING_ERROR: failed networkd cfg 1"
            fail 202
        }
    fi

    configure_dhclient

    if [[ $AWS -eq 1 ]]; then
        echo "Looking for network..."
        check_for_network || {
            echo "PROVISIONING_ERROR: failed networkd cfg 2"
            fail 203
        }
    fi

    systemctl restart systemd-networkd

    if [[ $AWS -eq 1 ]]; then
        echo "Looking for network..."
        check_for_network || {
            echo "PROVISIONING_ERROR: failed networkd cfg 3"
            fail 204
        }
    fi

    reset_fw || fail 205

    echo done
}

# Configure network for redhat7-like distributions (rhel, centos, ...)
configure_network_redhat() {
    echo "Configuring network (redhat7-like)..."

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
    stop_svc NetworkManager &>/dev/null
    disable_svc NetworkManager &>/dev/null
    yum remove -y NetworkManager &>/dev/null

    # Configure all network interfaces in dhcp
    for IF in $NICS; do
        if [[ ${IF} != "lo" ]]; then
            cat >/etc/sysconfig/network-scripts/ifcfg-${IF} <<-EOF
DEVICE=$IF
BOOTPROTO=dhcp
ONBOOT=yes
NM_CONTROLLED=no
EOF
            {{- if .DNSServers }}
            i=1
            {{- range .DNSServers }}
            echo "DNS$i={{ . }}" >>/etc/sysconfig/network-scripts/ifcfg-${IF}
            i=$((i+1))
            {{- end }}
            {{- else }}
            EXISTING_DNS=$(grep nameserver /etc/resolv.conf | awk '{print $2}')
            if [[ -z ${EXISTING_DNS} ]]; then
                echo "DNS1=1.1.1.1" >>/etc/sysconfig/network-scripts/ifcfg-${IF}
            else
                echo "DNS1=$EXISTING_DNS" >>/etc/sysconfig/network-scripts/ifcfg-${IF}
            fi
            {{- end }}
        fi
    done

    configure_dhclient

    {{- if .AddGateway }}
    echo "GATEWAY={{ .DefaultRouteIP }}" >/etc/sysconfig/network
    {{- end }}

    enable_svc network
    restart_svc network

    echo "exclude=NetworkManager" >>/etc/yum.conf

    reset_fw || fail 206

    echo done
}

check_for_ip() {
    ip=$(ip -f inet -o addr show $1 | cut -d' ' -f7 | cut -d' ' -f1)
    [ -z "$ip" ] && echo "Failure checking for ip '$ip' when evaluating '$1'" && return 1
    return 0
}
export -f check_for_ip

# Checks network is set correctly
# - DNS and routes (by pinging a FQDN)
# - IP address on "physical" interfaces
check_for_network() {
    NETROUNDS=24
    REACHED=0

    for i in $(seq $NETROUNDS); do
        if which wget; then
            wget -T 10 -O /dev/null www.google.com &>/dev/null && REACHED=1 && break
        else
            ping -n -c1 -w10 -i5 www.google.com && REACHED=1 && break
        fi
    done

    [ $REACHED -eq 0 ] && echo "Unable to reach network" && return 1

    [ ! -z "$PU_IF" ] && {
        sfRetry 3m 10 check_for_ip $PU_IF || return 1
    }
    for i in $PR_IFs; do
        sfRetry 3m 10 check_for_ip $i || return 1
    done
    return 0
}

configure_as_gateway() {
    echo "Configuring host as gateway..."

    if [[ ! -z ${PR_IFs} ]]; then
        # Enable forwarding
        for i in /etc/sysctl.d/* /etc/sysctl.conf; do
            grep -v "net.ipv4.ip_forward=" ${i} >${i}.new
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

    if [[ ! -z ${PU_IF} ]]; then
        # Dedicated public interface available...

        # Allows ping
        firewall-offline-cmd --direct --add-rule ipv4 filter INPUT 0 -p icmp -m icmp --icmp-type 8 -s 0.0.0.0/0 -d 0.0.0.0/0 -j ACCEPT
        # Allows masquerading on public zone
        firewall-offline-cmd --zone=public --add-masquerade
    fi
    # Enables masquerading on trusted zone (mainly for docker networks)
    firewall-offline-cmd --zone=trusted --add-masquerade

    # Allows default services on public zone
    firewall-offline-cmd --zone=public --add-service=ssh 2>/dev/null

    sed -i '/^\#*AllowTcpForwarding / s/^.*$/AllowTcpForwarding yes/' /etc/ssh/sshd_config || sfFail 207
    sed -i '/^.*PasswordAuthentication / s/^.*$/PasswordAuthentication no/' /etc/ssh/sshd_config || sfFail 208
    sed -i '/^.*ChallengeResponseAuthentication / s/^.*$/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config || sfFail 209
    systemctl restart sshd

    echo done
}

configure_dns_legacy() {
    echo "Configuring /etc/resolv.conf..."
    cp /etc/resolv.conf /etc/resolv.conf.bak

    rm -f /etc/resolv.conf
    {{- if .DNSServers }}
    if [[ -e /etc/dhcp/dhclient.conf ]]; then
        dnsservers=
        for i in {{range .DNSServers}} {{end}}; do
            [[ ! -z ${dnsservers} ]] && dnsservers="$dnsservers, "
        done
        [[ ! -z ${dnsservers} ]] && echo "prepend domain-name-servers $dnsservers;" >>/etc/dhcp/dhclient.conf
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

    op=-1
    CONNECTED=$(curl -I www.google.com -m 5 | grep "200 OK") && op=$? || true
    [ ${op} -ne 0 ] && echo "changing dns wasn't a good idea..." && cp /etc/resolv.conf.bak /etc/resolv.conf || echo "dns change OK..."

    echo done
}

configure_dns_resolvconf() {
    echo "Configuring resolvconf..."

    EXISTING_DNS=$(grep nameserver /etc/resolv.conf | awk '{print $2}')

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
            sfApt install -q -y systemd pciutils || fail 210
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
            yum install -q -y systemd pciutils yum-utils || fail 213
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

update_kernel_settings || fail 217

echo -n "0,linux,${LINUX_KIND},${VERSION_ID},$(hostname),$(date +%Y/%m/%d-%H:%M:%S)" >/opt/safescale/var/state/user_data.netsec.done

# !!! DON'T REMOVE !!! #insert_tag allows to add something just before exiting,
#                      but after the template has been realized (cf. libvirt Stack)
#insert_tag

force_dbus_restart

set +x
exit 0
