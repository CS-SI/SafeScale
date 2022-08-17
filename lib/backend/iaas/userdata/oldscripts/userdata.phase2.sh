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

function print_error() {
  read line file <<< $(caller)
  echo "An error occurred in line $line of file $file:" "{"$(sed "${line}q;d" "$file")"}" >&2
  {{.ExitOnError}}
}
trap print_error ERR

function fail() {
  echo "PROVISIONING_ERROR: $1"
  echo -n "$1,${LINUX_KIND},${FULL_VERSION_ID},$(date +%Y/%m/%d-%H:%M:%S)" > /opt/safescale/var/state/user_data.phase2.done

  collect_installed_packages

  # For compatibility with previous user_data implementation (until v19.03.x)...
  mkdir -p /var/tmp || true
  ln -s ${SF_VARDIR}/state/user_data.phase2.done /var/tmp/user_data.done || true

  exit $1
}

# Redirects outputs to /opt/safescale/log/user_data.phase2.log
exec 1<&-
exec 2<&-
exec 1<> /opt/safescale/var/log/user_data.phase2.log
exec 2>&1
set -x

# Includes the BashLibrary
{{ .BashLibrary }}
sfDetectFacts

function lkw_reset_fw() {
  case $LINUX_KIND in
  debian)
    sfRetry 3m 5 "sfApt update &>/dev/null" || return 1
    if [[ $(lsb_release -rs | cut -d. -f1) -eq 10 ]]; then
      codename=$(sfGetFact "linux_codename")
      sfRetry 3m 5 "sfApt install -q -y -t ${codename}-backports iptables" || return 1
      sfRetry 3m 5 "sfApt install -q -y -t ${codename}-backports firewalld" || return 1
    else
      sfRetry 3m 5 "sfApt install -q -y iptables" || return 1
      sfRetry 3m 5 "sfApt install -q -y firewalld" || return 1
    fi

    systemctl stop ufw
    systemctl disable ufw
    sfRetry 3m 5 "sfApt purge -q -y ufw &>/dev/null" || return 1
    ;;
  ubuntu)
    sfRetry 3m 5 "sfApt update &>/dev/null" || return 1
    sfRetry 3m 5 "sfApt install -q -y iptables" || return 1
    sfRetry 3m 5 "sfApt install -q -y firewalld" || return 1

    systemctl stop ufw
    systemctl disable ufw
    sfRetry 3m 5 "sfApt purge -q -y ufw &>/dev/null" || return 1
    ;;

  redhat | rhel | centos | fedora)
    # firewalld may not be installed
    if ! systemctl is-active firewalld &> /dev/null; then
      if ! systemctl status firewalld &> /dev/null; then
        sfRetry 3m 5 "sfYum install -q -y firewalld" || return 1
      fi
    fi
    ;;
  esac

  # Clear interfaces attached to zones
  for zone in public trusted; do
    for nic in $(firewall-offline-cmd --zone=$zone --list-interfaces || true); do
      firewall-offline-cmd --zone=$zone --remove-interface=$nic &> /dev/null || true
    done
  done

  # Attach Internet interface or source IP to zone public if host is gateway
  [ ! -z $PU_IF ] && {
    # sfFirewallAdd --zone=public --add-interface=$PU_IF || return 1
    firewall-offline-cmd --zone=public --add-interface=$PU_IF || return 1
  }
  {{- if or .PublicIP .IsGateway }}
  [[ -z ${PU_IF} ]] && {
    # sfFirewallAdd --zone=public --add-source=${PU_IP}/32 || return 1
    firewall-offline-cmd --zone=public --add-source=${PU_IP}/32 || return 1
  }
  {{- end }}
  # Attach LAN interfaces to zone trusted
  [[ ! -z ${PR_IFs} ]] && {
    for i in $PR_IFs; do
      # sfFirewallAdd --zone=trusted --add-interface=$PR_IFs || return 1
      firewall-offline-cmd --zone=trusted --add-interface=$PR_IFs || return 1
    done
  }
  # Attach lo interface to zone trusted
  # sfFirewallAdd --zone=trusted --add-interface=lo || return 1
  firewall-offline-cmd --zone=trusted --add-interface=lo || return 1

  # Allow service ssh on public zone
  op=-1
  SSHEC=$(firewall-offline-cmd --zone=public --add-service=ssh) && op=$? || true
  if [[ $op -eq 11 ]] || [[ $op -eq 12 ]] || [[ $op -eq 16 ]]; then
    op=0
  fi

  if [[ $(echo $SSHEC | grep "ALREADY_ENABLED") ]]; then
    op=0
  fi

  if [[ $op -ne 0 ]]; then
    return 1
  fi

  sfService enable firewalld &> /dev/null || return 1
  sfService start firewalld &> /dev/null || return 1

  sop=-1
  firewall-cmd --runtime-to-permanent && sop=$? || sop=$?
  if [[ $sop -ne 0 ]]; then
    if [[ $sop -ne 31 ]]; then
      return 1
    fi
  fi

  # Save current fw settings as permanent
  sfFirewallReload || return 1

  firewall-cmd --list-all --zone=trusted > /tmp/firewall-trusted.cfg || true
  firewall-cmd --list-all --zone=public > /tmp/firewall-public.cfg || true

  return 0
}

function reset_fw() {
  case $LINUX_KIND in
  debian)
    sfRetry 3m 5 "sfApt update &>/dev/null" || return 1
    if [[ $(lsb_release -rs | cut -d. -f1) -eq 10 ]]; then
      codename=$(sfGetFact "linux_codename")
      sfRetry 3m 5 "sfApt install -q -y -t ${codename}-backports iptables" || return 1
      sfRetry 3m 5 "sfApt install -q -y -t ${codename}-backports firewalld" || return 1
    else
      sfRetry 3m 5 "sfApt install -q -y iptables" || return 1
      sfRetry 3m 5 "sfApt install -q -y firewalld" || return 1
    fi

    systemctl stop ufw
    systemctl disable ufw
    sfRetry 3m 5 "sfApt purge -q -y ufw &>/dev/null" || return 1
    ;;
  ubuntu)
    sfRetry 3m 5 "sfApt update &>/dev/null" || return 1
    sfRetry 3m 5 "sfApt install -q -y iptables" || return 1
    sfRetry 3m 5 "sfApt install -q -y firewalld" || return 1

    systemctl stop ufw
    systemctl disable ufw
    sfRetry 3m 5 "sfApt purge -q -y ufw &>/dev/null" || return 1
    ;;

  redhat | rhel | centos | fedora)
    # firewalld may not be installed
    if ! systemctl is-active firewalld &> /dev/null; then
      if ! systemctl status firewalld &> /dev/null; then
        sfRetry 3m 5 "sfYum install -q -y firewalld" || return 1
      fi
    fi
    ;;
  esac

  FWCMD=firewall-offline-cmd # firewall-cmd --permanent "like" command
  FWCMDnop=$FWCMD            # firewall-cmd "like" command without --permanent
  FWPERSIST="firewall-cmd --runtime-to-permanent"
  FWRELOAD="systemctl enable firewalld"
  if [[ $(sfGetFact "redhat_like") == 1 && $(sfGetFact "distrib_version") -ge 8 ]]; then
    FWCMD=sfFirewallAdd
    FWCMDnop=sfFirewall
    FWRELOAD=sfFirewallReload
    systemctl enable firewalld &> /dev/null || return 1
    systemctl start firewalld &> /dev/null || return 1
  else
    systemctl disable firewalld &> /dev/null || return 1
    systemctl stop firewalld &> /dev/null || return 1
  fi

  # Clear interfaces attached to zones
  for zone in public trusted; do
    for nic in $($FWCMD --zone=$zone --list-interfaces); do
      $FWCMD --zone=$zone --remove-interface=$nic &> /dev/null || return 1
    done
  done

  # Attach Internet interface or source IP to zone public if host is gateway
  [ ! -z $PU_IF ] && {
    $FWCMD --zone=public --add-interface=$PU_IF || return 1
  }
  {{- if or .PublicIP .IsGateway }}
  [[ -z ${PU_IF} ]] && {
    $FWCMD --zone=public --add-source=${PU_IP}/32 || return 1
    op=-1
    SSHEC=$($FWCMDnop --set-default-zone=public 2>&1) && op=$? || op=$?
    if [[ $op -eq 11 ]] || [[ $op -eq 12 ]] || [[ $op -eq 16 ]]; then
      op=0
    fi

    if [[ $(echo $SSHEC | grep "ALREADY") ]]; then
      op=0
    fi

    if [[ $op -ne 0 ]]; then
      return 1
    fi
  }
  {{- else }}
  op=-1
  SSHEC=$($FWCMDnop --set-default-zone=trusted) && op=$? || op=$?
  if [[ $op -eq 11 ]] || [[ $op -eq 12 ]] || [[ $op -eq 16 ]]; then
    op=0
  fi
  if [[ $(echo $SSHEC | grep "ALREADY") ]]; then
    op=0
  fi

  if [[ $op -ne 0 ]]; then
    return 1
  fi
  {{- end }}
  # Attach LAN interfaces to zone trusted
  [[ ! -z ${PR_IFs} ]] && {
    for i in $PR_IFs; do
      $FWCMD --zone=trusted --add-interface=$PR_IFs || return 1
    done
  }
  # Attach lo interface to zone trusted
  $FWCMD --zone=trusted --add-interface=lo || return 1

  # Allow service ssh on public zone
  op=-1
  SSHEC=$($FWCMD --zone=public --add-service=ssh 2>&1) && op=$? || op=$?
  if [[ $op -eq 11 ]] || [[ $op -eq 12 ]] || [[ $op -eq 16 ]]; then
    op=0
  fi

  if [[ $(echo $SSHEC | grep "ALREADY_ENABLED") ]]; then
    op=0
  fi

  if [[ $op -ne 0 ]]; then
    return 1
  fi

  sfService enable firewalld &> /dev/null || return 1
  sfService start firewalld &> /dev/null || return 1

  sop=-1
  firewall-cmd --runtime-to-permanent && sop=$? || sop=$?
  if [[ $sop -ne 0 ]]; then
    if [[ $sop -ne 31 ]]; then
      return 1
    fi
  fi

  # Save current fw settings as permanent
  $FWRELOAD || return 1

  firewall-cmd --list-all --zone=trusted > /tmp/firewall-trusted.cfg || true
  firewall-cmd --list-all --zone=public > /tmp/firewall-public.cfg || true

  return 0
}

NICS=
# PR_IPs=
PR_IFs=
PU_IP=
PU_IF=
i_PR_IF=
o_PR_IF=
NETMASK=
AWS=
GCP=
OUT=

# Don't request dns name servers from DHCP server
# Don't update default route
function configure_dhclient() {
  # kill any dhclient process already running
  pkill dhclient || true

  [ -f /etc/dhcp/dhclient.conf ] && (sed -i -e 's/, domain-name-servers//g' /etc/dhcp/dhclient.conf || true)

  if [ -d /etc/dhcp/ ]; then
    HOOK_FILE=/etc/dhcp/dhclient-enter-hooks
    cat >> $HOOK_FILE <<- EOF
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

function is_ip_private() {
  ip=$1
  ipv=$(sfIP2long $ip)

  {{ if .EmulatedPublicNet}}
  r=$(sfCidr2iprange {{ .EmulatedPublicNet }})
  bv=$(sfIP2long $(cut -d- -f1 <<< $r))
  ev=$(sfIP2long $(cut -d- -f2 <<< $r))
  [ $ipv -ge $bv -a $ipv -le $ev ] && return 0
  {{- end }}
  for r in "192.168.0.0-192.168.255.255" "172.16.0.0-172.31.255.255" "10.0.0.0-10.255.255.255"; do
    bv=$(sfIP2long $(cut -d- -f1 <<< $r))
    ev=$(sfIP2long $(cut -d- -f2 <<< $r))
    [ $ipv -ge $bv -a $ipv -le $ev ] && return 0
  done
  return 1
}

function identify_nics() {
  NICS=$(for i in $(find /sys/devices -name net -print | grep -v virtual); do ls $i; done)
  NICS=${NICS/[[:cntrl:]]/ }

  NETMASK=$(echo {{ .CIDR }} | cut -d/ -f2)

  for IF in ${NICS}; do
    IP=$(ip a | grep $IF | grep inet | awk '{print $2}' | cut -d '/' -f1) || true
    [[ ! -z $IP ]] && is_ip_private $IP && PR_IFs="$PR_IFs $IF"
  done
  PR_IFs=$(echo ${PR_IFs} | xargs) || true
  PU_IF=$(ip route get 8.8.8.8 | awk -F"dev " 'NR==1{split($2,a," ");print a[1]}' 2> /dev/null) || true
  PU_IP=$(ip a | grep ${PU_IF} | grep inet | awk '{print $2}' | cut -d '/' -f1) || true
  if [[ ! -z ${PU_IP} ]]; then
    if is_ip_private $PU_IP; then
      PU_IF=

      NO404=$(curl -s -o /dev/null -w "%{http_code}" http://169.254.169.254/latest/meta-data/public-ipv4 2> /dev/null | grep 404) || true
      if [[ -z $NO404 ]]; then
        # Works with FlexibleEngine and potentially with AWS (not tested yet)
        PU_IP=$(curl http://169.254.169.254/latest/meta-data/public-ipv4 2> /dev/null) || true
        [[ -z $PU_IP ]] && PU_IP=$(curl ipinfo.io/ip 2> /dev/null)
      fi
    fi
  fi
  [[ -z ${PR_IFs} ]] && PR_IFs=$(substring_diff "$NICS" "$PU_IF")

  # Keeps track of interfaces identified for future scripting use
  echo "$PR_IFs" > ${SF_VARDIR}/state/private_nics
  echo "$PU_IF" > ${SF_VARDIR}/state/public_nics

  if [[ ! -z ${PU_IP} ]]; then
    if [[ -z ${PU_IF} ]]; then
      if [[ -z ${NO404} ]]; then
        echo "It seems AWS"
        AWS=1
      else
        AWS=0
      fi
    fi
  fi

  if [[ "{{.ProviderName}}" == "aws" ]]; then
    echo "It actually IS AWS"
    AWS=1
  else
    echo "It is NOT AWS"
    AWS=0
  fi

  if [[ "{{.ProviderName}}" == "gcp" ]]; then
    echo "It actually IS GCP"
    GCP=1
  else
    echo "It is NOT GCP"
    GCP=0
  fi

  if [[ "{{.ProviderName}}" == "outscale" ]]; then
    echo "It actually IS Outscale"
    OUT=1
  else
    echo "It is NOT Outscale"
    OUT=0
  fi

  echo "NICS identified: $NICS"
  echo "    private NIC(s): $PR_IFs"
  echo "    public NIC: $PU_IF"
  echo
}

function substring_diff() {
  read -a l1 <<< $1
  read -a l2 <<< $2
  echo "${l1[@]}" "${l2[@]}" | tr ' ' '\n' | sort | uniq -u
}

function collect_original_packages() {
  case $LINUX_KIND in
  debian | ubuntu)
    dpkg-query -l > ${SF_VARDIR}/log/packages_installed_before.phase2.list
    ;;
  redhat | rhel | centos | fedora)
    rpm -qa | sort > ${SF_VARDIR}/log/packages_installed_before.phase2.list
    ;;
  *) ;;
  esac
}

function ensure_curl_is_installed() {
  case $LINUX_KIND in
  ubuntu | debian)
    if [[ -n $(which curl) ]]; then
      return 0
    fi
    DEBIAN_FRONTEND=noninteractive apt-get update || return 1
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl || return 1
    ;;
  redhat | rhel | centos | fedora)
    if [[ -n $(which curl) ]]; then
      return 0
    fi
    sfRetry 3m 5 "sfYum install -y -q curl &>/dev/null" || return 1
    ;;
  *)
    echo "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND'!"
    fail 216
    ;;
  esac

  return 0
}

function collect_installed_packages() {
  case $LINUX_KIND in
  debian | ubuntu)
    dpkg-query -l > ${SF_VARDIR}/log/packages_installed_after.phase2.list
    ;;
  redhat | rhel | centos | fedora)
    rpm -qa | sort > ${SF_VARDIR}/log/packages_installed_after.phase2.list
    ;;
  *) ;;

  esac
}

# If host isn't a gateway, we need to configure temporarily and manually gateway on private hosts to be able to update packages
function ensure_network_connectivity() {
  op=1
  is_network_reachable && op=$? || true
  if [[ $op -ne 0 ]]; then
    echo "ensure_network_connectivity started WITHOUT network..."
  else
    echo "ensure_network_connectivity started WITH network..."
  fi

  {{- if .AddGateway }}
  if [[ -n $(which route) ]]; then
    route del -net default &> /dev/null
    route add -net default gw {{ .DefaultRouteIP }}
  else
    ip route del default
    ip route add default via {{ .DefaultRouteIP }}
  fi
  {{- else }}
  :
  {{- end}}

  op=1
  is_network_reachable && op=$? || true
  if [[ $op -ne 0 ]]; then
    echo "ensure_network_connectivity finished WITHOUT network..."
  else
    echo "ensure_network_connectivity finished WITH network..."
  fi

  if [[ $op -ne 0 ]]; then
    return 1
  fi

  return 0
}

function configure_dns() {
  if systemctl status systemd-resolved &> /dev/null; then
    echo "Configuring dns with resolved"
    configure_dns_systemd_resolved
  elif systemctl status resolvconf &> /dev/null; then
    echo "Configuring dns with resolvconf"
    configure_dns_resolvconf
  else
    echo "Configuring dns legacy"
    configure_dns_legacy
  fi
}

# adds entry in /etc/hosts corresponding to FQDN hostname with private IP
# Follows CentOS rules :
# - if there is a domain suffix in hostname, /etc/hosts contains FQDN as first entry and short hostname as second, after the IP
# - if there is no domain suffix in hostname, /etc/hosts contains short hostname as first entry, after the IP
function update_fqdn() {
  cat /etc/hosts

  FULL_HOSTNAME="{{ .HostName }}"
  SHORT_HOSTNAME="${FULL_HOSTNAME%%.*}"

  # FlexibleEngine seems to add an entry "not not" in /etc/hosts, replace it with
  sed -i -nr '/^not /!p' /etc/hosts

  IF=${PR_IFs[0]}
  if [[ -z ${IF} ]]; then
    sed -i -nr '/^127.0.1.1/!p;$a127.0.1.1\t'"${SHORT_HOSTNAME}" /etc/hosts
  else
    IP=$(ip a | grep ${IF} | grep inet | awk '{print $2}' | cut -d '/' -f1) || true
    sed -i -nr '/^127.0.1.1/!p' /etc/hosts
    if [[ "${SHORT_HOSTNAME}" == "${FULL_HOSTNAME}" ]]; then
      sed -i -nr '/^'"${IP}"'/!p;$a'"${IP}"'\t'"${SHORT_HOSTNAME}" /etc/hosts
    else
      sed -i -nr '/^'"${IP}"'/!p;$a'"${IP}"'\t'"${FULL_HOSTNAME} ${SHORT_HOSTNAME}" /etc/hosts
    fi
  fi

  cat /etc/hosts
}

function install_route_if_needed() {
  case $LINUX_KIND in
  debian)
    if [[ -z $(which route) ]]; then
      sfRetry 3m 5 "sfApt install -y net-tools" || return 1
    fi
    ;;
  ubuntu)
    if [[ -z $(which route) ]]; then
      sfRetry 3m 5 "sfApt install -y net-tools" || return 1
    fi
    ;;
  redhat | rhel | centos)
    if [[ -z $(which route) ]]; then
      sfRetry 3m 5 "sfYum install -y net-tools" || return 1
    fi
    ;;
  fedora)
    if [[ -z $(which route) ]]; then
      sfRetry 3m 5 "sfYum install -y net-tools" || return 1
    fi
    ;;
  *)
    echo "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND $(lsb_release -rs)'!"
    return 1
    ;;
  esac
  return 0
}

function allow_custom_env_ssh_vars() {
  cat >> /etc/ssh/sshd_config <<- EOF
AcceptEnv SAFESCALESSHUSER
AcceptEnv SAFESCALESSHPASS
EOF
  systemctl reload sshd
}

function configure_network() {
  case $LINUX_KIND in
  debian | ubuntu)
    if systemctl status systemd-networkd &> /dev/null; then
      install_route_if_needed
      configure_network_systemd_networkd
    elif systemctl status networking &> /dev/null; then
      install_route_if_needed
      configure_network_debian
    else
      echo "PROVISIONING_ERROR: failed to determine how to configure network"
      fail 192
    fi
    ;;

  redhat | rhel | centos)
    # Network configuration
    if systemctl status systemd-networkd &> /dev/null; then
      install_route_if_needed
      configure_network_systemd_networkd
    else
      install_route_if_needed
      configure_network_redhat
    fi
    ;;

  fedora)
    install_route_if_needed
    configure_network_redhat
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

  update_fqdn
  allow_custom_env_ssh_vars

  check_for_network || {
    echo "PROVISIONING_ERROR: missing or incomplete network connectivity"
    fail 196
  }
}

# Configure network for Debian distribution
function configure_network_debian() {
  echo "Configuring network (debian-like)..."

  local path=/etc/network/interfaces.d
  mkdir -p ${path}
  local cfg=${path}/50-cloud-init.cfg
  rm -f ${cfg}

  for IF in ${NICS}; do
    if [[ "$IF" == "$PU_IF" ]]; then
      cat <<- EOF > ${path}/10-${IF}-public.cfg
auto ${IF}
iface ${IF} inet dhcp
EOF
    else
      cat <<- EOF > ${path}/11-${IF}-private.cfg
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

  reset_fw || {
    echo "PROVISIONING_ERROR: failure setting firewall"
    fail 200
  }

  echo "done"
}

# Configure network using systemd-networkd
function configure_network_systemd_networkd() {
  echo "Configuring network (using netplan and systemd-networkd)..."

  {{- if .IsGateway }}
  ISGW=1
  {{- else}}
  ISGW=0
  {{- end}}

  mkdir -p /etc/netplan
  rm -f /etc/netplan/*

  # Recreate netplan configuration with last netplan version and more settings
  for IF in ${NICS}; do
    if [[ "$IF" == "$PU_IF" ]]; then
      cat <<- EOF > /etc/netplan/10-${IF}-public.yaml
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
      cat <<- EOF > /etc/netplan/11-${IF}-private.yaml
network:
  version: 2
  renderer: networkd

  ethernets:
    ${IF}:
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

  if [[ "{{.ProviderName}}" == "aws" ]]; then
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
      for IF in ${NICS}; do
        if [[ "$IF" == "$PU_IF" ]]; then
          cat <<- EOF > /etc/netplan/10-$IF-public.yaml
network:
  version: 2
  renderer: networkd

  ethernets:
    ${IF}:
      dhcp4: true
      dhcp6: false
      critical: true
      dhcp4-overrides:
          use-dns: true
          use-routes: true
EOF
        else
          cat <<- EOF > /etc/netplan/11-${IF}-private.yaml
network:
  version: 2
  renderer: networkd

  ethernets:
    ${IF}:
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

  NETERR=0

  if [[ ${AWS} -eq 1 ]]; then
    echo "Looking for network..."
    check_for_network || {
      echo "PROVISIONING_ERROR: failed networkd cfg 0"
      NETERR=1
    }
  fi

  # netplan generate
  netplan generate && netplan apply || fail 198

  if [[ ${AWS} -eq 1 ]]; then
    echo "Looking for network..."
    check_for_network || {
      echo "PROVISIONING_ERROR: failed networkd cfg 1"
      NETERR=1
    }
  fi

  configure_dhclient

  if [[ ${AWS} -eq 1 ]]; then
    echo "Looking for network..."
    check_for_network || {
      echo "PROVISIONING_ERROR: failed networkd cfg 2"
      NETERR=1
    }
  fi

  systemctl restart systemd-networkd

  if [[ ${AWS} -eq 1 ]]; then
    echo "Looking for network..."
    check_for_network || {
      echo "PROVISIONING_ERROR: failed networkd cfg 3"
      NETERR=1
    }
  fi

  case $LINUX_KIND in
  ubuntu)
    if [[ $(lsb_release -rs | cut -d. -f1) -eq 20 ]]; then
      if [[ ${NETERR} -eq 1 ]]; then
        echo "Ignoring problems on AWS, ubuntu 20.04 LTS ..."
      fi
    else
      if [[ ${NETERR} -eq 1 ]]; then
        check_for_network || fail 196
      fi
    fi
    ;;
  *) ;;
  esac

  if [[ $GCP -eq 1 ]]; then
    lkw_reset_fw || (echo "PROVISIONING_ERROR: failure setting firewall" && fail 199)
  elif [[ $OUT -eq 1 ]]; then
    lkw_reset_fw || (echo "PROVISIONING_ERROR: failure setting firewall" && fail 199)
  else
    reset_fw || (echo "PROVISIONING_ERROR: failure setting firewall" && fail 199)
  fi

  echo "done"
}

# Configure network for redhat alike distributions (rhel, centos, ...)
function configure_network_redhat() {
  echo "Configuring network (redhat-like)..."

  if [[ -z $VERSION_ID || $VERSION_ID -lt 7 ]]; then
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

  NMCLI=$(which nmcli 2> /dev/null) || true
  if [[ ${AWS} -eq 1 && $(sfGetFact "distrib_version") -ge 8 ]]; then
    configure_network_redhat_without_nmcli || {
      echo "PROVISIONING_ERROR: failed to set network without NetworkManager"
      fail 208
    }
  elif [[ ${GCP} -eq 1 ]]; then
    configure_network_redhat_without_nmcli || {
      echo "PROVISIONING_ERROR: failed to set network without NetworkManager"
      fail 208
    }
  elif [[ ${OUT} -eq 1 ]]; then
    configure_network_redhat_without_nmcli || {
      echo "PROVISIONING_ERROR: failed to set network without NetworkManager"
      fail 208
    }
  else
    NMCLI=$(which nmcli 2> /dev/null) || true
    if [[ -z "${NMCLI}" ]]; then
      configure_network_redhat_without_nmcli || {
        echo "PROVISIONING_ERROR: failed to set network without NetworkManager"
        fail 208
      }
    else
      configure_network_redhat_with_nmcli || {
        echo "PROVISIONING_ERROR: failed to set network with NetworkManager"
        fail 209
      }
    fi
  fi

  if [[ $GCP -eq 1 ]]; then
    lkw_reset_fw || {
      echo "PROVISIONING_ERROR: failure setting firewall"
      fail 210
    }
  elif [[ $OUT -eq 1 ]]; then
    lkw_reset_fw || {
      echo "PROVISIONING_ERROR: failure setting firewall"
      fail 210
    }
  else
    reset_fw || {
      echo "PROVISIONING_ERROR: failure setting firewall"
      fail 210
    }
  fi

  echo "done"
}

# Configure network for redhat 6- alike distributions (rhel, centos, ...)
function configure_network_redhat_without_nmcli() {
  echo "Configuring network (RedHat 6- alike)..."

  # We don't want NetworkManager if RedHat/CentOS < 7
  stop_svc NetworkManager &> /dev/null
  disable_svc NetworkManager &> /dev/null
  sfRetry 3m 5 "sfYum remove -y NetworkManager &>/dev/null"
  echo "exclude=NetworkManager" >> /etc/yum.conf

  if which dnf; then
    dnf install -q -y network-scripts || true
  else
    yum install -q -y network-scripts || true
  fi

  # Configure all network interfaces in dhcp
  for IF in $NICS; do
    if [[ $IF != "lo" ]]; then
      cat > /etc/sysconfig/network-scripts/ifcfg-${IF} <<- EOF
DEVICE=$IF
BOOTPROTO=dhcp
ONBOOT=yes
NM_CONTROLLED=no
EOF
      {{- if .DNSServers }}
      i=1
      {{- range .DNSServers }}
      echo "DNS${i}={{ . }}" >> /etc/sysconfig/network-scripts/ifcfg-${IF}
      i=$((i + 1))
      {{- end }}
      {{- else }}
      EXISTING_DNS=$(grep nameserver /etc/resolv.conf | awk '{print $2}')
      if [[ -z ${EXISTING_DNS} ]]; then
        echo "DNS1=1.1.1.1" >> /etc/sysconfig/network-scripts/ifcfg-${IF}
      else
        echo "DNS1=$EXISTING_DNS" >> /etc/sysconfig/network-scripts/ifcfg-${IF}
      fi
      {{- end }}

      {{- if .AddGateway }}
      echo "GATEWAY={{ .DefaultRouteIP }}" >> /etc/sysconfig/network-scripts/ifcfg-${IF}
      {{- end}}
    fi
  done

  configure_dhclient

  {{- if .AddGateway }}
  echo "GATEWAY={{ .DefaultRouteIP }}" > /etc/sysconfig/network
  {{- end }}

  enable_svc network
  restart_svc network

  return 0
}

# Configure network for redhat7+ alike distributions (rhel, centos, ...)
function configure_network_redhat_with_nmcli() {
  echo "Configuring network (RedHat 7+ alike with Network Manager)..."

  # Do some cleanup inside /etc/sysconfig/network-scripts
  CONNECTIONS=$(nmcli -f "NAME,DEVICE" -c no -t con)
  for i in $CONNECTIONS; do
    NAME=$(echo ${i} | cut -d':' -f1)
    DEVICE=$(echo ${i} | cut -d':' -f2)
    [[ -z "${DEVICE}" ]] && mv /etc/sysconfig/network-scripts/ifcfg-${NAME} /etc/sysconfig/network-scripts/disabled.ifcfg-${NAME}
  done

  # Configure all network interfaces
  for IF in $(nmcli -f 'DEVICE' -c no -t dev); do
    # We change nothing on device lo
    [[ "${IF}" == "lo" ]] && continue

    DEV_IP=$(nmcli -g IP4.ADDRESS dev show "${IF}")
    # We change nothing on device with Public IP Address
    is_ip_private $(echo ${DEV_IP} | cut -d/ -f1) || continue

    CONN=$(nmcli -c no -t -f "NAME,DEVICE" con | grep ${IF} | cut -d: -f1)
    nmcli con mod "${CONN}" connection.autoconnect yes || return 1
    # Assume the IP Address cannot change even if the first time it is affected by DHCP
    nmcli con mod "${CONN}" ipv4.addresses "${DEV_IP}" || return 1
    nmcli con mod "${CONN}" ipv4.method manual || return 1
    {{- if .DNSServers }}
    {{- range .DNSServers }}
    nmcli con mod "${CONN}" +ipv4.dns {{ . }} || return 1
    {{- end }}
    {{- else }}
    EXISTING_DNS=$(grep nameserver /etc/resolv.conf | awk '{print $2}')
    if [[ -z ${EXISTING_DNS} ]]; then
      ${NMCLI} con mod "${CONN}" +ipv4.dns 1.1.1.1 || return 1
    else
      ${NMCLI} con mod "${CONN}" +ipv4.dns ${EXISTING_DNS} || return 1
    fi
    {{- end }}

    {{- if .AddGateway }}
    nmcli con mod "${CONN}" ipv4.gateway "{{ .DefaultRouteIP }}"
    {{- end}}

  done

  nmcli con reload

  configure_dhclient || return 1

  enable_svc NetworkManager
  restart_svc NetworkManager

  return 0
}

function check_for_ip() {
  case $LINUX_KIND in
  debian)
    lsb_release -rs | grep "8." && return 0
    ;;
  *) ;;
  esac

  allip=$(ip -f inet -o addr show)
  ip=$(ip -f inet -o addr show $1 | cut -d' ' -f7 | cut -d' ' -f1)

  case $LINUX_KIND in
  ubuntu)
    if [[ $(lsb_release -rs | cut -d. -f1) -eq 16 ]]; then
      if [[ $(echo $allip | grep $1) == "" ]]; then
        echo "Ubuntu 16.04 is expected to fail this test..."
        return 0
      fi
    fi
    ;;
  debian)
    if [[ $(lsb_release -rs | cut -d. -f1) -eq 8 ]]; then
      if [[ $(echo $allip | grep $1) == "" ]]; then
        echo "Debian 8 is expected to fail this test..."
        return 0
      fi
    fi
    ;;
  *) ;;
  esac

  [[ -z "$ip" ]] && echo "Failure checking for ip '$ip' when evaluating '$1'" && return 1
  return 0
}

# Checks network is set correctly
# - DNS and routes (by pinging a FQDN)
# - IP address on "physical" interfaces
function check_for_network() {
  is_network_reachable || return 1

  [[ ! -z "$PU_IF" ]] && {
    check_for_ip ${PU_IF} || return 1
  }
  for i in ${PR_IFs}; do
    check_for_ip ${i} || return 1
  done

  return 0
}

function configure_as_gateway() {
  echo "Configuring host as gateway..."

  if [[ ! -z $PR_IFs ]]; then
    # Enable forwarding
    for i in /etc/sysctl.d/* /etc/sysctl.conf; do
      grep -v "net.ipv4.ip_forward=" ${i} > ${i}.new
      mv -f ${i}.new ${i}
    done
    cat > /etc/sysctl.d/21-gateway.conf <<- EOF
net.ipv4.ip_forward=1
net.ipv4.ip_nonlocal_bind=1
EOF
    case $LINUX_KIND in
    ubuntu) systemctl restart systemd-sysctl ;;
    *) sysctl -p ;;
    esac
  fi

  if [[ ! -z $PU_IF ]]; then
    # Dedicated public interface available...

    # Allows ping
    firewall-offline-cmd --direct --add-rule ipv4 filter INPUT 0 -p icmp -m icmp --icmp-type 8 -s 0.0.0.0/0 -d 0.0.0.0/0 -j ACCEPT
    # Allows masquerading on public zone
    firewall-offline-cmd --zone=public --add-masquerade
  fi
  # Enables masquerading on trusted zone (mainly for docker networks)
  firewall-offline-cmd --zone=trusted --add-masquerade

  # Allows default services on public zone
  firewall-offline-cmd --zone=public --add-service=ssh 2> /dev/null
  # Applies fw rules
  # sfFirewallReload

  sed -i '/^\#*AllowTcpForwarding / s/^.*$/AllowTcpForwarding yes/' /etc/ssh/sshd_config || sfFail 196
  sed -i '/^.*PasswordAuthentication / s/^.*$/PasswordAuthentication no/' /etc/ssh/sshd_config || sfFail 197
  systemctl restart sshd || sfFail 197

  echo "done"
}

function install_keepalived() {
  # Try installing network-scripts if available
  case $LINUX_KIND in
  redhat | rhel | centos | fedora)
    sfRetry 3m 5 "sfYum install -q -y network-scripts" || true
    ;;
  *) ;;

  esac

  case $LINUX_KIND in
  ubuntu | debian)
    sfRetry 3m 5 "sfApt update" || return 1
    sfRetry 3m 5 "sfApt -y install keepalived" || return 1
    ;;

  redhat | rhel | centos | fedora)
    sfRetry 3m 5 "sfYum install -q -y keepalived" || return 1
    ;;
  *)
    echo "Unsupported Linux distribution '$LINUX_KIND'!"
    return 1
    ;;
  esac

  NETMASK=$(echo {{ .CIDR }} | cut -d/ -f2)

  cat > /etc/keepalived/keepalived.conf <<- EOF
vrrp_instance vrrp_group_gws_internal {
    state {{ if eq .IsPrimaryGateway true }}MASTER{{ else }}BACKUP{{ end }}
    interface ${PR_IFs[0]}
    virtual_router_id 1
    priority {{ if eq .IsPrimaryGateway true }}151{{ else }}100{{ end }}
    nopreempt
    advert_int 2
    authentication {
        auth_type PASS
        auth_pass {{ .GatewayHAKeepalivedPassword }}
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
    if [[ $(sfGetFact "redhat_like") -eq 1 ]]; then
      cat > /etc/systemd/system/keepalived.service.d/override.conf << EOF
[Unit]
Requires=network.service
PartOf=network.service
EOF
    else
      cat > /etc/systemd/system/keepalived.service.d/override.conf << EOF
[Unit]
Requires=systemd-networkd.service
PartOf=systemd-networkd.service
EOF
    fi
    systemctl daemon-reload
  fi

  sfService enable keepalived || return 1

  op=-1
  msg=$(sfService restart keepalived 2>&1) && op=$? || true

  kop=-1
  echo $msg | grep "Unit network.service not found" && kop=$? || true

  if [[ op -ne 0 ]]; then
    if [[ kop -eq 0 ]]; then
      case $LINUX_KIND in
      redhat | rhel | centos | fedora)
        sfRetry 3m 5 "sfYum install -q -y network-scripts" || return 1
        ;;
      *) ;;

      esac
    fi
  fi

  sfService restart keepalived || return 1
  return 0
}

function configure_dns_legacy() {
  echo "Configuring /etc/resolv.conf..."
  cp /etc/resolv.conf /etc/resolv.conf.bak

  rm -f /etc/resolv.conf
  {{- if .DNSServers }}
  if [[ -e /etc/dhcp/dhclient.conf ]]; then
    dnsservers=
    for i in {{range .DNSServers}} {{end}}; do
      [ ! -z $dnsservers ] && dnsservers="$dnsservers, "
    done
    [ ! -z $dnsservers ] && echo "prepend domain-name-servers $dnsservers;" >> /etc/dhcp/dhclient.conf
  else
    echo "dhclient.conf not modified"
  fi
  {{- else }}
  if [[ -e /etc/dhcp/dhclient.conf ]]; then
    echo "prepend domain-name-servers 1.1.1.1;" >> /etc/dhcp/dhclient.conf
  else
    echo "/etc/dhcp/dhclient.conf not modified"
  fi
  {{- end }}
  cat <<- 'EOF' > /etc/resolv.conf
{{- if .DNSServers }}
  {{- range .DNSServers }}
nameserver {{ . }}
  {{- end }}
{{- else }}
nameserver 1.1.1.1
{{- end }}
EOF

  # VPL: need to determine if it's a good idea to update resolv.conf with search domain...
  #      The DNS servers will not be able to resolve hosts from the DNSDOMAIN by themselves, there is a need for an internal DNS server
  #    DNSDOMAIN="$(hostname -d)"
  #    if [[ ! -z "$DNSDOMAIN" ]]; then
  #cat <<-EOF >>/etc/resolv.conf
  #search $DNSDOMAIN
  #EOF
  #    fi

  cp /etc/resolv.conf /etc/resolv.conf.edited
  touch /etc/resolv.conf && sleep 2 || true

  op=-1
  is_network_reachable && op=$? || true

  [[ ${op} -ne 0 ]] && echo "changing dns wasn't a good idea..." && cp /etc/resolv.conf.bak /etc/resolv.conf && touch /etc/resolv.conf && sleep 2 || echo "dns change OK..."

  echo "done"
}

function configure_dns_resolvconf() {
  echo "Configuring resolvconf..."

  EXISTING_DNS=$(grep nameserver /etc/resolv.conf | awk '{print $2}')

  cat <<- 'EOF' > /etc/resolvconf/resolv.conf.d/head
{{- if .DNSServers }}
  {{- range .DNSServers }}
nameserver {{ . }}
  {{- end }}
{{- else }}
nameserver 1.1.1.1
{{- end }}
EOF

  # VPL: need to determine if it's a good idea to update resolv.conf with search domain...
  #      The DNS servers will not be able to resolve hosts from the DNSDOMAIN by themselves, there is a need for an internal DNS server
  #    DNSDOMAIN="$(hostname -d)"
  #    if [[ ! -z "$DNSDOMAIN" ]]; then
  #        cat <<-EOF >>/etc/resolvconf/resolv.conf.d/head
  #search $DNSDOMAIN
  #EOF
  #    fi

  resolvconf -u
  echo "done"
}

function configure_dns_systemd_resolved() {
  echo "Configuring systemd-resolved..."

  {{- if not .DefaultRouteIP }}
  rm -f /etc/resolv.conf
  ln -s /run/systemd/resolve/resolv.conf /etc
  {{- end }}

  cat <<- 'EOF' > /etc/systemd/resolved.conf
[Resolve]
{{- if .DNSServers }}
DNS={{ range .DNSServers }}{{ . }} {{ end }}
{{- else }}
DNS=1.1.1.1
{{- end}}
Cache=yes
DNSStubListener=yes
EOF

  # VPL: need to determine if it's a good idea to update resolv.conf with search domain...
  #      The DNS servers will not be able to resolve hosts from the DNSDOMAIN by themselves, there is a need for an internal DNS server
  #    DNSDOMAIN=$(hostname -d)
  #    if [[ ! -z "$DNSDOMAIN" ]]; then
  #        cat <<-EOF >>/etc/systemd/resolved.conf
  #Domains=$DNSDOMAIN
  #EOF
  #    fi

  systemctl restart systemd-resolved
  echo "done"
}

function install_drivers_nvidia() {
  case $LINUX_KIND in
  ubuntu)
    sfFinishPreviousInstall
    add-apt-repository -y ppa:graphics-drivers &> /dev/null
    sfRetry 3m 5 "sfApt update" || fail 201
    sfRetry 3m 5 "sfApt -y install nvidia-410 &>/dev/null" || {
      sfRetry 3m 5 "sfApt -y install nvidia-driver-410 &>/dev/null" || fail 201
    }
    ;;

  debian)
    if [ ! -f /etc/modprobe.d/blacklist-nouveau.conf ]; then
      echo -e "blacklist nouveau\nblacklist lbm-nouveau\noptions nouveau modeset=0\nalias nouveau off\nalias lbm-nouveau off" >> /etc/modprobe.d/blacklist-nouveau.conf
      rmmod nouveau
    fi
    sfRetry 3m 5 "sfApt update &>/dev/null"
    sfRetry 3m 5 "sfApt install -y dkms build-essential linux-headers-$(uname -r) gcc make &>/dev/null" || fail 202
    dpkg --add-architecture i386 &> /dev/null
    sfRetry 3m 5 "sfApt update &>/dev/null"
    sfRetry 3m 5 "sfApt install -y lib32z1 lib32ncurses5 &>/dev/null" || fail 203
    wget http://us.download.nvidia.com/XFree86/Linux-x86_64/410.78/NVIDIA-Linux-x86_64-410.78.run &> /dev/null || fail 204
    bash NVIDIA-Linux-x86_64-410.78.run -s || fail 205
    ;;

  redhat | rhel | centos | fedora)
    if [ ! -f /etc/modprobe.d/blacklist-nouveau.conf ]; then
      echo -e "blacklist nouveau\noptions nouveau modeset=0" >> /etc/modprobe.d/blacklist-nouveau.conf
      dracut --force
      rmmod nouveau
    fi
    sfRetry 3m 5 "sfYum -y -q install kernel-devel.$(uname -i) kernel-headers.$(uname -i) gcc make &>/dev/null" || fail 206
    wget http://us.download.nvidia.com/XFree86/Linux-x86_64/410.78/NVIDIA-Linux-x86_64-410.78.run || fail 207
    # if there is a version mismatch between kernel sources and running kernel, building the driver would require 2 reboots to get it done, right now this is unsupported
    if [ $(uname -r) == $(sfYum list installed | grep kernel-headers | awk {'print $2'}).$(uname -i) ]; then
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

function early_packages_update() {
  is_network_reachable || return 1

  # Ensure IPv4 will be used before IPv6 when resolving hosts (the latter shouldn't work regarding the network configuration we set)
  cat > /etc/gai.conf <<- EOF
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

    sfRetry 3m 5 "sfApt update"
    # Force update of systemd, pciutils
    sfRetry 3m 5 "sfApt install -q -y systemd pciutils" || fail 210
    # systemd, if updated, is restarted, so we may need to ensure again network connectivity
    ensure_network_connectivity
    is_network_reachable
    ;;

  ubuntu)
    # Disable interactive installations
    export DEBIAN_FRONTEND=noninteractive
    # # Force use of IPv4 addresses when installing packages
    # echo 'Acquire::ForceIPv4 "true";' >/etc/apt/apt.conf.d/99force-ipv4

    sfRetry 3m 5 "sfApt update"
    # Force update of systemd, pciutils and netplan
    if dpkg --compare-versions $(sfGetFact "distrib_version") ge 17.10; then
      sfRetry 3m 5 "sfApt install -y systemd pciutils netplan.io" || fail 211
    else
      sfRetry 3m 5 "sfApt install -y systemd pciutils" || fail 212
    fi
    # systemd, if updated, is restarted, so we may need to ensure again network connectivity
    ensure_network_connectivity
    is_network_reachable

    # # Security updates ...
    # sfApt update &>/dev/null && sfApt install -qy unattended-upgrades && unattended-upgrades -v
    ;;

  redhat | rhel | centos | fedora)
    # # Force use of IPv4 addresses when installing packages
    # echo "ip_resolve=4" >>/etc/yum.conf

    # Force update of systemd and pciutils
    sfRetry 3m 5 "sfYum install -q -y pciutils yum-utils" || fail 213

    if [[ "{{.ProviderName}}" == "huaweicloud" ]]; then
      if [ "$(lscpu --all --parse=CORE,SOCKET | grep -Ev "^#" | sort -u | wc -l)" = "1" ]; then
        echo "Skipping upgrade of systemd when only 1 core is available"
      else
        # systemd, if updated, is restarted, so we may need to ensure again network connectivity
        if which dnf; then
          op=-1
          msg=$(sfRetry 3m 5 "sfYum install -q -y systemd 2>&1") && op=$? || true
          echo $msg | grep "Nothing to do" && return
          [ $op -ne 0 ] && sfFail 213
        else
          op=-1
          msg=$(sfRetry 3m 5 "sfYum install -q -y systemd 2>&1") && op=$? || true
          echo $msg | grep "Nothing to do" && return
          [ $op -ne 0 ] && sfFail 213
        fi
        ensure_network_connectivity
        is_network_reachable
      fi
    else
      if which dnf; then
        op=-1
        msg=$(sfRetry 3m 5 "sfYum install -q -y systemd 2>&1") && op=$? || true
        echo $msg | grep "Nothing to do" && return
        [ $op -ne 0 ] && sfFail 213
      else
        op=-1
        msg=$(sfRetry 3m 5 "sfYum install -q -y systemd 2>&1") && op=$? || true
        echo $msg | grep "Nothing to do" && return
        [ $op -ne 0 ] && sfFail 213
      fi
      ensure_network_connectivity
      is_network_reachable
    fi

    # # install security updates
    # yum install -y yum-plugin-security yum-plugin-changelog && yum update -y --security
    ;;
  esac
  sfProbeGPU
}

function install_packages() {
  case $LINUX_KIND in
  ubuntu | debian)
    sfRetry 4m 5 "sfApt install -y -qq jq zip time &>/dev/null" || fail 214
    ;;
  redhat | rhel | centos)
    sfRetry 4m 5 "sfYum install --enablerepo=epel -y -q wget jq time zip &>/dev/null" || fail 215
    ;;
  fedora)
    sfRetry 4m 5 "sfYum install -y -q wget jq time zip &>/dev/null" || fail 215
    ;;
  *)
    echo "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND'!"
    fail 216
    ;;
  esac
}

function add_backport_repos() {
  case $LINUX_KIND in
  debian)
    sfFinishPreviousInstall
    codename=$(sfGetFact "linux_codename")
    echo "deb http://deb.debian.org/debian ${codename}-backports main" >> /etc/apt/sources.list
    ;;
  esac
}

function add_common_repos() {
  case $LINUX_KIND in
  ubuntu)
    sfFinishPreviousInstall
    add-apt-repository universe -y || fail 217
    codename=$(sfGetFact "linux_codename")
    echo "deb http://archive.ubuntu.com/ubuntu/ ${codename}-proposed main" > /etc/apt/sources.list.d/${codename}-proposed.list
    ;;
  redhat | rhel | centos)
    if which dnf; then
      # Install EPEL repo ...
      sfRetry 3m 5 "dnf install -y epel-release" || fail 217
      sfRetry 3m 5 "dnf makecache -y" || fail 218
      # ... but don't enable it by default
      sfRetry 3m 5 "sfYum config-manager --set-disabled epel &>/dev/null" || true
    else
      # Install EPEL repo ...
      sfRetry 3m 5 "yum install -y epel-release" || fail 217
      sfRetry 3m 5 "yum makecache" || fail 218
      # ... but don't enable it by default
      yum-config-manager --disablerepo=epel &> /dev/null || true
    fi
    ;;
  fedora)
    sfRetry 3m 5 "dnf makecache -y" || fail 218
    ;;
  esac
}

function configure_locale() {
  case $LINUX_KIND in
  ubuntu | debian)
    locale-gen en_US.UTF-8
    ;;
  esac
  export LANGUAGE=en_US.UTF-8 LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8
}

function force_dbus_restart() {
  case $LINUX_KIND in
  ubuntu)
    sudo sed -i 's/^RefuseManualStart=.*$/RefuseManualStart=no/g' /lib/systemd/system/dbus.service
    sudo systemctl daemon-reexec
    sudo systemctl restart dbus.service
    ;;
  esac
}

# sets root password to the same as the one for SafeScale OperatorUsername (on distribution where root needs password),
# to be able to connect root on console when emergency shell arises.
# Root account not being usable remotely (and OperatorUsername being able to become root with sudo), this is not
# considered a security risk. Especially when set after SSH and Firewall configuration applied.
function configure_root_password_if_needed() {
  case ${LINUX_KIND} in
  redhat | rhel | centos | fedora)
    echo "root:{{.Password}}" | chpasswd
    ;;
  esac
}

function update_kernel_settings() {
  cat > /etc/sysctl.d/20-safescale.conf <<- EOF
vm.max_map_count=262144
EOF
  case $LINUX_KIND in
  ubuntu) systemctl restart systemd-sysctl ;;
  *) sysctl -p ;;
  esac
}

function use_cgroups_v1_if_needed() {
  case $LINUX_KIND in
  fedora)
    if [[ -n $(which lsb_release) ]]; then
      if [[ $(lsb_release -rs | cut -d. -f1) -gt 30 ]]; then
        sfRetry 3m 5 "sfYum install -y grubby" || return 1
        grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=0" || return 1
      fi
    else
      if [[ $(echo ${VERSION_ID}) -gt 30 ]]; then
        sfRetry 3m 5 "sfYum install -y grubby" || return 1
        grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=0" || return 1
      fi
    fi
    ;;
  esac

  return 0
}

function fail_fast_unsupported_distros() {
  case $LINUX_KIND in
  debian)
    lsb_release -rs | grep "8." && {
      echo "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND $(lsb_release -rs)'!"
      fail 201
    } || true
    ;;
  ubuntu)
    if [[ $(lsb_release -rs | cut -d. -f1) -le 17 ]]; then
      if [[ $(lsb_release -rs | cut -d. -f1) -ne 16 ]]; then
        echo "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND $(lsb_release -rs)'!"
        fail 201
      fi
    fi
    ;;
  redhat | rhel | centos)
    if [[ -n $(which lsb_release) ]]; then
      if [[ $(lsb_release -rs | cut -d. -f1) -lt 7 ]]; then
        echo "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND $(lsb_release -rs)'!"
        fail 201
      fi
    else
      if [[ $(echo ${VERSION_ID}) -lt 7 ]]; then
        echo "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND $VERSION_ID'!"
        fail 201
      fi
    fi
    ;;
  fedora)
    if [[ -n $(which lsb_release) ]]; then
      if [[ $(lsb_release -rs | cut -d. -f1) -lt 30 ]]; then
        echo "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND $(lsb_release -rs)'!"
        fail 201
      fi
    else
      if [[ $(echo ${VERSION_ID}) -lt 30 ]]; then
        echo "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND $VERSION_ID'!"
        fail 201
      fi
    fi
    ;;
  *)
    echo "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND $(lsb_release -rs)'!"
    fail 201
    ;;
  esac
}

function check_network_reachable() {
  NETROUNDS=2
  REACHED=0
  TRIED=0

  for i in $(seq ${NETROUNDS}); do
    if which curl; then
      TRIED=1
      curl -s -I www.google.com -m 4 | grep "200 OK" && REACHED=1 && break
    fi

    if [[ ${TRIED} -eq 1 ]]; then
      break
    fi

    if which wget; then
      TRIED=1
      wget -T 4 -O /dev/null www.google.com &> /dev/null && REACHED=1 && break
    fi

    if [[ ${TRIED} -eq 1 ]]; then
      break
    fi

    ping -n -c1 -w4 -i1 www.google.com && REACHED=1 && break
  done

  if [[ ${REACHED} -eq 0 ]]; then
    echo "PROVISIONING_ERROR: Unable to reach network"
    fail 221
  fi

  return 0
}

function check_dns_configuration() {
  if [[ -r /etc/resolv.conf ]]; then
    echo "Getting DNS using resolv.conf..."
    THE_DNS=$(cat /etc/resolv.conf | grep -i '^nameserver' | head -n1 | cut -d ' ' -f2) || true

    if [[ -n ${THE_DNS} ]]; then
      timeout 2s bash -c "echo > /dev/tcp/${THE_DNS}/53" && echo "DNS ${THE_DNS} up and running" || echo "Failure connecting to DNS ${THE_DNS}"
    fi
  fi

  if which systemd-resolve; then
    echo "Getting DNS using systemd-resolve"
    THE_DNS=$(systemd-resolve --status | grep "Current DNS" | awk '{print $4}') || true
    if [[ -n ${THE_DNS} ]]; then
      timeout 2s bash -c "echo > /dev/tcp/${THE_DNS}/53" && echo "DNS ${THE_DNS} up and running" || echo "Failure connecting to DNS ${THE_DNS}"
    fi
  fi

  if which resolvectl; then
    echo "Getting DNS using resolvectl"
    THE_DNS=$(resolvectl | grep "Current DNS" | awk '{print $4}') || true
    if [[ -n ${THE_DNS} ]]; then
      timeout 2s bash -c "echo > /dev/tcp/${THE_DNS}/53" && echo "DNS ${THE_DNS} up and running" || echo "Failure connecting to DNS ${THE_DNS}"
    fi
  fi

  timeout 2s bash -c "echo > /dev/tcp/www.google.com/80" && echo "Network OK" && return 0 || echo "Network not reachable"
  return 1
}

function is_network_reachable() {
  NETROUNDS=6
  REACHED=0
  TRIED=0

  for i in $(seq ${NETROUNDS}); do
    if which curl; then
      TRIED=1
      curl -s -I www.google.com -m 4 | grep "200 OK" && REACHED=1 && break
    fi

    if [[ ${TRIED} -eq 1 ]]; then
      continue
    fi

    if which wget; then
      TRIED=1
      wget -T 4 -O /dev/null www.google.com &> /dev/null && REACHED=1 && break
    fi

    if [[ ${TRIED} -eq 1 ]]; then
      continue
    fi

    ping -n -c1 -w4 -i1 www.google.com && REACHED=1 && break
  done

  if [[ ${REACHED} -eq 0 ]]; then
    echo "Unable to reach network"
    return 1
  fi

  return 0
}

function compatible_network() {
  # Try installing network-scripts if available
  case $LINUX_KIND in
  redhat | rhel | centos | fedora)
    sfRetry 3m 5 "sfYum install -q -y network-scripts" || true
    ;;
  *) ;;
  esac
}

function make_ready_for_ansible() {
  # Try installing python3 if available, a failure is not considered an error
  case $LINUX_KIND in
  debian | ubuntu)
    sfRetry 3m 5 "sfApt install -y python3" || true
    ;;
  redhat | rhel | centos | fedora)
    sfRetry 3m 5 "sfYum install -q -y python3" || true
    ;;
  *) ;;
  esac
}

function track_time() {
  uptime
  last
}

# ---- Main

PHASE_DONE=/opt/safescale/var/state/user_data.phase2.done
if [[ -f "$PHASE_DONE" ]]; then
  echo "$PHASE_DONE already there."
  set +x
  exit 0
fi

track_time

collect_original_packages

fail_fast_unsupported_distros

configure_locale

op=1
ensure_curl_is_installed && op=$? || true
if [[ ${op} -ne 0 ]]; then
  echo "Curl not available yet"
else
  echo "Curl installed"
fi

check_dns_configuration || true

op=1
is_network_reachable && op=$? || true
in_reach_before_dns=$op

configure_dns

op=1
is_network_reachable && op=$? || true
in_reach_after_dns=$op

if [[ ${in_reach_after_dns} -eq 1 ]]; then
  if [[ ${in_reach_before_dns} -eq 0 ]]; then
    echo "PROVISIONING_ERROR: Changing DNS messed up connectivity" && fail 191
  fi
fi

op=1
ensure_network_connectivity && op=$? || true
network_connectivity_ok=$op

op=1
is_network_reachable && op=$? || true
in_reach_after_gateway_setup=$op

if [[ ${in_reach_after_gateway_setup} -eq 1 ]]; then
  if [[ ${in_reach_after_dns} -eq 0 ]]; then
    echo "PROVISIONING_ERROR: Changing Gateway messed up connectivity" && fail 192
  fi
fi

add_common_repos
add_backport_repos

early_packages_update

install_route_if_needed
install_packages

make_ready_for_ansible

lspci | grep -i nvidia &> /dev/null && install_drivers_nvidia

use_cgroups_v1_if_needed || fail 235

update_kernel_settings || fail 236
configure_root_password_if_needed || fail 237

identify_nics
configure_network

is_network_reachable || fail 238

collect_installed_packages

echo -n "0,linux,${LINUX_KIND},${FULL_VERSION_ID},$(hostname),$(date +%Y/%m/%d-%H:%M:%S)" > /opt/safescale/var/state/user_data.phase2.done

# For compatibility with previous user_data implementation (until v19.03.x)...
mkdir -p /var/tmp || true
ln -s ${SF_VARDIR}/state/user_data.phase2.done /var/tmp/user_data.done || true

# !!! DON'T REMOVE !!! #insert_tag allows to add something just before exiting,
#                      but after the template has been realized (cf. libvirt Stack)
#insert_tag

force_dbus_restart

track_time

set +x
exit 0
