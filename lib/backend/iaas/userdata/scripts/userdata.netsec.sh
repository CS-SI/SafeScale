#!/bin/bash -x
#
# Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
# Script customized for {{.ProviderName}} driver

# shellcheck disable=SC1009
# shellcheck disable=SC1073
# shellcheck disable=SC1054
{{.Header}}

last_error=

function print_error() {
  read -r line file <<< "$(caller)"
  echo "An error occurred in line $line of file $file:" "{$(sed "${line}q;d" "$file")}" >&2
  {{.ExitOnError}}
}
trap print_error ERR

function failure() {
  MYIP="$(ip -br a | grep UP | awk '{print $3}') | head -n 1"
  if [ $# -eq 1 ]; then
    echo "PROVISIONING_ERROR: $1"
    echo -n "$1,${LINUX_KIND},${VERSION_ID},$(hostname),$MYIP,$(date +%Y/%m/%d-%H:%M:%S),PROVISIONING_ERROR:$1" > /opt/safescale/var/state/user_data.netsec.done
    (
      sync
      echo 3 > /proc/sys/vm/drop_caches
      sleep 2
    ) || true
    exit $1
  elif [ $# -eq 2 -a $1 -ne 0 ]; then
    echo "PROVISIONING_ERROR: $1, $2"
    echo -n "$1,${LINUX_KIND},${VERSION_ID},$(hostname),$MYIP,$(date +%Y/%m/%d-%H:%M:%S),PROVISIONING_ERROR:$2" > /opt/safescale/var/state/user_data.netsec.done
    (
      sync
      echo 3 > /proc/sys/vm/drop_caches
      sleep 2
    ) || true
    exit $1
  fi
}
export -f failure

function rv() {
  declare -n ret=$1
  local message=$3
  ret=$message
  return $2
}

function return_failure() {
  rv last_error $1 "$2"
}
export -f return_failure

# Redirects outputs to /opt/safescale/var/log/user_data.netsec.log
LOGFILE=/opt/safescale/var/log/user_data.netsec.log

### All output to one file and all output to the screen
{{- if .Debug }}
if [[ -e /home/{{.Username}}/tss ]]; then
  exec > >(/home/{{.Username}}/tss | tee -a ${LOGFILE} /opt/safescale/var/log/ss.log) 2>&1
else
  exec > >(tee -a ${LOGFILE} /opt/safescale/var/log/ss.log) 2>&1
fi
{{- else }}
exec > >(tee -a ${LOGFILE} /opt/safescale/var/log/ss.log) 2>&1
{{- end }}

set -x

date

# Tricks BashLibrary's waitUserData to believe the current phase 'netsec' is already done (otherwise will deadlock)
uptime > /opt/safescale/var/state/user_data.netsec.done

# Includes the BashLibrary
# shellcheck disable=SC1009
# shellcheck disable=SC1073
# shellcheck disable=SC1054
{{ .reserved_BashLibrary }}
rm -f /opt/safescale/var/state/user_data.netsec.done

function reset_fw() {
  {{- if .WithoutFirewall }}
  return 0
  {{- end }}

  is_network_reachable || failure 206 "reset_fw(): failure resetting firewall because network is not reachable"

  case $LINUX_KIND in
  debian)
    echo "Reset firewall"
    sfApt update || failure 207 "reset_fw(): failure running apt update"
    sfRetry4 "sfApt -y autoclean autoremove" || failure 210 "reset_fw(): failure running cleanup"
    sfRetry4 "sfApt install -q -y --no-install-recommends iptables" || failure 210 "reset_fw(): failure installing iptables"
    sfRetry4 "sfApt install -q -y --no-install-recommends firewalld python3" || failure 211 "reset_fw(): failure installing firewalld"

    systemctl is-active ufw &> /dev/null && {
      echo "Stopping ufw"
      systemctl stop ufw || true # set to true to fix issues
    }
    systemctl is-enabled ufw &> /dev/null && {
      systemctl disable ufw || true # set to true to fix issues
    }
    dpkg --purge --force-remove-reinstreq ufw &>/dev/null || failure 212 "reset_fw(): failure purging ufw"
    ;;

  ubuntu)
    echo "Reset firewall"
    sfApt update || failure 213 "reset_fw(): failure running apt update"
    sfRetry4 "sfApt -y autoclean autoremove" || failure 213 "reset_fw(): failure running cleanup"
    sfRetry4 "sfApt install -q -y --no-install-recommends iptables" || failure 214 "reset_fw(): failure installing iptables"
    sfRetry4 "sfApt install -q -y --no-install-recommends firewalld python3" || failure 215 "reset_fw(): failure installing firewalld"

    systemctl is-active ufw &> /dev/null && {
      echo "Stopping ufw"
      systemctl stop ufw || true # set to true to fix issues
    }
    systemctl is-enabled ufw &> /dev/null && {
      systemctl disable ufw || true # set to true to fix issues
    }
    dpkg --purge --force-remove-reinstreq ufw &>/dev/null || failure 216 "reset_fw(): failure purging ufw"
    ;;

  redhat | rhel | centos | fedora)
    # firewalld may not be installed
    if ! systemctl is-active firewalld &> /dev/null; then
      if ! systemctl status firewalld &> /dev/null; then
        is_network_reachable || failure 219 "reset_fw(): failure installing firewalld because repositories are not reachable"
        if [ $(versionchk ${VERSION_ID}) -ge $(versionchk "8.0") ]; then
          sudo dnf config-manager -y --disable epel-modular
          sudo dnf config-manager -y --disable epel
        fi
        sfRetry4 "sfYum install -q -y firewalld python3" || failure 220 "reset_fw(): failure installing firewalld"
      fi
    fi
    ;;
  esac

  {{- if .DefaultFirewall }}
  firewall-cmd --add-service={ssh,dhcpv6-client,dns,mdns} || failure 221 "reset_fw(): firewall-offline-cmd failed with $? adding services"
  firewall-cmd --runtime-to-permanent || failure 221 "reset_fw(): firewall-offline-cmd failed with $? making permanent"
  sudo sed -i 's/^LogDenied=.*$/LogDenied=all/g' /etc/firewalld/firewalld.conf
  sudo systemctl restart firewalld.service
  return 0
  {{- end }}

  # Clear interfaces attached to zones
  for zone in public trusted; do
    for nic in $(firewall-offline-cmd --zone=$zone --list-interfaces || true); do
      firewall-offline-cmd --zone=$zone --remove-interface=$nic &> /dev/null || true
    done
  done

  # Attach Internet interface or source IP to zone public if host is gateway
  [[ ! -z ${PU_IF} ]] && {
    firewall-offline-cmd --zone=public --add-interface=${PU_IF} || failure 221 "reset_fw(): firewall-offline-cmd failed with $? adding interfaces"
  }

  {{- if or .PublicIP .IsGateway }}
  [[ -z ${PU_IF} ]] && {
    firewall-offline-cmd --zone=public --add-source=${PU_IP}/32 || failure 222 "reset_fw(): firewall-offline-cmd failed with $? adding sources"
  }
  {{- end }}

  # Sets the default target of packets coming from public interface to DROP
  firewall-offline-cmd --zone=public --set-target=DROP || failure 223 "reset_fw(): firewall-offline-cmd failed with $? dropping public zone"

  # Enable masquerade
  # firewall-offline-cmd --zone=public --add-masquerade

  {{- if or .PublicIP .IsGateway }}
  # Attach LAN interfaces to zone public, adding to trusted zone results in all ports visible from internet using nmap
  [[ ! -z ${PR_IFs} ]] && {
    for i in ${PR_IFs}; do
      firewall-offline-cmd --zone=trusted --add-interface=${PR_IFs} || failure 224 "reset_fw(): firewall-offline-cmd failed with $? adding ${PR_IFs} to trusted"
    done
  }
  {{- else }}
  # Other machines can trust internal network...
  [[ ! -z ${PR_IFs} ]] && {
      for i in ${PR_IFs}; do
        firewall-offline-cmd --zone=trusted --add-interface=${PR_IFs} || failure 224 "reset_fw(): firewall-offline-cmd failed with $? adding ${PR_IFs} to trusted"
      done
    }
  {{- end }}

  # Attach lo interface to zone trusted
  firewall-offline-cmd --zone=trusted --add-interface=lo || failure 225 "reset_fw(): firewall-offline-cmd failed with $? adding lo to trusted"

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
    failure 226 "reset_fw(): firewall-offline-cmd failed with $op adding ssh service"
  fi

  sfService enable firewalld &> /dev/null || failure 227 "reset_fw(): service firewalld enable failed with $?"
  sfService start firewalld &> /dev/null || failure 228 "reset_fw(): service firewalld start failed with $?"

  sop=-1
  firewall-cmd --runtime-to-permanent && sop=$? || sop=$?
  if [[ $sop -ne 0 ]]; then
    if [[ $sop -ne 31 ]]; then
      failure 229 "reset_fw(): saving rules with firewall-cmd failed with $sop"
    fi
  fi

  # Log dropped packets
  sudo sed -i 's/^LogDenied=.*$/LogDenied=all/g' /etc/firewalld/firewalld.conf

  # Save current fw settings as permanent
  sfFirewallReload || (echo "reloading firewall failed with $?" && return 1)

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
FEN=

# Don't request dns name servers from DHCP server
# Don't update default route
function configure_dhclient() {
  # kill any dhclient process already running
  sudo pkill dhclient || true

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

function check_providers() {
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

  if [[ "{{.ProviderName}}" == "huaweicloud" ]]; then
    echo "It actually IS huaweicloud"
    FEN=1
  else
    echo "It is NOT huaweicloud"
    FEN=0
  fi
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

  check_providers

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
    DEBIAN_FRONTEND=noninteractive UCF_FORCE_CONFFNEW=1 apt-get update || return 1
    DEBIAN_FRONTEND=noninteractive UCF_FORCE_CONFFNEW=1 apt-get install --no-install-recommends -y curl || return 1
    ;;
  redhat | rhel | centos | fedora)
    if [[ -n $(which curl) ]]; then
      return 0
    fi
    sfRetry4 "sfYum install -y -q curl &>/dev/null" || return 1
    ;;
  *)
    failure 216 "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND'!"
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
  op=-1
  CONNECTED=$(curl -I www.google.com -m 5 | grep "200 OK") && op=$? || true
  [ $op -ne 0 ] && echo "ensure_network_connectivity started WITHOUT network..." || echo "ensure_network_connectivity started WITH network..."

  {{- if .AddGateway }}
  if [[ -n $(PATH=$PATH:/usr/sbin:/sbin which route) ]]; then
    PATH=$PATH:/usr/sbin:/sbin sudo route del -net default &> /dev/null
    PATH=$PATH:/usr/sbin:/sbin sudo route add -net default gw {{ .DefaultRouteIP }}
  else
    PATH=$PATH:/usr/sbin:/sbin sudo ip route del default
    PATH=$PATH:/usr/sbin:/sbin sudo ip route add default via {{ .DefaultRouteIP }}
  fi
  {{- else }}
  :
  {{- end}}

  op=-1
  CONNECTED=$(curl -I www.google.com -m 5 | grep "200 OK") && op=$? || true
  [ $op -ne 0 ] && echo "ensure_network_connectivity finished WITHOUT network..." || echo "ensure_network_connectivity finished WITH network..."

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
  IF=${PR_IFs[0]}
  [ -z ${IF} ] && return
  IP=$(ip a | grep $IF | grep inet | awk '{print $2}' | cut -d '/' -f1) || true
  sed -i -nr "/^${IP}"'/!p;$a'"${IP}"'\t{{ .HostName }}' /etc/hosts
}

function install_route_if_needed() {
  case $LINUX_KIND in
  debian)
    if [[ -z $(which route) ]]; then
      for iter in {1..4}
      do
        sfApt install -y --no-install-recommends net-tools && break
        [[ "$iter" == '4' ]] && return 1
      done
    fi
    ;;
  ubuntu)
    if [[ -z $(which route) ]]; then
      for iter in {1..4}
      do
        sfApt install -y --no-install-recommends net-tools && break
        [[ "$iter" == '4' ]] && return 1
      done
    fi
    ;;
  redhat | rhel | centos)
    if [[ -z $(which route) ]]; then
      sfRetry4 "sfYum install -y net-tools" || return 1
    fi
    ;;
  fedora)
    if [[ -z $(which route) ]]; then
      sfRetry4 "sfYum install -y net-tools" || return 1
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
      failure 192 "failed to determine how to configure network"
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
    failure 193 "Unsupported Linux distribution '$LINUX_KIND'!"
    ;;
  esac

  {{- if .IsGateway }}
  configure_as_gateway || failure 194 "failed to configure machine as a gateway"
  {{- end }}

  update_fqdn
  allow_custom_env_ssh_vars

  check_for_network || {
    failure 195 "missing or incomplete network connectivity"
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
      cat > ${path}/10-${IF}-public.cfg <<- EOF
				auto ${IF}
				iface ${IF} inet dhcp
EOF
    else
      cat > ${path}/11-${IF}-private.cfg <<- EOF
				auto ${IF}
				iface ${IF} inet dhcp
				{{- if .AddGateway }}
					up route add -net default gw {{ .DefaultRouteIP }}
				{{- end}}
EOF
    fi
  done

  {{- if .IsGateway }}
  {{- else }}
  for IF in ${NICS}; do
    if [[ "$IF" == "$PU_IF" ]]; then
      :
    else
      local tmppath=/tmp
      local altpath=/etc/network/if-up.d
      cat <<- EOF > ${tmppath}/my-route
			#!/bin/sh
			if [ "\${IFACE}" = "${IF}" ]; then
			  ip route add default via {{ .DefaultRouteIP }}
			  sudo /usr/sbin/resolvconf -u
			fi
EOF
      sudo cp ${tmppath}/my-route ${altpath}/my-route
      sudo chmod 751 ${altpath}/my-route
    fi
  done
  {{- end }}

  echo "Looking for network..."
  check_for_network || {
    failure 196 "failed network cfg 0"
  }

  configure_dhclient

  sudo /sbin/dhclient || true

  echo "Looking for network..."
  check_for_network || {
    failure 197 "failed network cfg 1"
  }

  systemctl restart networking

  PATH=$PATH:/usr/sbin:/sbin sudo dhclient || true

  echo "Looking for network..."
  check_for_network || {
    failure 199 "failed network cfg 2"
  }

  is_network_reachable || {
    failure 200 "without network"
  }

  reset_fw || failure 200 "failure resetting firewall"

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

  {{- if .IsGateway }}
  {{- else }}
  case $LINUX_KIND in
  debian)
    for IF in ${NICS}; do
      if [[ "$IF" == "$PU_IF" ]]; then
        :
      else
        local tmppath=/tmp
        local altpath=/etc/network/if-up.d
        cat <<- EOF > ${tmppath}/my-route
				#!/bin/sh
				if [ "\${IFACE}" = "${IF}" ]; then
				  ip route add default via {{ .DefaultRouteIP }}
				  sudo /usr/sbin/resolvconf -u
				fi
EOF
        sudo cp ${tmppath}/my-route ${altpath}/my-route
        sudo chmod 751 ${altpath}/my-route
      fi
    done
    ;;
  *);;
  esac

  {{- end }}

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

  netplan generate || failure 202 "failure running netplan generate"
  netplan apply || failure 203 "failure running netplan apply"

  configure_dhclient
  sleep 5

  if [[ $AWS -eq 1 ]]; then
    echo "Looking for network..."
    check_for_network || {
      failure 204 "failed networkd cfg 2"
    }
  fi

  systemctl restart systemd-networkd
  sleep 5

  if [[ $AWS -eq 1 ]]; then
    echo "Looking for network..."
    check_for_network || {
      failure 205 "failed networkd cfg 3"
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
        check_for_network || failure 206 "no network found"
      fi
    fi
    ;;
  *) ;;
  esac

  reset_fw || failure 206 "failure resetting firewall"

  echo "done"
}

# Configure network for redhat alike distributions (rhel, centos, ...)
function configure_network_redhat() {
  echo "Configuring network (redhat-like)..."

  if [ $VERSION_ID -eq 8 ]; then
    echo "Configuring network (redhat8-like)..."
    nmcli c mod eth0 connection.autoconnect yes || true
  fi

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
      failure 208 "failed to set network without NetworkManager"
    }
  elif [[ ${GCP} -eq 1 ]]; then
    configure_network_redhat_without_nmcli || {
      failure 208 "failed to set network without NetworkManager"
    }
  elif [[ ${OUT} -eq 1 ]]; then
    configure_network_redhat_without_nmcli || {
      failure 208 "failed to set network without NetworkManager"
    }
  elif [[ ${FEN} -eq 1 ]]; then
    configure_network_redhat_without_nmcli || {
      failure 208 "failed to set network without NetworkManager"
    }
  else
    NMCLI=$(which nmcli 2> /dev/null) || true
    if [[ -z "${NMCLI}" ]]; then
      configure_network_redhat_without_nmcli || {
        failure 208 "failed to set network without NetworkManager"
      }
    else
      configure_network_redhat_with_nmcli || {
        failure 209 "failed to set network with NetworkManager"
      }
    fi
  fi

  reset_fw || {
    failure 210 "failure setting firewall"
  }

  echo "done"
}

# Configure network for redhat 6- alike distributions (rhel, centos, ...)
function configure_network_redhat_without_nmcli() {
  echo "Configuring network (RedHat 6- alike)..."

  # We don't want NetworkManager if RedHat/CentOS < 7
  stop_svc NetworkManager &> /dev/null
  disable_svc NetworkManager &> /dev/null
  if [[ ${FEN} -eq 0 ]]; then
    sfRetry4 "sfYum remove -y NetworkManager &>/dev/null"
    echo "exclude=NetworkManager" >> /etc/yum.conf

    if which dnf; then
      dnf install -q -y network-scripts || {
        dnf install -q -y NetworkManager-config-routing-rules
        echo net.ipv4.ip_forward=1 >> /etc/sysctl.d/90-override.conf
        sysctl -w net.ipv4.ip_forward=1
        sysctl -p
        firewall-cmd --complete-reload
      }
    else
      sfYum install -q -y network-scripts || {
        sfYum install -q -y NetworkManager-config-routing-rules
        echo net.ipv4.ip_forward=1 >> /etc/sysctl.d/90-override.conf
        sysctl -w net.ipv4.ip_forward=1
        sysctl -p
        firewall-cmd --complete-reload
      }
    fi
  else
    sfYum remove -y NetworkManager &> /dev/null
  fi

  # Configure all network interfaces in dhcp
  for IF in $NICS; do
    if [[ ${IF} != "lo" ]]; then
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
      {{- end }}
    fi
  done

  configure_dhclient
  sleep 5

  {{- if .AddGateway }}
  echo "GATEWAY={{ .DefaultRouteIP }}" > /etc/sysconfig/network
  {{- end }}

  enable_svc network
  restart_svc network

  echo "exclude=NetworkManager" >> /etc/yum.conf
  sleep 5

  reset_fw || failure 206 "problem resetting firewall"

  echo "done"
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
  ip=$(ip -f inet -o addr show $1 | cut -d' ' -f7 | cut -d' ' -f1)
  [ -z "$ip" ] && echo "Failure checking for ip '$ip' when evaluating '$1'" && return 1
  return 0
}
export -f check_for_ip

function check_for_network_refined() {
  NETROUNDS=$1
  REACHED=0

  for i in $(seq $NETROUNDS); do
    if which wget; then
      wget -T 10 -O /dev/null www.google.com &> /dev/null && REACHED=1 && break
      ping -n -c1 -w10 -i5 www.google.com && REACHED=1 && break
    else
      ping -n -c1 -w10 -i5 www.google.com && REACHED=1 && break
    fi
  done

  [ $REACHED -eq 0 ] && echo "Unable to reach network" && return 1

  [ ! -z "$PU_IF" ] && {
    sfRetry4 check_for_ip $PU_IF || return 1
  }
  for i in $PR_IFs; do
    sfRetry4 check_for_ip $i || return 1
  done
  return 0
}

# Checks network is set correctly
# - DNS and routes (by pinging a FQDN)
# - IP address on "physical" interfaces
function check_for_network() {
  op=-1
  check_for_network_refined 12 && op=$? || true
  return $op
}

function configure_as_gateway() {
  echo "Configuring host as gateway..."

  if [[ ! -z ${PR_IFs} ]]; then
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
  firewall-offline-cmd --zone=public --add-service=ssh 2> /dev/null
  # Applies fw rules

  # Update ssh port
  [ ! -f /etc/firewalld/services/ssh.xml ] && [ -f /usr/lib/firewalld/services/ssh.xml ] && cp /usr/lib/firewalld/services/ssh.xml /etc/firewalld/services/ssh.xml
  sed -i -E "s/<port(.*)protocol=\"tcp\"(.*)port=\"([0-9]+)\"(.*)\/>/<port\1protocol=\"tcp\"\2port=\"{{ .SSHPort }}\"\4\/>/gm" /etc/firewalld/services/ssh.xml
  sed -i -E "s/<port(.*)port=\"([0-9]+)\"(.*)protocol=\"tcp\"(.*)\/>/<port\1port=\"{{ .SSHPort }}\"\3protocol=\"tcp\"\4\/>/gm" /etc/firewalld/services/ssh.xml
  sfFirewallReload

  sed -i '/^\#*AllowTcpForwarding / s/^.*$/AllowTcpForwarding yes/' /etc/ssh/sshd_config || failure 208 "failure allowing tcp forwarding"

  systemctl restart sshd

  case $LINUX_KIND in
  centos)
    echo net.ipv4.ip_forward=1 >> /etc/sysctl.d/90-override.conf
    sysctl -w net.ipv4.ip_forward=1
    sysctl -p
    firewall-cmd --complete-reload
    ;;
  *) ;;
  esac

  echo "done"
}

function configure_dns_legacy_issues() {
  case $LINUX_KIND in
  debian)
    if [ $VERSION_ID -eq 9 ]; then
      cp /etc/resolv.conf.tested /etc/resolv.conf
    fi
    ;;
  *) ;;

  esac
}

function configure_dns_fallback() {
  echo "Configuring /etc/resolv.conf..."
  cp /etc/resolv.conf /etc/resolv.conf.bak

  rm -f /etc/resolv.conf
  if [[ -e /etc/dhcp/dhclient.conf ]]; then
    echo "prepend domain-name-servers 1.1.1.1;" >> /etc/dhcp/dhclient.conf
  else
    echo "/etc/dhcp/dhclient.conf not modified"
  fi
  cat > /etc/resolv.conf <<- EOF
		nameserver 1.1.1.1
EOF

  cp /etc/resolv.conf /etc/resolv.conf.tested
  touch /etc/resolv.conf && sleep 2 || true

  # give it a try
  PATH=$PATH:/usr/sbin:/sbin sudo dhclient
  sleep 2

  op=-1
  CONNECTED=$(curl -I www.google.com -m 5 | grep "200 OK") && op=$? || true
  [ ${op} -ne 0 ] && echo "changing dns wasn't a good idea..." && cp /etc/resolv.conf.bak /etc/resolv.conf || echo "dns change OK..."

  configure_dns_legacy_issues

  echo "done"
}

function configure_dns_legacy() {
  echo "Configuring /etc/resolv.conf..."
  cp /etc/resolv.conf /etc/resolv.conf.bak

  rm -f /etc/resolv.conf
  {{- if .DNSServers }}
  if [[ -e /etc/dhcp/dhclient.conf ]]; then
    dnsservers=
    for i in {{range .DNSServers}} {{end}}; do
      [[ ! -z ${dnsservers} ]] && dnsservers="$dnsservers, "
    done
    [[ ! -z ${dnsservers} ]] && echo "prepend domain-name-servers $dnsservers;" >> /etc/dhcp/dhclient.conf
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
  cat > /etc/resolv.conf <<- EOF
		{{- if .DNSServers }}
		{{- range .DNSServers }}
		nameserver {{ . }}
		{{- end }}
		{{- else }}
		nameserver 1.1.1.1
		{{- end }}
EOF

  cp /etc/resolv.conf /etc/resolv.conf.tested
  touch /etc/resolv.conf && sleep 2 || true

  # give it a try
  PATH=$PATH:/usr/sbin:/sbin sudo dhclient
  sleep 2

  op=-1
  CONNECTED=$(curl -I www.google.com -m 5 | grep "200 OK") && op=$? || true
  [ ${op} -ne 0 ] && echo "changing dns wasn't a good idea..." && cp /etc/resolv.conf.bak /etc/resolv.conf || echo "dns change OK..."

  configure_dns_legacy_issues

  echo "done"
}

function configure_dns_resolvconf() {
  echo "Configuring resolvconf..."

  EXISTING_DNS=$(grep nameserver /etc/resolv.conf | awk '{print $2}')

  cat > /etc/resolvconf/resolv.conf.d/head <<- EOF
		{{- if .DNSServers }}
		{{- range .DNSServers }}
		nameserver {{ . }}
		{{- end }}
		{{- else }}
		nameserver 1.1.1.1
		{{- end }}
EOF

  resolvconf -u
  echo "done"
}

function configure_dns_systemd_resolved() {
  echo "Configuring systemd-resolved..."

  {{- if not .DefaultRouteIP }}
  rm -f /etc/resolv.conf
  ln -s /run/systemd/resolve/resolv.conf /etc
  {{- end }}

  cat > /etc/systemd/resolved.conf <<- EOF
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
  echo "done"
}

function is_network_reachable() {
  NETROUNDS=4
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

function install_drivers_nvidia() {
  case $LINUX_KIND in
  ubuntu)
    sfFinishPreviousInstall
    add-apt-repository -y ppa:graphics-drivers &> /dev/null
    sfApt update || failure 201 "apt update failed"
    sfRetry4 "sfApt -y install nvidia-410 &>/dev/null" || {
      sfRetry4 "sfApt -y install nvidia-driver-410 &>/dev/null" || failure 201 "failed nvidia driver install"
    }
    ;;

  debian)
    if [ ! -f /etc/modprobe.d/blacklist-nouveau.conf ]; then
      echo -e "blacklist nouveau\nblacklist lbm-nouveau\noptions nouveau modeset=0\nalias nouveau off\nalias lbm-nouveau off" >> /etc/modprobe.d/blacklist-nouveau.conf
      rmmod nouveau
    fi
    sfApt update
    sfRetry4 "sfApt install -y --no-install-recommends dkms build-essential linux-headers-$(uname -r) gcc make &>/dev/null" || failure 202 "failure installing nvdiia requirements"
    dpkg --add-architecture i386 &> /dev/null
    sfApt update
    sfRetry4 "sfApt install -y --no-install-recommends lib32z1 lib32ncurses5 &>/dev/null" || failure 203 "failure installing nvidia requirements"
    wget http://us.download.nvidia.com/XFree86/Linux-x86_64/410.78/NVIDIA-Linux-x86_64-410.78.run &> /dev/null || failure 204 "failure downloading nvidia installer"
    bash NVIDIA-Linux-x86_64-410.78.run -s || failure 205 "failure running nvidia installer"
    ;;

  redhat | rhel | centos | fedora)
    if [ ! -f /etc/modprobe.d/blacklist-nouveau.conf ]; then
      echo -e "blacklist nouveau\noptions nouveau modeset=0" >> /etc/modprobe.d/blacklist-nouveau.conf
      dracut --force
      rmmod nouveau
    fi
    sfRetry4 "sfYum -y -q install kernel-devel.$(uname -i) kernel-headers.$(uname -i) gcc make &>/dev/null" || failure 206 "failure installing nvidia requirements"
    wget http://us.download.nvidia.com/XFree86/Linux-x86_64/410.78/NVIDIA-Linux-x86_64-410.78.run || failure 207 "failure downloading nvidia installer"
    # if there is a version mismatch between kernel sources and running kernel, building the driver would require 2 reboots to get it done, right now this is unsupported
    if [ $(uname -r) == $(sfYum list installed | grep kernel-headers | awk {'print $2'}).$(uname -i) ]; then
      bash NVIDIA-Linux-x86_64-410.78.run -s || failure 208 "failure running nvidia installer"
    fi
    rm -f NVIDIA-Linux-x86_64-410.78.run
    ;;
  *)
    failure 209 "Unsupported Linux distribution '$LINUX_KIND'!"
    ;;
  esac
}

function early_packages_update() {
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
    export UCF_FORCE_CONFFNEW=1
    # # Force use of IPv4 addresses when installing packages
    # echo 'Acquire::ForceIPv4 "true";' >/etc/apt/apt.conf.d/99force-ipv4

    sfApt update || {
      echo "problem updating package repos"
      return 209
    }
    # Force update of systemd, pciutils
    sfApt install -q -y systemd pciutils sudo || {
      echo "failure installing systemd and other basic requirements"
      return 209
    }
    # systemd, if updated, is restarted, so we may need to ensure again network connectivity
    ensure_network_connectivity
    ;;

  ubuntu)
    # Disable interactive installations
    export DEBIAN_FRONTEND=noninteractive
    export UCF_FORCE_CONFFNEW=1
    # # Force use of IPv4 addresses when installing packages
    # echo 'Acquire::ForceIPv4 "true";' >/etc/apt/apt.conf.d/99force-ipv4

    sfApt update || {
      echo "problem updating package repos"
      return 210
    }
    # Force update of systemd, pciutils and netplan

    if dpkg --compare-versions $(sfGetFact "linux_version") ge 17.10; then
      sfApt install -y --no-install-recommends pciutils || {
        echo "problem installing pciutils"
        return 210
      }
      if [[ ! -z ${FEN} && ${FEN} -eq 0 ]]; then
        which netplan || {
          sfApt install -y --no-install-recommends netplan.io || {
            echo "problem installing netplan.io"
            return 210
          }
        }
      else
        sfApt install -y --no-install-recommends netplan.io || {
          echo "problem installing netplan.io"
          return 210
        }
      fi
      # netplan.io may break networking... So ensure networking is working as expected
      ensure_network_connectivity
      sfApt install -y --no-install-recommends sudo || {
        echo "problem installing sudo"
        return 210
      }
    else
      sfApt install -y --no-install-recommends systemd pciutils sudo || {
        echo "problem installing pciutils and sudo"
        return 211
      }
    fi

    if dpkg --compare-versions $(sfGetFact "linux_version") ge 20.04; then
      if [ "{{.ProviderName}}" == "aws" ]; then
        : # do nothing
      else
        sfApt install -y --no-install-recommends systemd || {
          echo "problem installing systemd"
          return 210
        }
      fi
    else
      sfApt install -y --no-install-recommends systemd || {
        echo "problem installing systemd"
        return 210
      }
      # systemd, if updated, is restarted, so we may need to ensure again network connectivity
      ensure_network_connectivity
    fi

    # # Security updates ...
    # sfApt update &>/dev/null && sfApt install -qy unattended-upgrades && unattended-upgrades -v
    ;;

  redhat | centos)
    # # Force use of IPv4 addresses when installing packages
    # echo "ip_resolve=4" >>/etc/yum.conf

    # Force update of systemd and pciutils
    sfYum install -q -y systemd pciutils yum-utils sudo || {
      echo "failure installing systemd and other basic requirements"
      return 212
    }
    # systemd, if updated, is restarted, so we may need to ensure again network connectivity
    ensure_network_connectivity

    # # install security updates
    # sfYum install -y yum-plugin-security yum-plugin-changelog && sfYum update -y --security
    ;;
  esac
  sfProbeGPU
}

function install_packages() {
  case $LINUX_KIND in
  ubuntu | debian)
    sfApt install -y -qq --no-install-recommends wget curl jq zip unzip time at sshpass &> /dev/null || failure 213 "failure installing utility packages: jq zip time at"
    ;;
  redhat | centos)
    if [ $(versionchk ${VERSION_ID}) -ge $(versionchk "8.0") ]; then
      sfYum install -y -q wget curl jq zip unzip time at sshpass &> /dev/null || failure 214 "failure installing utility packages: jq zip time at"
    else
      sfYum install --enablerepo=epel -y -q wget curl jq zip unzip time at sshpass &> /dev/null || failure 214 "failure installing utility packages: jq zip time at"
    fi
    ;;
  *)
    failure 215 "Unsupported Linux distribution '$LINUX_KIND'!"
    ;;
  esac
}

function install_rclone() {
  case $LINUX_KIND in
  debian | ubuntu)
    curl -kqSsL --fail -O https://downloads.rclone.org/rclone-current-linux-amd64.zip &&
      unzip rclone-current-linux-amd64.zip &&
      cp rclone-*-linux-amd64/rclone /usr/bin &&
      mkdir -p /usr/share/man/man1 &&
      cp rclone-*-linux-amd64/rclone.1 /usr/share/man/man1/ &&
      rm -rf rclone-* &&
      chown root:root /usr/bin/rclone &&
      chmod 755 /usr/bin/rclone &&
      mandb
    ;;
  redhat | centos)
    if [ $(versionchk ${VERSION_ID}) -ge $(versionchk "8.0") ]; then
      curl -kqSsL --fail -O https://downloads.rclone.org/rclone-current-linux-amd64.zip &&
        unzip rclone-current-linux-amd64.zip &&
        cp rclone-*-linux-amd64/rclone /usr/bin &&
        mkdir -p /usr/share/man/man1 &&
        cp rclone-*-linux-amd64/rclone.1 /usr/share/man/man1/ &&
        rm -rf rclone-* &&
        chown root:root /usr/bin/rclone &&
        chmod 755 /usr/bin/rclone &&
        mandb
    else
      sfYum install -y rclone || sfFail 192 "Problem installing node common requirements"
    fi
    ;;
  fedora)
    dnf install -y rclone || sfFail 192 "Problem installing node common requirements"
    ;;
  *)
    sfFail 1 "Unmanaged linux distribution type '$(sfGetFact "linux_kind")'"
    ;;
  esac

  ln -s /usr/bin/rclone /sbin/mount.rclone && ln -s /usr/bin/rclone /usr/bin/rclonefs || sfFail 192 "failed to create rclone soft links"
  return 0
}

function no_daily_update() {
  case $LINUX_KIND in
  debian | ubuntu)
    # If it's not there, nothing to do
    systemctl list-units --all apt-daily.service | egrep -q 'apt-daily' || return 0

    # first kill apt-daily
    systemctl stop apt-daily.service
    systemctl kill --kill-who=all apt-daily.service

    # wait until apt-daily dies
    while ! (systemctl list-units --all apt-daily.service | egrep -q '(dead|failed)'); do
      systemctl stop apt-daily.service
      systemctl kill --kill-who=all apt-daily.service
      sleep 1
    done
    ;;
  redhat | fedora | centos)
    # If it's not there, nothing to do
    systemctl list-units --all yum-cron.service | egrep -q 'yum-cron' || return 0
    systemctl stop yum-cron.service
    systemctl kill --kill-who=all yum-cron.service

    # wait until yum-cron dies
    while ! (systemctl list-units --all yum-cron.service | egrep -q '(dead|failed)'); do
      systemctl stop yum-crom.service
      systemctl kill --kill-who=all yum-cron.service
      sleep 1
    done
    ;;
  esac
}

function add_common_repos() {
  case $LINUX_KIND in
  ubuntu)
    sfFinishPreviousInstall
    no_daily_update
    add-apt-repository universe -y || return 1
    codename=$(sfGetFact "linux_codename")
    echo "deb http://archive.ubuntu.com/ubuntu/ ${codename}-proposed main" > /etc/apt/sources.list.d/${codename}-proposed.list
    ;;
  debian)
    sfFinishPreviousInstall
    ;;
  redhat | rhel | centos)
    if which dnf; then
      # Install EPEL repo ...
      if [ $(versionchk ${VERSION_ID}) -ge $(versionchk "8.0") ]; then
        sudo bash -c "echo '8-stream' > /etc/yum/vars/releasever"
        sfRetry4 "dnf install -y epel-release" || {
          echo "failure installing custom epel repo"
          return 217
        }
      else
        sfRetry4 "dnf install -y epel-release" || {
          echo "failure installing default epel repo"
          return 217
        }
      fi
      sfRetry4 "dnf makecache fast -y || dnf makecache -y" || {
        echo "failure updating cache"
        return 218
      }
      # ... but don't enable it by default
      dnf config-manager --set-disabled epel &> /dev/null || true
    else
      # Install EPEL repo ...
      sfRetry4 "yum install -y epel-release" || {
        echo "failure installing epel repo"
        return 217
      }
      sfRetry4 "yum makecache fast || yum makecache" || {
        echo "failure updating cache"
        return 218
      }
      # ... but don't enable it by default
      yum-config-manager --disablerepo=epel &> /dev/null || true
    fi
    ;;
  fedora)
    sfRetry4 "dnf makecache fast -y || dnf makecache -y" || {
      echo "failure updating cache"
      return 218
    }
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
  return 0
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

function update_credentials() {
  echo "{{.Username}}:{{.Password}}" | chpasswd

  dd if=/dev/urandom of=/home/{{.Username}}/.ssh/authorized_keys conv=notrunc bs=4096 count=8
  echo "{{.FinalPublicKey}}" > /home/{{.Username}}/.ssh/authorized_keys
  dd if=/dev/urandom of=/home/{{.Username}}/.ssh/id_rsa conv=notrunc bs=4096 count=8
  echo "{{.FinalPrivateKey}}" > /home/{{.Username}}/.ssh/id_rsa
  chmod 0700 /home/{{.Username}}/.ssh
  chmod -R 0600 /home/{{.Username}}/.ssh/*
}

function enable_at_daemon() {
  case $LINUX_KIND in
  redhat | rhel | centos | fedora)
    if [ $VERSION_ID -eq 8 ]; then
      crontab -l | {
        cat
        echo "@reboot sleep 30 && /usr/sbin/dhclient eth0"
      } | crontab -
    fi
    sfRetry4 "service atd start" || true
    sleep 4
    ;;
  *) ;;
  esac
}

# for testing purposes
function unsafe_update_credentials() {
  echo "{{.Username}}:safescale" | chpasswd

  dd if=/dev/urandom of=/home/{{.Username}}/.ssh/authorized_keys conv=notrunc bs=4096 count=8
  echo "{{.FinalPublicKey}}" > /home/{{.Username}}/.ssh/authorized_keys
  dd if=/dev/urandom of=/home/{{.Username}}/.ssh/id_rsa conv=notrunc bs=4096 count=8
  echo "{{.FinalPrivateKey}}" > /home/{{.Username}}/.ssh/id_rsa
  chmod 0700 /home/{{.Username}}/.ssh
  chmod -R 0600 /home/{{.Username}}/.ssh/*
}

function check_unsupported() {
  case $LINUX_KIND in
  centos)
    {{- if or .PublicIP .IsGateway }}
    if [ $(versionchk ${VERSION_ID}) -ge $(versionchk "8.0") ]; then
      failure 211 "unsupported CentOS version for gateways: ${VERSION_ID}"
    fi
    {{- end }}
    ;;
  *) ;;

  esac
}

# ---- Main
check_unsupported
check_providers

{{- if .Debug }}
unsafe_update_credentials
{{- else }}
update_credentials
{{- end }}

configure_locale

{{- if .IsGateway }}
{{- else }}
# Without the route in place, we won't have working DNS either, so we set the route first
ensure_network_connectivity || echo "Network not ready yet: setting the route for machines other than the gateways"
{{- end }}

# Now, we can check if DNS works, if it's a gateway it should work every time; if not it depends on the previous route working
check_dns_configuration && echo "DNS is ready" || echo "DNS NOT ready yet"
configure_dns || failure 213 "problem configuring DNS"
check_dns_configuration || {
  configure_dns_fallback || failure 213 "problem configuring DNS, fallback didn't work either"
  check_dns_configuration || {
    failure 214 "DNS NOT ready after being configured"
  }
}

{{- if .IsGateway }}
ensure_network_connectivity || echo "Network not ready yet"
{{- end }}

cr=-1
ep=-1
is_network_reachable && {
  add_common_repos && cr=0 || echo "failure adding common repos, 1st try"
  early_packages_update && ep=0 || echo "failure in early packages update, 1st try"
}

identify_nics
configure_network || failure 215 "failure configuring network"
is_network_reachable || failure 215 "network is NOT ready after trying changing its DNS and configuration"

[[ $cr -eq -1 ]] && {
  add_common_repos || failure 215 "failure adding common repos, 2nd try"
}

[[ $ep -eq -1 ]] && {
  early_packages_update || failure 215 "failure in early packages update, 2nd try"
}

install_packages || failure 215 "failure installing packages"
install_rclone || failure 216 "failure installing rclone"

update_kernel_settings || failure 217 "failure updating kernel settings"

force_dbus_restart || failure 218 "failure restarting dbus"

systemctl restart sshd || failure 219 "failure restarting sshd"

enable_at_daemon || failure 220 "failure starting at daemon"
# ---- EndMain

echo -n "0,linux,${LINUX_KIND},${VERSION_ID},$(hostname),$(date +%Y/%m/%d-%H:%M:%S)" > /opt/safescale/var/state/user_data.netsec.done

# !!! DON'T REMOVE !!! #insert_tag allows to add something just before exiting,
#                      but after the template has been realized (cf. libvirt Stack)
#insert_tag

(
  sync
  echo 3 > /proc/sys/vm/drop_caches
  sleep 2
) || true

set +x
exit 0
