#!/bin/bash -x
#
# Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

{{.Header}}

function print_error() {
  read -r line file <<<"$(caller)"
  echo "An error occurred in line $line of file $file:" "{$(sed "${line}q;d" "$file")}" >&2
  {{.ExitOnError}}
}
trap print_error ERR

function failure() {
  MYIP="$(ip -br a | grep UP | awk '{print $3}') | head -n 1"
  if [ $# -eq 1 ]; then
    echo "PROVISIONING_ERROR: $1"
    echo -n "$1,${LINUX_KIND},${VERSION_ID},$(hostname),$MYIP,$(date +%Y/%m/%d-%H:%M:%S),PROVISIONING_ERROR:$1" >/opt/safescale/var/state/user_data.netsec.done
    (
      sync
      echo 3 >/proc/sys/vm/drop_caches
      sleep 2
    ) || true
    exit $1
  elif [ $# -eq 2 -a $1 -ne 0 ]; then
    echo "PROVISIONING_ERROR: $1, $2"
    echo -n "$1,${LINUX_KIND},${VERSION_ID},$(hostname),$MYIP,$(date +%Y/%m/%d-%H:%M:%S),PROVISIONING_ERROR:$2" >/opt/safescale/var/state/user_data.netsec.done
    (
      sync
      echo 3 >/proc/sys/vm/drop_caches
      sleep 2
    ) || true
    exit $1
  fi
}
export -f failure

# Redirects outputs to /opt/safescale/var/log/user_data.netsec.log
LOGFILE=/opt/safescale/var/log/user_data.netsec.log

### All output to one file and all output to the screen
exec > >(tee -a ${LOGFILE} /opt/safescale/var/log/ss.log) 2>&1
set -x

# Tricks BashLibrary's waitUserData to believe the current phase 'netsec' is already done (otherwise will deadlock)
uptime >/opt/safescale/var/state/user_data.netsec.done

# Includes the BashLibrary
{{ .reserved_BashLibrary }}
rm -f /opt/safescale/var/state/user_data.netsec.done

function reset_fw() {
  is_network_reachable || failure 206 "failure resetting firewall because network is not reachable"

  case $LINUX_KIND in
  debian)
    echo "Reset firewall"
    sfRetryEx 3m 5 "sfApt update &>/dev/null" || failure 206 "failure running apt update"
    if [[ $(lsb_release -rs | cut -d. -f1) -eq 10 ]]; then
      codename=$(sfGetFact "linux_codename")
      sfRetryEx 3m 5 "sfApt install -q -y -t ${codename}-backports iptables" || failure 206 "failure installing iptables"
      sfRetryEx 3m 5 "sfApt install -q -y -t ${codename}-backports firewalld"  || failure 206 "failure installing firewalld"
    else
      sfRetryEx 3m 5 "sfApt install -q -y iptables" || failure 206 "failure installing iptables"
      sfRetryEx 3m 5 "sfApt install -q -y firewalld" || failure 206 "failure installing firewalld"
    fi

    echo "Stopping ufw"
    systemctl stop ufw || true    # set to true to fix issues
    systemctl disable ufw || true # set to true to fix issues
    sfRetryEx 3m 5 "sfApt purge -q -y ufw &>/dev/null"  || failure 206 "failure purging ufw"
    ;;

  ubuntu)
    echo "Reset firewall"
    sfRetryEx 3m 5 "sfApt update &>/dev/null" || failure 206 "failure running apt update"
    sfRetryEx 3m 5 "sfApt install -q -y iptables" || failure 206 "failure installing iptables"
    sfRetryEx 3m 5 "sfApt install -q -y firewalld" || failure 206 "failure installing firewalld"

    echo "Stopping ufw"
    systemctl stop ufw || failure 206 "failure stopping ufw"
    systemctl disable ufw || failure 206 "failure disabling ufw"
    sfRetryEx 3m 5 "sfApt purge -q -y ufw &>/dev/null"  || failure 206 "failure purging ufw"
    ;;

  redhat | rhel | centos | fedora)
    # firewalld may not be installed
    if ! systemctl is-active firewalld &>/dev/null; then
      if ! systemctl status firewalld &>/dev/null; then
        is_network_reachable || failure 206 "failure installing firewalld because repositories are not reachable"
        sfRetryEx 3m 5 "sfYum install -q -y firewalld" || failure 206 "failure installing firewalld"
      fi
    fi
    ;;
  esac

  # Clear interfaces attached to zones
  for zone in public trusted; do
    for nic in $(firewall-offline-cmd --zone=$zone --list-interfaces || true); do
      firewall-offline-cmd --zone=$zone --remove-interface=$nic &>/dev/null || true
    done
  done

  # Attach Internet interface or source IP to zone public if host is gateway
  [ ! -z $PU_IF ] && {
    # sfFirewallAdd --zone=public --add-interface=$PU_IF || return 1
    firewall-offline-cmd --zone=public --add-interface=$PU_IF || failure 206 "firewall-offline-cmd failed with $? adding interfaces"
  }
  {{- if or .PublicIP .IsGateway }}
  [[ -z ${PU_IF} ]] && {
    # sfFirewallAdd --zone=public --add-source=${PU_IP}/32 || return 1
    firewall-offline-cmd --zone=public --add-source=${PU_IP}/32 || failure 206 "firewall-offline-cmd failed with $? adding sources"
  }
  {{- end }}

  # Sets the default target of packets coming from public interface to DROP
  firewall-offline-cmd --zone=public --set-target=DROP || failure 206 "firewall-offline-cmd failed with $? dropping public zone"

  # Attach LAN interfaces to zone trusted
  [[ ! -z ${PR_IFs} ]] && {
    for i in $PR_IFs; do
      # sfFirewallAdd --zone=trusted --add-interface=$PR_IFs || return 1
      firewall-offline-cmd --zone=trusted --add-interface=$PR_IFs || failure 206 "firewall-offline-cmd failed with $? adding $PR_IFs to trusted"
    done
  }
  # Attach lo interface to zone trusted
  # sfFirewallAdd --zone=trusted --add-interface=lo || return 1
  firewall-offline-cmd --zone=trusted --add-interface=lo || failure 206 "firewall-offline-cmd failed with $? adding lo to trusted"

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
    failure 206 "firewall-offline-cmd failed with $op adding ssh service"
  fi

  sfService enable firewalld &>/dev/null || failure 206 "service firewalld enable failed with $?"
  sfService start firewalld &>/dev/null || failure 206 "service firewalld start failed with $?"

  sop=-1
  firewall-cmd --runtime-to-permanent && sop=$? || sop=$?
  if [[ $sop -ne 0 ]]; then
    if [[ $sop -ne 31 ]]; then
      failure 206 "saving rules with firewall-cmd failed with $sop"
    fi
  fi

  # Save current fw settings as permanent
  sfFirewallReload || (echo "reloading firewall failed with $?" && return 1)

  firewall-cmd --list-all --zone=trusted >/tmp/firewall-trusted.cfg || true
  firewall-cmd --list-all --zone=public >/tmp/firewall-public.cfg || true

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

function is_ip_private() {
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
  PU_IF=$(ip route get 8.8.8.8 | awk -F"dev " 'NR==1{split($2,a," ");print a[1]}' 2>/dev/null) || true
  PU_IP=$(ip a | grep ${PU_IF} | grep inet | awk '{print $2}' | cut -d '/' -f1) || true
  if [[ ! -z ${PU_IP} ]]; then
    if is_ip_private $PU_IP; then
      PU_IF=

      NO404=$(curl -s -o /dev/null -w "%{http_code}" http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null | grep 404) || true
      if [[ -z $NO404 ]]; then
        # Works with FlexibleEngine and potentially with AWS (not tested yet)
        PU_IP=$(curl http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null) || true
        [[ -z $PU_IP ]] && PU_IP=$(curl ipinfo.io/ip 2>/dev/null)
      fi
    fi
  fi
  [[ -z ${PR_IFs} ]] && PR_IFs=$(substring_diff "$NICS" "$PU_IF")

  # Keeps track of interfaces identified for future scripting use
  echo "$PR_IFs" >${SF_VARDIR}/state/private_nics
  echo "$PU_IF" >${SF_VARDIR}/state/public_nics

  check_providers

  echo "NICS identified: $NICS"
  echo "    private NIC(s): $PR_IFs"
  echo "    public NIC: $PU_IF"
  echo
}

function substring_diff() {
  read -a l1 <<<$1
  read -a l2 <<<$2
  echo "${l1[@]}" "${l2[@]}" | tr ' ' '\n' | sort | uniq -u
}

function collect_original_packages() {
  case $LINUX_KIND in
  debian | ubuntu)
    dpkg-query -l >${SF_VARDIR}/log/packages_installed_before.phase2.list
    ;;
  redhat | rhel | centos | fedora)
    rpm -qa | sort >${SF_VARDIR}/log/packages_installed_before.phase2.list
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
    DEBIAN_FRONTEND=noninteractive UCF_FORCE_CONFFNEW=1 apt-get install -y curl || return 1
    ;;
  redhat | rhel | centos | fedora)
    if [[ -n $(which curl) ]]; then
      return 0
    fi
    sfRetryEx 3m 5 "sfYum install -y -q curl &>/dev/null" || return 1
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
    dpkg-query -l >${SF_VARDIR}/log/packages_installed_after.phase2.list
    ;;
  redhat | rhel | centos | fedora)
    rpm -qa | sort >${SF_VARDIR}/log/packages_installed_after.phase2.list
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
  if [[ -n $(which route) ]]; then
    route del -net default &>/dev/null
    route add -net default gw {{ .DefaultRouteIP }}
  else
    ip route del default
    ip route add default via {{ .DefaultRouteIP }}
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
      sfRetryEx 3m 5 "sfApt install -y net-tools" || return 1
    fi
    ;;
  ubuntu)
    if [[ -z $(which route) ]]; then
      sfRetryEx 3m 5 "sfApt install -y net-tools" || return 1
    fi
    ;;
  redhat | rhel | centos)
    if [[ -z $(which route) ]]; then
      sfRetryEx 3m 5 "sfYum install -y net-tools" || return 1
    fi
    ;;
  fedora)
    if [[ -z $(which route) ]]; then
      sfRetryEx 3m 5 "sfYum install -y net-tools" || return 1
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
  cat >>/etc/ssh/sshd_config <<-EOF
AcceptEnv SAFESCALESSHUSER
AcceptEnv SAFESCALESSHPASS
EOF
  systemctl reload sshd
}

function configure_network() {
  case $LINUX_KIND in
  debian | ubuntu)
    if systemctl status systemd-networkd &>/dev/null; then
      install_route_if_needed
      configure_network_systemd_networkd
    elif systemctl status networking &>/dev/null; then
      install_route_if_needed
      configure_network_debian
    else
      failure 192 "failed to determine how to configure network"
    fi
    ;;

  redhat | rhel | centos)
    # Network configuration
    if systemctl status systemd-networkd &>/dev/null; then
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
      cat <<-EOF >${path}/10-${IF}-public.cfg
				auto ${IF}
				iface ${IF} inet dhcp
			EOF
    else
      cat <<-EOF >${path}/11-${IF}-private.cfg
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
    failure 196 "failed network cfg 0"
  }

  configure_dhclient

  /sbin/dhclient || true

  echo "Looking for network..."
  check_for_network || {
    failure 197 "failed network cfg 1"
  }

  systemctl restart networking

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
      cat <<-EOF >/etc/netplan/10-${IF}-public.yaml
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
      cat <<-EOF >/etc/netplan/11-${IF}-private.yaml
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
          cat <<-EOF >/etc/netplan/10-$IF-public.yaml
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
          cat <<-EOF >/etc/netplan/11-${IF}-private.yaml
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

  NMCLI=$(which nmcli 2>/dev/null) || true
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
    NMCLI=$(which nmcli 2>/dev/null) || true
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
  stop_svc NetworkManager &>/dev/null
  disable_svc NetworkManager &>/dev/null
  if [[ ${FEN} -eq 0 ]]; then
    sfRetryEx 3m 5 "sfYum remove -y NetworkManager &>/dev/null"
    echo "exclude=NetworkManager" >>/etc/yum.conf

    if which dnf; then
      dnf install -q -y network-scripts || {
        dnf install -q -y NetworkManager-config-routing-rules
        echo net.ipv4.ip_forward=1 >> /etc/sysctl.d/90-override.conf
        sysctl -w net.ipv4.ip_forward=1
        sysctl -p
        firewall-cmd --complete-reload
      }
    else
      yum install -q -y network-scripts || {
        yum install -q -y NetworkManager-config-routing-rules
        echo net.ipv4.ip_forward=1 >> /etc/sysctl.d/90-override.conf
        sysctl -w net.ipv4.ip_forward=1
        sysctl -p
        firewall-cmd --complete-reload
      }
    fi
  else
    yum remove -y NetworkManager &>/dev/null
  fi

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
      echo "DNS${i}={{ . }}" >>/etc/sysconfig/network-scripts/ifcfg-${IF}
      i=$((i + 1))
      {{- end }}
      {{- else }}
      EXISTING_DNS=$(grep nameserver /etc/resolv.conf | awk '{print $2}')
      if [[ -z ${EXISTING_DNS} ]]; then
        echo "DNS1=1.1.1.1" >>/etc/sysconfig/network-scripts/ifcfg-${IF}
      else
        echo "DNS1=$EXISTING_DNS" >>/etc/sysconfig/network-scripts/ifcfg-${IF}
      fi
      {{- end }}

      {{- if .AddGateway }}
      echo "GATEWAY={{ .DefaultRouteIP }}" >>/etc/sysconfig/network-scripts/ifcfg-${IF}
      {{- end}}
    fi
  done

  configure_dhclient
  sleep 5

  {{- if .AddGateway }}
  echo "GATEWAY={{ .DefaultRouteIP }}" >/etc/sysconfig/network
  {{- end }}

  enable_svc network
  restart_svc network

  echo "exclude=NetworkManager" >>/etc/yum.conf
  sleep 5

  is_network_reachable || {
    failure 206 "without network"
  }

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
      wget -T 10 -O /dev/null www.google.com &>/dev/null && REACHED=1 && break
      ping -n -c1 -w10 -i5 www.google.com && REACHED=1 && break
    else
      ping -n -c1 -w10 -i5 www.google.com && REACHED=1 && break
    fi
  done

  [ $REACHED -eq 0 ] && echo "Unable to reach network" && return 1

  [ ! -z "$PU_IF" ] && {
    sfRetryEx 3m 10 check_for_ip $PU_IF || return 1
  }
  for i in $PR_IFs; do
    sfRetryEx 3m 10 check_for_ip $i || return 1
  done
  return 0
}

# Checks network is set correctly
# - DNS and routes (by pinging a FQDN)
# - IP address on "physical" interfaces
function check_for_network() {
  check_for_network_refined 12
  return $?
}

function configure_as_gateway() {
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
  firewall-offline-cmd --zone=public --add-service=ssh 2>/dev/null
  # Applies fw rules
  # sfFirewallReload

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
    [[ ! -z ${dnsservers} ]] && echo "prepend domain-name-servers $dnsservers;" >>/etc/dhcp/dhclient.conf
  else
    echo "dhclient.conf not modified"
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

  cp /etc/resolv.conf /etc/resolv.conf.tested

  op=-1
  CONNECTED=$(curl -I www.google.com -m 5 | grep "200 OK") && op=$? || true
  [ ${op} -ne 0 ] && echo "changing dns wasn't a good idea..." && cp /etc/resolv.conf.bak /etc/resolv.conf || echo "dns change OK..."

  configure_dns_legacy_issues

  echo "done"
}

function configure_dns_resolvconf() {
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
  echo "done"
}

function configure_dns_systemd_resolved() {
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
  echo "done"
}

function is_network_reachable() {
  NETROUNDS=2
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
      wget -T 4 -O /dev/null www.google.com &>/dev/null && REACHED=1 && break
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
    add-apt-repository -y ppa:graphics-drivers &>/dev/null
    sfRetryEx 3m 5 "sfApt update" || failure 201 "apt update failed"
    sfRetryEx 3m 5 "sfApt -y install nvidia-410 &>/dev/null" || {
      sfRetryEx 3m 5 "sfApt -y install nvidia-driver-410 &>/dev/null" || failure 201 "failed nvidia driver install"
    }
    ;;

  debian)
    if [ ! -f /etc/modprobe.d/blacklist-nouveau.conf ]; then
      echo -e "blacklist nouveau\nblacklist lbm-nouveau\noptions nouveau modeset=0\nalias nouveau off\nalias lbm-nouveau off" >>/etc/modprobe.d/blacklist-nouveau.conf
      rmmod nouveau
    fi
    sfRetryEx 3m 5 "sfApt update &>/dev/null"
    sfRetryEx 3m 5 "sfApt install -y dkms build-essential linux-headers-$(uname -r) gcc make &>/dev/null" || failure 202 "failure installing nvdiia requirements"
    dpkg --add-architecture i386 &>/dev/null
    sfRetryEx 3m 5 "sfApt update &>/dev/null"
    sfRetryEx 3m 5 "sfApt install -y lib32z1 lib32ncurses5 &>/dev/null" || failure 203 "failure installing nvidia requirements"
    wget http://us.download.nvidia.com/XFree86/Linux-x86_64/410.78/NVIDIA-Linux-x86_64-410.78.run &>/dev/null || failure 204 "failure downloading nvidia installer"
    bash NVIDIA-Linux-x86_64-410.78.run -s || failure 205 "failure running nvidia installer"
    ;;

  redhat | rhel | centos | fedora)
    if [ ! -f /etc/modprobe.d/blacklist-nouveau.conf ]; then
      echo -e "blacklist nouveau\noptions nouveau modeset=0" >>/etc/modprobe.d/blacklist-nouveau.conf
      dracut --force
      rmmod nouveau
    fi
    sfRetryEx 3m 5 "sfYum -y -q install kernel-devel.$(uname -i) kernel-headers.$(uname -i) gcc make &>/dev/null" || failure 206 "failure installing nvidia requirements"
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

function disable_upgrades() {
  case $LINUX_KIND in
  ubuntu)
    sfApt remove -y unattended-upgrades || true
    ;;
  *)
    ;;
  esac
}

function early_packages_update() {
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
    export UCF_FORCE_CONFFNEW=1
    # # Force use of IPv4 addresses when installing packages
    # echo 'Acquire::ForceIPv4 "true";' >/etc/apt/apt.conf.d/99force-ipv4

    sfApt update
    # Force update of systemd, pciutils
    sfApt install -q -y systemd pciutils sudo || failure 209 "failure installing systemd and other basic requirements"
    # systemd, if updated, is restarted, so we may need to ensure again network connectivity
    ensure_network_connectivity
    ;;

  ubuntu)
    # Disable interactive installations
    export DEBIAN_FRONTEND=noninteractive
    export UCF_FORCE_CONFFNEW=1
    # # Force use of IPv4 addresses when installing packages
    # echo 'Acquire::ForceIPv4 "true";' >/etc/apt/apt.conf.d/99force-ipv4

    disable_upgrades

    sfApt update || failure 210 "problem updating package repos"
    # Force update of systemd, pciutils and netplan

    if dpkg --compare-versions $(sfGetFact "linux_version") ge 17.10; then
      sfApt install -y --force-yes pciutils || failure 210 "problem installing pciutils"
      if [[ ! -z ${FEN} && ${FEN} -eq 0 ]]; then
        which netplan || {
          sfApt install -y --force-yes netplan.io || failure 210 "problem installing netplan.io"
        }
      else
        sfApt install -y --force-yes netplan.io || failure 210 "problem installing netplan.io"
      fi
      # netplan.io may break networking... So ensure networking is working as expected
      ensure_network_connectivity
      sfApt install -y --force-yes sudo || failure 210 "problem installing sudo"
    else
      sfApt install -y systemd pciutils sudo || failure 211
    fi

    if dpkg --compare-versions $(sfGetFact "linux_version") ge 20.04; then
      if [ "{{.ProviderName}}" == "aws" ]; then
        : # do nothing
      else
        sfApt install -y --force-yes systemd || failure 210 "problem installing systemd"
      fi
    else
      sfApt install -y --force-yes systemd || failure 210 "problem installing systemd"
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
    yum install -q -y systemd pciutils yum-utils sudo || failure 212 "failure installing systemd and other basic requirements"
    # systemd, if updated, is restarted, so we may need to ensure again network connectivity
    ensure_network_connectivity

    # # install security updates
    # yum install -y yum-plugin-security yum-plugin-changelog && yum update -y --security
    ;;
  esac
  sfProbeGPU
}

function install_packages() {
  case $LINUX_KIND in
  ubuntu | debian)
    sfApt install -y -qq wget curl jq zip unzip time at &>/dev/null || failure 213 "failure installing utility packages: jq zip time at"
    ;;
  redhat | centos)
    yum install --enablerepo=epel -y -q wget curl jq zip unzip time at &>/dev/null || failure 214 "failure installing utility packages: jq zip time at"
    ;;
  *)
    failure 215 "Unsupported Linux distribution '$LINUX_KIND'!"
    ;;
  esac
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
    echo "deb http://archive.ubuntu.com/ubuntu/ ${codename}-proposed main" >/etc/apt/sources.list.d/${codename}-proposed.list
    ;;
  debian)
    sfFinishPreviousInstall
    ;;
  redhat | rhel | centos)
    if which dnf; then
    # Install EPEL repo ...
      sfRetryEx 3m 5 "dnf install -y epel-release" || failure 217 "failure installing epel repo"
      sfRetryEx 3m 5 "dnf makecache fast -y || dnf makecache -y" || failure 218 "failure updating cache"
      # ... but don't enable it by default
      dnf config-manager --set-disabled epel &>/dev/null || true
    else
      # Install EPEL repo ...
      sfRetryEx 3m 5 "yum install -y epel-release" || failure 217 "failure installing epel repo"
      sfRetryEx 3m 5 "yum makecache fast || yum makecache" || failure 218 "failure updating cache"
      # ... but don't enable it by default
      yum-config-manager --disablerepo=epel &>/dev/null || true
    fi
    ;;
  fedora)
    sfRetryEx 3m 5 "dnf makecache fast -y || dnf makecache -y" || failure 218 "failure updating cache"
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
  cat >/etc/sysctl.d/20-safescale.conf <<-EOF
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
	echo "{{.FinalPublicKey}}" >/home/{{.Username}}/.ssh/authorized_keys
	dd if=/dev/urandom of=/home/{{.Username}}/.ssh/id_rsa conv=notrunc bs=4096 count=8
	echo "{{.FinalPrivateKey}}" >/home/{{.Username}}/.ssh/id_rsa
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
    sfRetryEx 1m 5 "service atd start" || true
    sleep 4
    ;;
  *) ;;
  esac
}

# for testing purposes
function unsafe_update_credentials() {
  echo "{{.Username}}:safescale" | chpasswd

  dd if=/dev/urandom of=/home/{{.Username}}/.ssh/authorized_keys conv=notrunc bs=4096 count=8
  echo "{{.FinalPublicKey}}" >/home/{{.Username}}/.ssh/authorized_keys
  dd if=/dev/urandom of=/home/{{.Username}}/.ssh/id_rsa conv=notrunc bs=4096 count=8
  echo "{{.FinalPrivateKey}}" >/home/{{.Username}}/.ssh/id_rsa
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
  *)
    ;;
  esac
}

# ---- Main

check_unsupported
#unsafe_update_credentials
check_providers
update_credentials
configure_locale
configure_dns
ensure_network_connectivity || true
is_network_reachable && {
  add_common_repos || failure 215 "failure adding common repos, 1st try"
}
is_network_reachable && {
  early_packages_update || failure 215 "failure in early packages update, 1st try"
}

identify_nics
configure_network

is_network_reachable && {
  add_common_repos || failure 215 "failure adding common repos, 2nd try"
}
is_network_reachable && {
  early_packages_update || failure 215 "failure in early packages update, 2nd try"
}

install_packages || failure 215 "failure installing packages"

update_kernel_settings || failure 216 "failure updating kernel settings"

force_dbus_restart || failure 217 "failure restarting dbus"

systemctl restart sshd || failure 217 "failure restarting sshd"

enable_at_daemon || failure 217 "failure starting at daemon"

echo -n "0,linux,${LINUX_KIND},${VERSION_ID},$(hostname),$(date +%Y/%m/%d-%H:%M:%S)" >/opt/safescale/var/state/user_data.netsec.done

# !!! DON'T REMOVE !!! #insert_tag allows to add something just before exiting,
#                      but after the template has been realized (cf. libvirt Stack)
#insert_tag

(
  sync
  echo 3 >/proc/sys/vm/drop_caches
  sleep 2
) || true

set +x
exit 0
