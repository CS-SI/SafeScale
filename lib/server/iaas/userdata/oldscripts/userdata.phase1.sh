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
  echo -n "2,${LINUX_KIND},${FULL_VERSION_ID},$(hostname),$(date +%Y/%m/%d-%H:%M:%S)" > /opt/safescale/var/state/user_data.phase1.done
}
trap print_error ERR

function fail() {
  echo "PROVISIONING_ERROR: $1"
  echo -n "$1,${LINUX_KIND},${FULL_VERSION_ID},$(hostname),$(date +%Y/%m/%d-%H:%M:%S)" > /opt/safescale/var/state/user_data.phase1.done
  set +x
  exit $1
}

mkdir -p /opt/safescale/etc /opt/safescale/bin &> /dev/null
mkdir -p /opt/safescale/var/log &> /dev/null
mkdir -p /opt/safescale/var/run /opt/safescale/var/state /opt/safescale/var/tmp &> /dev/null

exec 1<&-
exec 2<&-
exec 1<> /opt/safescale/var/log/user_data.phase1.log
exec 2>&1
set -x

function sfApt() {
  rc=-1
  DEBIAN_FRONTEND=noninteractive apt "$@" && rc=$?
  [ $rc -eq -1 ] && return 1
  return $rc
}
export -f sfApt

# try using dnf instead of yum if available
function sfYum() {
  rc=-1
  if [[ -n $(which dnf) ]]; then
    dnf "$@" && rc=$?
  else
    yum "$@" && rc=$?
  fi
  [ $rc -eq -1 ] && return 1
  return $rc
}
export -f sfYum

# sfRetry <timeout> <delay> command
# retries command until success, with sleep of <delay> seconds
function sfRetry() {
  local timeout=$1
  local delay=$2
  shift 2
  local result

  { code=$(< /dev/stdin); } <<- EOF
        fn() {
            local r
            local rc
            while true; do
                r=\$($*)
                rc=\$?
                [ \$rc -eq 0 ] && echo \$r && break
                sleep $delay
            done
            return \$rc
        }
        export -f fn
EOF
  eval "$code"
  result=$(timeout $timeout bash -c -x fn)
  rc=$?
  unset fn
  [ $rc -eq 0 ] && echo $result && return 0
  echo "sfRetry: timeout!"
  return $rc
}
export -f sfRetry

LINUX_KIND=
VERSION_ID=
FULL_VERSION_ID=
FULL_HOSTNAME=

function sfAvail() {
  rc=-1
  case $LINUX_KIND in
  redhat | rhel | centos | fedora)
    if [[ -n $(which dnf) ]]; then
      dnf list available "$@" &> /dev/null && rc=$?
    else
      yum list available "$@" &> /dev/null && rc=$?
    fi
    ;;
  debian | ubuntu)
    DEBIAN_FRONTEND=noninteractive apt search "$@" &> /dev/null && rc=$?
    ;;
  esac
  [ $rc -eq -1 ] && return 1
  return $rc
}
export -f sfAvail

function sfDetectFacts() {
  [[ -f /etc/os-release ]] && {
    . /etc/os-release
    LINUX_KIND=$ID
    FULL_HOSTNAME=$VERSION_ID
    FULL_VERSION_ID=$VERSION_ID
  } || {
    which lsb_release &> /dev/null && {
      LINUX_KIND=$(lsb_release -is)
      LINUX_KIND=${LINUX_KIND,,}
      VERSION_ID=$(lsb_release -rs | cut -d. -f1)
      FULL_VERSION_ID=$(lsb_release -rs)
    } || {
      [[ -f /etc/redhat-release ]] && {
        LINUX_KIND=$(cat /etc/redhat-release | cut -d' ' -f1)
        LINUX_KIND=${LINUX_KIND,,}
        VERSION_ID=$(cat /etc/redhat-release | cut -d' ' -f3 | cut -d. -f1)
        FULL_VERSION_ID=$(cat /etc/redhat-release | cut -d' ' -f3)
        case $VERSION_ID in
        '' | *[!0-9]*)
          VERSION_ID=$(cat /etc/redhat-release | cut -d' ' -f4 | cut -d. -f1)
          FULL_VERSION_ID=$(cat /etc/redhat-release | cut -d' ' -f4)
          ;;
        *) ;;

        esac
      }
    }
  }
}
export -f sfDetectFacts

# Detect facts
sfDetectFacts

function create_user() {
  echo "Creating user {{.User}}..."
  useradd {{.User}} --home-dir /home/{{.User}} --shell /bin/bash --comment "" --create-home || true
  echo "{{.User}}:{{.Password}}" | chpasswd
  groupadd -r docker
  usermod -aG docker {{.User}}
  SUDOERS_FILE=/etc/sudoers.d/{{.User}}
  [ ! -d "$(dirname $SUDOERS_FILE)" ] && SUDOERS_FILE=/etc/sudoers
  cat >> $SUDOERS_FILE <<- 'EOF'
Defaults:{{.User}} !requiretty
{{.User}} ALL=(ALL) NOPASSWD:ALL
EOF

  mkdir /home/{{.User}}/.ssh
  echo "{{.PublicKey}}" >> /home/{{.User}}/.ssh/authorized_keys
  echo "{{.PrivateKey}}" > /home/{{.User}}/.ssh/id_rsa
  chmod 0700 /home/{{.User}}/.ssh
  chmod -R 0600 /home/{{.User}}/.ssh/*

  cat >> /home/{{.User}}/.bashrc <<- 'EOF'
pathremove() {
		local IFS=':'
		local NEWPATH=""
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
pathappend /opt/safescale/bin

if [[ ! -v SAFESCALESSHUSER ]]; then
    :
elif [[ -z "$SAFESCALESSHUSER" ]]; then
    :
else
    if [[ ! -v SAFESCALESSHPASS ]]; then
        :
    elif [[ -z "$SAFESCALESSHPASS" ]]; then
        :
    else
        echo "$SAFESCALESSHPASS" | sudo -S -u $SAFESCALESSHUSER sudo -S -l 2>&1 | grep "incorrect" && exit
        sudo -u $SAFESCALESSHUSER -i;exit
    fi
fi
EOF

  chown -R {{.User}}:{{.User}} /opt/safescale
  chmod -R 0640 /opt/safescale
  find /opt/safescale -type d -exec chmod a+rx {} \;
  chmod 1777 /opt/safescale/var/tmp

  chown -R {{.User}}:{{.User}} /home/{{.User}}

  for i in /home/{{.User}}/.hushlogin /home/{{.User}}/.cloud-warnings.skip; do
    touch $i
    chown root:{{.User}} $i
    chmod ug+r-wx,o-rwx $i
  done

  echo "done"
}

# Follows the CentOS rules:
# - /etc/hostname contains short hostname
function put_hostname_in_hosts() {
  FULL_HOSTNAME="{{ .HostName }}"
  SHORT_HOSTNAME="${FULL_HOSTNAME%%.*}"

  echo "" >> /etc/hosts
  echo "127.0.0.1 ${SHORT_HOSTNAME}" >> /etc/hosts
  echo "${SHORT_HOSTNAME}" > /etc/hostname
  hostname "${SHORT_HOSTNAME}"
}

# Disable cloud-init automatic network configuration to be sure our configuration won't be replaced
function disable_cloudinit_network_autoconf() {
  fname=/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
  mkdir -p $(dirname $fname)
  echo "network: {config: disabled}" > $fname
}

function disable_services() {
  case $LINUX_KIND in
  debian | ubuntu)
    if [[ -n $(which systemctl) ]]; then
      systemctl stop apt-daily.service &> /dev/null
      systemctl kill --kill-who=all apt-daily.service &> /dev/null
    fi
    if [[ -n $(which system) ]]; then
      which system && service stop apt-daily.service &> /dev/null
    fi
    ;;
  esac
}

function check_dns_configuration() {
  if [[ -r /etc/resolv.conf ]]; then
    echo "Getting DNS using resolv.conf..."
    THE_DNS=$(cat /etc/resolv.conf | grep -i '^nameserver' | head -n1 | cut -d ' ' -f2) || true

    if [[ -n ${THE_DNS} ]]; then
      timeout 2s bash -c "echo > /dev/tcp/${THE_DNS}/53" && echo "DNS ${THE_DNS} up and running" && return 0 || echo "Failure connecting to DNS ${THE_DNS}"
    fi
  fi

  if which systemd-resolve; then
    echo "Getting DNS using systemd-resolve"
    THE_DNS=$(systemd-resolve --status | grep "Current DNS" | awk '{print $4}') || true
    if [[ -n ${THE_DNS} ]]; then
      timeout 2s bash -c "echo > /dev/tcp/${THE_DNS}/53" && echo "DNS ${THE_DNS} up and running" && return 0 || echo "Failure connecting to DNS ${THE_DNS}"
    fi
  fi

  if which resolvectl; then
    echo "Getting DNS using resolvectl"
    THE_DNS=$(resolvectl | grep "Current DNS" | awk '{print $4}') || true
    if [[ -n ${THE_DNS} ]]; then
      timeout 2s bash -c "echo > /dev/tcp/${THE_DNS}/53" && echo "DNS ${THE_DNS} up and running" && return 0 || echo "Failure connecting to DNS ${THE_DNS}"
    fi
  fi

  timeout 2s bash -c "echo > /dev/tcp/www.google.com/80" && echo "Network OK" && return 0 || echo "Network not reachable"
  return 1
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

# If host isn't a gateway, we need to configure temporarily and manually gateway on private hosts to be able to update packages
function ensure_network_connectivity() {
  op=-1
  is_network_reachable && op=$? || true
  if [[ ${op} -eq 0 ]]; then
    echo "ensure_network_connectivity started WITH network..."
  else
    echo "ensure_network_connectivity started WITHOUT network..."
  fi

  {{- if .AddGateway }}
  echo "This is NOT a gateway"
  route del -net default &> /dev/null
  route add -net default gw {{ .DefaultRouteIP }}
  {{- else }}
  echo "This IS a gateway"
  :
  {{- end}}

  op=-1
  is_network_reachable && op=$? || true
  if [[ ${op} -eq 0 ]]; then
    echo "ensure_network_connectivity finished WITH network..."
    return 0
  else
    echo "ensure_network_connectivity finished WITHOUT network..."
  fi

  echo "" >> /etc/resolv.conf
  echo "nameserver 1.1.1.1" >> /etc/resolv.conf

  op=-1
  is_network_reachable && op=$? || true
  if [[ ${op} -eq 0 ]]; then
    echo "ensure_network_connectivity finished WITH network AFTER putting custom DNS..."
    return 0
  else
    echo "ensure_network_connectivity finished WITHOUT network, not even custom DNS was enough..."
    return 1
  fi
}

function fail_fast_unsupported_distros() {
  case $LINUX_KIND in
  debian)
    lsb_release -rs | grep "8." && {
      echo "PROVISIONING_ERROR: Unsupported Linux distribution (docker) '$LINUX_KIND $(lsb_release -rs)'!"
      fail 199
    } || true
    ;;
  ubuntu)
    if [[ $(lsb_release -rs | cut -d. -f1) -le 17 ]]; then
      if [[ $(lsb_release -rs | cut -d. -f1) -ne 16 ]]; then
        echo "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND $(lsb_release -rs)'!"
        fail 199
      fi
    fi
    ;;
  redhat | rhel | centos)
    if [[ -n $(which lsb_release) ]]; then
      if [[ $(lsb_release -rs | cut -d. -f1) -lt 7 ]]; then
        echo "PROVISIONING_ERROR: Unsupported Linux distribution (firewalld) '$LINUX_KIND $(lsb_release -rs)'!"
        fail 199
      fi
    else
      if [[ $(echo ${VERSION_ID}) -lt 7 ]]; then
        echo "PROVISIONING_ERROR: Unsupported Linux distribution (firewalld) '$LINUX_KIND $VERSION_ID'!"
        fail 199
      fi
    fi
    ;;
  fedora)
    if [[ -n $(which lsb_release) ]]; then
      if [[ $(lsb_release -rs | cut -d. -f1) -lt 30 ]]; then
        echo "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND $(lsb_release -rs)'!"
        fail 199
      fi
    else
      if [[ $(echo ${VERSION_ID}) -lt 30 ]]; then
        echo "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND $VERSION_ID'!"
        fail 199
      fi
    fi
    ;;
  *)
    echo "PROVISIONING_ERROR: Unsupported Linux distribution '$LINUX_KIND $(lsb_release -rs)'!"
    fail 199
    ;;
  esac
}

function compatible_network() {
  # Try installing network-scripts if available
  case $LINUX_KIND in
  redhat | rhel | centos | fedora)
    op=-1
    sfAvail network-scripts && op=$?
    if [[ ${op} -ne 0 ]]; then
      return 0
    fi
    sfRetry 3m 5 "sfYum install -q -y network-scripts" || true
    ;;
  *) ;;
  esac
}

function silent_compatible_network() {
  # If network works, try to install network-scripts; if install fails, no need to log this because the gateway is not yet configured
  op=-1
  is_network_reachable && op=$? || true
  if [[ ${op} -eq 0 ]]; then
    case $LINUX_KIND in
    redhat | rhel | centos | fedora)
      nop=-1
      sfAvail network-scripts && nop=$?
      if [[ ${nop} -ne 0 ]]; then
        return 0
      fi
      sfRetry 3m 5 "sfYum install -q -y network-scripts &>/dev/null" || true
      ;;
    *) ;;
    esac
  fi
}

function track_time() {
  uptime
  last
}

# ---- Main

export DEBIAN_FRONTEND=noninteractive

PHASE_DONE=/opt/safescale/var/state/user_data.phase1.done
if [[ -f "$PHASE_DONE" ]]; then
  echo "$PHASE_DONE already there."
  set +x
  exit 0
fi

PHASE_DONE=/opt/safescale/var/state/user_data.phase2.done
if [[ -f "$PHASE_DONE" ]]; then
  echo "$PHASE_DONE already there."
  set +x
  exit 0
fi

put_hostname_in_hosts

track_time

check_dns_configuration || true

disable_cloudinit_network_autoconf
disable_services
create_user

silent_compatible_network

ensure_network_connectivity || true

compatible_network

touch /etc/cloud/cloud-init.disabled

fail_fast_unsupported_distros

track_time

echo -n "0,linux,${LINUX_KIND},${FULL_VERSION_ID},$(hostname),$(date +%Y/%m/%d-%H:%M:%S)" > /opt/safescale/var/state/user_data.phase1.done
set +x
exit 0
