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

{{.Header}}

last_error=

function print_error() {
  read -r line file <<< "$(caller)"
  echo "An error occurred in line $line of file $file:" "{$(sed "${line}q;d" "$file")}" >&2
  {{.ExitOnError}}
}
trap print_error ERR

function fail() {
  MYIP="$(ip -br a | grep UP | awk '{print $3}') | head -n 1"
  if [ $# -eq 1 ]; then
    echo "PROVISIONING_ERROR: $1"
    echo -n "$1,${LINUX_KIND},${VERSION_ID},$(hostname),$MYIP,$(date +%Y/%m/%d-%H:%M:%S),PROVISIONING_ERROR:$1" > /opt/safescale/var/state/user_data.init.done
    (
      sync
      echo 3 > /proc/sys/vm/drop_caches
      sleep 2
    ) || true
    exit $1
  elif [ $# -eq 2 -a $1 -ne 0 ]; then
    echo "PROVISIONING_ERROR: $1, $2"
    echo -n "$1,${LINUX_KIND},${VERSION_ID},$(hostname),$MYIP,$(date +%Y/%m/%d-%H:%M:%S),PROVISIONING_ERROR:$2" > /opt/safescale/var/state/user_data.init.done
    (
      sync
      echo 3 > /proc/sys/vm/drop_caches
      sleep 2
    ) || true
    exit $1
  fi
}
export -f fail

mkdir -p /opt/safescale/etc/rclone /opt/safescale/bin &> /dev/null
mkdir -p /opt/safescale/var/log &> /dev/null
mkdir -p /opt/safescale/var/run /opt/safescale/var/state /opt/safescale/var/tmp &> /dev/null

LOGFILE=/opt/safescale/var/log/user_data.init.log

### All output to one file and all output to the screen
exec > >(tee -a ${LOGFILE} /opt/safescale/var/log/ss.log) 2>&1
set -x

date

LINUX_KIND=
VERSION_ID=
FULL_HOSTNAME=
FULL_VERSION_ID=

function sfDetectFacts() {
  [ -f /etc/os-release ] && {
    . /etc/os-release
    LINUX_KIND=$ID
    FULL_HOSTNAME=$VERSION_ID
    FULL_VERSION_ID=$VERSION_ID
  } || {
    command -v lsb_release &> /dev/null && {
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

function drop_user() {
  userdel -r {{.Username}} || echo "User {{.Username}} not exists"
}

function create_user() {
  echo "Creating user {{.Username}}..."
  if getent passwd {{.Username}}; then
    echo "User {{.Username}} already exists !"
    useradd {{.Username}} --home-dir /home/{{.Username}} --shell /bin/bash --comment "" --create-home || true
  else
    useradd {{.Username}} --home-dir /home/{{.Username}} --shell /bin/bash --comment "" --create-home
  fi
  # This password will be changed at phase 2 and can be used only from console (not remotely)
  echo "{{.Username}}:safescale" | chpasswd

  if getent group docker; then
    echo "Group docker already exists !"
  else
    groupadd -r docker
  fi
  usermod -aG docker {{.Username}}
  SUDOERS_FILE=/etc/sudoers.d/{{.Username}}
  [ ! -d "$(dirname $SUDOERS_FILE)" ] && SUDOERS_FILE=/etc/sudoers
  cat >> $SUDOERS_FILE <<- EOF
		Defaults:{{.Username}} !requiretty
		{{.Username}} ALL=(ALL) NOPASSWD:ALL
EOF

  mkdir /home/{{.Username}}/.ssh
  echo "{{.FirstPublicKey}}" > /home/{{.Username}}/.ssh/authorized_keys
  echo "{{.FirstPrivateKey}}" > /home/{{.Username}}/.ssh/id_rsa
  chmod 0700 /home/{{.Username}}/.ssh
  chmod -R 0600 /home/{{.Username}}/.ssh/*
  cat /home/{{.Username}}/.ssh/id_rsa

  chown -R {{.Username}}:{{.Username}} /opt/safescale
  chmod -R 0640 /opt/safescale
  find /opt/safescale -type d -exec chmod a+rx {} \;
  chmod 1777 /opt/safescale/var/tmp

  chown -R {{.Username}}:{{.Username}} /home/{{.Username}}

  for i in /home/{{.Username}}/.hushlogin /home/{{.Username}}/.cloud-warnings.skip; do
    touch $i
    chown root:{{.Username}} $i
    chmod ug+r-wx,o-rwx $i
  done

  echo "done"
}

# Follows the CentOS rules:
# - /etc/hostname contains short hostname
function put_hostname_in_hosts() {
  echo "{{ .HostName }}" > /etc/hostname
  echo "127.0.0.1 {{ .HostName }}" >> /etc/hosts
  hostname {{ .HostName }}
  SHORT_HOSTNAME=$(hostname -s)
  [[ "$SHORT_HOSTNAME" == "{{ .HostName }}" ]] && return
  ping -n -c1 -w5 $SHORT_HOSTNAME 2> /dev/null || sed -i -nr '/^127.0.1.1/!p;$a127.0.1.1\t'"${SHORT_HOSTNAME}" /etc/hosts
}

# Disable cloud-init automatic network configuration to be sure our configuration won't be replaced
function disable_cloudinit_network_autoconf() {
  fname=/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
  mkdir -p $(dirname $fname)
  echo "network: {config: disabled}" > $fname
}

# For testing purposes
function failover_sshd() {
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.old
  cat > /etc/ssh/sshd_config <<- EOF
  Port 22
  PubkeyAuthentication yes
  PasswordAuthentication yes
  ChallengeResponseAuthentication no
  UsePAM yes
  AllowTcpForwarding yes
  X11Forwarding yes
  PrintMotd no
  AcceptEnv LANG LC_*
  Subsystem	sftp	/usr/lib/openssh/sftp-server
EOF
}

function unsafe_sshd() {
  {{- if .IsGateway }}
  sed -i -E 's/(#|)Port\ ([0-9]+)/Port\ {{ .SSHPort }}/g' /etc/ssh/sshd_config || fail 208 "failure changing ssh service port"
  {{- end }}
  sed -i '/^.*PasswordAuthentication / s/^.*$/PasswordAuthentication yes/' /etc/ssh/sshd_config &&
    sed -i '/^.*ChallengeResponseAuthentication / s/^.*$/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config &&
    sed -i '/^.*PubkeyAuthentication / s/^.*$/PubkeyAuthentication yes/' /etc/ssh/sshd_config &&
    systemctl restart sshd
}

function secure_sshd() {
  {{- if .IsGateway }}
  sed -i -E 's/(#|)Port\ ([0-9]+)/Port\ {{ .SSHPort }}/g' /etc/ssh/sshd_config || fail 208 "failure changing ssh service port"
  {{- end }}
  sed -i '/^.*PasswordAuthentication / s/^.*$/PasswordAuthentication no/' /etc/ssh/sshd_config &&
    sed -i '/^.*ChallengeResponseAuthentication / s/^.*$/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config &&
    sed -i '/^.*PubkeyAuthentication / s/^.*$/PubkeyAuthentication yes/' /etc/ssh/sshd_config &&
    systemctl restart sshd
}

function disable_services() {
  case $LINUX_KIND in
  debian | ubuntu)
    if [[ -n $(command -v systemctl) ]]; then
      systemctl stop apt-daily.service &> /dev/null
      systemctl kill --kill-who=all apt-daily.service &> /dev/null
    fi
    if [[ -n $(command -v system) ]]; then
      which system && service stop apt-daily.service &> /dev/null
    fi
    ;;
  esac
}

function sfFinishPreviousInstall() {
  local unfinished
  unfinished=$(dpkg -l | grep -v ii | grep -v rc | tail -n +4 | wc -l)
  if [[ "$unfinished" == 0 ]]; then
    echo "good"
    return 0
  else
    echo "there are unconfigured packages !"
    sudo dpkg --configure -a --force-all && {
      return $?
    }
    return 0
  fi
}
export -f sfFinishPreviousInstall

function disable_upgrades() {
  case $LINUX_KIND in
  ubuntu)
    sfFinishPreviousInstall
    dpkg --remove --force-remove-reinstreq unattended-upgrades || true
    ;;
  *) ;;

  esac
}
export -f disable_upgrades

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

function remove_setuptools() {
  case $LINUX_KIND in
  debian | ubuntu)
    # If it's not there, nothing to do
    sudo dpkg -l python3-setuptools || true
    sudo dpkg -l python3-setuptools | grep ii && echo "python3-setuptools already there"
    sudo dpkg -l python3-setuptools | grep ii && sudo apt-get remove -y python3-setuptools
    ;;
  redhat | fedora | centos)
    sfYum remove -y python3-setuptools || true
  esac
}
export -f remove_setuptools

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
export -f no_daily_update

# ---- Main
export DEBIAN_FRONTEND=noninteractive
export UCF_FORCE_CONFFNEW=1

put_hostname_in_hosts
disable_cloudinit_network_autoconf
disable_services
disable_upgrades

{{- if .Debug}}
failover_sshd
{{- end}}

{{- if .Debug }}
unsafe_sshd
{{- else }}
secure_sshd
{{- end }}

{{- if .Debug }}
drop_user
{{- end }}

create_user

remove_setuptools

no_daily_update

touch /etc/cloud/cloud-init.disabled
# ---- EndMain

echo -n "0,linux,${LINUX_KIND},${VERSION_ID},$(hostname),$(date +%Y/%m/%d-%H:%M:%S)" > /opt/safescale/var/state/user_data.init.done

(
  sync
  echo 3 > /proc/sys/vm/drop_caches
  sleep 2
) || true

set +x
exit 0
