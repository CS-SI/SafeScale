#!/bin/bash -x

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

# Redirects outputs to /opt/safescale/var/log/node_install_requirements.log
LOGFILE=/opt/safescale/var/log/node_install_requirements.log

### All output to one file and all output to the screen
exec > >(tee -a ${LOGFILE} /opt/safescale/var/log/ss.log) 2>&1
set -x

# shellcheck disable=SC1009
# shellcheck disable=SC1073
# shellcheck disable=SC1054
{{ .reserved_BashLibrary }}

#### Installs and configure common tools for any kind of nodes ####

install_docker() {
  docker ps && docker-compose version && sfExit
  case $LINUX_KIND in
      debian|ubuntu)
          export DEBIAN_FRONTEND=noninteractive
          sfRetry "sfApt update --allow-insecure-repositories"
          sfRetry "dpkg --remove --force-remove-reinstreq docker docker-engine docker.io containerd runc"
          ;;
      centos|redhat)
          sfRetry "yum remove -y docker docker-client docker-client-latest \
                                         docker-common docker-latest docker-latest-logrotate \
                                         docker-logrotate docker-engine"
          ;;
      fedora)
          sfRetry "dnf remove -y docker docker-client docker-client-latest docker-common \
                                         docker-latest docker-latest-logrotate docker-logrotate \
                                         docker-selinux docker-engine-selinux docker-engine"
          ;;
      *)
          echo "Unsupported operating system '$LINUX_KIND'"
          sfFail 192 "Unsupported operating system '$LINUX_KIND'"
          ;;
  esac
  case $LINUX_KIND in
      debian)
          export DEBIAN_FRONTEND=noninteractive
          sfRetryEx 14m 4 "sfApt update --allow-insecure-repositories" || sfFail 192 "error updating"
          sfRetryEx 14m 4 "sfApt install --allow-change-held-packages -qqy apt-transport-https ca-certificates" || sfFail 193 "error installing apt tools (exit code $?)"
          sfRetryEx 14m 4 "(apt-cache show gnupg2 && apt install -qqy --allow-change-held-packages gnupg2) || (apt-cache show gnupg && apt install -qqy --allow-change-held-packages gnupg)"
          sfRetryEx 14m 4 "curl -fsSL https://download.docker.com/linux/$LINUX_KIND/gpg | apt-key add -" || sfFail 194 "error updating gpg keys"
          echo "deb [arch=amd64] https://download.docker.com/linux/$LINUX_KIND $(lsb_release -cs) stable" >/etc/apt/sources.list.d/docker.list
          sfRetryEx 14m 4 "sfApt update --allow-insecure-repositories" || sfFail 192 "error updating"
          sfRetryEx 14m 4 "sfApt install -qqy docker-ce" || sfFail 195 "error installing docker-ce (exit code $?)"
          ;;
      ubuntu)
          export DEBIAN_FRONTEND=noninteractive
          sfRetryEx 14m 4 "sfApt update --allow-insecure-repositories" || sfFail 192 "error updating"
          sfRetryEx 14m 4 "sfApt install -qqy --allow-change-held-packages apt-transport-https ca-certificates" || sfFail 193 "error installing apt tools (exit code $?)"
          sfRetryEx 14m 4 "curl -fsSL https://download.docker.com/linux/$LINUX_KIND/gpg | apt-key add -" || sfFail 194 "error updating gpg keys"
          echo "deb [arch=amd64] https://download.docker.com/linux/$LINUX_KIND $(lsb_release -cs) stable" >/etc/apt/sources.list.d/docker.list
          sfRetryEx 14m 4 "sfApt update --allow-insecure-repositories" || sfFail 192 "error updating"
          sfRetryEx 14m 4 "sfApt install -qqy docker-ce" || sfFail 195 "error installing docker-ce (exit code $?)"
          ;;
      centos|redhat|rhel)
          sfRetryEx 14m 4 "yum install -y yum-utils device-mapper-persistent-data lvm2" || sfFail 196 "error installing yum prerequisites"
          sfRetryEx 14m 4 "yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo" || sfFail 197 "error adding docker-ce repo"
          op=-1
          yum install -y curl --nobest &>/dev/null && op=$? || true
          if [ $op -ne 0 ]; then
              sfRetryEx 14m 4 "yum install -y curl &>/dev/null" && op=$? || true
              if [ $op -ne 0 ]; then
                  sfFail 198 "error installing curl"
              else
                  sfRetryEx 14m 4 "yum install -y docker-ce docker-ce-cli containerd.io" || sfFail 199 "error installing docker-ce (exit code $?)"
              fi
          else
              sfRetryEx 14m 4 "yum install -y docker-ce docker-ce-cli containerd.io --nobest" || sfFail 200"error installing docker-ce --nobest (exit code $?)"
          fi
          cat /etc/redhat-release | grep 8. && systemctl enable --now docker || true
          ;;
      fedora)
          sfRetryEx 14m 4 "dnf install -y yum-utils device-mapper-persistent-data lvm2" || sfFail 201
          sfRetryEx 14m 4 "dnf config-manager --add-repo=https://download.docker.com/linux/fedora/docker-ce.repo"
          op=-1
          dnf install -y curl --nobest &>/dev/null && op=$? || true
          if [ $op -ne 0 ]; then
              dnf install -y curl &>/dev/null && op=$? || true
              if [ $op -ne 0 ]; then
                  sfFail 202 "error installing curl"
              else
                  sfRetryEx 14m 4 "dnf install -y docker-ce docker-ce-cli containerd.io" || sfFail 203 "error installing docker-ce (exit code $?)"
              fi
          else
              sfRetryEx 14m 4 "dnf install -y docker-ce docker-ce-cli containerd.io --nobest" || sfFail 204 "error installing docker-ce (exit code $?)"
          fi
          systemctl enable --now docker || true
          ;;
      *)
          echo "Unsupported operating system '$LINUX_KIND'"
          sfFail 205 "Unsupported operating system '$LINUX_KIND'"
          ;;
  esac
  mkdir -p /etc/docker
  if [ "$(sfGetFact use_systemd)" = "1" ]; then
      DRIVER=systemd
  else
      DRIVER=cgroupfs
  fi
  if [ "$(sfGetFact redhat_like)" = "1" ]; then
      cat > /etc/docker/daemon.json <<-EOF
  {
      "iptables": false,
      "exec-opts": [
          "native.cgroupdriver=${DRIVER}"
      ],
      "no-new-privileges": false,
      "log-driver": "json-file",
      "log-level":"info",
      "log-opts": {
          "max-size": "100m"
      },
      "experimental": true,
      "metrics-addr": "0.0.0.0:9323",
      "storage-driver": "overlay2",
      "userland-proxy": false,
      "storage-opts": [
          "overlay2.override_kernel_check=true"
      ]
  }
EOF
  else
      cat > /etc/docker/daemon.json <<-EOF
  {
      "no-new-privileges": false,
      "log-driver": "json-file",
      "log-level":"info",
      "log-opts": {
          "max-size": "100m"
      },
      "experimental": true,
      "metrics-addr": "0.0.0.0:9323",
      "storage-driver": "overlay2"
  }
EOF
  fi
  # First once dockerd, allowing it to create needed firewalld zone docker...
  sfFirewallReload || sfFail 208 "failed to reload firewalld, ensuring it works correctly"
  sfService restart docker || sfFail 209 "failed to restart dockerd for the first time"
  # ... and if no such zone is created, create needed firewalld rules
  # FIXME: it should be better to create a configuration identical to the one created by docker 20.10+...
  sfFirewall --info-zone=docker 2>&1 >/dev/null || {
      sfFirewallAdd --zone=trusted --add-interface=docker0
      sfFirewallAdd --zone=trusted --add-masquerade
      sfFirewallReload || sfFail 210 "Firewall problem"
  }
  sfService enable docker || sfFail 211
  sfService restart docker || sfFail 212
  sleep 6
  op=-1
  sfService status docker &>/dev/null && op=$? || true
  [ $op -ne 0 ] && sfFail 213
  rm -f /tmp/docker-fail.txt || true
  VERSION=$(curl -kSsL https://api.github.com/repos/docker/compose/releases/latest | jq -r .name) && op=$? || true
  [ $op -ne 0 ] && sfFail 206 "error getting latest docker-compose version"
  curl -SL https://github.com/docker/compose/releases/download/${VERSION}/docker-compose-$(uname -s)-$(uname -m) -o /usr/bin/docker-compose
  chmod ugo+x /usr/bin/docker-compose
  op=-1
  sfRetryEx 5m 5 "docker pull hello-world 2>>/tmp/docker-fail.txt 7>>/tmp/docker-fail.txt" && op=$? || op=$?
  if [[ $op -ne 0 ]]; then
      sfFail 214 "$(cat /tmp/docker-fail.txt)\nexit code $op"
  fi
  rm -f /tmp/docker-fail.txt || true
  docker run hello-world | grep "working correctly" || sfFail 215 "failure running hello-world docker image"
  rm -f /tmp/docker-fail.txt || true
  if [[ "{{.DockerHubUsername}}" != "" ]]; then
      docker login --username="{{.DockerHubUsername}}" --password-stdin <<< "{{.DockerHubPassword}}" > /tmp/docker-fail.txt
      if [[ "$(cat /tmp/docker-fail.txt)" != "Login Succeeded" ]]; then
          sfFail 216 "$(cat /tmp/docker-fail.txt)"
      fi
  fi
  rm -f /tmp/docker-fail.txt || true
}
export -f install_docker

install_docker || sfFail $? "Problem installing docker"

sfExit
