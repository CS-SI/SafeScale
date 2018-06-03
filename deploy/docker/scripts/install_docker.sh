#!/usr/bin/env bash
#
# Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
#
# install_docker.sh
#
# Installs Docker

{{.CommonTools}}

echo "Install Docker"

case $LINUX_KIND in
    debian|ubuntu)
        export DEBIAN_FRONTEND=noninteractive
        wait_for_apt && apt update
        wait_for_apt && apt-get install -y  apt-transport-https ca-certificates curl gnupg2 software-properties-common
        curl -fsSL https://download.docker.com/linux/$LINUX_KIND/gpg | apt-key add -
        add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/$LINUX_KIND $(lsb_release -cs) stable"
        wait_for_apt && apt update
        wait_for_apt && apt-get install -qqy  docker-ce
        ;;
    centos|rhel)
       yum install -y yum-utils device-mapper-persistent-data lvm2
        yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        yum install -y docker-ce
        ;;
    fedora)
        dnf -y install dnf-plugins-core
        dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
        dnf install -y docker-ce
        ;;
    *)
        echo "Unsupported operating system '$LINUX_KIND'"
        exit 1
        ;;
esac
gpasswd -a "${USER}" docker
exit 0