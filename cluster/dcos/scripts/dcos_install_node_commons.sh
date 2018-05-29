#!/usr/bin/env bash
#
# Copyright 2015-2018 CS Systemes d'Information
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
# Installs and configure common tools for any kind of nodes

# Disables installation of docker-python from yum
yum remove -y docker-python
yum install -y yum-versionlock
yum versionlock exclude docker-python

# Installs PIP
yum install -y python-pip

# Installs docker-python with pip
pip install -y docker-py==1.10.6

# Enable overlay module
echo overlay >/etc/modules-load.d/overlay.conf

# Loads overlay module
modprobe overlay

# Enables docker yum repo
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# Creates docker systemd directory
mkdir -p /etc/systemd/system/docker.service.d && chmod 0755 /etc/systemd/system/docker.service.d

# Configure docker to use overlay driver
echo >/etc/systemd/system/docker.service.d/override.conf <<- EOF
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd --storage-driver=overlay --log-driver=none
EOF

# Installs docker
sudo yum upgrade --assumeyes --tolerant
sudo yum update --assumeyes
yum install -y docker-ce-17.06.2

# Enable docker at boot
systemctl enable docker.service

# Enables admin user to use docker
usermod -aG docker {{.AdminUsername}}
