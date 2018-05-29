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
#
# Installs and configure a master node
# This script must be executed on server to configure as master node

# Installs and configures everything needed on any node
{{.IncludeInstallCommons}}

# Installs graphical environment
yum install -y tigervnc-server

# Installs SafeScale containers
curl http://{{.BootstrapIP}}:{{.BootstrapPort}}/docker/guacamole.tar.gz 2>/dev/null | docker image load
curl http://{{.BootstrapIP}}:{{.BootstrapPort}}/docker/proxy.tar.gz 2>/dev/null | docker image load

# Get install script from bootstrap server
mkdir /tmp/dcos && cd /tmp/dcos
curl -O http://{{.BootstrapIP}}:{{.BootstrapPort}}/dcos_install.sh || exit 1

# Launch installation
bash dcos_install.sh master
retcode=$?

#  Do some cleanup
#rm -rf /tmp/dcos

exit $retcode