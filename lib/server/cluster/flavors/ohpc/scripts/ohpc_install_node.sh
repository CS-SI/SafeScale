#!/usr/bin/env bash -x
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
#
# Installs and configure a DCOS agent node
# This script must be executed on agent node.

# Redirects outputs to ohpc_install_node.log
rm -f /opt/safescale/var/log/ohpc_install_node.log
exec 1<&-
exec 2<&-
exec 1<>/opt/safescale/var/log/ohpc_/install_node.log
exec 2>&1

{{ .reserved_BashLibrary }}

# Installs and configures everything needed on any node
{{ .reserved_CommonRequirements }}

echo "Node installed successfully."
exit 0