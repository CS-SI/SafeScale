#!/usr/bin/env bash -x
#
# Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

# Redirects outputs to k8s_install_master.log
rm -f /opt/safescale/var/log/k8s_install_master.log
exec 1<&-
exec 2<&-
exec 1<>/opt/safescale/var/log/k8s_install_master.log
exec 2>&1

{{ .reserved_BashLibrary }}

# Installs and configures everything needed on any node
{{ .reserved_CommonRequirements }}

echo "Master installed successfully."
exit 0
