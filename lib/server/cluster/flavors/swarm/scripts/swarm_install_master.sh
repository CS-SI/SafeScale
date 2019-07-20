#!/usr/bin/env bash -x
#
# Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

# Redirects outputs to swarm_install_master.log
rm -f /opt/safescale/var/log/swarm_install_master.log
exec 1<&-
exec 2<&-
exec 1<>/opt/safescale/var/log/swarm_install_master.log
exec 2>&1

{{ .reserved_BashLibrary }}

# Installs and configures everything needed on any node
{{ .reserved_CommonRequirements }}

# Installs safescale binaries
LIST=$(curl -s https://api.github.com/repos/CS-SI/Safescale/releases/latest | grep browser_download_url | grep safescale | cut -d'"' -f4)
cd /usr/local/bin
for i in $LIST; do
    sfDownload "$i" "$(basename $i)" 5m 5 || exit 192
done
mv safescaled-Linux-x86_64.bin safescaled
mv safescale-Linux-x86_64.bin safescale
chown root:root safescale*
chmod u+rwx,go+rx-w safescale*

# Set tenant.json file
mkdir -p /etc/safescale
cat >/etc/safescale/tenants.json <<-'EOF'
{{ .reserved_TenantJSON }}
EOF

echo "Master installed successfully."
exit 0
