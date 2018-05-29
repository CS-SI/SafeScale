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
# Deploys a DCOS cluster with minimum requirements
#
# This script has to be executed on the bootstrap/upgrade server

# Install DCOS environment
mkdir -p /usr/local/dcos/{{.cluster_name}}/genconf
cd /usr/local/dcos/{{.cluster_name}}

cat genconf/config.yaml <<- EOF
---
bootstrap_url: http://{{.bootstrap_ip}}:{{.bootstrap_port}}
cluster_name: {{.cluster_name}}
exhibitor_storage_backend: static
master_discovery: static
ip_detect_public_filename: genconf/ip-detect-public.sh
master_list:
- {{.master_private_ip}}
resolvers:
- {{.dns_server_1}}
- {{.dns_server_2}}
use_proxy: 'true'
http_proxy: http://{{.http_proxy_host}}:{{.http_proxy_port}}
https_proxy: https://{{.https_proxy_host}}:{{.https_proxy_port}}
no_proxy:
- 'foo.bar.com'
- '.baz.com'
EOF

cat genconf/ip-detect-public.sh <<- EOF
#!/usr/bin/env bash
set -o nounset -o errexit
export PATH=/usr/sbin:/usr/bin:$PATH
echo $(ip addr show eth0 | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
EOF

sudo bash dcos_generate_config.sh

sudo docker run -d -p <your-port>:80 -v /usr/local/dcos/{{.cluster_name}}/genconf/serve:/usr/share/nginx/html:ro nginx

if [ "{{.dcos_ha}}" = "yes" ]; then
    MODE=advanced
    master_count=$(echo "{{.master_ips}} | wc -w")
    if [ $master_count -ne 3 ]; then
        stop_install "Invalid number of master IPs: $master_count; must be 3."
    fi
else
    MODE=minimum
    master_count=$(echo "{{.master_ips}} | wc -w")
    if [ $master_count -ne ]; then
        stop_install "Invalid number of master IPs: $master_count; must be 1."
    fi
fi

for master in {{.master_ips}}; do
    deploy_dcos_master_node.sh $master
done

for agent in {{.public_agent_ips}}; do
    deploy_dcos_agent_node.sh $agent yes
done

for agent in {{.private_agent_ips}}; do
    dcos_install_agent_node.sh $agent no
done
