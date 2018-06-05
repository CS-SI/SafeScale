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
# Deploys a DCOS bootstrap/upgrade server with minimum requirements
#
# This script has to be executed on the bootstrap/upgrade server

# Redirects outputs to /var/tmp/install_bootstrap_node.log
exec 1<&-
exec 2<&-
exec 1<>/var/tmp/install_bootstrap_node.log
exec 2>&1

{{.IncludeInstallCommons}}

# Pulling nginx in parallel to save some time
docker pull nginx &

# Install DCOS environment
mkdir -p /usr/local/dcos/genconf
cd /usr/local/dcos

cat >genconf/config.yaml <<-'EOF'
---
bootstrap_url: http://{{ .BootstrapIP }}:{{ .BootstrapPort }}
cluster_name: {{ .ClusterName }}
exhibitor_storage_backend: static
master_discovery: static
ip_detect_public_filename: genconf/ip-detect
master_list:
{{- range .MasterIPs }}
- {{.}}
{{- end}}
{{- if .DNSServerIPs }}
resolvers:
{{- range .DNSServerIPs }}
- {{ . }}
{{- end }}
{{- end }}
ssh_key_path: genconf/ssh_key
ssh_user: cladm
ssh_port: 22
use_proxy: 'false'
#use_proxy: 'true'
#http_proxy: http://{{.HTTPProxyHost}}:{{.HTTPProxyPort}}
#https_proxy: https://{{.HTTPSProxyHost}}:{{.HTTPSProxyPortr}}
#no_proxy:
#- 'foo.bar.com'
#- '.baz.com'
oauth_enabled: 'false'
EOF

# Private SSH Key corresponding to the ssh_user
cat >genconf/ssh_key <<'EOF'
{{.SSHPrivateKey}}
EOF
chmod 0600 genconf/ssh_key

# Public SSH key to the home dir of the ssh_user
cat >>/home/cladm/.ssh/authorized_keys <<-'EOF'
{{ .SSHPublicKey}}
EOF
chmod 0600 /home/cladm/.ssh/authorized_keys && chown -R cladm:cladm /home/cladm

# Script to detect IP
cat >genconf/ip-detect <<-'EOF'
#!/usr/bin/env bash
#curl ipinfo.io/ip
ifconfig eth0 | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*'
EOF
chmod a+rx genconf/ip-detect

# Download if needed the file dcos_generate_config.sh and executes it
[ ! -f dcos_generate_config.sh ] && wget -q https://downloads.dcos.io/dcos/stable/{{.DCOSVersion}}/dcos_generate_config.sh
if [ -f dcos_generate_config.sh ]; then
    bash dcos_generate_config.sh || exit 1
fi
echo "Executing dcos_generate_config.sh..."

# Starts local nginx server to serve files
docker run -d -p 80:80 -v $PWD/genconf/serve:/usr/share/nginx/html:ro nginx >/dev/null && exit 0

# Inserts the code to prepare docker images
{{ .PrepareDockerImages }}

# Reaching this point, something wrong happened
exit 1
