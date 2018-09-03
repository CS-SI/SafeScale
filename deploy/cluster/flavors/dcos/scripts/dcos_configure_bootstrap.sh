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


# Redirects outputs to /var/tmp/configure_bootstrap.log
rm -f /var/tmp/configure_bootstrap.log
exec 1<&-
exec 2<&-
exec 1<>/var/tmp/configure_bootstrap.log
exec 2>&1

{{ .reserved_BashLibrary }}

# Stats build of needed docker images in backgroud
#bg_start GUACAMOLE 30m bash /var/tmp/docker_image_create_guacamole.sh
#bg_start PROXY 30m bash /var/tmp/docker_image_create_proxy.sh

cd /usr/local/dcos

# "DCOS config generator" configuration file
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

### Private SSH Key corresponding to cladm user
cat >genconf/ssh_key <<'EOF'
{{ .SSHPrivateKey }}
EOF
chmod 0600 genconf/ssh_key

### Public SSH key to the home dir of cladm user
cat >>/home/cladm/.ssh/authorized_keys <<-'EOF'
{{ .SSHPublicKey }}
EOF
chmod 0600 /home/cladm/.ssh/authorized_keys && chown -R cladm:cladm /home/cladm

### Script to detect IP
cat >genconf/ip-detect <<-'EOF'
#!/usr/bin/env bash
ifconfig eth0 | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*'
EOF
chmod a+rx genconf/ip-detect

# Executes DCOS configuration generator
bash dcos_generate_config.sh || exit {{ errcode "DcosGenerateConfig" }}

# Starts local nginx server to serve files
docker run -d --restart always -p {{ .BootstrapPort }}:80 -v $PWD/genconf/serve:/usr/share/nginx/html:ro --name nginx nginx >/dev/null || {
    exit {{ errcode "DockerNginxStart" }}
}

# Awaits the proxy docker image is built
#echo "Waiting for proxy docker image..."
#bg_wait PROXY {{ errcode "DockerProxyBuild" }}
#docker run -d --restart always -p 443:443 --hostname proxy --name proxy proxy:latest >/dev/null || exit {{ errcode "DockerProxyStart" }}
# ... and instructs host firewall to allow access on port 443
#iptables -t filter -A INPUT -p tcp --dport https -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#save_iptables_rules

# Awaits the build of Guacamole Docker Image...
#bg_wait GUACAMOLE {{ errcode "DockerGuacamoleBuild" }}

echo
echo "Bootstrap successfully configured."
exit 0
