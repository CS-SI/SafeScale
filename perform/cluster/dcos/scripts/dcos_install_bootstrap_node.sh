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

### Lauch downloads in parallel
mkdir -p /usr/local/dcos/genconf/serve/docker
cd /usr/local/dcos
yum makecache fast >/dev/null
yum install -y wget >/dev/null

# Download if needed the file dcos_generate_config.sh and executes it
function download_dcos_config_generator {
    [ ! -f dcos_generate_config.sh ] && {
        while true; do
            wget -q https://downloads.dcos.io/dcos/stable/{{.DCOSVersion}}/dcos_generate_config.sh
            [ $? -eq 0 ] && break
            echo "Retrying to download DCOS configuration generator..."
        done
    }
    exit 0
}

function download_dcos_bin() {
    [ ! -f /usr/local/dcos/genconf/serve/dcos.bin ] && {
        while true; do
            wget -q -O /usr/local/dcos/genconf/serve/dcos.bin https://downloads.dcos.io/binaries/cli/linux/x86-64/dcos-1.11/dcos
            [ $? -eq 0 ] && break
            echo "Retrying to download DCOS cli..."
        done
    }
    exit 0
}

function download_kubectl_bin() {
    [ ! -f /usr/local/dcos/genconf/serve/kubectl.bin ] && {
        while true; do
            wget -q -O /usr/local/dcos/genconf/serve/kubectl.bin https://storage.googleapis.com/kubernetes-release/release/v1.10.4/bin/linux/amd64/kubectl
            [ $? -eq 0 ] && break
            echo "Retrying to download kubectl binary..."
        done
    }
    exit 0
}

export -f download_dcos_config_generator download_dcos_bin download_kubectl_bin
timeout 10m bash -c download_dcos_config_generator &>/var/tmp/ddcg.log &
DDCG_PID=$!
timeout 10m bash -c download_dcos_bin &>/var/tmp/ddb.log &
DDB_PID=$!
timeout 10m bash -c download_kubectl_bin &>/var/tmp/dkb.log &
DKB_PID=$!

# Install prerequsites for DCOS environment
{{ .IncludeInstallCommons }}

### Pulling nginx in parallel to save some time
docker pull nginx &>/var/tmp/dpn.log &
DPN_PID=$!

# Stats build of needed docker images in backgroud
bash /var/tmp/docker_image_create_guacamole.sh &>/var/tmp/guacamole.log &
G_PID=$!
bash /var/tmp/docker_image_create_proxy.sh &>/var/tmp/proxy.log &
P_PID=$!

### "DCOS config generator" configuration file
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

# Executes DCOS configuration generator as soon as the download is finished
wait $DDCG_PID
retcode=$?
cat /var/tmp/ddcg.log ; rm -f /var/tmp/ddcg.log
[ $retcode -ne 0 ] && exit $retcode
bash dcos_generate_config.sh || {
    retcode=$?
    echo "Failed to generate DCOS configuration"
    exit $retcode
}

### Starts local nginx server to serve files, as soon as nginx image is pulled
wait $DPN_PID
retcode=$?
cat /var/tmp/dpn.log ; rm -f /var/tmp/dpn.log
[ $retcode -ne 0 ] && exit $retcode
docker run -d --restart always -p {{ .BootstrapPort }}:80 -v $PWD/genconf/serve:/usr/share/nginx/html:ro --name nginx nginx >/dev/null || {
    retcode=$?
    echo "Failed to start nginx"
    exit $retcode
}

# docker-compose file to starts guacamole+proxy containers
cat >/usr/local/dcos/genconf/serve/docker/dcos-master.yml <<-'EOF'
version: '2.2'

services:
    guacamole:
        container_name: guacamole
        hostname: guacamole
        image: guacamole:latest
        ports:
            - "9080:8080"
            - "4822:4822"
EOF

# Starts the reverse proxy on the bootstrap server as soon as the image is built
wait $P_PID
retcode=$?
cat /var/tmp/proxy.log ; rm -f /var/tmp/proxy.log
[ $retcode -ne 0 ] && exit $retcode
docker run -d --restart always -p 443:443 --name proxy proxy >/dev/null || {
    retcode=$?
    echo "Failed to start proxy"
    exit $retcode
}

# Awaits the guacamole image is built
wait $G_PID
retcode=$?
cat /var/tmp/guacamole.log ; rm -f /var/tmp/guacamole.log
[ $retcode -ne 0 ] && exit $retcode

# Awaits the download of DCOS binary
wait $DDB_PID
retcode=$?
cat /var/tmp/ddb.log ; rm -f /var/tmp/ddb.log
[ $retcode -ne 0 ] && exit $retcode

# Awaits the download of kubectl binary
wait $DKB_PID
retcode=$?
cat /var/tmp/dkb.log ; rm -f /var/tmp/dkb.log
[ $retcode -ne 0 ] && exit $retcode

exit 0
