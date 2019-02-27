#!/usr/bin/env bash
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
# Deploys a DCOS bootstrap/upgrade server with minimum requirements
#
# This script has to be executed on the bootstrap/upgrade server

# Redirects outputs to /var/tmp/prepare_bootstrap.log
rm -f /var/tmp/prepare_bootstrap.log
exec 1<&-
exec 2<&-
exec 1<>/var/tmp/prepare_bootstrap.log
exec 2>&1

{{ .reserved_BashLibrary }}

# Download if needed the file dcos_generate_config.sh and executes it
download_dcos_config_generator() {
    [ ! -f dcos_generate_config.sh ] && {
        echo "-------------------------------"
        echo "download_dcos_config_generator:"
        echo "-------------------------------"
        local URL=https://downloads.dcos.io/dcos/stable/{{ .DCOSVersion }}/dcos_generate_config.sh
        sfRetry 14m 5 "curl -qkSsL -o dcos_generate_config.sh $URL" || exit 200
    }
    echo "dcos_generate_config.sh successfully downloaded."
    exit 0
}
export -f download_dcos_config_generator

download_dcos_bin() {
    [ ! -f /usr/local/dcos/genconf/serve/dcos.bin ] && {
        echo "------------------"
        echo "download_dcos_bin:"
        echo "------------------"
        local URL=/usr/local/dcos/genconf/serve/dcos.bin https://downloads.dcos.io/binaries/cli/linux/x86-64/dcos-1.11/dcos
        sfRetry 5m 5 "curl -qkSsL -o /usr/local/dcos/genconf/serve/dcos.bin $URL" || exit 201
    }
    echo "dcos cli successfully downloaded."
    exit 0
}
export -f download_dcos_bin

download_kubectl_bin() {
    [ ! -f /usr/local/dcos/genconf/serve/kubectl.bin ] && {
        echo "---------------------"
        echo "download_kubectl_bin:"
        echo "---------------------"
        local URL=https://storage.googleapis.com/kubernetes-release/release/v1.10.4/bin/linux/amd64/kubectl
        sfRetry 2m 5 "curl -qkSsL -o /usr/local/dcos/genconf/serve/kubectl.bin $URL" || exit 202
    }
    echo "kubectl successfully downloaded."
    exit 0
}
export -f download_kubectl_bin

download_nginx_image() {
    echo "---------------------"
    echo "download_nginx_image:"
    echo "---------------------"
    sfRetry 1m 5 "systemctl status docker || systemctl restart docker" && \
    sfRetry 8m 5 "docker pull nginx:latest" || exit 203
}
export -f download_nginx_image

mkdir -p /usr/local/dcos/genconf/serve/docker && \
cd /usr/local/dcos && \
yum makecache fast && \
yum install -y wget curl time jq unzip
[ $? -ne 0 ] && exit 204

# Lauch downloads in parallel
sfAsyncStart DDCG 15m bash -c download_dcos_config_generator
sfAsyncStart DDB 10m bash -c download_dcos_bin
sfAsyncStart DKB 10m bash -c download_kubectl_bin
sfAsyncStart DNI 10m bash -c download_nginx_image

# Install requirements for DCOS environment
{{ .reserved_CommonRequirements }}

# Awaits download of DCOS configuration generator
echo "Waiting for download_dcos_config_generator..."
sfAsyncWait DDCG || exit 205

# Awaits pull of docker nginx image
echo "Waiting for docker nginx image..."
sfAsyncWait DNI || exit 206

# Awaits the download of DCOS binary
echo "Waiting for download_dcos_binary..."
sfAsyncWait DDB || exit 207

# Awaits the download of kubectl binary
echo "Waiting for download_kubectl_binary..."
sfAsyncWait DKB || exit 208

echo
echo "Bootstrap prepared successfully."
exit 0
