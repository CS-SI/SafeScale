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

# Redirects outputs to /var/tmp/prepare_bootstrap.log
rm -f /var/tmp/prepare_bootstrap.log
exec 1<&-
exec 2<&-
exec 1<>/var/tmp/prepare_bootstrap.log
exec 2>&1

{{ .CommonTools }}

wait_for_userdata

# Download if needed the file dcos_generate_config.sh and executes it
download_dcos_config_generator() {
    [ ! -f dcos_generate_config.sh ] && {
        echo "-------------------------------"
        echo "download_dcos_config_generator:"
        echo "-------------------------------"
        >dcos_generate_config.sh
        while true; do
            wget -q -c https://downloads.dcos.io/dcos/stable/{{ .DCOSVersion }}/dcos_generate_config.sh
            [ $? -eq 0 ] && break
            echo "Retrying to download DCOS configuration generator..."
        done
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
        while true; do
            wget -q -O /usr/local/dcos/genconf/serve/dcos.bin https://downloads.dcos.io/binaries/cli/linux/x86-64/dcos-1.11/dcos
            [ $? -eq 0 ] && break
            echo "Retrying to download DCOS cli..."
        done
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
        while true; do
            wget -q -O /usr/local/dcos/genconf/serve/kubectl.bin https://storage.googleapis.com/kubernetes-release/release/v1.10.4/bin/linux/amd64/kubectl
            [ $? -eq 0 ] && break
            echo "Retrying to download kubectl binary..."
        done
    }
    echo "kubectl successfully downloaded."
    exit 0
}
export -f download_kubectl_bin

mkdir -p /usr/local/dcos/genconf/serve/docker && \
cd /usr/local/dcos && \
yum makecache fast && \
yum install -y time
[ $? -ne 0 ] && exit {{ errcode "ToolsInstall" }}

# Lauch downloads in parallel
bg_start DDCG 15m bash -c download_dcos_config_generator
bg_start DDB 10m bash -c download_dcos_bin
bg_start DKB 10m bash -c download_kubectl_bin

# Install requirements for DCOS environment
{{ .InstallCommonRequirements }}

# Pulling nginx in parallel to save some time
bg_start DPN 10m docker pull nginx

# Awaits download of DCOS configuration generator
echo "Waiting for download_dcos_config_generator..."
bg_wait DDCG {{ errcode "DcosConfigGeneratorDownload" }}

# Awaits pull of docker nginx image
echo "Waiting for docker pull nginx..."
bg_wait DPN {{ errcode "DockerNginxDownload" }}

# Awaits the download of DCOS binary
echo "Waiting for download_dcos_binary..."
bg_wait DDB {{ errcode "DcosCliDownload" }}

# Awaits the download of kubectl binary
echo "Waiting for download_kubectl_binary..."
bg_wait DKB {{ errcode "KubectlDownload" }}

echo
echo "Bootstrap prepared successfully."
exit 0
