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

# Download if needed the file dcos_generate_config.sh and executes it
download_dcos_config_generator() {
    [ ! -f dcos_generate_config.sh ] && {
        echo "-------------------------------"
        echo "download_dcos_config_generator:"
        echo "-------------------------------"
        while true; do
            wget -q https://downloads.dcos.io/dcos/stable/{{.DCOSVersion}}/dcos_generate_config.sh
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

download_rclone_package() {
    [ ! -f /usr/local/dcos/genconf/serve/rclone.rpm ] && {
        echo "--------------------"
        echo "download_rclone_bin:"
        echo "--------------------"
        while true; do
            wget -q -O /usr/local/dcos/genconf/serve/rclone.rpm https://downloads.rclone.org/rclone-current-linux-amd64.rpm
            [ $? -eq 0 ] && break
            echo "Retrying to download rclone package..."
        done
    }
    echo "Rclone successfully downloaded."
    exit 0
}
export -f download_rclone_package

# Lauch downloads in parallel
mkdir -p /usr/local/dcos/genconf/serve/docker && \
cd /usr/local/dcos && \
yum makecache fast && \
yum install -y wget time && \
[ $? -ne 0 ] && exit {{ errcode "ToolsInstall" }}

# bg_start <what> <duration> <command>...
bg_start() {
    local pid=${1}_PID
    local log=${1}.log
    local duration=$2
    shift 2
    timeout $duration /usr/bin/time -p $* &>/var/tmp/$log &
    eval $pid=$!
}

# bg_wait <what> <error message>
bg_wait() {
    local pid="${1}_PID"
    local log="${1}.log"
    eval "wait \$$pid"
    retcode=$?
    cat /var/tmp/$log
    [ $retcode -ne 0 ] && exit $2
    rm -f /var/tmp/$log
}

#timeout 15m /usr/bin/time -p bash -c download_dcos_config_generator &>/var/tmp/DDCG.log &
#DDCG_PID=$!
bg_start DDCG 15m bash -c download_dcos_config_generator
#timeout 10m /usr/bin/time -p bash -c download_dcos_bin &>/var/tmp/DDB.log &
#DDB_PID=$!
bg_start DDB 10m bash -c download_dcos_bin
#timeout 10m /usr/bin/time -p bash -c download_kubectl_bin &>/var/tmp/DKB.log &
#DKB_PID=$!
bg_start DKB 10m bash -c download_kubectl_bin
#timeout 10m /usr/bin/time -p bash -c download_rclone_package &>/var/tmp/DRP.log &
#DRP_PID=$!
bg_start DRP 10m bash -c download_rclone_package

# Install requirements for DCOS environment
{{ .InstallCommonRequirements }}

# Pulling nginx in parallel to save some time
#/usr/bin/time -p docker pull nginx &>/var/tmp/DPN.log &
#DPN_PID=$!
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

# Awaits the download of rclone package
echo "Waiting for download_rclone_package..."
bg_wait DRP {{ errcode "RcloneDownload" }}
rpm -U /usr/local/dcos/genconf/serve/rclone.rpm || exit {{ errcode "RcloneInstall" }}

echo
echo "Bootstrap prepared successfully."
exit 0
