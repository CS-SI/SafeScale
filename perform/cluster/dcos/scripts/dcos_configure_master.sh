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
# Installs and configure a master node
# This script must be executed on server to configure as master node

# Redirects outputs to /var/tmp/configure_master.log
rm -f /var/tmp/configure_master.log
exec 1<&-
exec 2<&-
exec 1<>/var/tmp/configure_master.log
exec 2>&1

download_safescale_guacamole_image() {
    while true; do
        while true; do
            wget -q -O /var/tmp/guacamole.tar.gz http://{{ .BootstrapIP }}:{{ .BootstrapPort }}/docker/guacamole.tar.gz
            [ $? -eq 0 ] && break
            echo "Trying again to download guacamole docker image..."
        done
        docker image load -i /var/tmp/guacamole.tar.gz
        [ $? -eq 0 ] && break
        echo "Trying again to download guacamole docker image..."
    done
    rm -f /var/tmp/guacamole.tar.gz
    exit 0
}
export -f download_safescale_guacamole_image

# Get install script from bootstrap server
download_dcos_install() {
    mkdir -p /usr/local/dcos
    cd /usr/local/dcos
    [ ! -f dcos_install.sh ] && {
        while true; do
            wget -c http://{{ .BootstrapIP }}:{{ .BootstrapPort }}/dcos_install.sh
            [ $? -eq 0 ] && break
            echo "Trying again to download dcos_install.sh from Bootstrap server..."
        done
    }
    exit 0
}
export -f download_dcos_install

# Get the dcos binary
download_dcos_binary() {
    while true; do
        wget -q -c -O ~cladm/.local/bin/dcos http://{{ .BootstrapIP }}:{{ .BootstrapPort }}/dcos.bin
        [ $? -eq 0 ] && break
        echo "Trying again to download dcos binary from Bootstrap server..."
    done
    chmod ug+rx ~cladm/.local/bin/dcos
    chown -R cladm:cladm ~cladm
    exit 0
}
export -f download_dcos_binary

# Get the kubectl binary
download_kubectl_binary() {
    while true; do
        wget -q -c -O ~cladm/.local/bin/kubectl http://{{ .BootstrapIP }}:{{ .BootstrapPort }}/kubectl.bin
        [ $? -eq 0 ] && break
        echo "Trying again to download dcos binary from Bootstrap server..."
    done
    chmod ug+rx ~cladm/.local/bin/kubectl
    chown -R cladm:cladm ~cladm
    exit 0
}
export -f download_kubectl_binary

# Get rclone package
download_rclone_package() {
    while true; do
        wget -q -c -O /var/tmp/rclone.rpm http://{{ .BootstrapIP }}:{{ .BootstrapPort }}/rclone.rpm
        [ $? -eq 0 ] && break
        echo "Trying again to download rclone package from Bootstrap server..."
    done
    exit 0
}
export -f download_rclone_package

# bg_start <what> <duration> <command>...
bg_start() {
    local pid=${1}_PID
    local log=${1}.log
    local duration=$2
    shift 2
    timeout $duration /usr/bin/time -p $* &>/var/tmp/$log &
    eval ${pid}=$!
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

# Launch background download tasks
#timeout 10m /usr/bin/time -p bash -c download_safescale_guacamole_image &>/var/tmp/DSGI.log &
#DSGI_PID=$!
bg_start DSGI 10m bash -c download_safescale_guacamole_image
#timeout 10m /usr/bin/time -p bash -c download_dcos_install &>/var/tmp/DDI.log &
#DDI_PID=$!
bg_start DDI 10m bash -c download_dcos_install
#timeout 10m /usr/bin/time -p bash -c download_dcos_binary &>/var/tmp/DDB.log &
#DDB_PID=$!
bg_start DDB 10m bash -c download_dcos_binary
#timeout 10m /usr/bin/time -p bash -c download_kubectl_binary &>/var/tmp/DKB.log &
#DKB_PID=$!
bg_start DKB 10m bash -c download_kubectl_binary
#timeout 10m /usr/bin/time -p bash -c download_rclone_package &>/var/tmp/DRP.log &
#DRP_PID=$!
bg_start DRP 10m bash -c download_rclone_package

# Configure Xvnc parameters
mkdir -p ~cladm/.vnc
cat >~cladm/.vnc/xstartup <<-'EOF'
#!/bin/sh
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
exec startxfce4
EOF

cat >~cladm/.vnc/config <<-'EOF'
screen=0 1600x900x24
desktop={{ .ClusterName }}-dcosmaster-{{ .MasterIndex }}
extension=GLX
noreset
SecurityTypes=None
ZlibLevel=0
EOF
chown -R cladm:cladm ~cladm/.vnc

# Starts Xvnc
systemctl restart vncserver\@:0.service
[ $? -ne 0 ] && exit {{ errcode "DesktopStart" }}

# Launch DCOS installation
echo "Waiting for DCOS Installer download..."
bg_wait DDI {{ errcode "DcosInstallDownload" }}
cd /usr/local/dcos
bash dcos_install.sh master || exit {{ errcode "DcosInstallExecution" }}

# Sets the url of the dcos master
echo "Waiting for DCOS cli download..."
bg_wait DDB {{ errcode "DcosCliDownload" }}
SETUP_MASTER="dcos cluster setup http://localhost"
cat >>~cladm/.profile <<-EOF
# Makes sure dcos is configured correctly
$SETUP_MASTER &>/dev/null
EOF
chown -R cladm:cladm ~cladm
sudo -u cladm -i $SETUP_MASTER

# Starts containers for RemoteDesktop
echo "Waiting for Guacamole Image download..."
bg_wait DSGI {{ errcode "GuacamoleImageDownload" }}
cat >/var/tmp/user-mapping.xml <<-'EOF'
<user-mapping>
    <authorize username="cladm" password="{{ .CladmPassword }}">

        <!-- First authorized connection -->
        <connection name="master-{{ .MasterIndex }}">
            <protocol>vnc</protocol>
            <param name="hostname">{{ .Host }}</param>
            <param name="port">5900</param>
            <param name="enable-sftp">true</param>
            <param name="sftp-username">cladm</param>
            <param name="sftp-password">{{ .CladmPassword }}</param>
            <param name="sftp-directory">/home/cladm/Desktop</param>
            <param name="sftp-root-directory">/home/cladm</param>
            <param name="sftp-server-alive-interval">60</param>
            <param name="color-depth">16</param>
        </connection>
    </authorize>
</user-mapping>
EOF

cat >/var/tmp/Dockerfile.guacamole <<-'EOF'
FROM guacamole:latest
ADD user-mapping.xml /root/.guacamole/
EOF
GUACAMOLE_TAG=master-{{ .MasterIndex }}
docker build -f /var/tmp/Dockerfile.guacamole -t guacamole:$GUACAMOLE_TAG /var/tmp
rm -f /var/tmp/Dockerfile.guacamole /var/tmp/user-mapping.xml
docker run -d --restart always -p 9080:8080 -p 4822:4822 --name guacamole guacamole:$GUACAMOLE_TAG >/dev/null || exit {{ errcode "DockerProxyStart" }}

# Install rclone
echo "Waiting for Rclone download..."
bg_wait DRP {{ errcode "RCloneDownload" }}
rpm -U /var/tmp/rclone.rpm || exit {{ errcode "RcloneInstall" }}
rm -f /var/tmp/rclone.rpm

# awaits the end of the download of kubectl binary
echo "Waiting for kubectl download..."
bg_wait DKB {{ errcode "KubectlDownload" }}

echo
echo "Master configured successfully."
exit 0