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

{{ .reserved_BashLibrary }}

###############################################
### Defining functions used asynchroniously ###
###############################################

# Download Guacamole docker image from Bootstrap server
#download_safescale_guacamole_image() {
#    while true; do
#        while true; do
#            wget -q -O /var/tmp/guacamole.tar.gz http://{{ .BootstrapIP }}:{{ .BootstrapPort }}/docker/guacamole.tar.gz
#            [ $? -eq 0 ] && break
#            echo "Trying again to download guacamole docker image..."
#        done
#        docker image load -i /var/tmp/guacamole.tar.gz
#        [ $? -eq 0 ] && break
#        echo "Trying again to download guacamole docker image..."
#    done
#    rm -f /var/tmp/guacamole.tar.gz
#    exit 0
#}
#export -f download_safescale_guacamole_image

# Get install script from Bootstrap server
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

# Get the dcos binary from Bootstrap server
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

# Get the kubectl binary from Bootstrap server
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

# Installs and configure graphical environment on Master server
#install_desktop() {
#    yum groupinstall -y -t Xfce && \
#    yum install -y -t tigervnc-server xorg-x11-fonts-Type1 firefox && \
#    cp -s /lib/systemd/system/vncserver\@.service /etc/systemd/system/vncserver\@:0.service && \
#    sed -i -e "s/<USER>/cladm/g" /etc/systemd/system/vncserver\@:0.service && \
#    systemctl daemon-reload && \
#    systemctl enable vncserver\@:0.service
#    [ $? -ne 0 ] && exit {{ errcode "DesktopInstall" }}
#
#    # Configure Xvnc parameters
#    mkdir -p ~cladm/.vnc
#    cat >~cladm/.vnc/xstartup <<-'EOF'
##!/bin/sh
#unset SESSION_MANAGER
#unset DBUS_SESSION_BUS_ADDRESS
#export DISPLAY=:0
#exec startxfce4
#EOF
#    chmod u+rx ~cladm/.vnc/xstartup
#
#    cat >~cladm/.vnc/config <<-'EOF'
#screen=0 1600x900x24
#geometry=1600x900
#desktop={{ .ClusterName }}-master-{{ .MasterIndex }}
#passwordfile=
#extension=GLX
#noreset
#SecurityTypes=None
#ZlibLevel=0
#EOF
#    chown -R cladm:cladm ~cladm/.vnc
#
#    systemctl restart vncserver\@:0.service
#    [ $? -ne 0 ] && exit {{ errcode "DesktopStart" }}
#}
#export -f install_desktop

########################################
### Launch background download tasks ###
########################################

#bg_start ID 10m bash -c install_desktop
#bg_start DSGI 10m bash -c download_safescale_guacamole_image
bg_start DDI 10m bash -c download_dcos_install
bg_start DDB 10m bash -c download_dcos_binary
bg_start DKB 10m bash -c download_kubectl_binary

#########################
### DCOS installation ###
#########################

echo "Waiting for DCOS Installer download..."
bg_wait DDI {{ errcode "DcosInstallDownload" }}

# Launch DCOS installation
cd /usr/local/dcos
bash dcos_install.sh master || exit {{ errcode "DcosInstallExecution" }}

# Sets the url of the dcos master
echo "Waiting for DCOS cli download..."
bg_wait DDB {{ errcode "DcosCliDownload" }}
cat >>~cladm/.bashrc <<-EOF

# Makes sure dcos is configured correctly
dcos cluster setup http://localhost &>/dev/null
EOF
chown -R cladm:cladm ~cladm

###################################
### Install Desktop environment ###
###################################

#install_desktop

##########################################################
### Guacamole docker container configuration and start ###
##########################################################



#echo "Waiting for Guacamole Image download..."
#bg_wait DSGI {{ errcode "GuacamoleImageDownload" }}
#
## Configuring guacamole image
#cat >/var/tmp/user-mapping.xml <<-'EOF'
#<user-mapping>
#    <authorize username="cladm" password="{{ .CladmPassword }}">
#        <connection name="master-{{ .MasterIndex }}">
#            <protocol>vnc</protocol>
#            <param name="hostname">{{ .Host }}</param>
#            <param name="port">5900</param>
#            <param name="enable-sftp">true</param>
#            <param name="sftp-username">cladm</param>
#            <param name="sftp-password">{{ .CladmPassword }}</param>
#            <param name="sftp-directory">/home/cladm/Desktop</param>
#            <param name="sftp-root-directory">/home/cladm</param>
#            <param name="sftp-server-alive-interval">60</param>
#            <param name="color-depth">16</param>
#        </connection>
#    </authorize>
#</user-mapping>
#EOF
#cat >/var/tmp/Dockerfile.guacamole <<-'EOF'
#FROM guacamole:latest
#ADD user-mapping.xml /root/.guacamole/
#EOF
#docker build -f /var/tmp/Dockerfile.guacamole -t guacamole:master-{{ .MasterIndex }} /var/tmp
#rm -f /var/tmp/Dockerfile.guacamole /var/tmp/user-mapping.xml
#
## guacd need sshd to authorize password authentication...
#cat >>/etc/ssh/sshd_config <<-'EOF'
# Allow Password Authentication from docker default bridge network, for guacd to work
#Match address 172.17.0.0/16
#    PasswordAuthentication yes
#EOF
#systemctl reload sshd
#
## Starting Guacamole container
#docker run -d \
#           --restart always \
#           -p 9080:8080 -p 4822:4822 \
#           --hostname guacamole --name guacamole \
#           guacamole:master-{{ .MasterIndex }} >/dev/null || exit {{ errcode "DockerProxyStart" }}

########################################################
### awaits the end of the download of kubectl binary ###
########################################################

echo "Waiting for kubectl download..."
bg_wait DKB {{ errcode "KubectlDownload" }}

### Done
echo
echo "Master configured successfully."
exit 0