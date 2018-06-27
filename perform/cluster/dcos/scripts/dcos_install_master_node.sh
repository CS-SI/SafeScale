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

# Redirects outputs to /var/tmp/install_master_node.log
exec 1<&-
exec 2<&-
exec 1<>/var/tmp/install_master_node.log
exec 2>&1

# Installs and configures everything needed on any node
{{ .IncludeInstallCommons }}

download_safescale_guacamole_image() {
    [ ! $(docker image ls | grep guacamole) ] && {
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
    }
    exit 0
}

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

# Get the dcos binary
download_dcos_binary() {
    [ ! -f ~cladm/.local/bin/dcos ] && {
        while true; do
            wget -q -c -O ~cladm/.local/bin/dcos http://{{ .BootstrapIP }}:{{ .BootstrapPort }}/dcos.bin
            [ $? -eq 0 ] && break
            echo "Trying again to download dcos binary from Bootstrap server..."
        done
    }
    chmod ug+rx ~cladm/.local/bin/dcos
    chown -R cladm:cladm ~cladm
    exit 0
}

# Get the kubectl binary
download_kubectl_binary() {
    [ ! -f ~cladm/.local/bin/kubectl ] && {
        while true; do
            wget -q -c -O ~cladm/.local/bin/kubectl http://{{ .BootstrapIP }}:{{ .BootstrapPort }}/kubectl.bin
            [ $? -eq 0 ] && break
            echo "Trying again to download dcos binary from Bootstrap server..."
        done
    }
    chmod ug+rx ~cladm/.local/bin/kubectl
    chown -R cladm:cladm ~cladm
    exit 0
}

# Launch backgroud download tasks
export -f download_safescale_guacamole_image download_dcos_install download_dcos_binary
timeout 10m bash -c download_safescale_guacamole_image &>/var/tmp/DSGI.log &
DSGI_PID=$!
timeout 10m bash -c download_dcos_install &>/var/tmp/DDI.log &
DDI_PID=$!
timeout 10m bash -c download_dcos_binary &>/var/tmp/DDB.log &
DDB_PID=$!
timeout 10m bash -c download_kubectl_binary &>/var/tmp/DKB.log &
DKB_PID=$!

# Installs and configure graphical environment
yum groupinstall -y Xfce
yum install -y tigervnc-server xorg-x11-fonts-Type1 firefox
cp -s /lib/systemd/system/vncserver\@.service /etc/systemd/system/vncserver\@:0.service
sed -i -e "s/<USER>/cladm/g" /etc/systemd/system/vncserver\@:0.service
mkdir -p ~cladm/.vnc
cat >~cladm/.vnc/config <<-'EOF'
screen=0 1600x900x24
desktop={{ .ClusterName }}-dcosmaster-{{ .MasterIndex }}
extension=GLX
noreset
SecurityTypes=None
ZlibLevel=0
EOF
cat >~cladm/.vnc/xstartup <<-'EOF'
#!/bin/sh
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
exec startxfce4
EOF

chown -R cladm:cladm ~cladm/.vnc
systemctl daemon-reload
systemctl enable vncserver\@:0.service
systemctl start vncserver\@:0.service

# Launch installation
wait $DDI_PID
retcode=$?
[ $retcode -ne 0 ] && {
    cat /var/tmp/DDI.log
    exit $retcode
}
cd /usr/local/dcos
bash dcos_install.sh master || {
    retcode=$?
    echo "Failed to install DCOS on master"
    exit $retcode
}

# Sets the url of the dcos master
wait $DDB_PID
retcode=$?
[ $retcode -ne 0 ] && {
    cat /var/tmp/DDB.log
    exit $retcode
}
sudo -u cladm -i dcos cluster setup http://localhost

# Starts containers for RemoteDesktop
wait $DSGI_PID
retcode=$?
[ $retcode -ne 0 ] && {
    cat /var/tmp/DSGI.log
    exit $retcode
}
curl -sS -L -q -o dcos-master.yml http://{{ .BootstrapIP }}:{{ .BootstrapPort }}/docker/dcos-master.yml || {
    retcode=$?
    echo "Failed to download dcos-master.yml from Bootstrap server"
    exit $retcode
}
/usr/local/bin/docker-compose -f /usr/local/dcos/dcos-master.yml up -d || {
    retcode=$?
    echo "Failed to start standalone docker containers"
    exit $retcode
}

# awaits the end of the download of kubectl binary
wait $DKB_PID
retcode=$?
[ $retcode -ne 0 ] && {
    cat /var/tmp/DKB.log
    exit $retcode
}

exit 0