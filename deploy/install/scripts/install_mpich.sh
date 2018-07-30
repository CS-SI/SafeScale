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
# Installs MPICH v3.2.1 on host

rm -f /var/tmp/install_mpich.log
exec 1<&-
exec 2<&-
exec 1<>/var/tmp/install_mpich.log
exec 2>&1

{{ .CommonTools }}

# Install requirements to compile
case $LINUX_KIND in
    redhat|centos)
        yum makecache fast
        yum groupinstall -y "Development Tools"
        ;;
    debian|ubuntu)
        apt update
        apt install -y build-essential
        ;;
    *)
        exit {{ errcode "UnsupportedDistribution" }}
        ;;
esac

# Download MPICH
cd /var/tmp
wget http://www.mpich.org/static/downloads/3.2.1/mpich-3.2.1.tar.gz || exit {{ errcode "MPICHDownload" }}

# Extract and compile
tar -zxvf mpich-3.2.1.tar.gz
cd mpich-3.2.1
./configure --disable-fortran
make || exit {{ errcode "MPICHCompile" }}

# Install MPICH
make install || exit {{ errcode "MPICHInstall" }}

rm -rf mpich-3.2.1*
exit 0