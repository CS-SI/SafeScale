#!/bin/bash

#Check if hardware acceleration is available
#egrep '^flags.*(vmx|svm)' /proc/cpuinfo

MACVLN="safescalemacvlan0"

LINUX_KIND=$(cat /etc/os-release | grep "^ID=" | cut -d= -f2 | sed 's/"//g')
case $LINUX_KIND in
	#only linux 16.04 has been tested
    debian|ubuntu)
        sudo apt install -y qemu-kvm libvirt-bin virtinst libvirt-dev libguestfs-tools
		;;
    redhat|centos)
        sudo yum install -y qemu-kvm libvirt-bin virtinst libvirt-dev libguestfs-tools
        ;;
    *)
        echo "Unsupported Linux distribution '$LINUX_KIND'!"
        exit 1
        ;;
esac

# Add the user to the right groups to create & manage VMs without sudo privileges
USER=$(whoami)
sudo usermod -a -G libvirtd $USER
sudo usermod -a -G kvm $USER
newgrp

# Launch object storage (here a minio S3 storage with docker)
sudo docker run -d -p 9000:9000 --name minio1 -e "MINIO_ACCESS_KEY=acsKey" -e "MINIO_SECRET_KEY=secretKey" -v /home/gpac/data:/data -v /mnt/config:/root/.minio minio/minio server /data

# Create a macvlan interface
HWLINK=$(ip -o route | grep default | awk '{{print $5}}')
IP=$(ip address show dev $HWLINK | grep "inet " | awk '{print $2}')
NETWORK=$(ip -o route | grep $HWLINK | grep $IP | awk '{print $1}')
GATEWAY=$(ip -o route | grep default | awk '{print $3}')
 
sudo ip link add link $HWLINK $MACVLN type macvlan mode bridge
sudo ip address add $IP dev $MACVLN
sudo ip link set dev $MACVLN up
 
sudo ip route flush dev $HWLINK
sudo ip route flush dev $MACVLN
 
sudo ip route add $NETWORK dev $MACVLN metric 0
sudo ip route add default via $GATEWAY

# Add read rights to the kernel executable to allow virt-sysprep to works well without admin privileges
sudo chmod 744 /boot/vmlinuz/`uname -r` 