#!/bin/bash

#Check if hardware acceleration is available
#egrep '^flags.*(vmx|svm)' /proc/cpuinfo

LINUX_KIND=$(cat /etc/os-release | grep "^ID=" | cut -d= -f2 | sed 's/"//g')
case $LINUX_KIND in
    debian|ubuntu)
        #linux 16.04/18.04 (need universe repository for virtinst & libguestfs-tools)
        sudo add-apt-repository universe
        sudo apt install -y qemu-kvm libvirt-bin libvirt-dev virtinst libguestfs-tools
		;;

    redhat|centos)
    #centos 7
        sudo yum install -y qemu-kvm libvirt virt-install libvirt-devel libguestfs-tools
        sudo systemctl enable libvirtd
        sudo systemctl start libvirtd
        #only for bridged vms
        #sudo firewall-cmd --zone=public --permanent --add-port=1000-63553/tcp
        #sudo firewall-cmd --reload
        ;;

    *)
        echo "Unsupported Linux distribution '$LINUX_KIND'!"
        exit 1
        ;;
esac

# Add the user to the right groups to create & manage VMs without sudo privileges
USER=$(whoami)
sudo usermod -a -G libvirtd $USER || sudo usermod -a -G libvirt $USER
sudo usermod -a -G kvm $USER
# Enable the new groups
# TODO stay in the same shell 
sudo su $USER

# Add read rights to the kernel executable to allow virt-sysprep to works well without admin privileges
sudo chmod 744 /boot/vmlinuz/`uname -r` || sudo chmod 744 /boot/vmlinuz-`uname -r`

# Launch object storage (here a minio S3 storage with docker)
sudo docker run -d -p 9000:9000 --name minio1 -e "MINIO_ACCESS_KEY=accessKey" -e "MINIO_SECRET_KEY=secretKey" -v /home/gpac/data:/data -v /mnt/config:/root/.minio minio/minio server /data



 

 

 
