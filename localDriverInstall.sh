#!/bin/bash

#Check if hardware acceleration is available
#egrep '^flags.*(vmx|svm)' /proc/cpuinfo

MINIO_ACCESS_KEY="accessKey"
MINIO_SECRET_KEY="secretKey"

LINUX_KIND=$(cat /etc/os-release | grep "^ID=" | cut -d= -f2 | sed 's/"//g')
case $LINUX_KIND in
    ubuntu)
    #ubuntu 18.04 
        # need universe repository (for virtinst & libguestfs-tools)
        sudo add-apt-repository universe
        sudo apt install -y qemu-kvm libvirt-bin libvirt-dev virtinst libguestfs-tools
		;;
    debian) 
    #debian 9
        sudo apt install -y pkg-config dnsmasq ebtables
        # need testing repository 
        sudo apt install -y qemu-kvm libvirt-dev libvirt-clients libvirt-daemon-system virtinst libguestfs-tools
        ;;

    centos)
    #centos 7
        #!! e2fsck is outdated (1.42) and will block with some images (ubuntu 18.04), e2fsck v=1.44 needed
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
sudo su $USER

# Add read rights to the kernel executable to allow virt-sysprep to works well without admin privileges
sudo chmod 744 /boot/vmlinuz/`uname -r` || sudo chmod 744 /boot/vmlinuz-`uname -r`

# Launch object storage (here a minio S3 storage with docker)
sudo docker run -d -p 9000:9000 --name minio1 -e "MINIO_ACCESS_KEY=$MINIO_ACCESS_KEY" -e "MINIO_SECRET_KEY=$MINIO_SECRET_KEY" -v /home/gpac/data:/data -v /mnt/config:/root/.minio minio/minio server /data



 

 

 
