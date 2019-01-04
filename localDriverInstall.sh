#!/bin/bash

#Check if hardware acceleration is available
#egrep '^flags.*(vmx|svm)' /proc/cpuinfo

LINUX_KIND=$(cat /etc/os-release | grep "^ID=" | cut -d= -f2 | sed 's/"//g')
case $LINUX_KIND in
    debian|ubuntu)
        #linux 16.04/18.04 (need universe repository for virtinst & libguestfs-tools)
        sudo apt install -y qemu-kvm libvirt-bin libvirt-dev virtinst libguestfs-tools
		;;

    redhat|centos)
    #centos 7
        sudo yum install -y qemu-kvm libvirt virt-install libvirt-devel libguestfs-tools
        systemctl enable libvirtd
        systemctl start libvirtd
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

# Create a macvlan interface
# Script creating the macvlan
cat <<-'EOF' > ~/ssmacvlan.sh
#!/bin/bash
MACVLN="ssmacvlan0"
HWLINK=$(ip -o route | grep default | awk '{{print $5}}')
IP=$(ip address show dev $HWLINK | grep "inet " | awk '{print $2}')
NETWORK=$(ip -o route | grep $HWLINK | grep `echo $IP|cut -d/ -f1` | awk '{print $1}')
GATEWAY=$(ip -o route | grep default | awk '{print $3}')

ip link add link $HWLINK $MACVLN type macvlan mode bridge
ip address add $IP dev $MACVLN
ip link set dev $MACVLN up

ip route flush dev $HWLINK
ip route flush dev $MACVLN

ip route add $NETWORK dev $MACVLN metric 0
ip route add default via $GATEWAY
EOF
chmod u+x ~/ssmacvlan.sh
sudo mv ~/ssmacvlan.sh /sbin/

#Launch the scrip on each boot
cat <<-'EOF' > ~/ssmacvlan.service
Description=create safescale macvlan
After=network.target

[Service]
ExecStart=/sbin/ssmacvlan.sh
Restart=on-failure
StartLimitIntervalSec=10

[Install]
WantedBy=multi-user.target
EOF
sudo mv ~/ssmacvlan.service /etc/systemd/system/
sudo systemctl enable ssmacvlan
sudo systemctl start ssmacvlan



 

 

 
