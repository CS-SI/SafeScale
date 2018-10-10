 #!/bin/bash

broker tenant set $1

echo "Create network and front node ..."
#the front node is also the network gateway
broker network create cluster-net --cidr 192.168.2.0/24 --gwname cluster-front --cpu 8 --ram 30 --os "Ubuntu 16.04"

#get front node ip
front_ip=$(broker host inspect cluster-front | jq -r .PRIVATE_IP)
#get front node public key
front_public_key=$(echo "cat .ssh/authorized_keys" | broker ssh connect cluster-front)


echo "Create cluster nodes in parallel..."
node_ips=$(mktemp)

for num in {1..4} 
do
    (\
    #create a node and get node private ip
    node_ip=$(broker host create cluster-node-${num} --net cluster-net --cpu 16 --ram 60 --os "Ubuntu 16.04" | jq -r .PRIVATE_IP) && \
    echo "${node_ip} cluster-node-${num}" >> $node_ips\
    )&
done
wait

hosts=$(cat $node_ips)
host_names=$(cut -d' ' -f2 $node_ips)
rm $node_ips

echo "Configure nodes ..."
for num in {1..4} 
do
    #add front public key to node authorized keys list and install python2
    (echo "printf '${front_public_key}\n' >> .ssh/authorized_keys && sudo sh -c 'apt install -y python > /dev/null 2>&1'" | broker ssh connect cluster-node-${num})&
done
wait
echo "Configure front"
#add nodes to front /etc/hosts
#install and configure ansible
#create ansible inventory
#test ansible
cat<<-EOT| broker ssh connect cluster-front
    sudo -s
    printf "${hosts}\n" >> /etc/hosts
    apt install -y ansible > /dev/null 2>&1
    sed -i 's/#host_key_checking = False/host_key_checking = False/g' /etc/ansible/ansible.cfg
    printf "${host_names}\n" >> /etc/ansible/hosts
    exit
    ansible all -m ping
EOT
