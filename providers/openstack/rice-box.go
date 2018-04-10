package openstack

import (
	"github.com/GeertJohan/go.rice/embedded"
	"time"
)

func init() {

	// define files
	file2 := &embedded.EmbeddedFile{
		Filename:    "userdata.sh",
		FileModTime: time.Unix(1523285795, 0),
		Content:     string("#!/bin/bash\n\nadduser {{.User}} -gecos \"\" --disabled-password\necho \"{{.User}} ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers\n\nmkdir /home/{{.User}}/.ssh\necho \"{{.Key}}\" > /home/{{.User}}/.ssh/authorized_keys\n\n# Create flag file to deactivate Welcome message on ssh\ntouch /home/{{.User}}/.hushlogin\n\necho \"{{.ConfIF}}\"\n\n# Network interfaces configuration\n{{ if .ConfIF }}\nrm -f /etc/network/interfaces.d/50-cloud-init.cfg\nmkdir -p /etc/network/interfaces.d\n# Configure all network interfaces in dhcp\nfor IF in $(ls /sys/class/net)\ndo\n   if [ $IF != \"lo\" ]\n   then\n        echo \"auto ${IF}\" >> /etc/network/interfaces.d/50-cloud-init.cfg\n        echo \"iface ${IF} inet dhcp\" >> /etc/network/interfaces.d/50-cloud-init.cfg\n   fi\ndone\n\nsystemctl restart networking\n# Restart networkk interfaces except lo\n# for IF in $(ls /sys/class/net)\n# do\n#     if [ $IF != \"lo\" ]\n#     then\n#         IF_UP = $(ip a |grep ${IF} | grep 'state UP' | wc -l)\n#         if [ ${IF_UP} = \"1\" ]\n#         then\n#             ifconfig ${IF} down\n#         fi\n#         ifconfig ${IF} up\n#     fi\n# done\n{{ end }}\n\n\n\n# Acitvates IP forwarding\n{{ if .IsGateway }}\n\nPUBLIC_IP=$(curl ipinfo.io/ip)\nPUBLIC_IF=$(netstat -ie | grep -B1 ${PUBLIC_IP} | head -n1 | awk '{print $1}')\n\nPRIVATE_IP=''\nfor IF in $(ls /sys/class/net)\ndo\n   if [ ${IF} != \"lo\" ] && [ ${IF} != ${PUBLIC_IF} ]\n   then\n        PRIVATE_IP=$(ip a |grep ${IF} | grep inet | awk '{print $2}' | cut -d '/' -f1)\n   fi\ndone\n\nif [ -z ${PRIVATE_IP} ]\nthen\n    exit 1\nfi\nPRIVATE_IF=$(netstat -ie | grep -B1 ${PRIVATE_IP} | head -n1 | awk '{print $1}')\n\nif [ ! -z $PUBLIC_IF ] && [ ! -z $PRIVATE_IF ]\nthen\nsed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf\nsysctl -p /etc/sysctl.conf\n\ncat <<- EOF > /sbin/routing\n#!/bin/sh -\necho \"activate routing\"\niptables -t nat -A POSTROUTING -o ${PUBLIC_IF} -j MASQUERADE\niptables -A FORWARD -i ${PRIVATE_IF} -o ${PUBLIC_IF} -j ACCEPT\niptables -A FORWARD -i ${PUBLIC_IF} -o ${PRIVATE_IF} -m state --state RELATED,ESTABLISHED -j ACCEPT\nEOF\nchmod u+x /sbin/routing\ncat <<- EOF > /etc/systemd/system/routing.service\n[Unit]\nDescription=activate routing from ${PRIVATE_IF} to ${PUBLIC_IF}\nAfter=network.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/sbin/routing\n\n[Install]\nWantedBy=multi-user.target\nEOF\n\nsystemctl enable routing\nsystemctl start routing\nfi\n\n{{ end }}\n\n# Acitvates IP forwarding\n{{ if .AddGateway }}\necho \"AddGateway\"\n\nGW=$(ip route show | grep default | cut -d ' ' -f3)\nif [ -z $GW ]\nthen\n\ncat <<-EOF > /etc/resolv.conf.gw\n{{.ResolveConf}}\nEOF\n\ncat <<- EOF > /sbin/gateway\n#!/bin/sh -\necho \"configure default gateway\"\n/sbin/route add default gw {{.GatewayIP}}\ncp /etc/resolv.conf.gw /etc/resolv.conf\nEOF\nchmod u+x /sbin/gateway\ncat <<- EOF > /etc/systemd/system/gateway.service\nDescription=create default gateway\nAfter=network.target\n\n[Service]\nExecStart=/sbin/gateway\n\n[Install]\nWantedBy=multi-user.target\nEOF\n\nsystemctl enable gateway\nsystemctl start gateway\n\nfi\n\n{{ end }}\n"),
	}

	// define dirs
	dir1 := &embedded.EmbeddedDir{
		Filename:   "",
		DirModTime: time.Unix(1520929015, 0),
		ChildFiles: []*embedded.EmbeddedFile{
			file2, // "userdata.sh"

		},
	}

	// link ChildDirs
	dir1.ChildDirs = []*embedded.EmbeddedDir{}

	// register embeddedBox
	embedded.RegisterEmbeddedBox(`scripts`, &embedded.EmbeddedBox{
		Name: `scripts`,
		Time: time.Unix(1520929015, 0),
		Dirs: map[string]*embedded.EmbeddedDir{
			"": dir1,
		},
		Files: map[string]*embedded.EmbeddedFile{
			"userdata.sh": file2,
		},
	})
}
