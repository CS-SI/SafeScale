#!/bin/bash
#
# Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

{{.Header}}

print_error() {
	read line file <<<$(caller)
	echo "An error occurred in line $line of file $file:" "{"`sed "${line}q;d" "$file"`"}" >&2
}
trap print_error ERR

fail() {
	echo -n "$1,${LINUX_KIND},$(date +%Y/%m/%d-%H:%M:%S)" >/opt/safescale/var/state/user_data.phase2.done
	# For compatibility with previous user_data implementation (until v19.03.x)...
	ln -s /opt/safescale/var/state/user_data.phase2.done /var/tmp/user_data.done
	exit $1
}

# Redirects outputs to /opt/safescale/log/user_data.phase2.log
exec 1<&-
exec 2<&-
exec 1<>/opt/safescale/var/log/user_data.phase2.log
exec 2>&1
set -x

# Tricks BashLibrary's waitUserData to believe the current phase (2) is already done
>/opt/safescale/var/state/user_data.phase2.done
# Includes the BashLibrary
{{ .BashLibrary }}

reset_fw() {
	case $LINUX_KIND in
		debian|ubuntu)
			sfWaitForApt && apt update &>/dev/null
			sfWaitForApt && {
				apt install -qy firewalld || fail 192
			}
			systemctl stop ufw
			systemctl start firewalld || fail 193
			systemctl disable ufw
			systemctl enable firewalld
			sfWaitForApt && {
				apt purge -qy ufw &>/dev/null || fail 194
			}
			;;

		rhel|centos)
			;;
	esac

	# Clear interfaces attached to zones
	for zone in $(firewall-cmd --get-active-zones | grep -v interfaces | grep -v sources); do
		for nic in $(firewall-cmd --zone=$zone --list-interfaces); do
			firewall-cmd --zone=trusted --remove-interface=$nic
		done
	done
	# Attach inteface lo to zone trusted
	firewall-cmd --zone=trusted --add-interface=lo
	# Attach Internet interface or source IP to zone public
	[ ! -z $PU_IF ] && {
		firewall-cmd --zone=public --add-interface=$PU_IF
	} || {
		firewall-cmd --zone=public --add-source=${PU_IP}/32
	}
	# Attach LAN interfaces to zone trusted
	[ ! -z $PR_IFs ] && {
		for i in $PR_IFs; do
			firewall-cmd --zone=trusted --add-interface=$PR_IFs
		done
	}
	# Attach lo interface to zone trusted
	firewall-cmd --zone=trusted --add-interface=lo
	# Allow service ssh
	firewall-cmd --add-service=ssh
	# Sets default zone to trusted
	firewall-cmd --set-default-zone=trusted
	# Save current fw settings as permanent
	firewall-cmd --runtime-to-permanent
}

NICS=
# PR_IPs=
PR_IFs=
PU_IP=
PU_IF=
i_PR_IF=
o_PR_IF=

# Don't request dns name servers from DHCP server
# Don't update default route
configure_dhclient() {
	sed -i -e 's/, domain-name-servers//g' /etc/dhcp/dhclient.conf

	HOOK_FILE=/etc/dhcp/dhclient-enter-hooks
	cat >>$HOOK_FILE <<-EOF
make_resolv_conf() {
	:
}

{{- if not .IsGateway }}
unset new_routers
{{- end}}
EOF
	chmod +x $HOOK_FILE
}

is_ip_private() {
	ip=$1
	ipv=$(sfIP2long $ip)

{{ if .EmulatedPublicNet}}
	r=$(sfCidr2iprange {{ .EmulatedPublicNet }})
	bv=$(sfIP2long $(cut -d- -f1 <<<$r))
	ev=$(sfIP2long $(cut -d- -f2 <<<$r))
	[ $ipv -ge $bv -a $ipv -le $ev ] && return 0
{{- end }}
	for r in "192.168.0.0-192.168.255.255" "172.16.0.0-172.31.255.255" "10.0.0.0-10.255.255.255"; do
		bv=$(sfIP2long $(cut -d- -f1 <<<$r))
		ev=$(sfIP2long $(cut -d- -f2 <<<$r))
		[ $ipv -ge $bv -a $ipv -le $ev ] && return 0
	done
	return 1
}

identify_nics() {
	NICS=$(for i in $(find /sys/devices -name net -print | grep -v virtual); do ls $i; done)
	NICS=${NICS/[[:cntrl:]]/ }

	for IF in $NICS; do
		IP=$(ip a | grep $IF | grep inet | awk '{print $2}' | cut -d '/' -f1)
		[ ! -z $IP ] && is_ip_private $IP && PR_IFs="$PR_IFs $IF"
	done
	PR_IFs=$(echo $PR_IFs | xargs)
	PU_IF=$(ip route get 8.8.8.8 | awk -F"dev " 'NR==1{split($2,a," ");print a[1]}' 2>/dev/null)
	PU_IP=$(ip a | grep $PU_IF | grep inet | awk '{print $2}' | cut -d '/' -f1)
	[ ! -z $PU_IP ] && is_ip_private $PU_IP && PU_IF= && PU_IP=
	[ -z $PR_IFs ] && PR_IFs=$(substring_diff "$NICS" "$PU_IF")

	echo "NICS identified: $NICS"
	echo "    private NIC(s): $PR_IFs"
	echo "    public NIC: $PU_IF"
	echo
}

substring_diff() {
	read -a l1 <<<$1
	read -a l2 <<<$2
	echo ${l1[@]} ${l2[@]} | tr ' ' '\n' | sort | uniq -u
}

# Configure network for Debian distribution
configure_network_debian() {
	echo "Configuring network (debian-like)..."

{{- if .AddGateway }}
	# Needs to configure quickly gateway on private hosts to be able to update packages
	route del -net default &>/dev/null
	route add -net default gw {{ .GatewayIP }}
{{- end}}

	reset_fw

	local path=/etc/network/interfaces.d
	mkdir -p $path
	local cfg=$path/50-cloud-init.cfg
	rm -f $cfg

	for IF in $NICS; do
		if [ "$IF" = "$PU_IF" ]; then
			cat <<-EOF >$path/10-$IF-public.cfg
auto ${IF}
iface ${IF} inet dhcp
EOF
		else
			cat <<-EOF >$path/11-$IF-private.cfg
auto ${IF}
iface ${IF} inet dhcp
{{- if .AddGateway }}
  up route add -net default gw {{ .GatewayIP }} || true
{{- end}}
EOF
		fi
	done

	configure_dhclient

	/sbin/dhclient || true
	systemctl restart networking

	echo done
}

# Configure network using systemd-networkd
configure_network_systemd_networkd() {
	echo "Configuring network (using netplan and systemd-networkd)..."

	mkdir -p /etc/netplan
	rm -f /etc/netplan/*

{{- if .AddGateway }}
	# Needs to configure quickly gateway to be able to update packages
	route del -net default &>/dev/null
	route add -net default gw {{ .GatewayIP }}
{{- end}}

	# Update netplan to last available release
	case $LINUX_KIND in
		debian)
			sfWaitForApt && {
				apt update && apt install -qy netplan.io || fail 195
			};;
		ubuntu)
			echo "deb http://archive.ubuntu.com/ubuntu/ bionic-proposed main" >/etc/apt/sources.list.d/bionic-proposed.list
			sfWaitForApt && {
				apt update && apt install -qy netplan.io || fail 196
			}
			;;
		redhat|centos)
			yum install -y netplan.io || fail 197
			;;
		*)
			echo "unsupported Linux distribution '$LINUX_KIND'"
			fail 199
			;;
	esac

	reset_fw

	# Recreate netplan configuration with last netplan version and more settings
	for IF in $NICS; do
		if [ "$IF" = "$PU_IF" ]; then
			cat <<-EOF >/etc/netplan/10-$IF-public.yaml
network:
  version: 2
  renderer: networkd

  ethernets:
    $IF:
      dhcp4: true
      dhcp6: false
      critical: true
      dhcp4-overrides:
          use-dns: false
          use-routes: true
EOF
		else
			cat <<-EOF >/etc/netplan/11-$IF-private.yaml
network:
  version: 2
  renderer: networkd

  ethernets:
    $IF:
      dhcp4: true
      dhcp6: false
      critical: true
      dhcp4-overrides:
        use-dns: false
        use-routes: false
{{- if .AddGateway }}
      routes:
      - to: 0.0.0.0/0
        via: {{ .GatewayIP }}
        scope: global
        on-link: true
{{- end}}
EOF
		fi
	done
	netplan generate && netplan apply || fail 198

	configure_dhclient

	systemctl restart systemd-networkd

	echo done
}

# Configure network for redhat7-like distributions (rhel, centos, ...)
configure_network_redhat() {
	echo "Configuring network (redhat-like)..."

	if [ -z $VERSION_ID ]; then
		disable_svc() {
			chkconfig $1 off
		}
		stop_svc() {
			service $1 stop
		}
		start_svc() {
			service $1 start
		}
	else
		disable_svc() {
			systemctl disable $1
		}
		stop_svc() {
			systemctl stop $1
		}
		start_svc() {
			systemct start $1
		}
	fi

{{- if .AddGateway }}
	# Needs to configure quickly gateway to be able to update packages
	route del -net default &>/dev/null
	route add -net default gw {{ .GatewayIP }}
{{- end}}

	reset_fw

	# We don't want NetworkManager
	disable_svc NetworkManager &>/dev/null
	stop_svc NetworkManager &>/dev/null
	yum remove -y NetworkManager &>/dev/null

	# Configure all network interfaces in dhcp
	for IF in $NICS; do
		if [ $IF != "lo" ]; then
			cat >/etc/sysconfig/network-scripts/ifcfg-$IF <<-EOF
DEVICE=$IF
BOOTPROTO=dhcp
ONBOOT=yes
EOF
			{{- if .DNSServers }}
			i=1
			{{- range .DNSServers }}
			echo "DNS$i={{ . }}" >>/etc/sysconfig/network-scripts/ifcfg-$IF
			i=$((i+1))
			{{- end }}
			{{- else }}
			echo "DNS1=1.1.1.1" >>/etc/sysconfig/network-scripts/ifcfg-$IF
			{{- end }}
		fi
	done

	configure_dhclient

{{- if .AddGateway }}
	echo "GATEWAY={{ .GatewayIP }}" >/etc/sysconfig/network
{{- end }}

	case $VERSION_ID in
		6) start_svc network;;
		7) start_svc systemd-networkd;;
	esac

	echo done
}

check_for_ip() {
	ip=$(ip -f inet -o addr show $1 | cut -d' ' -f7 | cut -d' ' -f1)
	[ -z "$ip" ] && return 1
	return 0
}

# Checks network is set correctly
# - DNS
# - routes
# - IP address on "physical" interfaces
check_for_network() {
	ping -n -c1 -w5 www.google.com || return 1
	[ ! -z "$PU_IF" ] && {
		check_for_ip $PU_IF || return 1
	}
	for i in $PR_IFs; do
		check_for_ip $i || return 1
	done
	return 0
}

configure_as_gateway() {
	echo "Configuring host as gateway..."

	if [ ! -z $PR_IFs ]; then
		# Enable forwarding
		for i in /etc/sysctl.d/* /etc/sysctl.conf; do
			grep -v "net.ipv4.ip_forward=" $i >${i}.new
			mv -f ${i}.new ${i}
		done
		echo "net.ipv4.ip_forward=1" >/etc/sysctl.d/98-forward.conf
		systemctl restart systemd-sysctl
	fi

	[ ! -z $PU_IF ] && {
		# Allow ping
		firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -p icmp -m icmp --icmp-type 8 -s 0.0.0.0/0 -d 0.0.0.0/0 -j ACCEPT
		# Allow masquerading on public zone
		firewall-cmd --zone=public --add-masquerade
		# Save current fw settings as permanent
		firewall-cmd --runtime-to-permanent
	}

	grep -vi AllowTcpForwarding /etc/ssh/sshd_config >/etc/ssh/sshd_config.new
	echo "AllowTcpForwarding yes" >>/etc/ssh/sshd_config.new
	mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config
	systemctl restart ssh

	echo done
}

configure_dns_legacy() {
	echo "Configuring /etc/resolv.conf..."
	rm -f /etc/resolv.conf
	{{- if .DNSServers }}
	if [[ -e /etc/dhcp/dhclient.conf ]]; then echo "prepend domain-name-servers {{range .DNSServers}}{{.}} {{end}};" >> /etc/dhcp/dhclient.conf; else echo "Dhclient.conf not modified"; fi
	{{- else }}
	if [[ -e /etc/dhcp/dhclient.conf ]]; then echo "prepend domain-name-servers 1.1.1.1;" >> /etc/dhcp/dhclient.conf; else echo "Dhclient.conf not modified"; fi
	{{- end }}
	cat <<-'EOF' >/etc/resolv.conf
{{- if .DNSServers }}
  {{- range .DNSServers }}
nameserver {{ . }}
  {{- end }}
{{- else }}
nameserver 1.1.1.1
{{- end }}
EOF
	echo done
}

configure_dns_resolvconf() {
	echo "Configuring resolvconf..."

	cat <<-'EOF' >/etc/resolvconf/resolv.conf.d/head
{{- if .DNSServers }}
  {{- range .DNSServers }}
nameserver {{ . }}
  {{- end }}
{{- else }}
nameserver 1.1.1.1
{{- end }}
EOF

	resolvconf -u
	echo done
}

configure_dns_systemd_resolved() {
	echo "Configuring systemd-resolved..."

{{- if not .AddGateway }}
	rm -f /etc/resolv.conf
	ln -s /run/systemd/resolve/resolv.conf /etc
{{- end }}

	cat <<-'EOF' >/etc/systemd/resolved.conf
[Resolve]
{{- if .DNSServers }}
DNS={{ range .DNSServers }}{{ . }} {{ end }}
{{- else }}
DNS=1.1.1.1
{{- end}}
Cache=yes
DNSStubListener=yes
EOF
	systemctl restart systemd-resolved
	echo done
}

install_drivers_nvidia() {
	case $LINUX_KIND in
		ubuntu)
			sfFinishPreviousInstall
			add-apt-repository -y ppa:graphics-drivers &>/dev/null
			sfApt update &>/dev/null
			sfApt -y install nvidia-410 &>/dev/null || {
				sfApt -y install nvidia-driver-410 &>/dev/null || fail 199
			}
			;;

		debian)
			if [ ! -f /etc/modprobe.d/blacklist-nouveau.conf ]; then
				echo -e "blacklist nouveau\nblacklist lbm-nouveau\noptions nouveau modeset=0\nalias nouveau off\nalias lbm-nouveau off" >>/etc/modprobe.d/blacklist-nouveau.conf
				rmmod nouveau
			fi
			sfWaitForApt && apt update &>/dev/null
			sfWaitForApt && apt install -y dkms build-essential linux-headers-$(uname -r) gcc make &>/dev/null || fail 200
			dpkg --add-architecture i386 &>/dev/null
			sfWaitForApt && apt update &>/dev/null
			sfWaitForApt && apt install -y lib32z1 lib32ncurses5 &>/dev/null || fail 201
			wget http://us.download.nvidia.com/XFree86/Linux-x86_64/410.78/NVIDIA-Linux-x86_64-410.78.run &>/dev/null || fail 202
			bash NVIDIA-Linux-x86_64-410.78.run -s || fail 205
			;;

		redhat|centos)
			if [ ! -f /etc/modprobe.d/blacklist-nouveau.conf ]; then
				echo -e "blacklist nouveau\noptions nouveau modeset=0" >>/etc/modprobe.d/blacklist-nouveau.conf
				dracut --force
				rmmod nouveau
			fi
			yum -y -q install kernel-devel.$(uname -i) kernel-headers.$(uname -i) gcc make &>/dev/null || fail 203
			wget http://us.download.nvidia.com/XFree86/Linux-x86_64/410.78/NVIDIA-Linux-x86_64-410.78.run || fail 204
			bash NVIDIA-Linux-x86_64-410.78.run -s || fail 205
			rm -f NVIDIA-Linux-x86_64-410.78.run
			;;
		*)
			echo "Unsupported Linux distribution '$LINUX_KIND'!"
			fail 206
			;;
	esac
}

install_packages() {
	 case $LINUX_KIND in
		ubuntu|debian)
			sfApt install -y -qq pciutils jq &>/dev/null || fail 207
			;;
		redhat|centos)
			yum install -y -q pciutils wget jq &>/dev/null || fail 208
			;;
		*)
			echo "Unsupported Linux distribution '$LINUX_KIND'!"
			fail 209
			;;
	 esac
}

add_common_repos() {
	case $LINUX_KIND in
		ubuntu)
			sfFinishPreviousInstall
			add-apt-repository universe -y || return 1
			sfApt update &>/dev/null
			;;
	esac
	return 0
}

# ---- Main

export DEBIAN_FRONTEND=noninteractive

export LANGUAGE=en_US.UTF-8 LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8
locale-gen en_US.UTF-8

add_common_repos
identify_nics

case $LINUX_KIND in
	debian|ubuntu)
		# Force update of systemd
		sfApt update && sfApt install -y systemd

		# # Security updates ...
		# sfApt update &>/dev/null && sfApt install -qy unattended-upgrades && unattended-upgrades -v

		# DNS configuration
		systemctl status systemd-resolved &>/dev/null && {
			configure_dns_systemd_resolved
		} || {
			systemctl status resolvconf &>/dev/null && {
				configure_dns_resolvconf
			} || {
				configure_dns_legacy
			}
		}

		# Network configuration for anything that is not Ubuntu 18.04
		# [ "$LINUX_KIND" != "ubuntu" -o "$VERSION_ID" != "1804" ] && {
			systemctl status systemd-networkd &>/dev/null && {
				configure_network_systemd_networkd
			} || {
				systemctl status networking &>/dev/null && {
					configure_network_debian
				} || {
					echo "PROVISIONING_ERROR: failed to determine how to configure network"
					fail 210
				}
			}
		# }
		;;

	redhat|centos)
		# Force update of systemd
		yum install -qy systemd

		# # install security updates
		# yum install -y yum-plugin-security yum-plugin-changelog && yum update -y --security

		# DNS configuration
		systemctl status systemd-resolved &>/dev/null && {
			configure_dns_systemd_resolved
		} || {
			systemctl status resolvconf &>/dev/null && {
				configure_dns_resolvconf
			} || {
				configure_dns_legacy
			}
		}

		# Network configuration
		systemctl status systemd-networkd &>/dev/null && {
			configure_network_systemd_networkd
		} || configure_network_redhat
		;;

	*)
		echo "Unsupported Linux distribution '$LINUX_KIND'!"
		fail 211
		;;
esac

{{- if .IsGateway }}
configure_as_gateway
{{- end }}

check_for_network || {
	echo "PROVISIONING_ERROR: no or incomplete network connectivity"
	fail 212
}

install_packages
lspci | grep -i nvidia &>/dev/null && install_drivers_nvidia

echo -n "0,linux,${LINUX_KIND},$(date +%Y/%m/%d-%H:%M:%S)" >/opt/safescale/var/state/user_data.phase2.done
# For compatibility with previous user_data implementation (until v19.03.x)...
ln -s /opt/safescale/var/state/user_data.phase2.done /var/tmp/user_data.done

# !!! DON'T REMOVE !!! #insert_tag is used to allow to add something just before exiting
#instert_tag

set +x
exit 0
