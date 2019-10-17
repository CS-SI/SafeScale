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
  ec=$?
  read line file <<<$(caller)
  echo "An error occurred in line $line of file $file (exit code $ec) :" "{"`sed "${line}q;d" "$file"`"}" >&2
}
trap print_error ERR

fail() {
	echo -n "$1,${LINUX_KIND},$(date +%Y/%m/%d-%H:%M:%S)" >/opt/safescale/var/state/user_data.phase1.done
	exit $1
}

mkdir -p /opt/safescale/etc &>/dev/null
mkdir -p /opt/safescale/var/log &>/dev/null
mkdir -p /opt/safescale/var/run /opt/safescale/var/state /opt/safescale/var/tmp &>/dev/null
chmod -R 0640 /opt/safescale
find /opt/safescale -type d -exec chmod ug+x {} \;

exec 1<&-
exec 2<&-
exec 1<>/opt/safescale/var/log/user_data.phase1.log
exec 2>&1
set -x

LINUX_KIND=
VERSION_ID=

sfDetectFacts() {
	[ -f /etc/os-release ] && {
		. /etc/os-release
		LINUX_KIND=$ID
	} || {
		which lsb_release &>/dev/null && {
			LINUX_KIND=$(lsb_release -is)
			LINUX_KIND=${LINUX_KIND,,}
			VERSION_ID=$(lsb_release -rs | cut -d. -f1)
		} || {
			[ -f /etc/redhat-release ] && {
				LINUX_KIND=$(cat /etc/redhat-release | cut -d' ' -f1)
				LINUX_KIND=${LINUX_KIND,,}
				VERSION_ID=$(cat /etc/redhat-release | cut -d' ' -f3 | cut -d. -f1)
			}
		}
	}
}
sfDetectFacts

sfFinishPreviousInstall() {
	local unfinished=$(dpkg -l | grep -v ii | grep -v rc | tail -n +4 | wc -l)
	if [[ "$unfinished" == 0 ]]; then echo "good"; else sudo dpkg --configure -a --force-all; fi
}
# export -f sfFinishPreviousInstall

sfWaitForApt() {
	sfFinishPreviousInstall || true
	sfWaitLockfile apt /var/{lib/{dpkg,apt/lists},cache/apt/archives}/lock
}

sfWaitLockfile() {
	local ROUNDS=600
	name=$1
	shift
	params="$@"
	echo "check $name lock"
	echo ${params}
	if fuser ${params} &>/dev/null; then
		echo "${name} is locked, waiting... "
		local i
		for i in $(seq $ROUNDS); do
			sleep 6
			fuser ${params} &>/dev/null || break
		done
		if [ $i -ge $ROUNDS ]; then
			echo "Timed out waiting (1 hour!) for ${name} lock!"
			exit 100
		else
			t=$(($i*6))
			echo "${name} is unlocked (waited $t seconds), continuing."
		fi
	else
		echo "${name} is ready"
	fi
}

create_user() {
	echo "Creating user {{.User}}..."
	if getent passwd {{.User}}; then
	  echo "User {{.User}} already exists !"
	  useradd {{.User}} --home-dir /home/{{.User}} --shell /bin/bash --comment "" --create-home || true
	else
	  useradd {{.User}} --home-dir /home/{{.User}} --shell /bin/bash --comment "" --create-home
	fi
	echo "{{.User}}:{{.Password}}" | chpasswd
	groupadd -r docker
	usermod -aG docker {{.User}}
	SUDOERS_FILE=/etc/sudoers.d/{{.User}}
	[ ! -d "$(dirname $SUDOERS_FILE)" ] && SUDOERS_FILE=/etc/sudoers
	cat >>$SUDOERS_FILE <<-'EOF'
Defaults:{{.User}} !requiretty
{{.User}} ALL=(ALL) NOPASSWD:ALL
EOF

	mkdir /home/{{.User}}/.ssh
	echo "{{.PublicKey}}" >>/home/{{.User}}/.ssh/authorized_keys
	echo "{{.PrivateKey}}" >/home/{{.User}}/.ssh/id_rsa
	chmod 0700 /home/{{.User}}/.ssh
	chmod -R 0600 /home/{{.User}}/.ssh/*

	cat >>/home/{{.User}}/.bashrc <<-'EOF'
pathremove() {
		local IFS=':'
		local NEWPATH
		local DIR
		local PATHVARIABLE=${2:-PATH}
		for DIR in ${!PATHVARIABLE} ; do
				if [ "$DIR" != "$1" ] ; then
				  NEWPATH=${NEWPATH:+$NEWPATH:}$DIR
				fi
		done
		export $PATHVARIABLE="$NEWPATH"
}
pathprepend() {
		pathremove $1 $2
		local PATHVARIABLE=${2:-PATH}
		export $PATHVARIABLE="$1${!PATHVARIABLE:+:${!PATHVARIABLE}}"
}
pathappend() {
		pathremove $1 $2
		local PATHVARIABLE=${2:-PATH}
		export $PATHVARIABLE="${!PATHVARIABLE:+${!PATHVARIABLE}:}$1"
}
pathprepend $HOME/.local/bin
EOF

	chown -R {{.User}}:{{.User}} /home/{{.User}}
	chown -R root:{{.User}} /opt/safescale
	chmod 1777 /opt/safescale/var/tmp

	for i in /home/{{.User}}/.hushlogin /home/{{.User}}/.cloud-warnings.skip; do
		touch $i
		chown root:{{.User}} $i
		chmod ug+r-wx,o-rwx $i
	done

	echo done
}

put_hostname_in_hosts() {
	HON=$(hostname)
	ping -n -c1 -w5 $HON 2>/dev/null || echo "127.0.1.1 $HON" >>/etc/hosts
}

# Disable cloud-init automatic network configuration to be sure our configuration won't be replaced
disable_cloudinit_network_autoconf() {
	fname=/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
	mkdir -p $(dirname $fname)
	echo "network: {config: disabled}" >$fname
}

disable_services() {
    case $LINUX_KIND in
        debian|ubuntu)
            sfService stop apt-daily.service &>/dev/null
            systemctl kill --kill-who=all apt-daily.service &>/dev/null
            ;;
    esac
}

# ---- Main

export DEBIAN_FRONTEND=noninteractive

put_hostname_in_hosts
disable_cloudinit_network_autoconf
disable_services
create_user

touch /etc/cloud/cloud-init.disabled

echo -n "0,linux,${LINUX_KIND},$(date +%Y/%m/%d-%H:%M:%S)" >/opt/safescale/var/state/user_data.phase1.done
set +x
exit 0
