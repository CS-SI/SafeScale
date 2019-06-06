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

export SF_BASEDIR=/opt/safescale
export SF_ETCDIR=${SF_BASEDIR}/etc:wait
export SF_VARDIR=${SF_BASEDIR}/var
export SF_TMPDIR=${SF_VARDIR}/tmp
export SF_LOGDIR=${SF_VARDIR}/log

sfFinishPreviousInstall() {
	local unfinished=$(dpkg -l | grep -v ii | grep -v rc | tail -n +4 | wc -l)
	if [[ "$unfinished" == 0 ]]; then echo "good"; else sudo dpkg --configure -a --force-all; fi
}
export -f sfFinishPreviousInstall

# sfWaitForApt waits an already running apt-like command to finish
sfWaitForApt() {
	sfFinishPreviousInstall || true
	sfWaitLockfile apt /var/{lib/{dpkg,apt/lists},cache/apt/archives}/lock
}
export -f sfWaitForApt

# sfApt does exactly what apt does, but we call sfWaitForApt first
sfApt() {
	sfWaitForApt
	apt $@
}

sfWaitLockfile() {
	local ROUNDS=600
	name=$1
	shift
	params=$@
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
export -f sfWaitLockfile

sfIP2long() {
	local a b c d
	IFS=. read -r a b c d <<<$*
	echo $(((((((a << 8) | b) << 8) | c) << 8) | d))
}

sfLong2IP() {
	local ui32=$1
	local ip n
	for n in 1 2 3 4; do
		ip=$((ui32 & 0xff))${ip:+.}$ip
		ui32=$((ui32 >> 8))
	done
	echo $ip
}

# Convert netmask to CIDR
sfNetmask2cidr() {
	# Assumes there's no "255." after a non-255 byte in the mask
	local x=${1##*255.}
	set -- 0^^^128^192^224^240^248^252^254^ $(( (${#1} - ${#x})*2 )) ${x%%.*}
	x=${1%%$3*}
	echo $(( $2 + (${#x}/4) ))
}
export -f sfNetmask2cidr

# Convert CIDR to netmask
sfCidr2netmask() {
	local bits=${1#*/}
	local mask=$((0xffffffff << (32-$bits)))
	sfLong2IP $mask
}
export -f sfCidr2netmask

# Convert CIDR to network
sfCidr2network()
{
	local base=${1%%/*}
	local bits=${1#*/}
	local long=$(sfIP2long $base); shift
	local mask=$((0xffffffff << (32-$bits))); shift
	sfLong2IP $((long & mask))
}
export -f sfCidr2network

# Convert CIDR to broadcast
sfCidr2broadcast()
{
	local base=${1%%/*}
	local bits=${1#*/}
	local long=$(sfIP2long $base); shift
	local mask=$((0xffffffff << (32-$bits))); shift
	sfLong2IP $((long | ~mask))
}
export -f sfCidr2broadcast

sfCidr2iprange() {
	local network=$(sfCidr2network $1)
	local broadcast=$(sfCidr2broadcast $1)
	echo ${network}-${broadcast}
}
export -f sfCidr2iprange

# sfAsyncStart <what> <duration> <command>...
sfAsyncStart() {
	local pid=${1}_PID
	local log=${1}.log
	local duration=$2
	shift 2
	#/usr/bin/tim is only set on ubuntu (not debian)
	timeout $duration /usr/bin/time -p $* &>${SF_LOGDIR}/$log &
	eval "$pid=$!"
}
export -f sfAsyncStart

# sfAsyncWait <what>
# return 0 on success, !=0 on failure
sfAsyncWait() {
	local pid="${1}_PID"
	local log="${1}.log"
	eval "wait \$$pid"
	rc=$?
	eval "unset $pid"
	[ -f "${SF_LOGDIR}/$log" ] && cat "${SF_LOGDIR}/$log"
	[ $rc -ne 0 ] && {
		[ $rc -eq 124 ] && echo "timeout"
		return $rc
	}
	rm -f ${SF_LOGDIR}/$log
	return 0
}
export -f sfAsyncWait

# sfRetry <timeout> <delay> command
# retries command until success, with sleep of <delay> seconds
sfRetry() {
	local timeout=$1
	local delay=$2
	shift 2
	local result

	{ code=$(</dev/stdin); } <<-EOF
		fn() {
			local r
			while true; do
				r=\$($*)
				rc=\$?
				[ \$? -eq 0 ] && echo \$r && break
				sleep $delay
			done
			return 0
		}
		export -f fn
EOF
	eval "$code"
	result=$(timeout $timeout bash -c fn)
	rc=$?
	unset fn
	[ $rc -eq 0 ] && echo $result && return 0
	echo "sfRetry: timeout!"
	return $rc
}
export -f sfRetry

# sfFirewall sets a runtime firewall rule (using firewall-cmd, so arguments are firewall-cmd ones)
# rule doesn't need sfFirewallReload to be applied, but isn't save as permanent (except if you add --permanent parameter,
# but you may use sfFirewallAdd in this case)
sfFirewall() {
	[ $# -eq 0 ] && return 0
	which firewall-cmd &>/dev/null || return 1
	firewall-cmd $@
}
export -f sfFirewall

# sfFirewallAdd sets a permanent firewall rule (using firewall-cmd, so arguments are firewall-cmd ones)
# sfFirewallReload needed to apply rule
sfFirewallAdd() {
	sfFirewall --permanent $@
}
export -f sfFirewallAdd

# sfFirewallReload reloads firewall rules
sfFirewallReload() {
	which firewall-cmd &>/dev/null || return 1
	firewall-cmd --reload
}
export -f sfFirewallReload

# sfInstall installs a package and exits if it fails...
sfInstall() {
	case $LINUX_KIND in
		debian|ubuntu)
			export DEBIAN_FRONTEND=noninteractive
			sfRetry 5m 3 "sfWaitForApt && apt-get update"
			apt-get install $1 -y || exit 194
			which $1 || exit 194
			;;
		centos|rhel)
			yum install -y $1 || exit 194
			which $1 || exit 194
			;;
		*)
			echo "Unsupported operating system '$LINUX_KIND'"
			exit 195
			;;
	esac
	return 0
}
export -f sfInstall

# sfDownload url filename timeout delay
sfDownload() {
	local url="$1"
	local encoded=$(echo "$url" | md5sum | cut -d' ' -f1)
	local filename="$2"
	local timeout=$3
	local delay=$4
	local name=DOWN_${encoded}_LOAD
	local fn=download_$encoded
	{ code=$(</dev/stdin); } <<-EOF
		$fn() {
			while true; do
				#wget -q -nc -O "$filename" "$url"
				curl -L -k -SsL -o "$filename" "$url"
				rc=\$?
				# if $filename exists, remove it and restart without delay
				[ \$rc -eq 1 ] && rm -f $filename && continue
				# break if download succeeded or if not found (no benefit to loop on this kind of error)
				[ \$rc -eq 0 -o \$rc -eq 8 ] && break
				sleep $delay
			done
			return \$rc
		}
		export -f $fn
EOF
	eval "$code"
	sfAsyncStart $name $timeout bash -c $fn
	sfAsyncWait $name
	rc=$?
	unset $fn
	return $rc
}
export -f sfDownload

create_dropzone() {
	mkdir -p ~cladm/.dropzone
	chown cladm:cladm ~cladm/.dropzone
	chmod ug+s ~cladm/.dropzone
}

sfDownloadInDropzone() {
	create_dropzone &>/dev/null
	cd ~cladm/.dropzone
	sfDownload $@
}
export -f sfDownloadInDropzone

# Copy local file to drop zone in remote
sfDropzonePush() {
	local file="$1"
	create_dropzone &>/dev/null
	cp -f $file ~cladm/.dropzone/
	chown -R cladm:cladm ~cladm/.dropzone
}
export -f sfDropzonePush

# Copy content of local dropzone to remote dropzone (parameter can be IP or name)
sfDropzoneSync() {
	local remote="$1"
	create_dropzone &>/dev/null
	scp -i ~cladm/.ssh/id_rsa -r ~cladm/.dropzone cladm@${remote}:~/
}
export -f sfDropzoneSync

# Moves file (1st parameter) from drop zone to folder (2nd parameter)
# Dropzone shall be empty after the operation
sfDropzonePop() {
	local file="$1"
	local dest="$2"
	create_dropzone &>/dev/null
	mkdir -p "$dest" &>/dev/null
	mv -f ~cladm/.dropzone/$file "$dest"
}
export -f sfDropzonePop

sfDropzoneUntar() {
	local file="$1"
	local dest="$2"
	shift 2
	create_dropzone &>/dev/null
	tar zxvf ~cladm/.dropzone/"$file" -C "$dest"
}
export -f sfDropzoneUntar

sfDropzoneClean() {
	rm -rf ~cladm/.dropzone/* ~cladm/.dropzone/.[^.]*
}
export -f sfDropzoneClean

# Executes a remote command with SSH
sfRemoteExec() {
	local remote=$1
	shift
	ssh -i ~cladm/.ssh/id_rsa -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no cladm@$remote $*
}
export -f sfRemoteExec

sfKubectl() {
	sudo -u cladm -i kubectl $@
}
export -f sfKubectl

sfDcos() {
	sudo -u cladm -i dcos $@
}
export -f sfDcos

sfMarathon() {
	sudo -u cladm -i marathon $@
}
export -f sfMarathon

sfProbeGPU() {
	if which lspci &>/dev/null; then
		val=$(lspci | grep nvidia 2>/dev/null)
		[ ! -z $val ] && FACTS["nVidia GPU"]=$val
	fi
}

sfReverseProxyReload() {
	id=$(docker ps --filter "name=reverseproxy_kong-proxy_1" {{ "--format \"{{.ID}}\"" }})
	[ ! -z "$id" ] && docker exec -ti $id kong reload >/dev/null
}
export -f sfReverseProxyReload

# echoes a random string
# $1 is the size of the result (optional)
# $2 is the characters to choose from (optional); use preferably [:xxx:] notation (like [:alnum:] for all letters and digits)
sfRandomString() {
	local count=16
	[ $# -ge 1 ] && count=$1
	local characters="[:graph:]"
	[ $# -ge 2 ] && characters="$2"
	</dev/urandom tr -dc "$characters" | head -c${count}
}

declare -A FACTS
LINUX_KIND=
VERSION_ID=
sfDetectFacts() {
	if [ -f /etc/os-release ]; then
			. /etc/os-release
			FACTS["linux kind"]=$ID
			LINUX_KIND=${ID,,}
			FACTS["linux version"]=$VERSION_ID
			VERSION_ID=$VERSION_ID
			[ ! -z ${VERSION_CODENAME+x} ] && FACTS["linux codename"]=${VERSION_CODENAME,,}
	else
			if which lsb_release &>/dev/null; then
					LINUX_KIND=$(lsb_release -is)
					LINUX_KIND=${LINUX_KIND,,}
					VERSION_ID=$(lsb_release -rs | cut -d. -f1)
			else
					[ -f /etc/redhat-release ] && {
							LINUX_KIND=$(cat /etc/redhat-release | cut -d' ' -f1)
							LINUX_KID=${LINUX_KIND,,}
							VERSION_ID=$(cat /etc/redhat-release | cut -d' ' -f3 | cut -d. -f1)
					}
			fi
			FACTS["linux kind"]=${LINUX_KIND,,}
			FACTS["linux version"]=$VERSION_ID
	fi


	val=$(LANG=C lscpu | grep "Socket(s)" | cut -d: -f2 | sed 's/"//g')
	FACTS["sockets"]=${val//[[:blank:]]/}
	val=$(LANG=C lscpu | grep "Core(s) per socket" | cut -d: -f2 | sed 's/"//g')
	FACTS["cores/socket"]=${val//[[:blank:]]/}
	FACTS["cores"]=$(( ${FACTS["sockets"]} * ${FACTS["cores/socket"]} ))
	val=$(LANG=C lscpu | grep "Thread(s) per core" | cut -d: -f2 | sed 's/"//g')
	FACTS["threads/core"]=${val//[[:blank:]]/}
	FACTS["threads"]=$(( ${FACTS["cores"]} * ${FACTS["threads/core"]} ))
	val=$(( ${FACTS["threads"]} * 2 / 3 ))
	[ $val -le 0 ] && val=1
	FACTS["2/3 of threads"]=val

	sfProbeGPU

	return 0
}

sfGetFact() {
	[ $# -ne 0 ] && [ ! -z "${FACTS[$1]}" ] && echo ${FACTS[$1]}
}

# Waits the completion of the execution of userdata
waitForUserdata() {
	while true; do
		[ -f /opt/safescale/var/state/user_data.phase2.done ] && break
		echo "Waiting userdata completion..."
		sleep 5
	done
}

waitForUserdata
sfDetectFacts
