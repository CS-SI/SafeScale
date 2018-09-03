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

# wait_for_apt waits an already running apt-like command to finish
wait_for_apt() {
    wait_lockfile apt /var/{lib/{dpkg,apt/lists},cache/apt/archives}/lock
}

wait_lockfile() {
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

# Convert netmask to CIDR
netmask2cidr() {
    # Assumes there's no "255." after a non-255 byte in the mask
    local x=${1##*255.}
    set -- 0^^^128^192^224^240^248^252^254^ $(( (${#1} - ${#x})*2 )) ${x%%.*}
    x=${1%%$3*}
    echo $(( $2 + (${#x}/4) ))
}

# Convert CIDR to netmask
cidr2netmask() {
    local m=${1#*/}
    local v=$(( 0xffffffff ^ ((1 << (32 - $m)) - 1) ))
    echo "$(( (v >> 24) & 0xff )).$(( (v >> 16) & 0xff )).$(( (v >> 8) & 0xff )).$(( v & 0xff ))"
}

# Convert CIDR to network
cidr2network() {
    local ip=${1%%/*}
    local mask=$(cidr2netmask $1)
    IFS=. read -r m1 m2 m3 m4 <<< $mask
    IFS=. read -r o1 o2 o3 o4 <<< $ip
    echo $(($o1 & $m1)).$(($o2 & $m2)).$(($o3 & $m3)).$(($o4 & $m4))
}

# Convert CIDR to broadcast
cidr2broadcast() {
    local ip=${1%%/*}
    local mask=$(cidr2netmask $1)
    IFS=. read -r m1 m2 m3 m4 <<< $mask
    IFS=. read -r o1 o2 o3 o4 <<< $ip
    echo $(($o1+(255-($o1 | $m1)))).$(($o2+(255-($o2 | $m2)))).$(($o3+(255-($o3 | $m3)))).$(($o4+(255-($o4 | $m4))))
}

# bg_start <what> <duration> <command>...
bg_start() {
   local pid=${1}_PID
   local log=${1}.log
   local duration=$2
   shift 2
   timeout $duration /usr/bin/time -p $* &>/var/tmp/$log &
   eval "$pid=$!"
}

# bg_wait <what> <error message>
bg_wait() {
   local pid="${1}_PID"
   local log="${1}.log"
   eval "wait \$$pid"
   retcode=$?
   cat /var/tmp/$log
   [ $retcode -ne 0 ] && exit $2
   rm -f /var/tmp/$log
}

# Waits the completion of the execution of userdata
wait_for_userdata() {
    while true; do
        [ -f /var/tmp/user_data.done ] && break
        echo "Waiting userdata finished..."
        sleep 5
    done
}

save_iptables_rules() {
    case $LINUX_KIND in
        rhel|centos) iptables-save >/etc/sysconfig/iptables ;;
        debian|ubuntu) iptables-save >/etc/iptables/rules.v4 ;;
    esac
}

detect_facts() {
    declare -gA FACTS
    [ -f /etc/os-release ] && {
        . /etc/os-release
        FACTS["linux kind"]=$ID
        local -g LINUX_KIND=$ID
        FACTS["version id"]=$VERSION_ID
        local -g VERSION_ID=$VERSION_ID
        FACTS["sockets"]=$(LANG=C lscpu | grep "Socket(s)" | cut -d: -f2 | sed 's/"//g')
        FACTS["cores per socket"]=$(LANG=C lscpu | grep "Core(s) per socket" | cut -d: -f2 | sed 's/"//g')
        FACTS["cores"]=$(( ${FACTS["sockets"]} * ${FACTS["cores per socket"]} ))
        FACTS["threads per core"]=$(LANG=C lscpu | grep "Thread(s) per core" | cut -d: -f2 | sed 's/"//g')
        FACTS["threads"]=$(( ${FACTS["cores"]} * ${FACTS["threads per core"]} ))
        FACTS["2 3rd of threads"]=$(( ${FACTS["threads"]} * 2 / 3 ))

        which lspci &>/dev/null || {
            case $LINUX_KIND in
                debian|ubuntu)
                    wait_for_apt && apt install -y pciutils
                    ;;
                centos|redhat)
                    yum install -y pciutils
                    ;;
                dnf)
                    dnf install -y pciutils
                    ;;
            esac
        }
        which lspci &>/dev/null && {
            FACTS["nVidia GPU"]=$(lspci | grep nvidia 2>/dev/null)
        }
        return
    }
}

wait_for_userdata
detect_facts
