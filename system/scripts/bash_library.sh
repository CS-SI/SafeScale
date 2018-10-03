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

# sfWaitForApt waits an already running apt-like command to finish
sfWaitForApt() {
    sfWaitLockfile apt /var/{lib/{dpkg,apt/lists},cache/apt/archives}/lock
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

# Convert netmask to CIDR
sfNetmask2Cidr() {
    # Assumes there's no "255." after a non-255 byte in the mask
    local x=${1##*255.}
    set -- 0^^^128^192^224^240^248^252^254^ $(( (${#1} - ${#x})*2 )) ${x%%.*}
    x=${1%%$3*}
    echo $(( $2 + (${#x}/4) ))
}

# Convert CIDR to netmask
sfCidr2Netmask() {
    local m=${1#*/}
    local v=$(( 0xffffffff ^ ((1 << (32 - $m)) - 1) ))
    echo "$(( (v >> 24) & 0xff )).$(( (v >> 16) & 0xff )).$(( (v >> 8) & 0xff )).$(( v & 0xff ))"
}

# Convert CIDR to network
sfCidr2Network() {
    local ip=${1%%/*}
    local mask=$(sfCidr2Netmask $1)
    IFS=. read -r m1 m2 m3 m4 <<< $mask
    IFS=. read -r o1 o2 o3 o4 <<< $ip
    echo $(($o1 & $m1)).$(($o2 & $m2)).$(($o3 & $m3)).$(($o4 & $m4))
}

# Convert CIDR to broadcast
sfCidr2Broadcast() {
    local ip=${1%%/*}
    local mask=$(sfCidr2Netmask $1)
    IFS=. read -r m1 m2 m3 m4 <<< $mask
    IFS=. read -r o1 o2 o3 o4 <<< $ip
    echo $(($o1+(255-($o1 | $m1)))).$(($o2+(255-($o2 | $m2)))).$(($o3+(255-($o3 | $m3)))).$(($o4+(255-($o4 | $m4))))
}

# sfAsyncStart <what> <duration> <command>...
sfAsyncStart() {
    local pid=${1}_PID
    local log=${1}.log
    local duration=$2
    shift 2
    timeout $duration /usr/bin/time -p $* &>/var/tmp/$log &
    eval "$pid=$!"
}

# sfAsyncWait <what>
# return 0 on success, !=0 on failure
sfAsyncWait() {
    local pid="${1}_PID"
    local log="${1}.log"
    eval "wait \$$pid"
    retcode=$?
    cat /var/tmp/$log
    [ $retcode -ne 0 ] && {
        [ $retcode -eq 124 ] && echo "timeout"
        return $retcode
    }
    rm -f /var/tmp/$log
    return 0
}

# sfRetry timeout <delay> command
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
    [ $rc -eq 0 ] && echo $result
    return $rc
}

# sfDownload url filename timeout delay
sfDownload() {
    url="$1"
    encoded=$(echo "$url" | md5sum | cut -d' ' -f1)
    filename="$2"
    timeout=$3
    delay=$4
    fn=download_$encoded
    { code=$(</dev/stdin); } <<-EOF
        $fn() {
            while true; do
                wget -q -nc -O "$filename" "$url"
                rc=\$?
                # if $filename exists, remove it and restart without delay
                [ \$rc -eq 1 ] && rm -f $filename && continue
                # break if wget succeeded or if not found (no benefit to loop on this kind of error)
                [ \$rc -eq 0 -o \$rc -eq 8 ] && break
                sleep $delay
            done
            return \$rc
        }
        export -f $fn
EOF
    eval "$code"
    sfAsyncStart DOWN_${encoded}_LOAD $timeout bash -c $fn
    sfAsyncWait DOWN_${encoded}_LOAD
    rc=$?
    unset DOWN_${encoded}_LOAD $fn
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

# Copy content of local dropzone to remote dropzone (parameter can be IP or name)
sfDropzoneSync() {
    local remote="$1"
    create_dropzone &>/dev/null
    scp -i ~cladm/.ssh/id_rsa -r ~cladm/.dropzone cladm@${remote}:~/
}

# Moves file (1st parameter) from drop zone to folder (2nd parameter)
# Dropzone shall be empty after the operation
sfDropzonePop() {
    local file="$1"
    local dest="$2"
    create_dropzone &>/dev/null
    mkdir -p "$dest" &>/dev/null
    mv -f ~cladm/.dropzone/$file "$dest"
}

sfDropzoneUntar() {
    local file="$1"
    local dest="$2"
    shift 2
    create_dropzone &>/dev/null
    tar zxvf ~cladm/.dropzone/"$file" -C "$dest"
}

sfDropzoneClean() {
    rm -rf ~cladm/.dropzone/* ~cladm/.dropzone/.[^.]*
}

# Executes a remote command with SSH
sfRemoteExec() {
    local remote=$1
    shift
    ssh -i ~cladm/.ssh/id_rsa -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no cladm@$remote $*
}

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

# Waits the completion of the execution of userdata
sfWaitForUserdata() {
    while true; do
        [ -f /var/tmp/user_data.done ] && break
        echo "Waiting userdata finished..."
        sleep 5
    done
}

sfSaveIptablesRules() {
    case $LINUX_KIND in
        rhel|centos) iptables-save >/etc/sysconfig/iptables ;;
        debian|ubuntu) iptables-save >/etc/iptables/rules.v4 ;;
    esac
}

sfDetectFacts() {
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
                    sfWaitForApt && apt install -y pciutils
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

sfGetFact() {
    [ $# -ne 0 ] && [ ! -z "${FACTS[$1]}" ] && echo ${FACTS[$1]}
}

sfWaitForUserdata
sfDetectFacts
