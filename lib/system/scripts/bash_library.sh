#
# Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
export SF_ETCDIR=${SF_BASEDIR}/etc
export SF_BINDIR=${SF_BASEDIR}/bin
export SF_VARDIR=${SF_BASEDIR}/var
export SF_TMPDIR=${SF_VARDIR}/tmp
export SF_LOGDIR=${SF_VARDIR}/log

declare -x SF_SERIALIZED_FACTS
SF_SERIALIZED_FACTS=$(mktemp)

declare -A FACTS
export LINUX_KIND=
export VERSION_ID=
export FULL_VERSION_ID=

function versionchk() { echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'; }
export -f versionchk

function sfFail() {
  if [ $# -eq 1 ]; then
    if [ "$1" -ne 0 ]; then
      echo "Exiting with error $1"
    fi
  elif [ $# -eq 2 ] && [ "$1" -ne 0 ]; then
    echo "Exiting with error $1: $2"
  fi
  (
    sync
    echo 3 > /proc/sys/vm/drop_caches
    sleep 2
  ) || true
  echo "exiting with errorcode $1"
  exit "$1"
}
export -f sfFail

function sfExit() {
  (
    sync
    echo 3 > /proc/sys/vm/drop_caches
    sleep 2
  ) || true
  echo "exiting with errorcode 0"
  exit 0
}
export -f sfExit

function sfFinishPreviousInstall() {
  local unfinished
  unfinished=$(dpkg -l | grep -v ii | grep -v rc | tail -n +4 | wc -l)
  if [[ "$unfinished" == 0 ]]; then
    echo "good"
    return 0
  else
    echo "there are unconfigured packages !"
    sudo dpkg --configure -a --force-all && {
      return $?
    }
    return 0
  fi
}
export -f sfFinishPreviousInstall

# sfWaitForApt waits an already running apt-like command to finish
function sfWaitForApt() {
  sfFinishPreviousInstall || true
  [ $? -ne 0 ] && return $?
  sfWaitLockfile apt /var/{lib/{dpkg,apt/lists},cache/apt/archives}/lock
  [ $? -ne 0 ] && return $?
  return 0
}
export -f sfWaitForApt

# sfApt does exactly what apt does, but we call sfWaitForApt first
function sfApt() {
  echo "waiting for apt lock..."
  sfWaitForApt
  [ $? -ne 0 ] && return $?
  echo "running apt " "$@"
  rc=-1
  DEBIAN_FRONTEND=noninteractive UCF_FORCE_CONFFNEW=1 apt -o Dpkg::Options::=--force-confnew "$@" && rc=$?
  [ $rc -eq -1 ] && return 1
  return $rc
}
export -f sfApt

# try using dnf instead of yum if available
function sfYum() {
  rc=-1
  if [[ -n $(which dnf) ]]; then
    dnf "$@" && rc=$?
  else
    yum "$@" && rc=$?
  fi
  [ $rc -eq -1 ] && return 1
  return $rc
}
export -f sfYum

function sfAvail() {
  rc=-1
  case $LINUX_KIND in
  redhat | rhel | centos | fedora)
    if [[ -n $(which dnf) ]]; then
      dnf list available "$@" &> /dev/null && rc=$?
    else
      yum list available "$@" &> /dev/null && rc=$?
    fi
    ;;
  debian | ubuntu)
    DEBIAN_FRONTEND=noninteractive UCF_FORCE_CONFFNEW=1 apt search "$@" &> /dev/null && rc=$?
    ;;
  esac
  [ $rc -eq -1 ] && return 1
  return $rc
}
export -f sfAvail

function sfWaitLockfile() {
  local ROUNDS=600
  name=$1
  shift
  params="$@"
  echo "check $name lock"
  echo ${params}
  if fuser ${params} &> /dev/null; then
    echo "${name} is locked, waiting... "
    local i
    for i in $(seq $ROUNDS); do
      sleep 6
      fuser ${params} &> /dev/null || break
    done
    if [ $i -ge $ROUNDS ]; then
      echo "Timed out waiting (1 hour!) for ${name} lock!"
      exit 100
    else
      t=$(($i * 6))
      echo "${name} is unlocked (waited $t seconds), continuing."
    fi
  else
    echo "${name} is ready"
  fi
}
export -f sfWaitLockfile

function sfIP2long() {
  local a b c d
  IFS=. read -r a b c d <<< $*
  echo $(((((((a << 8) | b) << 8) | c) << 8) | d))
}
export -f sfIP2long

function sfLong2IP() {
  local ui32=$1
  local ip n
  for n in 1 2 3 4; do
    ip=$((ui32 & 0xff))${ip:+.}$ip
    ui32=$((ui32 >> 8))
  done
  echo "$ip"
}
export -f sfLong2IP

# Convert netmask to CIDR
function sfNetmask2cidr() {
  # Assumes there's no "255." after a non-255 byte in the mask
  local x=${1##*255.}
  set -- 0^^^128^192^224^240^248^252^254^ $(((${#1} - ${#x}) * 2)) ${x%%.*}
  x=${1%%$3*}
  echo $(($2 + (${#x} / 4)))
}
export -f sfNetmask2cidr

# Convert CIDR to netmask
function sfCidr2netmask() {
  local bits=${1#*/}
  local mask=$((0xffffffff << (32 - $bits)))
  sfLong2IP $mask
}
export -f sfCidr2netmask

# Convert CIDR to network
function sfCidr2network() {
  local base=${1%%/*}
  local bits=${1#*/}
  local long=$(sfIP2long $base)
  shift
  local mask=$((0xffffffff << (32 - $bits)))
  shift
  sfLong2IP $((long & mask))
}
export -f sfCidr2network

# Convert CIDR to broadcast
function sfCidr2broadcast() {
  local base=${1%%/*}
  local bits=${1#*/}
  local long=$(sfIP2long $base)
  shift
  local mask=$((0xffffffff << (32 - $bits)))
  shift
  sfLong2IP $((long | ~mask))
}
export -f sfCidr2broadcast

function sfCidr2iprange() {
  local network=$(sfCidr2network $1)
  local broadcast=$(sfCidr2broadcast $1)
  echo ${network}-${broadcast}
}
export -f sfCidr2iprange

function sfInterfaceWithIP() {
  ifconfig | grep -B1 "$1" | grep -o "^\w*"
}
export -f sfInterfaceWithIP

#------ delays and timeouts ------

function sfDefaultDelay() {
  echo {{ default 10 .reserved_DefaultDelay }}
}
export -f sfDefaultDelay

function sfDefaultTimeout() {
  echo {{ default "3m" .reserved_DefaultTimeout }}
}
export -f sfDefaultTimeout

function sfLongTimeout() {
  echo {{ default "6m" .reserved_LongTimeout }}
}
export -f sfLongTimeout

function sfClusterJoinTimeout() {
  echo {{ default "14m" .reserved_ClusterJoinTimeout }}
}
export -f sfClusterJoinTimeout

function sfDockerImagePullTimeout() {
  echo {{ default "10m" .reserved_DockerImagePullTimeout }}
}
export -f sfDockerImagePullTimeout

#------

# sfAsyncStart <what> <duration> <command>...
function sfAsyncStart() {
  local pid=${1}_PID
  local log=${1}.log
  local duration=$2
  shift 2
  #/usr/bin/tim is only set on ubuntu (not debian)
  timeout $duration /usr/bin/time -p $* &> ${SF_LOGDIR}/$log &
  eval "$pid=$!"
}
export -f sfAsyncStart

# sfAsyncWait <what>
# return 0 on success, !=0 on failure
function sfAsyncWait() {
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

# sfRetryEx <timeout> <delay> command
# Retries command until success, with sleep of <delay> seconds
# Will timeout after <timeout>
function sfRetryEx() {
  local timeout=$1
  local delay=$2
  shift 2
  local result

  { code=$(< /dev/stdin); } <<- EOF
  fn() {
    local r
    local rc
    while true; do
      r=\$($*)
      rc=\$?
      [ \$rc -eq 0 ] && echo \$r && break
      sleep $delay
    done
    return \$rc
  }
  export -f fn
EOF
  eval "$code"
  result=$(timeout $timeout bash -c -x fn)
  rc=$?
  unset fn
  [ $rc -eq 0 ] && echo $result && return 0
  echo "sfRetry: timeout!"
  return $rc
}
export -f sfRetryEx

function sfRetry {
  sfRetryEx $(sfDefaultTimeout) $(sfDefaultDelay) $*
}
export -f sfRetry

function sfRetry4 {
  for iter in {1..4}
  do
    $* && break
    [[ "$iter" == '4' ]] && return 1
  done
  return 0
}

# sfSalvageDBusIfNeeded restarts dbus-daemon if needed (ie there are no or more than 1 dbus-daemon)
# returns 0 if nothing has been done, 1 if dbus has been salvaged
# Note: often dbus cannot be restarted automatically. It's necessary to restart a service that has dusb as dependency to
#       effectively restart dbus
function sfSalvageDBusIfNeeded() {
  count=$(ps ax | grep dbus-daemon | grep -v grep | wc -l)
  if [ $count -ne 1 ]; then
    echo "dbus-daemon in abnormal situation (process count=$count), restarting dbus.service"
    sfService stop dbus.service &> /dev/null
    sfService stop dbus.socket &> /dev/null
    pkill dbus-daemon
    rm -f /var/run/system_bus_socket &> /dev/null
    #VPL: dbus cannot be restarted interactively; only services with dependency to dbus can
    #sfService start dbus
    #echo "dbus.service restarted"
    return 1
  fi
  return 0
}
export sfSalvageDBusIfNeeded

# sfFirewall sets a runtime firewall rule (using firewall-cmd, so arguments are firewall-cmd ones)
# rule doesn't need sfFirewallReload to be applied, but isn't save as permanent (except if you add --permanent parameter,
# but you may use sfFirewallAdd in this case)
function sfFirewall() {
  [ $# -eq 0 ] && return 0

  # check existence of firewall-cmd binary
  command -v firewall-cmd &> /dev/null || return 1

  # check firewalld is running
  local op=-1
  local tried_restart=-1
  while [[ $op -eq -1 && $tried_restart -eq -1 ]]; do
    # try to get firewall state
    state=$(sudo timeout 10s firewall-cmd --state 2>&1 | tee -a /tmp/fw.txt)
    op=$?
    # Restart firewalld if failed
    if [[ $op -ne 0 || $state != "running" ]]; then
      sfService stop firewalld &> /dev/null
      sfSalvageDBusIfNeeded
      sfService start firewalld && op=$? || op=$?
      if [[ $op -ne 0 ]]; then
        echo "failed to restart firewalld.service"
      else
        echo "restarted firewalld.service"
      fi
      tried_restart=0
    fi
  done
  if [[ $op -ne 0 ]]; then
    echo "failed to start currently stopped firewalld.service"
    return 1
  fi

  # now run the real firewall-cmd command (sudo may be superfluous if executed as root, but won't harm)
  sudo firewall-cmd "$@" || true
}
export -f sfFirewall

# sfFirewallAdd sets a permanent firewall rule (using firewall-cmd, so arguments are firewall-cmd ones)
# sfFirewallReload needed to apply rule
function sfFirewallAdd() {
  sfFirewall --permanent "$@"
}
export -f sfFirewallAdd

# sfFirewallReload reloads firewall rules
function sfFirewallReload() {
  local op=-1
  sfFirewall --reload 2>&1 | tee -a /tmp/fw.txt && op=$? || op=$?
  local sop=-1
  if [[ $op -ne 0 ]]; then
    sfFirewall --complete-reload 2>&1 | tee -a /tmp/fw.txt && sop=$? || sop=$?
    if [[ $sop -ne 0 ]]; then
      echo "firewall-cmd reloading failed with $op first and then with $sop" # keep the error codes from firewall-cmd
      return $sop
    fi
  fi
  return 0
}
export -f sfFirewallReload

# sfInstall installs a package and exits if it fails...
function sfInstall() {
  case $LINUX_KIND in
  debian | ubuntu)
    export DEBIAN_FRONTEND=noninteractive
    export UCF_FORCE_CONFFNEW=1
    sfRetry4 "sfApt update"
    sfApt install $1 -y || return 194
    command -v $1 || return 194
    ;;
  centos | rhel)
    yum install -y $1 || return 194
    command -v $1 || return 194
    ;;
  *)
    echo "Unsupported operating system '$LINUX_KIND'"
    return 195
    ;;
  esac
  return 0
}
export -f sfInstall

# sfDownload url filename timeout delay
function sfDownload() {
  mkdir -p $SF_LOGDIR || true

  local url="$1"
  local encoded
  encoded=$(echo "$url" | md5sum | cut -d' ' -f1)
  local filename="$2"
  local timeout=$3
  local delay=$4
  local name=DOWN_${encoded}_LOAD
  local fn=download_$encoded
  { code=$(< /dev/stdin); } <<- EOF
		$fn() {
			while true; do
				rm -f $filename || true # begin by cleaning up
				curl -L -k -SsL --fail "$url" >"$filename"
				rc=\$?
				# break if download succeeded or if not found; 22 is the curl error code for 404
				[ \$rc -eq 0 -o \$rc -eq 22 ] && break
				# give wget a chance if installed
				if which wget &>/dev/null; then
					rm -f $filename || true # begin by cleaning up
					wget -q -nc -O "$filename" "$url"
					rc=\$?
					# break if download succeeded or not found; 8 is the wget error code for 404
					[ \$rc -eq 0 -o \$rc -eq 8 ] && break
				fi
				sleep $delay
			done
			return \$rc
		}
		export -f $fn
	EOF
  eval "$code"
  sfAsyncStart $name $timeout bash -c -x $fn
  sfAsyncWait $name
  rc=$?
  unset $fn
  return $rc
}
export -f sfDownload

__create_dropzone() {
  mkdir -p $SF_LOGDIR || true

  [[ ! -d ~cladm/.dropzone ]] && {
    mkdir -p ~cladm/.dropzone || return $?
  }
  chown -R cladm:cladm ~cladm/.dropzone || return $?
  chmod -R ug+s ~cladm/.dropzone || return $?
  return 0
}

function sfDownloadInDropzone() {
  __create_dropzone &> /dev/null || return $?
  cd ~cladm/.dropzone && {
    sfDownload "$@" || return $?
  }
  cd ~cladm/.dropzone || return 1
  return 0
}
export -f sfDownloadInDropzone

# Copy local file to drop zone in remote
function sfDropzonePush() {
  local file
  file="$1"
  __create_dropzone || {
    rco=$?
    echo "failed to create dropzone (exit code $rco)"
    return $rco
  }
  cp -rf "$file" ~cladm/.dropzone/ || {
    rco=$?
    echo "failed to copy '$file' in dropzone (exit code $rco)"
    return $rco
  }
  chown -R cladm:cladm ~cladm/.dropzone || {
    rco=$?
    echo "failed to set ownership of dropzone (exit code $rco)"
    return $rco
  }
  return 0
}
export -f sfDropzonePush

__cluster_admin_ssh_options__="-i ~cladm/.ssh/id_rsa -oIdentitiesOnly=yes -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=yes -oPasswordAuthentication=no -oLogLevel=error"

# Copy content of local dropzone to remote dropzone (parameter can be IP or name)
function sfDropzoneSync() {
  local remote="$1"
  __create_dropzone &> /dev/null || return $?
  scp $__cluster_admin_ssh_options__ -r ~cladm/.dropzone cladm@${remote}:~/ || return $?
  return 0
}
export -f sfDropzoneSync

# Moves all files in drop zone to folder (1st parameter)
# if 2nd parameter is set, moves only the file on folder
function sfDropzonePop() {
  [ $# -eq 0 ] && return 1
  local dest="$1"
  local file=
  [ $# -eq 2 ] && file="$2"
  __create_dropzone || {
    rco=$?
    echo "failed to create dropzone (exit code $rco)"
    return $rco
  }
  if [ ! -d "$dest" ]; then
    sudo mkdir -p "$dest" > /dev/null || {
      rco=$?
      echo "failed to create '$dest' folder (exit code $rco)"
      return $rco
    }
  fi
  if [ $# -eq 1 ]; then
    sudo mv -f ~cladm/.dropzone/* "$dest" || {
      rco=$?
      echo "failed to move all files in dropzone to '$dest' (exit code $rco)"
      return $rco
    }
  else
    sudo mv -f ~cladm/.dropzone/"$file" "$dest" || {
      rco=$?
      echo "failed to move file '$file' in dropzone to '$dest' (exit code $rco)"
      return $rco
    }
  fi
  return 0
}
export -f sfDropzonePop

function sfDropzoneUntar() {
  local file="$1"
  local dest="$2"
  shift 2
  __create_dropzone &> /dev/null || return $?
  tar zxvf ~cladm/.dropzone/"$file" -C "$dest" || return $?
  return 0
}
export -f sfDropzoneUntar

function sfDropzoneClean() {
  rm -rf ~cladm/.dropzone/* ~cladm/.dropzone/.[^.]* || return $?
  return 0
}
export -f sfDropzoneClean

# Executes a remote command with SSH
function sfRemoteExec() {
  local remote=$1
  shift
  ssh $__cluster_admin_ssh_options__ cladm@$remote "$@" || return $?
  return 0
}
export -f sfRemoteExec

function sfKubectl() {
  sudo -u cladm -i kubectl "$@" || return $?
  return 0
}
export -f sfKubectl

function sfHelm() {
  # analyzes parameters...
  local use_tls=--tls
  local stop=0
  for p in "$@"; do
    case "$p" in
    "--*") ;;

    "search" | "repo")
      stop=1
      use_tls=
      ;;
    "init")
      echo "sfHelm init is forbidden" && return 1
      ;;
    *)
      stop=1
      ;;
    esac
    [ $stop -eq 1 ] && break
  done

  sudo -u cladm -i helm "$@" $use_tls
  [ $? -ne 0 ] && return $?
  return 0
}
export -f sfHelm

function sfProbeGPU() {
  if command -v lspci &> /dev/null; then
    val=$(lspci | grep nvidia 2> /dev/null) || true
    [ ! -z "$val" ] && FACTS["nVidia GPU"]=$val || true
  fi
  return 0
}
export -f sfProbeGPU

function sfEdgeProxyReload() {
  id=$(sfGetFact "edgeproxy4subnet_docker_id")
  if [ ! -z ${id+x} ]; then
    docker exec $id kong reload > /dev/null
    return $?
  fi
  return 1
}
export -f sfEdgeProxyReload

function sfReverseProxyReload() {
  sfEdgeProxyReload
}
export -f sfReverseProxyReload

function sfSystemctl-exists() {
  [ "$(systemctl list-unit-files "${1}*" | wc -l)" -gt 3 ]
}
export -f sfSystemctl-exists

function sfServiceRuns() {
  [ $# -ne 1 ] && return 1

  local use_systemd=$(sfGetFact "use_systemd")
  local redhat_like=$(sfGetFact "redhat_like")

  # Preemptively run daemon-reload in case of changes
  [ "$use_systemd" = "1" ] && systemctl daemon-reload

  [ "$use_systemd" = "1" ] && systemctl status $2 && systemctl status $2 | grep active | grep running && return $?
  [ "$redhat_like" = "1" ] && service $2 status && service $2 status | grep running && return $?

  return 1
}
export -f sfServiceRuns

# sfService abstracts the command to use to manipulate services
function sfService() {
  [ $# -ne 2 ] && return 1

  local use_systemd=$(sfGetFact "use_systemd")
  local redhat_like=$(sfGetFact "redhat_like")

  # Preventive run daemon-reload in case of changes
  [ "$use_systemd" = "1" ] && systemctl daemon-reload

  case $1 in
  enable)
    [ "$use_systemd" = "1" ] && systemctl enable $2 && return $?
    [ "$redhat_like" = "1" ] && chkconfig $2 on && return $?
    ;;
  disable)
    [ "$use_systemd" = "1" ] && systemctl disable $2 && return $?
    [ "$redhat_like" = "1" ] && chkconfig $2 off && return $?
    ;;
  start)
    [ "$use_systemd" = "1" ] && systemctl start $2 && return $?
    [ "$redhat_like" = "1" ] && service $2 start && return $?
    ;;
  stop)
    [ "$use_systemd" = "1" ] && systemctl stop $2 && return $?
    [ "$redhat_like" = "1" ] && service $2 stop && return $?
    ;;
  restart)
    [ "$use_systemd" = "1" ] && systemctl restart $2 && return $?
    [ "$redhat_like" = "1" ] && service $2 restart && return $?
    ;;
  reload)
    [ "$use_systemd" = "1" ] && systemctl reload $2 && return $?
    [ "$redhat_like" = "1" ] && service $2 reload && return $?
    ;;
  status)
    [ "$use_systemd" = "1" ] && systemctl status $2 && return $?
    [ "$redhat_like" = "1" ] && service $2 status && return $?
    ;;
  *)
    echo "sfService(): unhandled command '$1'"
    ;;
  esac
  return 1
}
export -f sfService

# Displays the subnet of the docker bridge
function sfSubnetOfDockerBridge() {
  sfSubnetOfDockerNetwork bridge
}
export -f sfSubnetOfDockerBridge

# Displays the subnet of the docker swarm bridge
function sfSubnetOfDockerSwarmBridge() {
  sfSubnetOfDockerNetwork docker_gwbridge
}
export -f sfSubnetOfDockerSwarmBridge

# Displays the subnet of a docker network
function sfSubnetOfDockerNetwork() {
  [ $# -ne 1 ] && return 1
  docker network inspect $1 {{ "--format '{{json .}}'" }} | jq -r .IPAM.Config[0].Subnet
}
export -f sfSubnetOfDockerNetwork

# Tells if the node is registered as swarm node
function sfIsDockerSwarmInit() {
  STATE="$(docker info {{ "--format '{{.Swarm.LocalNodeState}}'" }})"
  case "$STATE" in
  "inactive" | "pending")
    echo "{{ .Hostname }} is not in a Swarm cluster"
    return 1
    ;;
  "active" | "locked")
    return 0
    ;;
  "error")
    echo "{{ .Hostname }} is in a Swarm error state"
    return 2
    ;;
  esac
  echo "Unknown Swarm state '$STATE' on host {{ .Hostname }}"
  return 3
}
export -f sfIsDockerSwarmInit

# tells if a container using a specific image (and optional name) is running in standalone mode
function sfDoesDockerRunContainer() {
  [ $# -eq 0 ] && return 1
  local IMAGE=$1
  shift
  local INSTANCE=
  [ $# -ge 1 ] && INSTANCE=$1
  # docker seems to have change .Names separator from underscore to dash in --format... May need to search for the
  # 2 different names in docker container ls
  local INSTANCE_2=$(echo $INSTANCE | tr -s "_" "-")
  [ "$INSTANCE" = "$INSTANCE_2" ] && INSTANCE_2=$(echo $INSTANCE | tr -s "-" "_")
  [ "$INSTANCE" = "$INSTANCE_2" ] && INSTANCE_2=

  local LIST=$(docker container ls {{ "--format '{{.Image}}|{{.Names}}|{{.Status}}'" }})
  [ -z "$LIST" ] && return 1
  [ "$IMAGE" != "$(echo "$LIST" | cut -d'|' -f1 | grep "$IMAGE" | uniq)" ] && return 1
  if [ ! -z "$INSTANCE" ]; then
    local FOUND=n
    if [ "$INSTANCE" == "$(echo "$LIST" | cut -d'|' -f2 | grep "$INSTANCE" | uniq)" ]; then
      FOUND=yes
    elif [ "$INSTANCE_2" != "$INSTANCE" ]; then
      if [ "$INSTANCE_2" == "$(echo "$LIST" | cut -d'|' -f2 | grep "$INSTANCE_2" | uniq)" ]; then
        found=y
      fi
    fi
    [ "$FOUND" != "y"] && return 1
  fi
  echo $LIST | cut -d'|' -f3 | grep -i "^up" &> /dev/null || return 1
  return 0
}
export -f sfDoesDockerRunContainer

# tells if a container using a specific image and name is running in Swarm mode
function sfDoesDockerRunService() {
  [ $# -ne 2 ] && return 1
  local IMAGE=$1
  local NAME=$2

  local LIST=$(docker service ps $NAME {{ "--format '{{.Image}}|{{.Name}}|{{.CurrentState}}'" }})
  if [ -z "$LIST" ]; then
    return 1
  fi
  local RIMAGE=$(echo "$LIST" | cut -d'|' -f1 | sort | uniq)
  if [ "$IMAGE" != "$RIMAGE" ]; then
    return 1
  fi
  local RNAME=$(echo "$LIST" | cut -d'|' -f2 | sort | uniq)
  if ! expr match "$RNAME" "^${NAME}\." &> /dev/null; then
    return 1
  fi
  if ! echo $LIST | cut -d'|' -f3 | grep -i "^running" > /dev/null; then
    return 1
  fi
  return 0
}
export -f sfDoesDockerRunService

# tells if a stack is running in Swarm mode
function sfDoesDockerRunStack() {
  [ $# -ne 1 ] && return 1
  local NAME=$1

  docker stack ps $NAME {{ "--filter 'desired-state=running'" }} &> /dev/null
  [ $? -ne 0 ] && return $?
}
export -f sfDoesDockerRunStack

function sfRemoveDockerImage() {
  local list=$(docker image ls {{ "--format '{{.Repository}}:{{.Tag}}|{{.ID}}'" }} | grep "^$1")
  if [ ! -z "$list" ]; then
    local i image id repo
    for i in $list; do
      image=$(echo $i | cut -d'|' -f1)
      repo=$(echo $image | cut -d: -f1)
      if [ "$image" = "$1" -o "$repo" = "$1" ]; then
        id=$(echo $i | cut -d'|' -f2)
        if [ ! -z "$id" ]; then
          docker image rm -f $id || return $?
        fi
      fi
    done
  fi
  return 0
}
export -f sfRemoveDockerImage

# Allows to create or update a docker secret
# password can be passed as second parameter or through stdin (preferred option)
function sfUpdateDockerSecret() {
  [ $# -lt 1 ] && return 1
  local name=$1
  shift

  local password=
  [ $# -eq 1 ] && password="$1"
  local _stdin=
  IFS= read -t 1 _stdin
  [ -z "$_stdin" -a -z "$password" ] && return 1
  [ ! -z "$_stdin" ] && password="$_stdin"

  if docker secret inspect $name &> /dev/null; then
    docker secret rm $name || return 1
  fi
  echo -n "$password" | docker secret create $name -
}
export -f sfUpdateDockerSecret

function sfRemoveDockerSecret() {
  [ $# -ne 1 ] && return 1
  if docker secret inspect $1 &> /dev/null; then
    docker secret rm $1
    return $?
  fi
  return 0
}
export -f sfRemoveDockerSecret

function sfIsPodRunning() {
  local pod=${1%@*}
  local domain=${1#*@}
  [ -z ${domain+x} ] && domain=default
  set +o pipefail
  (sfKubectl get -n $domain pod $pod 2>&1 | grep Running &> /dev/null)
  retcode=$?
  set -o pipefail
  [ $retcode = 0 ] && return 0 || return 1
}
export -f sfIsPodRunning

# Returns the version corresponding to latest release
function sfGitHubTagOfRelease() {
  curl -L -k -Ssl -X GET "https://api.github.com/repos/$1/$2/releases/$3" | jq -r .tag_name
}
export -f sfGitHubTagOfRelease

# Returns the tag name corresponding to latest release
function sfGithubLastRelease() {
  sfGitHubTagOfRelease $1 $2 latest
}
export -f sfGithubLastRelease

# Returns the tag name corresponding to the last non-beta release
function sfGithubLastNotBetaRelease() {
  curl -L -k -Ssl -X GET "https://api.github.com/repos/$1/$2/releases" | jq -c '.[] | select(.tag_name | contains("beta") | not)' | head -n 1 | jq -r .tag_name
}
export -f sfGithubLastNotBetaRelease

# echoes a random string
# $1 is the size of the result (optional)
# $2 is the characters to choose from (optional); use preferably [:xxx:] notation (like [:alnum:] for all letters and digits)
function sfRandomString() {
  local count=16
  [ $# -ge 1 ] && count=$1
  local charset="[:graph:]"
  [ $# -ge 2 ] && charset="$2"
  tr < /dev/urandom -dc "$charset" | head -c${count} || true
  return 0
}
export -f sfRandomString

# --------
# Workaround for associative array not exported in bash
declare -x SERIALIZED_FACTS=$(mktemp)
function factsCleanup() {
  rm -f "$SERIALIZED_FACTS" &> /dev/null || true
}
trap factsCleanup exit
# --------

function sfDetectFacts() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    FACTS["linux_kind"]=$ID
    LINUX_KIND=${ID,,}
    FACTS["linux_version"]=$VERSION_ID
    FACTS["distrib_version"]=$VERSION_ID
    VERSION_ID=$VERSION_ID
    FULL_VERSION_ID=$VERSION_ID
    [ ! -z ${VERSION_CODENAME+x} ] && FACTS["linux_codename"]=${VERSION_CODENAME,,}
  else
    if which lsb_release &> /dev/null; then
      LINUX_KIND=$(lsb_release -is)
      LINUX_KIND=${LINUX_KIND,,}
      VERSION_ID=$(lsb_release -rs | cut -d. -f1)
      FULL_VERSION_ID=$(lsb_release -rs)
    else
      [ -f /etc/redhat-release ] && {
        LINUX_KIND=$(cat /etc/redhat-release | cut -d' ' -f1)
        LINUX_KIND=${LINUX_KIND,,}
        VERSION_ID=$(cat /etc/redhat-release | cut -d' ' -f3 | cut -d. -f1)
        FULL_VERSION_ID=$(cat /etc/redhat-release | cut -d' ' -f3)
        case $VERSION_ID in
        '' | *[!0-9]*)
          VERSION_ID=$(cat /etc/redhat-release | cut -d' ' -f4 | cut -d. -f1)
          FULL_VERSION_ID=$(cat /etc/redhat-release | cut -d' ' -f4)
          ;;
        *) ;;

        esac
      }
    fi
    FACTS["linux_kind"]=${LINUX_KIND,,}
    FACTS["linux_version"]=$VERSION_ID
    FACTS["distrib_version"]=$VERSION_ID
  fi

  # Some facts about system
  case ${FACTS["linux_kind"]} in
  redhat | rhel | centos | fedora)
    FACTS["redhat_like"]=1
    FACTS["debian_like"]=0
    FACTS["docker_version"]=$(rpm -qi docker-ce 2> /dev/null | grep "^Version" | cut -d: -f2 || true)
    ;;
  debian | ubuntu)
    FACTS["redhat_like"]=0
    FACTS["debian_like"]=1
    FACTS["docker_version"]=$(apt show docker-ce 2> /dev/null | grep "^Version" | cut -d: -f3 | cut -d~ -f1 || true)
    ;;
  esac
  if systemctl | grep '\-.mount' &> /dev/null; then
    FACTS["use_systemd"]=1
  else
    FACTS["use_systemd"]=0
  fi

  # Some facts about hardware
  val=$(LANG=C lscpu | grep "Socket(s)" | cut -d: -f2 | sed 's/"//g')
  FACTS["sockets"]=${val//[[:blank:]]/}
  val=$(LANG=C lscpu | grep "Core(s) per socket" | cut -d: -f2 | sed 's/"//g')
  FACTS["cores/socket"]=${val//[[:blank:]]/}
  FACTS["cores"]=$((${FACTS["sockets"]} * ${FACTS["cores/socket"]}))
  val=$(LANG=C lscpu | grep "Thread(s) per core" | cut -d: -f2 | sed 's/"//g')
  FACTS["threads/core"]=${val//[[:blank:]]/}
  FACTS["threads"]=$((${FACTS["cores"]} * ${FACTS["threads/core"]}))
  val=$((${FACTS["threads"]} * 2 / 3))
  [ $val -le 0 ] && val=1
  FACTS["2/3_of_threads"]=$val

  sfProbeGPU

  if which docker &> /dev/null; then
    FACTS["docker_version"]=$(docker version {{ "--format '{{.Server.Version}}'" }} || true)

    # Some facts about installed features
    id=$(docker ps --filter "name=edgeproxy4subnet_proxy_1" {{ "--format '{{.ID}}'" }} 2> /dev/null || true)
    # legacy...
    [ -z "$id" ] && id=$(docker ps --filter "name=kong4gateway_proxy_1" {{ "--format '{{.ID}}'" }} 2> /dev/null || true)
    [ -z "$id" ] && id=$(docker ps --filter "name=kong_proxy_1" {{ "--format '{{.ID}}'" }} 2> /dev/null || true)
    FACTS["edgeproxy4subnet_docker_id"]=$id

    # VPL: not used anymore
    #		id=$(docker ps --filter "name=ingress4platform_server_1" {{ "--format '{{.ID}}'" }} 2>/dev/null || true)
    #		FACTS["ingress4platform_docker_id"]=$id
    #
    #		id=$(docker ps {{ "--format '{{.Names}}:{{.ID}}'" }} 2>/dev/null | grep postgresql4platform_db | cut -d: -f2 || true)
    #		FACTS["postgresql4platform_docker_id"]=$id
    #
    #		id=$(docker ps {{ "--format '{{.Names}}:{{.ID}}'" }} 2>/dev/null | grep keycloak4platform_server | cut -d: -f2 || true)
    #		FACTS["keycloak4platform_docker_id"]=$id
  fi

  # "Serialize" facts to file
  declare -p FACTS > "${SERIALIZED_FACTS}"
  return 0
}
export -f sfDetectFacts

function sfGetFact() {
  [ $# -eq 0 ] && return
  source "$SERIALIZED_FACTS"
  [ ${FACTS[$1]+x} ] && echo -n ${FACTS[$1]}
}
export -f sfGetFact

# Waits the completion of the execution of userdata
function waitForUserdata() {
  while true; do
    [ -f ${SF_VARDIR}/state/user_data.netsec.done ] && break
    # legacy: v20.06 and before
    [ -f ${SF_VARDIR}/state/user_data.phase2.done ] && break
    echo "Waiting userdata completion..."
    sleep 5
  done
}
export -f waitForUserdata

# .bats files are only on dev environments
if [ ! -f ./bash_library.bats ]; then
  set -x
  waitForUserdata
  sfDetectFacts
fi
