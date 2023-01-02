#!/bin/bash -x
#
# Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

#{{.Revision}}
# Script customized for {{.ProviderName}} driver

# shellcheck disable=SC1009
# shellcheck disable=SC1073
# shellcheck disable=SC1054
{{.Header}}

last_error=

function print_error() {
  read -r line file <<< "$(caller)"
  echo "An error occurred in line $line of file $file:" "{$(sed "${line}q;d" "$file")}" >&2
  {{.ExitOnError}}
}
trap print_error ERR

function fail() {
  MYIP="$(ip -br a | grep UP | awk '{print $3}') | head -n 1"
  if [ $# -eq 1 ]; then
    echo "PROVISIONING_ERROR: $1"
    echo -n "$1,${LINUX_KIND},${VERSION_ID},$(hostname),$MYIP,$(date +%Y/%m/%d-%H:%M:%S),PROVISIONING_ERROR:$1" > /opt/safescale/var/state/user_data.sysfix.done
    (
      sync
      echo 3 > /proc/sys/vm/drop_caches
      sleep 2
    ) || true
    exit $1
  elif [ $# -eq 2 -a $1 -ne 0 ]; then
    echo "PROVISIONING_ERROR: $1, $2"
    echo -n "$1,${LINUX_KIND},${VERSION_ID},$(hostname),$MYIP,$(date +%Y/%m/%d-%H:%M:%S),PROVISIONING_ERROR:$2" > /opt/safescale/var/state/user_data.sysfix.done
    (
      sync
      echo 3 > /proc/sys/vm/drop_caches
      sleep 2
    ) || true
    exit $1
  fi
}
export -f fail

# Redirects outputs to /opt/safescale/var/log/user_data.sysfix.log
LOGFILE=/opt/safescale/var/log/user_data.sysfix.log

### All output to one file and all output to the screen
{{- if .Debug }}
if [[ -e /home/{{.Username}}/tss ]]; then
  exec > >(/home/{{.Username}}/tss | tee -a ${LOGFILE} /opt/safescale/var/log/ss.log) 2>&1
else
  exec > >(tee -a ${LOGFILE} /opt/safescale/var/log/ss.log) 2>&1
fi
{{- else }}
exec > >(tee -a ${LOGFILE} /opt/safescale/var/log/ss.log) 2>&1
{{- end }}

set -x

date

# Tricks BashLibrary's waitUserData to believe the current phase 'sysfix' is already done (otherwise will deadlock)
uptime > /opt/safescale/var/state/user_data.sysfix.done

# Includes the BashLibrary
# shellcheck disable=SC1009
# shellcheck disable=SC1073
# shellcheck disable=SC1054
{{ .reserved_BashLibrary }}
rm -f /opt/safescale/var/state/user_data.sysfix.done

# ---- Main
# ---- EndMain

echo -n "0,linux,${LINUX_KIND},${VERSION_ID},$(hostname),$(date +%Y/%m/%d-%H:%M:%S)" > /opt/safescale/var/state/user_data.sysfix.done

(
  sync
  echo 3 > /proc/sys/vm/drop_caches
  sleep 2
) || true

set +x
exit 0
