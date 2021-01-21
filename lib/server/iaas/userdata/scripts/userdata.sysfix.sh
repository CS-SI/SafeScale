#!/bin/bash
#
# Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

{{.Header}}

function print_error() {
    read line file <<<$(caller)
    echo "An error occurred in line $line of file $file:" "{"`sed "${line}q;d" "$file"`"}" >&2
    {{.ExitOnError}}
}
trap print_error ERR

function fail() {
    echo "PROVISIONING_ERROR: $1"
    echo -n "$1,${LINUX_KIND},${VERSION_ID},$(hostname),$(date +%Y/%m/%d-%H:%M:%S)" >/opt/safescale/var/state/user_data.sysfix.done
    exit $1
}

# Redirects outputs to /opt/safescale/var/log/user_data.sysfix.log
LOGFILE=/opt/safescale/var/log/user_data.sysfix.log

### All output to one file and all output to the screen
exec > >(tee ${LOGFILE} /var/log/ss.log) 2>&1
set -x

# Tricks BashLibrary's waitUserData to believe the current phase 'sysfix' is already done (otherwise will deadlock)
>/opt/safescale/var/state/user_data.sysfix.done
# Includes the BashLibrary
{{ .BashLibrary }}
rm -f /opt/safescale/var/state/user_data.sysfix.done

# ---- Main

echo -n "0,linux,${LINUX_KIND},${VERSION_ID},$(hostname),$(date +%Y/%m/%d-%H:%M:%S)" >/opt/safescale/var/state/user_data.sysfix.done

set +x
exit 0
