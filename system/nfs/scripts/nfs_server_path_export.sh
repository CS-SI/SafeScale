#!/usr/bin/env bash
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
#
# nfs_server_path_export.sh
#
# Configures the NFS export of a local path

set -u -o pipefail

function print_error {
    read line file <<<$(caller)
    echo "An error occurred in line $line of file $file:" "{"`sed "${line}q;d" "$file"`"}" >&2
}
trap print_error ERR

function dns_fallback {
    grep nameserver /etc/resolv.conf && return 0
    echo -e "nameserver 1.1.1.1\n" > /tmp/resolv.conf
    sudo cp /tmp/resolv.conf /etc/resolv.conf
    return 0
}

dns_fallback

# Determines the FSID value to use
FSIDs=$(cat /etc/exports | sed -r 's/ /\n/g' | sed -r 's/,/\n/g' | grep fsid= | grep -o [0-9]* | uniq | sort -n)
LAST_FSID=$(echo "$FSIDs" | tail -n 1)
if [ -z "$LAST_FSID" ]; then
    FSID=1
else
    FSID=$((LAST_FSID + 1))
fi

# Adapts ACL
ACCESS_RIGHTS="{{.AccessRights}}"
FILTERED_ACCESS_RIGHTS=
if [ -z "$ACCESS_RIGHTS" ]; then
    # No access rights, using default ones
    FILTERED_ACCESS_RIGHTS="*(rw,fsid=$FSID,sync,no_root_squash,no_subtree_check)"
else
    # Wants to ensure FSID is valid otherwise updates it
    ACL=$(echo $ACCESS_RIGHTS | sed "s/.*(\(.*\))/\1/")
    if [ ! -z "$ACL" ]; then
        # If there is something between parenthesis, checks if there is some fsid directive, and check the values
        # are not already used for other shares
        ACL_FSIDs=$(echo $ACL | sed -r 's/ /\n/g' | sed -r 's/,/\n/g' | grep fsid= | grep -o [0-9]* | uniq | sort -n)
        for fsid in $ACL_FSIDs; do
            echo $FSIDs | grep "^${fsid}" && {
                # FSID value is already used, updating the Access Rights to use the calculated new FSID
                FILTERED_ACCESS_RIGHTS=$(echo $ACCESS_RIGHTS | sed -r "s/fsid=[[:numeric:]]*/fsid=$FSID/g")
            } && break
        done
        if [ -z $FILTERED_ACCESS_RIGHTS ]; then
            # No updated access rights, with something between parenthesis, adding fsid= directive
            FILTERED_ACCESS_RIGHTS=$(echo $ACCESS_RIGHTS | sed -r "s/\)/,fsid=$FSID)/g")
        fi
    else
        # No updated access rights without anything between parenthesis, adding fsid= directive
        FILTERED_ACCESS_RIGHTS=$(echo $ACCESS_RIGHTS | sed -r "s/\(\)/(fsid=$FSID)/g")
    fi
fi
#VPL: case not managed: nothing between braces...

# Create exported dir if necessary
mkdir -p "{{.Path}}"
chmod a+rwx "{{.Path}}"

# Configures export
echo "{{.Path}} $FILTERED_ACCESS_RIGHTS" >>/etc/exports

# Updates exports
exportfs -a
