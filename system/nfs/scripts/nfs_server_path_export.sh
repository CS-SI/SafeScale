#!/usr/bin/env bash
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
#
# nfs_server_path_export.sh
#
# Configures the NFS export of a local path

# Determines the FSID value to use
FSIDs=$(cat /etc/exports | sed -r 's/ /\n/g' | grep fsid= | sed -r 's/.+fsid=([[:alnum:]]+),.*/\1/g' | uniq | sort -n)
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
    ACL=$(echo $ACCESS_RIGHTS | sed -r 's/\((.*)\)')
    if [ ! -z "$ACL" ]; then
        # If there is something between parenthesis, checks if there is some fsid directive, and check the values
        # are not already used for other shares
        ACL_FSIDs=$(echo $ACL | sed -r 's/ /\n/g' | grep fsid= | sed -r 's/.+fsid=([[:alnum:]]+),.*/\1/g' | uniq | sort -n)
        for f in $ACL_FSIDs; do
            echo $FSIDs | grep "^${f}$" && {
                # FSID value is already used, updating the Access Rights to use the calculated new FSID
                FILTERED_ACCESS_RIGHTS=$(echo $ACCESS_RIGHTS | sed -r 's/fsid=[[:numeric:]]*/fsid=$FSID/g')
            }
            break
        done
        if [ -z $FILTERED_ACCESS_RIGHTS ]; then
            # No updated access rights, with something between parenthesis, adding fsid= directive
            FILTERED_ACCESS_RIGHTS=$(echo $ACCESS_RIGHTS | sed -r 's/\)/,fsid=$FSID\)/g')
        fi
    else
        # No updated access rights without anything between parenthesis, adding fsid= directive
        FILTERED_ACCESS_RIGHTS=$(echo $ACCESS_RIGHTS | sed -r 's/\)/fsid=$FSID/g')
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
