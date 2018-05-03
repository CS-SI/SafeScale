#!/usr/bin/env bash
#
# nfs_server_path_export.sh
#
# Configures the NFS export of a local path

# Determines the FSID value to use
FSIDs=$(cat exports | sed -r 's/ /\n/g' | grep fsid= | sed -r 's/.+fsid=([[:alnum:]]+),.*/\1/g' | uniq | sort -n)
LAST_FSID=$(echo $FSIDs | tail -n 1)
if [ -z $LAST_FSID ]; then
    FSID=1
else
    FSID=$(( $LAST_FSID +1 ))
fi

# Adapts ACL
ACCESS_RIGHTS="{{.AccessRights}}"
FILTERED_ACCESS_RIGHTS=
if [ -z "$ACCESS_RIGHTS" ]; then
    # No access rights, using default ones
    FILTERED_ACCESS_RIGHTS="*(rw,fsid=$FSID,sync,no_root_squash)"
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
            FILTERED_ACCESS_RIGHTS=(echo $ACCESS_RIGHTS | sed -r 's/\)/,fsid=$FSID\)/g')
        fi
    else
        # No updated access rights without anything between parenthesis, adding fsid= directive
        FILTERED_ACCESS_RIGHTS=(echo $ACCESS_RIGHTS | sed -r 's/\)/fsid=$FSID/g')
    fi
fi
#VPL: cas non traité : rien entre parenthèse...

# Configures export
echo "{{.Path}} $FILTERED_ACCESS_RIGHTS" >>/etc/exports

# Updates exports
exportfs -a
