#!/usr/bin/env bash

# wait_for_apt waits an already running apt-like command to finish
function wait_for_apt() {
    local ROUNDS=60

    if fuser /var/{lib/{dpkg,apt/lists},cache/apt/archives}/lock &>/dev/null; then
        echo "apt is locked, waiting... "
        local i
        for i in $(seq $ROUNDS); do
            sleep 60
            fuser /var/{lib/{dpkg,apt/lists},cache/apt/archives}/lock &>/dev/null || break
        done
        if [ $i -ge $ROUNDS ]; then
            echo "Timed out waiting (1 hour!) for apt lock!"
            exit 100
        else
            echo "apt is unlocked (waited $i mn), continuing."
        fi
    fi
}

# Convert netmask to CIDR
function netmask2cidr() {
    # Assumes there's no "255." after a non-255 byte in the mask
    local x=${1##*255.}
    set -- 0^^^128^192^224^240^248^252^254^ $(( (${#1} - ${#x})*2 )) ${x%%.*}
    x=${1%%$3*}
    echo $(( $2 + (${#x}/4) ))
}

# Convert CIDR to netmask
function cidr2netmask() {
    local m=${1#*/}
    local v=$(( 0xffffffff ^ ((1 << (32 - $m)) - 1) ))
    echo "$(( (v >> 24) & 0xff )).$(( (v >> 16) & 0xff )).$(( (v >> 8) & 0xff )).$(( v & 0xff ))"
}

# Convert CIDR to network
function cidr2network() {
    local ip=${1%%/*}
    local mask=$(cidr2netmask $1)
    IFS=. read -r m1 m2 m3 m4 <<< $mask
    IFS=. read -r o1 o2 o3 o4 <<< $ip
    echo $(($o1 & $m1)).$(($o2 & $m2)).$(($o3 & $m3)).$(($o4 & $m4))
}

# Convert CIDR to broadcast
function cidr2broadcast() {
    local ip=${1%%/*}
    local mask=$(cidr2netmask $1)
    IFS=. read -r m1 m2 m3 m4 <<< $mask
    IFS=. read -r o1 o2 o3 o4 <<< $ip
    echo $(($o1+(255-($o1 | $m1)))).$(($o2+(255-($o2 | $m2)))).$(($o3+(255-($o3 | $m3)))).$(($o4+(255-($o4 | $m4))))
}

# Determines the kind of Linux distribution
export LINUX_KIND=$(cat /etc/os-release | grep "^ID=" | cut -d= -f2 | sed 's/"//g')