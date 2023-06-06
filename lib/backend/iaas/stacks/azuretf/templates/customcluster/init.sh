#!/bin/bash
set -Eeuo pipefail

function change_centos_route() {
  #if route is not installed, use ip instead
  if ! [ -x "$(command -v route)" ]; then
    #delete the default route
    sudo ip route del default
    sudo ip route add default via {{.DefaultGateway}}
  else
    #delete the default route
    sudo route del default
    sudo route add default gw {{.DefaultGateway}}
  fi
}

function change_route() {
  #if this is centos, we need to change the route
  if [ -f /etc/redhat-release ]; then
    change_centos_route
  fi

  #if this is ubuntu or debian, we need to change the route
  if [ -f /etc/lsb-release ]; then
    change_ubuntu_route
  fi
}
export -f change_route

#if neither route nor ip is installed, log an error
if ! [ -x "$(command -v route)" ] && ! [ -x "$(command -v ip)" ]; then
  echo "Neither route nor ip is installed, cannot change the default route"
fi

exit 0