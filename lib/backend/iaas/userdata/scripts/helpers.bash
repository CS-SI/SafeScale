#!/bin/bash -x

function versionchk() { echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'; }
export -f versionchk

function checkVersion() {
  case $3 in
  ">")
    if [ $(versionchk "$1") -gt $(versionchk "$2") ]; then
      return 0
    fi
    return 1
    ;;
  ">=")
    if [ $(versionchk "$1") -ge $(versionchk "$2") ]; then
      return 0
    fi
    return 1
    ;;
  "=")
    if [ $(versionchk "$1") -eq $(versionchk "$2") ]; then
      return 0
    fi
    return 1
    ;;
  "<")
    if [ $(versionchk "$1") -lt $(versionchk "$2") ]; then
      return 0
    fi
    return 1
    ;;
  "<=")
    if [ $(versionchk "$1") -le $(versionchk "$2") ]; then
      return 0
    fi
    return 1
    ;;
  esac
}
export -f checkVersion

function MyIP() {
  MYIP="$(ip -br a | grep UP | awk '{print $3}') | head -n 1"
  echo -n "$MYIP"
}
export -f MyIP