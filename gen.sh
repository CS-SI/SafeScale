#!/usr/bin/env bash
   
# Get safescale directory
SCDIR="$(dirname "$(readlink -f "$0")")"
   
echo "Generating rice boxes"
echo " - openstack"
cd ${SCDIR}/providers/openstack
rice embed-go
echo " - brokerd"
cd ${SCDIR}/broker/brokerd/commands
rice embed-go
  
echo "Generating protocol buffer"
cd ${SCDIR}/broker
${SCDIR}/broker/gen.sh
   
echo "Generating executables"
echo " - brokerd"
cd ${SCDIR}/broker/brokerd
go build
echo " - broker"
cd ${SCDIR}/broker/broker
go build