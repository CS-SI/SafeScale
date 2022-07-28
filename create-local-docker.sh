#!/bin/bash

WRKDIR=$(readlink -f $(dirname "$0") >/dev/null 2>&1)

if [ ! -z "$1" ]
then
  if [[ $1 == "-f" ]]; then
    date > marker
  fi
fi

if [ -z "$WRKDIR" ]
then
  WRKDIR=.
fi

VERNAME=$(git rev-parse --abbrev-ref HEAD | awk -F/ '{print $NF}')

if [ ! -f ./marker ]; then
  curl https://api.github.com/repos/CS-SI/SafeScale/commits/$VERNAME 2>&1 | grep '"date"' | tail -n 1 > ./marker
else
  curl https://api.github.com/repos/CS-SI/SafeScale/commits/$VERNAME 2>&1 | grep '"date"' | tail -n 1 > ./newMarker
  diff ./marker ./newMarker && rm ./newMarker || mv ./newMarker ./marker
fi

stamp=`date +"%s"`

[ -z "$GOVERSION" ] && GOVERSION=1.17.12
[ -z "$PROTOVERSION" ] && PROTOVERSION=3.17.3

BRANCH_NAME=$VERNAME PROTOVERSION=$PROTOVERSION GOVERSION=$GOVERSION envsubst <Dockerfile.local > Dockerfile.$stamp
docker build --rm --network host --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy -f ${WRKDIR}/Dockerfile.$stamp -t safescale:local-$VERNAME ${WRKDIR}
if [ $? -ne 0 ]; then
  echo "Docker build failed !!"
  rm -f ./marker
  rm -f ./Dockerfile.$stamp
  exit 1
fi

echo "Docker build OK"

docker create -ti --name dummy safescale:local-$VERNAME bash
if [ $? -ne 0 ]; then
  echo "Failure extracting binaries 1/3"
  exit 1
fi

docker cp dummy:/exported .
if [ $? -ne 0 ]; then
  echo "Failure extracting binaries 2/3"
  exit 1
fi

docker rm -f dummy
if [ $? -ne 0 ]; then
  echo "Failure extracting binaries 3/3"
  exit 1
fi

rm -f ./Dockerfile.$stamp

echo "Binaries extracted successfully"
exit 0
