#!/bin/sh
WRKDIR=$(readlink -f $(dirname "$0"))

VERNAME=$(git rev-parse --abbrev-ref HEAD | awk -F/ '{print $NF}')

if [ ! -f ./marker ]; then
  curl https://api.github.com/repos/CS-SI/SafeScale/commits/$VERNAME 2>&1 | grep '"date"' | tail -n 1 > ./marker
else
  curl https://api.github.com/repos/CS-SI/SafeScale/commits/$VERNAME 2>&1 | grep '"date"' | tail -n 1 > ./newMarker
  diff ./marker ./newMarker && rm ./newMarker || mv ./newMarker ./marker
fi

docker build --rm --network host --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy -f ${WRKDIR}/Dockerfile.local -t safescale:local-$VERNAME ${WRKDIR}
[ $? -ne 0 ] && echo "Docker build failed !!" && rm -f ./marker && return 1

echo "Docker build OK"

docker create -ti --name dummy safescale:local-$VERNAME bash
[ $? -ne 0 ] && echo "Failure extracting binaries 1/3" && return 1
docker cp dummy:/exported .
[ $? -ne 0 ] && echo "Failure extracting binaries 2/3" && return 1
docker rm -f dummy
[ $? -ne 0 ] && echo "Failure extracting binaries 3/3" && return 1

echo "Binaries extracted successfully"
return 0