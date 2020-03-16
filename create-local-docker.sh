#!/bin/bash

WRKDIR=$(readlink -f $(dirname "$0"))

if [ ! -f ./marker ]; then
  curl https://api.github.com/repos/CS-SI/SafeScale/commits/$(git rev-parse --abbrev-ref HEAD) 2>&1 | grep '"date"' | tail -n 1 > ./marker
else
  curl https://api.github.com/repos/CS-SI/SafeScale/commits/$(git rev-parse --abbrev-ref HEAD) 2>&1 | grep '"date"' | tail -n 1 > ./newMarker
  diff ./marker ./newMarker 1>/dev/null && rm ./newMarker || mv ./newMarker ./marker
fi

stamp=`date +"%s"`

BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD) envsubst <Dockerfile.local > Dockerfile.$stamp
docker build --rm --network host --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy -f ${WRKDIR}/Dockerfile.$stamp -t safescale:local-$(git rev-parse --abbrev-ref HEAD | sed 's#/#\-#g') ${WRKDIR}
if [ $? -ne 0 ]; then
  echo "Docker build failed !!"
  rm -f ./marker
  rm -f ./Dockerfile.$stamp
  exit 1
fi

echo "Docker build OK"

docker create -ti --name dummy safescale:local-$(git rev-parse --abbrev-ref HEAD | sed 's#/#\-#g') bash
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
