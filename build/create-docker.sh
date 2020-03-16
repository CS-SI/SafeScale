#!/bin/bash
WRKDIR=$(readlink -f $(dirname "$0"))

if [ ! -z "$1" ]
then
  if [[ $1 == "-f" ]]; then
    date > marker
  fi
fi

if [ ! -f ./marker ]; then
  curl https://api.github.com/repos/CS-SI/SafeScale/commits/$(git rev-parse --abbrev-ref HEAD) 2>&1 | grep '"date"' | tail -n 1 > ./marker
else
  curl https://api.github.com/repos/CS-SI/SafeScale/commits/$(git rev-parse --abbrev-ref HEAD) 2>&1 | grep '"date"' | tail -n 1 > ./newMarker
  diff ./marker ./newMarker 1>/dev/null && rm ./newMarker && echo "Nothing to do !, if you want to force a docker build launch with the -f flag" && exit 0
fi

stamp=`date +"%s"`

BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD) GOVERSION=1.13.5 envsubst <Dockerfile > Dockerfile.$stamp
docker build --rm --network host --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy -f ${WRKDIR}/Dockerfile.$stamp -t safescale:$(git rev-parse --abbrev-ref HEAD | sed 's#/#\-#g') $WRKDIR
[ $? -ne 0 ] && echo "Docker build failed !!" && rm -f ./marker && exit 1

echo "Docker build OK"

docker create -ti --name dummy safescale:$(git rev-parse --abbrev-ref HEAD | sed 's#/#\-#g') bash
[ $? -ne 0 ] && echo "Failure extracting binaries 1/3" && exit 1
docker cp dummy:/exported .
[ $? -ne 0 ] && echo "Failure extracting binaries 2/3" && exit 1
docker rm -f dummy
[ $? -ne 0 ] && echo "Failure extracting binaries 3/3" && exit 1

echo "Binaries extracted successfully"
if [ -f ./newMarker ]; then
  mv ./newMarker ./marker
fi

rm -f ./Dockerfile.$stamp

exit 0