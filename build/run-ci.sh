#!/bin/bash
WRKDIR=$(readlink -f $(dirname "$0"))

if [ ! -f ./markerCi ]; then
	curl https://api.github.com/repos/CS-SI/SafeScale/commits/$(git rev-parse --abbrev-ref HEAD) 2>&1 | grep '"date"' | tail -n 1 > ./markerCi
else
  curl https://api.github.com/repos/CS-SI/SafeScale/commits/$(git rev-parse --abbrev-ref HEAD) 2>&1 | grep '"date"' | tail -n 1 > ./newMarkerCi
  diff ./markerCi ./newMarkerCi 1>/dev/null && rm ./newMarkerCi && echo "Nothing to do" && exit 0
fi

docker build --rm --network host --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy -f ${WRKDIR}/Dockerfile.ci -t safescale-ci:$(git rev-parse --abbrev-ref HEAD) $WRKDIR
RC=$?
[ $RC -ne 0 ] && echo "CI failed !!" && rm -f ./markerCi

docker create -ti --name dummy safescale-ci:$(git rev-parse --abbrev-ref HEAD) bash
[ $? -ne 0 ] && echo "Failure extracting logs 1/3" && exit 1
docker cp dummy:/root/.safescale ci-logs
[ $? -ne 0 ] && echo "Failure extracting logs 2/3" && exit 1
docker rm -f dummy
[ $? -ne 0 ] && echo "Failure extracting logs 3/3" && exit 1

echo "CI OK"

if [ -f ./newMarkerCi ]; then
  mv ./newMarkerCi ./markerCi
fi

exit 0