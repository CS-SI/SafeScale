#!/bin/sh
WRKDIR=$(readlink -f $(dirname "$0"))

if [ ! -f ./marker ]; then
	curl https://api.github.com/repos/CS-SI/SafeScale/commits/$(git rev-parse --abbrev-ref HEAD) 2>&1 | grep '"date"' | tail -n 1 > ./marker
else
  curl https://api.github.com/repos/CS-SI/SafeScale/commits/$(git rev-parse --abbrev-ref HEAD) 2>&1 | grep '"date"' | tail -n 1 > ./newMarker
  diff ./marker ./newMarker 1>/dev/null && rm ./newMarker && echo "Nothing to do" && exit 0
fi

docker build --rm --network host --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy -f ${WRKDIR}/Dockerfile -t safescale:$(git rev-parse --abbrev-ref HEAD) $WRKDIR
[ $? -ne 0 ] && echo "Docker build failed !!" && rm -f ./marker && exit 1

echo "Docker build OK"

docker create -ti --name dummy safescale:$(git rev-parse --abbrev-ref HEAD) bash
[ $? -ne 0 ] && echo "Failure extracting binaries 1/3" && exit 1
docker cp dummy:/exported .
[ $? -ne 0 ] && echo "Failure extracting binaries 2/3" && exit 1
docker rm -f dummy
[ $? -ne 0 ] && echo "Failure extracting binaries 3/3" && exit 1

echo "Binaries extracted successfully"
if [ -f ./newMarker ]; then
  mv ./newMarker ./marker
fi

exit 0