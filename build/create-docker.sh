#!/usr/bin/env bash

if [ "$(uname -s)" = "Darwin" ]; then
	WRKDIR=$(readlink -n $(dirname "$0"))
	[ -z "$WRKDIR" ] && WRKDIR=$(dirname "$0")
else
	WRKDIR=$(readlink -f $(dirname "$0"))
fi

if [ ! -z "$1" ]; then
	if [[ $1 == "-f" ]]; then
		date >marker
	fi
fi

if [ ! -f ./marker ]; then
	curl https://api.github.com/repos/CS-SI/SafeScale/commits/$(git rev-parse --abbrev-ref HEAD) 2>&1 | grep '"date"' | tail -n 1 >./marker
else
	curl https://api.github.com/repos/CS-SI/SafeScale/commits/$(git rev-parse --abbrev-ref HEAD) 2>&1 | grep '"date"' | tail -n 1 >./newMarker
	diff ./marker ./newMarker 1>/dev/null && rm ./newMarker && echo "Nothing to do !, if you want to force a docker build launch with the -f flag" && exit 0
fi

stamp=$(date +"%s")

[ -z "$BRANCH_NAME" ] && BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD)
[ -z "$GOVERSION" ] && GOVERSION=1.17.12
[ -z "$PROTOVERSION" ] && PROTOVERSION=3.17.3

BRANCH_NAME=$BRANCH_NAME PROTOVERSION=$PROTOVERSION GOVERSION=$GOVERSION COMMITSHA=$COMMITSHA envsubst <Dockerfile >Dockerfile.$stamp
if [ -z "$COMMITSHA" ]
then
	sed -i '/ENV COMMITSHA/d' Dockerfile.$stamp
fi

echo docker build --rm --network host --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy --build-arg BRANCH_NAME=$BRANCH_NAME --build-arg GOVERSION=$GOVERSION -f ${WRKDIR}/Dockerfile.$stamp -t "safescale:${BRANCH_NAME/\//_}" $WRKDIR
docker build --rm --network host --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy --build-arg BRANCH_NAME=$BRANCH_NAME --build-arg GOVERSION=$GOVERSION -f ${WRKDIR}/Dockerfile.$stamp -t "safescale:${BRANCH_NAME/\//_}" $WRKDIR
[ $? -ne 0 ] && echo "Docker build failed !!" && {
	rm -f ./marker
	rm -f ./Dockerfile.$stamp
	exit 1
}

echo "Docker build OK"

docker create -ti --name dummy "safescale:${BRANCH_NAME/\//_}" bash
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
