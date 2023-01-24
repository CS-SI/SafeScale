#!/usr/bin/env bash

if [ "$(uname -s)" = "Darwin" ]; then
	WRKDIR=$(readlink -n $(dirname "$0"))
	[ -z "$WRKDIR" ] && WRKDIR=$(dirname "$0")
else
	WRKDIR=$(readlink -f $(dirname "$0"))
fi

stamp=$(date +"%s")

[ -z "$BRANCH_NAME" ] && BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD)
[ -z "$GOVERSION" ] && GOVERSION=1.18.4
[ -z "$PROTOVERSION" ] && PROTOVERSION=3.17.3

[ -z "$TENANT" ] && {
	echo "You must specify a TENANT= prefix"
	exit 1
}

[ -z "$CLUTYPE" ] && {
	echo "You must specify a CLUTYPE= prefix"
	exit 1
}

[ -z "$OSTESTED" ] && {
	echo "You must specify a OSTESTED= prefix"
	exit 1
}

[ -z "$CLUSIZE" ] && {
	echo "You must specify a CLUSIZE= prefix"
	exit 1
}

BRANCH_NAME=${BRANCH_NAME/\//_} PROTOVERSION=$PROTOVERSION GOVERSION=$GOVERSION envsubst <Dockerfile.ci >Dockerfile.ci.$stamp
echo docker build --rm --network host --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy --build-arg BRANCH_NAME=${BRANCH_NAME/\//_} --build-arg GOVERSION=$GOVERSION -f ${WRKDIR}/Dockerfile.ci.$stamp -t "safescale:ci" $WRKDIR
docker build --rm --network host --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy --build-arg BRANCH_NAME=${BRANCH_NAME/\//_} --build-arg GOVERSION=$GOVERSION -f ${WRKDIR}/Dockerfile.ci.$stamp -t "safescale:ci" $WRKDIR
[ $? -ne 0 ] && {
	echo "Docker build failed !!"
	rm -f ./Dockerfile.ci.$stamp
	exit 1
}

echo "Docker CI image build OK"
rm -f ./Dockerfile.ci.$stamp

exit 0
