#!/usr/bin/env bash

if [ "$(uname -s)" = "Darwin" ]; then
    WRKDIR=$(readlink -n $(dirname "$0"))
    [ -z "$WRKDIR" ] && WRKDIR=$(dirname "$0")
else
WRKDIR=$(readlink -f $(dirname "$0"))
fi

[ -z "$GOVERSION" ] && GOVERSION=1.16.8
echo docker build --rm --network host --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy --build-arg BRANCH_NAME=$BRANCH_NAME --build-arg GOVERSION=$GOVERSION -f ${WRKDIR}/Dockerfile.ci -t "safescale:ci" $WRKDIR
docker build --rm --network host --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy --build-arg BRANCH_NAME=$BRANCH_NAME --build-arg GOVERSION=$GOVERSION -f ${WRKDIR}/Dockerfile.ci -t "safescale:ci" $WRKDIR
[ $? -ne 0 ] && echo "Docker build failed !!" && exit 1

echo "Docker CI image build OK"

exit 0
