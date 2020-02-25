#!/bin/sh
WRKDIR=$(readlink -f $(dirname "$0"))

if [ ! -f ./marker ]; then
    date > ./marker
fi

docker build --rm --network host --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy -f ${WRKDIR}/Dockerfile -t safescale:latest ${WRKDIR}

docker create -ti --name dummy safescale bash
docker cp dummy:/exported .
docker rm -f dummy
