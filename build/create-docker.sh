#!/bin/sh
WRKDIR=$(readlink -f $(dirname "$0"))
docker build --rm --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy -f ${WRKDIR}/Dockerfile -t safescale:latest ${WRKDIR}
