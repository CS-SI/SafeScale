#!/bin/sh
WRKDIR=$(readlink -f $(dirname "$0"))
docker build --rm -f ${WRKDIR}/Dockerfile -t safescale:latest ${WRKDIR}