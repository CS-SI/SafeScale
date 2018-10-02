#!/bin/sh
WRKDIR=$(readlink -f $(dirname "$0"))
docker build --rm -f ${WRKDIR}/DockerfileTest -t safescale-test:latest ${WRKDIR}