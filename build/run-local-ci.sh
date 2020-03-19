#!/bin/bash

SECONDS=0

function finish {
  ELAPSED="Elapsed: $(($SECONDS / 3600))hrs $((($SECONDS / 60) % 60))min $(($SECONDS % 60))sec"
  echo $ELAPSED
}

trap finish EXIT

WRKDIR=$(readlink -f $(dirname "$0"))

if [ -z "$1" ]
then
  echo "First parameter must be a tenant name..."
  exit 1
else
  grep name.=..$1 tenants.toml 1>/dev/null || echo "Tenant $1 not found in tenants.toml"
  grep name.=..$1 tenants.toml 1>/dev/null || exit 1
  export TENANT=$1
fi

if [ -z "$2" ]
then
  echo "Second parameter is cluster type..."
  exit 1
else
  export CLUTYPE=$2
fi

if [ -z "$3" ]
then
  echo "Third parameter is os..."
  exit 1
else
  export OSTESTED=$3
fi

if [ ! -z "$4" ]
then
  if [[ $4 == "-f" ]]; then
    date > markerCi-$1-$2
  fi
fi

stamp=`date +"%s"`

if [ ! -f ./markerCi-$1-$2 ]; then
	curl https://api.github.com/repos/CS-SI/SafeScale/commits/$(git rev-parse --abbrev-ref HEAD) 2>&1 | grep '"date"' | tail -n 1 > ./markerCi-$1-$2
else
  curl https://api.github.com/repos/CS-SI/SafeScale/commits/$(git rev-parse --abbrev-ref HEAD) 2>&1 | grep '"date"' | tail -n 1 > ./newMarkerCi-$1-$2
  diff ./markerCi-$1-$2 ./newMarkerCi-$1-$2 1>/dev/null && rm ./newMarkerCi-$1-$2 && echo "Nothing to do !, if you want to force a ci test lauch with -f flag" && exit 0
fi

THISBRANCH=local-$(git rev-parse --abbrev-ref HEAD | sed 's#/#\-#g') TENANT=$1 CLUTYPE=$2 OSTESTED="$3" envsubst <Dockerfile.ci > Dockerfile.cibranch-$1-$2
docker build --rm --network host --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy -f ${WRKDIR}/Dockerfile.cibranch-$1-$2 -t safescale-ci:$(git rev-parse --abbrev-ref HEAD | sed 's#/#\-#g')-$1-$2 $WRKDIR
RC=$?
if [ $RC -ne 0 ]; then
  echo "CI failed !!"
  rm -f ./Dockerfile.cibranch-$1-$2
  rm -f ./markerCi-$1-$2
  exit 1
fi

mkdir -p ./ci-logs/$stamp

docker create -ti --name dummy-$1-$2 safescale-ci:$(git rev-parse --abbrev-ref HEAD | sed 's#/#\-#g')-$1-$2 bash
[ $? -ne 0 ] && echo "Failure extracting logs 1/3" && exit 1
docker cp dummy-$1-$2:/root/.safescale ci-logs/$stamp
[ $? -ne 0 ] && echo "Failure extracting logs 2/3" && exit 1
docker rm -f dummy-$1-$2
[ $? -ne 0 ] && echo "Failure extracting logs 3/3" && exit 1

if [ -f ./newMarkerCi-$1-$2 ]; then
  mv ./newMarkerCi-$1-$2 ./markerCi-$1-$2
fi

rm -f ./Dockerfile.cibranch-$1-$2

docker rmi safescale-ci:$(git rev-parse --abbrev-ref HEAD | sed 's#/#\-#g')-$1-$2

if [ ! -f ./ci-logs/$stamp/.safescale/success ]; then
  echo "CI FAILED"
  rm -f ./ci-logs/success-$1-$2
  touch ./ci-logs/failure-$1-$2
  exit 1
else
  echo "CI OK"
  rm -f ./ci-logs/failure-$1-$2
  touch ./ci-logs/success-$1-$2
fi

exit 0
