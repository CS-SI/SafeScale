#!/bin/bash
WRKDIR=$(readlink -f $(dirname "$0"))

if [ -z "$1" ]
then
  echo "First parameter must be a tenant name..."
  exit 1
else
  grep name.=..$1 tenants.toml || echo "Tenant $1 not found in tenants.toml"
  grep name.=..$1 tenants.toml || exit 1
  export TENANT=$1
fi

if [ ! -z "$2" ]
then
  if [[ $2 == "-f" ]]; then
    date > markerCi
  fi
fi

stamp=`date +"%s"`

if [ ! -f ./markerCi ]; then
	curl https://api.github.com/repos/CS-SI/SafeScale/commits/$(git rev-parse --abbrev-ref HEAD) 2>&1 | grep '"date"' | tail -n 1 > ./markerCi
else
  curl https://api.github.com/repos/CS-SI/SafeScale/commits/$(git rev-parse --abbrev-ref HEAD) 2>&1 | grep '"date"' | tail -n 1 > ./newMarkerCi
  diff ./markerCi ./newMarkerCi 1>/dev/null && rm ./newMarkerCi && echo "Nothing to do !, if you want to force a ci test lauch with -f flag" && exit 0
fi

THISBRANCH=local-$(git rev-parse --abbrev-ref HEAD | sed 's#/#\-#g') TENANT=$1 envsubst <Dockerfile.ci > Dockerfile.cibranch-$1
docker build --rm --network host --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy -f ${WRKDIR}/Dockerfile.cibranch-$1 -t safescale-ci:$(git rev-parse --abbrev-ref HEAD | sed 's#/#\-#g')-$1 $WRKDIR
RC=$?
[ $RC -ne 0 ] && echo "CI failed !!" && rm -f ./markerCi

mkdir -p ./ci-logs/$stamp

docker create -ti --name dummy-$1 safescale-ci:$(git rev-parse --abbrev-ref HEAD | sed 's#/#\-#g')-$1 bash
[ $? -ne 0 ] && echo "Failure extracting logs 1/3" && exit 1
docker cp dummy-$1:/root/.safescale ci-logs/$stamp
[ $? -ne 0 ] && echo "Failure extracting logs 2/3" && exit 1
docker rm -f dummy-$1
[ $? -ne 0 ] && echo "Failure extracting logs 3/3" && exit 1

echo "CI OK"

if [ -f ./newMarkerCi ]; then
  mv ./newMarkerCi ./markerCi
fi

rm -f ./Dockerfile.cibranch-$1

exit 0