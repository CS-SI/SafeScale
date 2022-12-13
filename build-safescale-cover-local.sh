#! /bin/bash

echo "Checks..."
if [[ ! -v BUILD_ENV ]]; then
    echo "BUILD_ENV is not set, this script is intended to run inside a docker container"
    [[ $SHLVL -gt 2 ]] && return 1 || exit 1
fi

# ----------------------
# Create working directory
# ----------------------
echo "Accessing working directory"
BRANCH_NAME=${BRANCH_NAME:="develop"}
WRKDIR=${GOPATH=/go}
cd ${WRKDIR}

cd SafeScale
sed -i "s#\(.*\)develop#\1${BRANCH_NAME}#" common.mk

# ----------------------
# Compile
# ----------------------

echo "deps"
make getdevdeps

sleep 4

echo "mod"
make mod

sleep 4

make sdk

sleep 4

make force_sdk_python

sleep 4

make force_sdk_js

sleep 4

make generate

sleep 4

echo "Make All with coverage"
make allcover
[ $? -ne 0 ] && echo "Build failure" && exit 1

echo "Install"
make install
[ $? -ne 0 ] && echo "Install failure" && exit 1

echo "Export"
export CIBIN=/exported
mkdir -p /exported

CIBIN=/exported make installci force_sdk_python force_sdk_js
[ $? -ne 0 ] && echo "Export failure" && exit 1

cp ${WRKDIR}/SafeScale/go.mod /exported
cp ${WRKDIR}/SafeScale/go.sum /exported
cp ${WRKDIR}/SafeScale/lib/protocol/javascript/* /exported
cp ${WRKDIR}/SafeScale/lib/protocol/python3/* /exported

exit 0
