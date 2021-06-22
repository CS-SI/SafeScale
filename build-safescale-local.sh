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

echo "mod"
make mod

echo "Make All"
make all
[ $? -ne 0 ] && echo "Build failure" && exit 1

echo "Install"
make install
[ $? -ne 0 ] && echo "Install failure" && exit 1

echo "Export"
export CIBIN=/exported
mkdir -p /exported

CIBIN=/exported make installci
[ $? -ne 0 ] && echo "Export failure" && exit 1

exit 0
