#! /bin/sh

# ----------------------
# Create working directory
# ----------------------
echo "Accessing working directory"
BRANCH_NAME=${BRANCH_NAME:="firewalld-issue"}
WRKDIR=${GOPATH=/go}/src/github.com/CS-SI
cd ${WRKDIR}

cd SafeScale
sed -i "s/\(.*\)develop/\1${BRANCH_NAME}/" common.mk

# ----------------------
# Compile
# ----------------------
echo "Get dev deps"
make getdevdeps
[ $? -ne 0 ] && echo "Build getdevdeps failure" && return 1

echo "Ensure"
make ensure
[ $? -ne 0 ] && echo "Build ensure failure" && return 1

echo "All"
make all
[ $? -ne 0 ] && echo "Build failure" && return 1

echo "Install"
make install
[ $? -ne 0 ] && echo "Install failure" && return 1

echo "Export"
export CIBIN=/exported
mkdir -p /exported

CIBIN=/exported make installci
[ $? -ne 0 ] && echo "Export failure" && return 1

return 0