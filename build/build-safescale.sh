#! /bin/sh

# ----------------------
# Create working directory
# ----------------------
echo "Create working directory"
WRKDIR=${GOPATH=/go}/src/github.com/CS-SI
mkdir -p ${WRKDIR}
cd ${WRKDIR}
rm -rf SafeScale

# ----------------------
# Get source code
# ----------------------
echo "Get source code"
BRANCH_NAME=${BRANCH_NAME:="firewalld-issue"}
GIT_REPO_URL=${GIT_REPO_URL:="https://github.com/CS-SI/SafeScale.git"}
echo "Cloning branch '${BRANCH_NAME}' from repo '${GIT_REPO_URL}'"

git clone ${GIT_REPO_URL} -b ${BRANCH_NAME} --depth=1

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