#! /bin/bash

echo "Checks..."
if [[ ! -v BUILD_ENV ]]; then
    echo "BUILD_ENV is not set, this script is intended to run inside a docker container"
    [[ $SHLVL -gt 2 ]] && return 1 || exit 1
fi

# ----------------------
# Create working directory
# ----------------------
echo "Create working directory"
export WRKDIR=/opt
mkdir -p ${WRKDIR}
cd ${WRKDIR}
rm -rf SafeScale

# ----------------------
# Get source code
# ----------------------
echo "Get source code"
BRANCH_NAME=${BRANCH_NAME:="develop"}
GIT_REPO_URL=${GIT_REPO_URL:="https://github.com/CS-SI/SafeScale.git"}
echo "Cloning branch '${BRANCH_NAME}' from repo '${GIT_REPO_URL}'"

git clone ${GIT_REPO_URL} -b ${BRANCH_NAME} --depth=1

cd SafeScale
sed -i "s#\(.*\)develop#\1${BRANCH_NAME}#" common.mk

# ----------------------
# Compile
# ----------------------
echo "Get dev deps"
make getdevdeps
[ $? -ne 0 ] && echo "Build getdevdeps failure" && exit 1

counter=6
until [[ -n $(which stringer) ]]; do
  hash -r
  make getdevdeps
  [ $? -ne 0 ] && echo "Build getdevdeps failure" && exit 1
  sleep 35
  let counter-=1
  [ $counter -le 0 ] && echo "Build getdevdeps failure, too many iterations" && exit 1
done

echo "Ensure"
make ensure
[ $? -ne 0 ] && echo "Build ensure failure" && exit 1

echo "All"
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
