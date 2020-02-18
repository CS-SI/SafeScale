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
BRANCH_NAME=${BRANCH_NAME:="develop"}
GIT_REPO_URL=${GIT_REPO_URL:="https://github.com/CS-SI/SafeScale.git"}
echo "Cloning branch '${BRANCH_NAME}' from repo '${GIT_REPO_URL}'"

git clone ${GIT_REPO_URL} -b ${BRANCH_NAME} --depth=1

cd SafeScale

# ----------------------
# Compile
# ----------------------
echo "Compile"
make all

echo "Install"
make install

echo "Export"
export CIBIN=/exported
mkdir -p /exported

CIBIN=/exported make installci
[ $? -ne 0 ] && echo "Export failure" && return 1

return 0