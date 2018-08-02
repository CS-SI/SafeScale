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
# Get dependencies
# ----------------------
echo "Get dependencies"
make deps

# ----------------------
# Compile
# ----------------------
echo "Compile"
make

# ----------------------
# Install
# ----------------------
echo "Install"
export GOBIN=${GOBIN=/go/bin}
make install

# ----------------------
# Copy produced binaries to export directory
# ----------------------
EXPDIR=/usr/local/safescale/bin
echo "Copy produced binaries to export directory '${EXPDIR}'"
mkdir -p ${EXPDIR}
cp ${GOBIN}/broker ${EXPDIR}
cp ${GOBIN}/brokerd ${EXPDIR}
cp ${GOBIN}/deploy ${EXPDIR}
cp ${GOBIN}/perform ${EXPDIR}
