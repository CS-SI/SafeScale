#! /bin/sh

# ----------------------
# Creation working directory
# ----------------------
WRKDIR=${GOPATH=/go}/src/github.com/CS-SI
mkdir -p ${WRKDIR}
cd ${WRKDIR}
rm -rf SafeScale

# ----------------------
# Get source code
# ----------------------
BRANCH_NAME=${BRANCH_NAME:="develop"}
echo "Cloning branch ${BRANCH_NAME}"

GIT_REPO_URL=${GIT_REPO_URL:="https://github.com/CS-SI/SafeScale.git"}
git clone ${GIT_REPO_URL} -b ${BRANCH_NAME} --depth=1

cd SafeScale

# ----------------------
# Get dependencies
# ----------------------
make deps

# ----------------------
# Compile
# ----------------------
make

# ----------------------
# Install
# ----------------------
export GOBIN=${GOBIN=/go/bin}
make install

# ----------------------
# Copy produced binaries to export directory
# ----------------------
EXPDIR=/usr/local/safescale/bin
mkdir -p ${EXPDIR}
cp ${GOBIN}/broker ${EXPDIR}
cp ${GOBIN}/brokerd ${EXPDIR}
cp ${GOBIN}/deploy ${EXPDIR}
cp ${GOBIN}/perform ${EXPDIR}
