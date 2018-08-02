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
BRANCHNAME=${BRANCHNAME:="develop"}
echo "Cloning branch ${BRANCHNAME}"
git clone file:///home/saime/Projects/safescale/dev/SafeScale -b ${BRANCHNAME} --depth=1

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
