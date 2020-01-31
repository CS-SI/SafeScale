#! /bin/sh

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

# ----------------------
# Compile
# ----------------------
echo "Get dev deps"
make getdevdeps

echo "Ensure"
make ensure >/dev/null 2>&1
make ensure

echo "All"
make all

echo "Install"
make install

echo "Export"
CIBIN=/export make installci
