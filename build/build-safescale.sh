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

if [ -z "$COMMITSHA" ]
then
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
else
	# ----------------------
	# Get source code
	# ----------------------
	echo "Get source code, commit $COMMITSHA"
	GIT_REPO_URL=${GIT_REPO_URL:="https://github.com/CS-SI/SafeScale.git"}

	git clone ${GIT_REPO_URL}
	cd SafeScale

	git reset --hard $COMMITSHA
    sed -i "s#\(.*\)develop#\1${BRANCH_NAME}#" common.mk
fi

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

echo "Make All"
make release
[ $? -ne 0 ] && echo "Build failure" && exit 1

echo "Install"
make install
[ $? -ne 0 ] && echo "Install failure" && exit 1

echo "Export"
export CIBIN=/exported
mkdir -p /exported

CIBIN=/exported make installci force_sdk_js force_sdk_python
[ $? -ne 0 ] && echo "Export failure" && exit 1

cp ${WRKDIR}/SafeScale/go.mod /exported
cp ${WRKDIR}/SafeScale/go.sum /exported
cp ${WRKDIR}/SafeScale/lib/protocol/javascript/* /exported
cp ${WRKDIR}/SafeScale/lib/protocol/python3/* /exported

exit 0
