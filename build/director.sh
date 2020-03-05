#! /bin/bash -x

echo "Checks..."
if [[ ! -v BUILD_ENV ]]; then
    echo "BUILD_ENV is not set, this script is intented to run inside a docker container" && return 1
fi

export TENANT=google
./small.sh
