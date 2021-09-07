#!/usr/bin/env bats

cp ./bash_library.sh ./bash_library.bash
load ./bash_library

function wrong() {
    export SF_BASEDIR=/tmp
    export SF_VARDIR=${SF_BASEDIR}/var
    export SF_LOGDIR=${SF_VARDIR}/log
    sfDownload "https://nodejs.org/dist/v14.17.6/node-v14.17.6-linux-fx64.tar.xz" node_exporter.tar.gz 3m 5 || {
        rco=$?
        echo "failed to create dropzone (exit code $rco)"
        return $rco
    }
    return 0
}

function down_ok() {
    export SF_BASEDIR=/tmp
    export SF_VARDIR=${SF_BASEDIR}/var
    export SF_LOGDIR=${SF_VARDIR}/log
    sfDownload "https://nodejs.org/dist/v14.17.6/node-v14.17.6-linux-x64.tar.xz" node_exporter.tar.gz 3m 5 || {
        rco=$?
        echo "failed to create dropzone (exit code $rco)"
        return $rco
    }
    rm ./node_exporter.tar.gz || true
    return 0
}

@test "download the wrong file" {
  run wrong
  [ "$status" -eq 22 ]
}

@test "download the right file" {
  run down_ok
  [ "$status" -eq 0 ]
}

rm ./bash_library.bash