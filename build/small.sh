#! /bin/bash -x

whydied() {
    ./safescale ssh run -c "sudo zip -r /tmp/dump.zip /opt/safescale/" $1 || return 1
    ./safescale ssh copy $1:/tmp/dump.zip ~/.safescale/$2-$1-forensics.zip || return 2
    ./safescale ssh run -c "sudo rm -rf /tmp/dump.zip" $1 || return 3
    return 0
}

whylives() {
    ./safescale ssh run -c "sudo zip -r /tmp/dump.zip /opt/safescale/" $1 || return 1
    ./safescale ssh copy $1:/tmp/dump.zip ~/.safescale/$2-$1-alive.zip || return 2
    ./safescale ssh run -c "sudo rm -rf /tmp/dump.zip" $1 || return 3
    return 0
}

alert() {
	notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$1"
}

settos() {
    if [ -z "$1" ]
    then
        echo "No timeout specified"
    else
        export SAFESCALE_EXECUTION_TIMEOUT=$1
        export SAFESCALE_HOST_TIMEOUT=$1
        export SAFESCALE_HOST_CREATION_TIMEOUT=$1
        export SAFESCALE_SSH_CONNECT_TIMEOUT=$1
        export SAFESCALE_METADATA_SUFFIX=citests
        export SAFESCALE_FORENSICS=True
        export SAFESCALED_PORT=$((((RANDOM + RANDOM) % 43001) + 22000))
    fi
}

echo "Checks..."
if [[ ! -v BUILD_ENV ]]; then
    echo "BUILD_ENV is not set, this script is intented to run inside a docker container" && exit 1
fi

if [[ ! -v TENANT ]]; then
    echo "TENANT is not set..." && exit 1
fi

settos 24m

./safescaled -d -v &

sleep 3

./safescale tenant set $TENANT

sleep 3

RETCODE=0

ROUNDS=5

CODE=0
RUN=0
CLEAN=0

declare -a flavor=("k8s" "boh")

for fla in "${flavor[@]}"
do
  RUN=0

  for i in $(seq $ROUNDS); do
    ./safescale cluster delete clu-$TENANT-$fla-r$i -y
    ./safescale cluster create -F $fla --os "ubuntu 18.04" --sizing "cpu=2,ram>=2,disk>=10" --cidr 10.4.$i.0/24 clu-$TENANT-$fla-r$i
    RUN=$?
    if [[ $RUN -ne 0 ]]; then
      CODE=$((CODE + 1))
    fi
    machines=$(./safescale host ls | tail -n 1 | jq '.result' | jq -r '.[] | .name')
    stamp=`date +"%s"`
    nmach=$(echo $machines | wc -w)

    for machine in $machines
    do
    if [[ $RUN -eq 0 ]]; then
      whylives $machine $stamp
    else
      whydied $machine $stamp
    fi
    done

    if [[ $nmach -ne 3 ]]; then
      CLEAN=$((CLEAN + 1))
    fi

    ./safescale cluster delete clu-$TENANT-$fla-r$i -y
    if [[ $? -ne 0 ]]; then
      CLEAN=$((CLEAN + 1))
    fi

    if [[ $RUN -eq 0 ]]; then
      CODE=0
      break
    fi
  done

  if [[ $CODE -ne 0 ]]; then
    RETCODE=$((RETCODE + CODE))
  fi
  
  for i in $(seq $ROUNDS); do
    ./safescale cluster delete clu-$TENANT-$fla-r$i -y
    ./safescale cluster create -F $fla --os "centos 7" --sizing "cpu=2,ram>=2,disk>=10" --cidr 10.7.$i.0/24 clu-$TENANT-$fla-r$i
    RUN=$?
    if [[ $RUN -ne 0 ]]; then
      CODE=$((CODE + 1))
    fi
    machines=$(./safescale host ls | tail -n 1 | jq '.result' | jq -r '.[] | .name')
    stamp=`date +"%s"`
    nmach=$(echo $machines | wc -w)

    for machine in $machines
    do
    if [[ $RUN -eq 0 ]]; then
      whylives $machine $stamp
    else
      whydied $machine $stamp
    fi
    done

    if [[ $nmach -ne 3 ]]; then
      CLEAN=$((CLEAN + 1))
    fi

    ./safescale cluster delete clu-$TENANT-$fla-r$i -y
    if [[ $? -ne 0 ]]; then
      CLEAN=$((CLEAN + 1))
    fi

    if [[ $RUN -eq 0 ]]; then
      CODE=0
      break
    fi
  done

  if [[ $CODE -ne 0 ]]; then
    RETCODE=$((RETCODE + CODE))
  fi
done

if [[ $RETCODE -eq 0 ]]; then
  exit $RETCODE
fi

exit $((CLEAN + RETCODE))
