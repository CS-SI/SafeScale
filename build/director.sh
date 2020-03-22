#! /bin/bash -x

echo "Checks..."
if [[ ! -v BUILD_ENV ]]; then
    echo "BUILD_ENV is not set, this script is intented to run inside a docker container" && exit 1
fi

if [[ ! -v TENANT ]]; then
    echo "TENANT is not set..." && exit 1
fi

if [[ $(echo $TENANT | grep lexible) ]]; then
  sed -i 's/10.4/192.168/' small.sh
  sed -i 's/10.7/192.168/' small.sh
  sed -i 's/10.$frag.$i/192.168.$nfrag/' small.sh

  sed -i 's/10.4/192.168/' medium.sh
  sed -i 's/10.7/192.168/' medium.sh
  sed -i 's/10.$frag.$i/192.168.$nfrag/' medium.sh

  sed -i 's/10.4/192.168/' large.sh
  sed -i 's/10.7/192.168/' large.sh
  sed -i 's/10.$frag.$i/192.168.$nfrag/' large.sh

  sed -i 's/10.4/192.168/' poc.sh
  sed -i 's/10.7/192.168/' poc.sh
  sed -i 's/10.$frag.$i/192.168.$nfrag/' poc.sh
fi

./poc.sh || true

exit 0