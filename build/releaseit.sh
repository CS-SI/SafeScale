#! /bin/bash -x

if [ -z "$1" ]; then
	echo "Must specify a version number ..."
	exit 1
fi

export BRANCH_NAME=develop
docker system prune -a -f
BRANCH_NAME=develop ./create-docker.sh -f
docker system prune -a -f
BRANCH_NAME=develop GOOSX=darwin GOARCHX=arm64 ./create-docker2.sh -f
docker system prune -a -f
BRANCH_NAME=develop GOOSX=linux GOARCHX=arm ./create-docker2.sh -f
docker system prune -a -f
BRANCH_NAME=develop GOOSX=windows GOARCHX=amd64 ./create-docker2.sh -f
docker system prune -a -f
mv ./exported-windows-amd64/safescale ./exported-windows-amd64/safescale.exe
mv ./exported-windows-amd64/safescaled ./exported-windows-amd64/safescaled.exe
tar -czf safescale-$1-linux-amd64.tar.gz -C ./exported .
tar -czf safescale-$1-linux-arm.tar.gz -C ./exported-linux-arm .
tar -czf safescale-$1-darwin-arm64.tar.gz -C ./exported-darwin-arm64 .
tar -czf safescale-$1-windows-amd64.tar.gz -C ./exported-windows-amd64 .
