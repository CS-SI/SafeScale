#! /bin/bash -x

docker system prune -a -f
./create-docker.sh -f
docker system prune -a -f
GOOSX=darwin GOARCHX=arm64 ./create-docker2.sh -f
docker system prune -a -f
GOOSX=linux GOARCHX=arm ./create-docker2.sh -f
docker system prune -a -f
GOOSX=windows GOARCHX=amd64 ./create-docker2.sh -f
docker system prune -a -f
mv ./exported-windows-amd64/safescale ./exported-windows-amd64/safescale.exe
mv ./exported-windows-amd64/safescaled ./exported-windows-amd64/safescaled.exe
tar -czf safescale-$1-linux-amd64.tar.gz ./exported/sa*
tar -czf safescale-$1-linux-arm.tar.gz ./exported-linux-arm/sa*
tar -czf safescale-$1-darwin-arm64.tar.gz ./exported-darwin-arm64/sa*
tar -czf safescale-$1-windows-amd64.tar.gz ./exported-windows-amd64/sa*
