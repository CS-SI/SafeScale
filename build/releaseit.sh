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
tar -czf safescale-$1-linux-amd64.tar.gz -C ./exported/safescale ./exported/safescaled .
tar -czf safescale-$1-linux-arm.tar.gz -C ./exported-linux-arm/safescale ./exported-linux-arm/safescaled .
tar -czf safescale-$1-darwin-arm64.tar.gz -C ./exported-darwin-arm64/safescale ./exported-darwin-arm64/safescaled .
tar -czf safescale-$1-windows-amd64.tar.gz -C ./exported-windows-amd64/sa*.exe .
