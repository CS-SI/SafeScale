# Building SafeScale for Ubuntu

## Prepare environment
```
sudo apt-get update -y
sudo apt-get install -y build-essential make wget unzip vim git
```

## Install GO 1.13.12
Building requires at least `go` version 1.12 (at the time this documentation is written, the version provided is 1.14.3)
```
wget https://dl.google.com/go/go1.13.12.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.13.12.linux-amd64.tar.gz
rm ./go1.13.12.linux-amd64.tar.gz
```

## Install Protoc 3.6.1
Building requires at least `protoc` version 3.6.0 (at the time this documentation is written, the version provided is 3.12.1)
```
PROTOCZIP=$(echo "protoc-3.6.1-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m).zip")
wget https://github.com/google/protobuf/releases/download/v3.6.1/$PROTOCZIP
sudo unzip -d /usr/local/include/protoc $PROTOCZIP
sudo chmod ugo+r -R /usr/local/include/protoc
sudo ln -s /usr/local/include/protoc/bin/protoc /usr/local/bin/
rm -rf ./$PROTOCZIP
unset PROTOCZIP
```

## Prepare environment vars
```
echo -e "\nexport GOPATH=~/go" >> ~/.bashrc
echo -e "\nexport PATH=/usr/local/go/bin:/go/bin:\$PATH:~/go/bin" >> ~/.bashrc
source ~/.bashrc
```

## Build
```
# Prepare directory
mkdir -p ${GOPATH:-$HOME}/src/github.com/CS-SI

# Clone SafeScale
cd ${GOPATH:-$HOME}/src/github.com/CS-SI
git clone https://github.com/CS-SI/SafeScale

cd SafeScale
git checkout -b develop -t origin/develop

# Show help
make

# Build SafeScale
make all

# Copy the binaries to $HOME/go/bin
make install
```
