# Building SafeScale for Debian

## Prepare environment
```bash
$ sudo apt-get update -y
$ sudo apt-get install -y build-essential make wget unzip vim git
```

## Install GO 1.16.15
```bash
$ wget https://dl.google.com/go/go1.16.15.linux-amd64.tar.gz
$ sudo tar -C /usr/local -xzf go1.16.15.linux-amd64.tar.gz
$ rm ./go1.16.15.linux-amd64.tar.gz
```

## Install Protoc 3.17.3
```bash
$ PROTOCZIP=$(echo "protoc-3.17.3-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m).zip")
$ wget https://github.com/google/protobuf/releases/download/v3.17.3/$PROTOCZIP
$ sudo unzip -d /usr/local/include/protoc $PROTOCZIP
$ sudo ln -s /usr/local/include/protoc/bin/protoc /usr/local/bin/
$ rm -rf $PROTOCZIP
$ unset PROTOCZIP
```

## Prepare environment vars
```bash
$ echo -e "\nexport GOPATH=~/go" >> ~/.bashrc
$ echo -e "\nexport PATH=/usr/local/go/bin:/go/bin:\$PATH:~/go/bin" >> ~/.bashrc
$ source ~/.bashrc
```

## Build
```bash
# Prepare directory
$ mkdir -p ${GOPATH:-$HOME}/src/github.com/CS-SI

# Clone SafeScale
$ cd ${GOPATH:-$HOME}/src/github.com/CS-SI
$ git clone https://github.com/CS-SI/SafeScale

$ cd SafeScale
$ git checkout -b develop -t origin/develop

$ go mod tidy

# Show help
$ make

# Build SafeScale
$ make all

# Copy the binaries to $HOME/go/bin
$ make install
```
