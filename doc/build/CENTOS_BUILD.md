# Building SafeScale for Centos

## Prepare environment
```
sudo yum -y check-update
sudo yum groupinstall -y "Development Tools"
sudo yum install -y wget unzip vim git
```

## Install GO 1.10.3
```
wget https://dl.google.com/go/go1.10.3.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.10.3.linux-amd64.tar.gz
rm ./go1.10.3.linux-amd64.tar.gz
```

## Install Protoc 3.6
```
PROTOCZIP=$(echo "protoc-3.6.1-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m).zip")
wget https://github.com/google/protobuf/releases/download/v3.6.1/$PROTOCZIP
sudo unzip -d /usr/local/include/protoc $PROTOCZIP
sudo ln -s /usr/local/include/protoc/bin/protoc /usr/local/bin/
rm -rf protoc
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