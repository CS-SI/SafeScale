# Building SafeScale for MacOS

## Install brew
```
```

## Prepare environment
```
$ brew install 
```

## Install GO 1.10
```
wget https://dl.google.com/go/go1.10.3.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.10.3.linux-amd64.tar.gz
rm ./go1.10.3.linux-amd64.tar.gz
```

## Install Protoc 3.6.1
```
brew install protoc
```

## Prepare environment vars
```bash
echo -e "\nexport GOPATH=~/go" >> ~/.bashrc
echo -e "\nexport PATH=/usr/local/go/bin:/go/bin:\$PATH:~/go/bin" >> ~/.bashrc
source ~/.bashrc
```

```zsh
echo -e "\nexport GOPATH=~/go" >> ~/.zshrc
echo -e "\nexport PATH=/usr/local/go/bin:/go/bin:\$PATH:~/go/bin" >> ~/.zshrc
source ~/.zshrc
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

## Cross-Compilation
### Linux amd64 binaries
#### Using GOLANG cross-compilation capability
```bash
$ unset GOBIN
$ export GOOS=linux GOARCH=amd64
$ make clean && make all
```
Binaries will be saved in cli/safescale/safescale, cli/safescaled/safescaled, cli/scanner/scanner
Note: cross-compiled go binaries will not be able tyo handle data races...

#### Using docker container
```bash
$ cd build
$ build-safescale.sh
```
Binaries will be saved to ???
Note: these binaries will include data race handling.

### Linux ARMv5 binaries (Raspberry)
```bash
$ unset GOBIN
$ export GOOS=linux GOARCH=arm GOARM=v5
$ make clean && make all
```

Generated binaries will not contain data race handling
Note: cross-compiled go binaries will not be able tyo handle data races...
