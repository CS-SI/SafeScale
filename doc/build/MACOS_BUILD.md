# Building SafeScale for MacOS

## Install Homebrew
An important dependency before Homebrew can work is the Command Line Tools for Xcode. These include compilers that will allow you to build things from source.
Then, to install brew:
```bash
$ ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

## Install go
Should be at least `go` version 1.17; at the time this doc is written, it's 1.17.12.
```bash
$ brew update
$ brew install golang
```

## Install protoc-gen-go
Must provide at least `protoc-gen-go` version 1.3.
```bash
$ brew install protoc-gen-go
```

## Prepare environment
```bash
$ mkdir -p ~/go-workspace # replace go-workspace with the path you want
$ export GOPATH=~/go-workspace # don't forget to change your path correctly!
$ export GOROOT=/usr/local/opt/go/libexec
$ export PATH=$PATH:$GOPATH/bin
$ export PATH=$PATH:$GOROOT/bin
```
You may want to put these commands in ~/.bashrc or ~/.zshrc to keep them after logout/restart.
 
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
