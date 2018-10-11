# Building instructions for SafeScale

## Prerequisites

- Minimum go version, [GO 1.10](https://golang.org/dl/)
    - Add $GOPATH/bin to your PATH
        - ```echo "export PATH=$PATH:${GOPATH:-$HOME/go}/bin" >> $HOME/.profile ```
- Protoc
    - Download the precompiled version of protobuf for your platform in [github](https://github.com/google/protobuf/releases/)
    - Follow install instructions
    - ex: ```cd /tmp && PROTOCZIP=$(echo "protoc-3.6.1-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m).zip") && wget https://github.com/protocolbuffers/protobuf/releases/download/v3.6.1/$PROTOCZIP && unzip -d protoc $PROTOCZIP && cp /tmp/protoc/bin/protoc /usr/local/bin/ && cp -r /tmp/protoc/include /usr/local/include && rm -rf /tmp/protoc && rm /tmp/$PROTOCZIP && unset $PROTOCZIP```
- make


## Build

```bash
# Prepare directory
mkdir -p ${GOPATH:-$HOME/go}/src/github.com/CS-SI

# Clone SafeScale
cd ${GOPATH:-$HOME/go}/src/github.com/CS-SI
git clone https://github.com/CS-SI/SafeScale -b develop

cd SafeScale

# Show help
make

# Build SafeScale
make all
```

These commands initialize your working directory and produce the following binaries:

 - `broker` in `SafeScale/broker/client`: CLI to deal with daemon brokerd. Available commands are described in [usage](#USAGE.md)
 - `broker-cover` in `SafeScale/broker/client`: A version of broker that generates coverage reports. Intended only for developers.
 - `brokerd` in `SafeScale/broker/daemon`: daemon in charge of executing requests from broker on providers
 - `brokerd-cover` in `SafeScale/broker/daemon`: A version of brokerd that generates coverage reports.  Intended only for developers.
 - `perform` in `SafeScale/perform`: CLI to manage cluster. Available commands are described in [usage](#USAGE.md)