# Building instruction for SafeScale

## Prerequisites

- [GO 1.10](https://golang.org/dl/)
- Protoc
    - Download the compiler from [github](https://github.com/google/protobuf/releases/)
    - Follow install instruction
- make
- Transitive dependencies. Note: most dependencies are retrived with `make deps` command ([see below](#Build))


## Build

```bash
# Prepare directory
mkdir -p ${GOPATH:-$HOME}/src/github.com/CS-SI

# Clone SafeScale
cd ${GOPATH:-$HOME}/src/github.com/CS-SI
git clone https://github.com/CS-SI/SafeScale

# Show help
make

# Build SafeScale
make all
```

These commands intitialize your workging directory and produces the folowwing binaries:

 - `broker` in `SafeScale/broker/client`: CLI to deal with daemon brokerd. Available commands are described in [usage](#USAGE.md)
 - `brokerd` in `SafeScale/broker/daemon`: daemon in charge of executing requests from broker on providers
 - `perform` in `SafeScale/perform`: CLI to manage cluster. Available commands are described in [usage](#USAGE.md)