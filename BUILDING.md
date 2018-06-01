# Building instruction for SafeScale

## Prerequisites

- [GO 1.10](https://golang.org/dl/)
- Protoc
    - Download the compiler from [github](https://github.com/google/protobuf/releases/)
    - Follow install instruction
- make
- Transitive dependencies


## Build

```bash
# Prepare directory
mkdir -p ${GOPATH:-$HOME}/src/github.com/CS-SI

# Clone SafeScale
cd ${GOPATH:-$HOME}/src/github.com/CS-SI
git clone https://github.com/CS-SI/SafeScale

# Get dependecies
cd ${GOPATH:-$HOME}/src/github.com/CS-SI/SafeScale
make deps

# Build SafeScale
make
```