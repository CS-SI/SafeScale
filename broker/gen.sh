protoc -I. -I${GOPATH:-~/go}/src --go_out=plugins=grpc:. brokerd.proto
protoc -I. -I${GOPATH:-~/go}/src --python_out=plugins=grpc:. brokerd.proto
