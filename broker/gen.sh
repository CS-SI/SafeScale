protoc -I. -I${GOPATH:-~/go}/src --go_out=plugins=grpc:. brokerd.proto
