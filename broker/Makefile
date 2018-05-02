GOPATH?="~/go"

all:	sdk brokerd broker

.PHONY:	broker brokerd clean

sdk:	brokerd.proto
	protoc -I. -I$(GOPATH)/src --go_out=plugins=grpc:. brokerd.proto
	protoc -I. -I$(GOPATH)/src --python_out=plugins=grpc:. brokerd.proto

brokerd:
	@(cd brokerd && $(MAKE) $@)

broker:
	@(cd broker && $(MAKE) $@)

clean:
	@(cd broker && $(MAKE) $@)
	@(cd brokerd && $(MAKE) $@)
	@rm -f brokerd_pb2.py brokerd.pb.go
