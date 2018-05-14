GOPATH?=$(HOME)/go

all:	brokerd broker

.PHONY:	sdk broker brokerd clean

sdk:	broker.proto
	@protoc -I. -I$(GOPATH)/src --go_out=plugins=grpc:. broker.proto
	@protoc -I. -I$(GOPATH)/src --python_out=plugins=grpc:. broker.proto

brokerd:	sdk
	@(cd brokerd && $(MAKE) $@)

broker:	sdk
	@(cd broker && $(MAKE) $@)

clean:
	@(cd broker && $(MAKE) $@)
	@(cd brokerd && $(MAKE) $@)
	@(rm -f broker_pb2.py broker.pb.go)
