GOPATH?=$(HOME)/go
GO?=go

.PHONY:	sdk clean

all:	cli

vet:
	@$(GO) vet
	@$(GO) vet ./utils

sdk:	broker.proto
	@protoc -I. -I$(GOPATH)/src --go_out=plugins=grpc:. broker.proto

cli:	sdk
	@(cd cli && $(MAKE))

clean:
	@(cd cli && $(MAKE) $@)
	@($(RM) broker_pb2.py broker.pb.go)
